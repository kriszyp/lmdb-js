/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <limits.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap_pvt.h"
#include "lutil.h"
#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi.h"
#endif

/* protected by connections_mutex */
static ldap_pvt_thread_mutex_t connections_mutex;
static Connection *connections = NULL;
static unsigned long conn_nextid = 0;

/* structure state (protected by connections_mutex) */
#define SLAP_C_UNINITIALIZED	0x00	/* MUST BE ZERO (0) */
#define SLAP_C_UNUSED			0x01
#define SLAP_C_USED				0x02

/* connection state (protected by c_mutex ) */
#define SLAP_C_INVALID			0x00	/* MUST BE ZERO (0) */
#define SLAP_C_INACTIVE			0x01	/* zero threads */
#define SLAP_C_ACTIVE			0x02	/* one or more threads */
#define SLAP_C_BINDING			0x03	/* binding */
#define SLAP_C_CLOSING			0x04	/* closing */
#define SLAP_C_CLIENT			0x05	/* outbound client conn */

const char *
connection_state2str( int state )
{
	switch( state ) {
	case SLAP_C_INVALID:	return "!";
	case SLAP_C_INACTIVE:	return "|";
	case SLAP_C_ACTIVE:		return "";
	case SLAP_C_BINDING:	return "B";
	case SLAP_C_CLOSING:	return "C";
	case SLAP_C_CLIENT:		return "L";
	}

	return "?";
}

static Connection* connection_get( ber_socket_t s );

static int connection_input( Connection *c );
static void connection_close( Connection *c );

static int connection_op_activate( Operation *op );
static int connection_resched( Connection *conn );
static void connection_abandon( Connection *conn );
static void connection_destroy( Connection *c );

static ldap_pvt_thread_start_t connection_operation;

/*
 * Initialize connection management infrastructure.
 */
int connections_init(void)
{
	assert( connections == NULL );

	if( connections != NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO,
			"connections_init: already initialized.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "connections_init: already initialized.\n",
			0, 0, 0 );
#endif
		return -1;
	}

	/* should check return of every call */
	ldap_pvt_thread_mutex_init( &connections_mutex );

	connections = (Connection *) ch_calloc( dtblsize, sizeof(Connection) );

	if( connections == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR,
			"connections_init: allocation (%d * %ld) of connection "
			"array failed\n", dtblsize, (long) sizeof(Connection), 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"connections_init: allocation (%d*%ld) of connection array failed\n",
			dtblsize, (long) sizeof(Connection), 0 );
#endif
		return -1;
	}

	assert( connections[0].c_struct_state == SLAP_C_UNINITIALIZED );
	assert( connections[dtblsize-1].c_struct_state == SLAP_C_UNINITIALIZED );

	/*
	 * per entry initialization of the Connection array initialization
	 * will be done by connection_init()
	 */ 

	return 0;
}

/*
 * Destroy connection management infrastructure.
 */
int connections_destroy(void)
{
	ber_socket_t i;

	/* should check return of every call */

	if( connections == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO,
			"connections_destroy: nothing to destroy.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "connections_destroy: nothing to destroy.\n",
			0, 0, 0 );
#endif
		return -1;
	}

	for ( i = 0; i < dtblsize; i++ ) {
		if( connections[i].c_struct_state != SLAP_C_UNINITIALIZED ) {
			ber_sockbuf_free( connections[i].c_sb );
			ldap_pvt_thread_mutex_destroy( &connections[i].c_mutex );
			ldap_pvt_thread_mutex_destroy( &connections[i].c_write_mutex );
			ldap_pvt_thread_cond_destroy( &connections[i].c_write_cv );
#ifdef LDAP_SLAPI
			if ( slapi_plugins_used ) {
				slapi_x_free_object_extensions( SLAPI_X_EXT_CONNECTION, &connections[i] );
			}
#endif
		}
	}

	free( connections );
	connections = NULL;

	ldap_pvt_thread_mutex_destroy( &connections_mutex );
	return 0;
}

/*
 * shutdown all connections
 */
int connections_shutdown(void)
{
	ber_socket_t i;

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	for ( i = 0; i < dtblsize; i++ ) {
		if( connections[i].c_struct_state != SLAP_C_USED ) {
			continue;
		}
		/* give persistent clients a chance to cleanup */
		if( connections[i].c_conn_state == SLAP_C_CLIENT ) {
			ldap_pvt_thread_pool_submit( &connection_pool,
			connections[i].c_clientfunc, connections[i].c_clientarg );
			continue;
		}

		ldap_pvt_thread_mutex_lock( &connections[i].c_mutex );

		/* connections_mutex and c_mutex are locked */
		connection_closing( &connections[i] );
		connection_close( &connections[i] );

		ldap_pvt_thread_mutex_unlock( &connections[i].c_mutex );
	}

	ldap_pvt_thread_mutex_unlock( &connections_mutex );

	return 0;
}

/*
 * Timeout idle connections.
 */
int connections_timeout_idle(time_t now)
{
	int i = 0;
	int connindex;
	Connection* c;

	for( c = connection_first( &connindex );
		c != NULL;
		c = connection_next( c, &connindex ) )
	{
		/* Don't timeout a slow-running request or a persistent
		 * outbound connection */
		if( c->c_n_ops_executing ||
			c->c_conn_state == SLAP_C_CLIENT ) continue;

		if( difftime( c->c_activitytime+global_idletimeout, now) < 0 ) {
			/* close it */
			connection_closing( c );
			connection_close( c );
			i++;
		}
	}
	connection_done( c );

	return i;
}

static Connection* connection_get( ber_socket_t s )
{
	/* connections_mutex should be locked by caller */

	Connection *c;

#ifdef NEW_LOGGING
	LDAP_LOG( CONNECTION, ENTRY, "connection_get: socket %ld\n", (long)s, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS,
		"connection_get(%ld)\n",
		(long) s, 0, 0 );
#endif

	assert( connections != NULL );

	if(s == AC_SOCKET_INVALID) {
		return NULL;
	}

#ifndef HAVE_WINSOCK
	c = &connections[s];

	assert( c->c_struct_state != SLAP_C_UNINITIALIZED );

#else
	c = NULL;
	{
		ber_socket_t i, sd;

		for(i=0; i<dtblsize; i++) {
			if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( connections[i].c_sb == 0 );
				break;
			}

			ber_sockbuf_ctrl( connections[i].c_sb,
				LBER_SB_OPT_GET_FD, &sd );

			if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( sd == AC_SOCKET_INVALID );
				continue;
			}

			/* state can actually change from used -> unused by resched,
			 * so don't assert details here.
			 */

			if( sd == s ) {
				c = &connections[i];
				break;
			}
		}
	}
#endif

	if( c != NULL ) {
		ber_socket_t	sd;

		ldap_pvt_thread_mutex_lock( &c->c_mutex );

		ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_GET_FD, &sd );
		if( c->c_struct_state != SLAP_C_USED ) {
			/* connection must have been closed due to resched */

			assert( c->c_conn_state == SLAP_C_INVALID );
			assert( sd == AC_SOCKET_INVALID );

#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, ARGS, 
				"connection_get: connection %d not used\n", s, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"connection_get(%d): connection not used\n",
				s, 0, 0 );
#endif

			ldap_pvt_thread_mutex_unlock( &c->c_mutex );
			return NULL;
		}
		if( c->c_conn_state == SLAP_C_CLIENT ) sd = 0;

#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, RESULTS, 
			"connection_get: get for %d got connid %lu\n", s, c->c_connid, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"connection_get(%d): got connid=%lu\n",
			s, c->c_connid, 0 );
#endif

		c->c_n_get++;

		assert( c->c_struct_state == SLAP_C_USED );
		assert( c->c_conn_state != SLAP_C_INVALID );
		assert( sd != AC_SOCKET_INVALID );

#ifdef SLAPD_MONITOR
		c->c_activitytime = slap_get_time();
#else
		if( global_idletimeout > 0 ) {
			c->c_activitytime = slap_get_time();
		}
#endif
	}

	return c;
}

static void connection_return( Connection *c )
{
	ldap_pvt_thread_mutex_unlock( &c->c_mutex );
}

long connection_init(
	ber_socket_t s,
	Listener *listener,
	const char* dnsname,
	const char* peername,
	int flags,
	slap_ssf_t ssf,
	const char *authid )
{
	unsigned long id;
	Connection *c;

	assert( connections != NULL );

	assert( listener != NULL );
	assert( dnsname != NULL );
	assert( peername != NULL );

#ifndef HAVE_TLS
	assert( flags != CONN_IS_TLS );
#endif

	if( s == AC_SOCKET_INVALID ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_init: init of socket %ld invalid.\n", (long)s, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"connection_init: init of socket %ld invalid.\n", (long)s, 0, 0 );
#endif
		return -1;
	}

	assert( s >= 0 );
#ifndef HAVE_WINSOCK
	assert( s < dtblsize );
#endif

	ldap_pvt_thread_mutex_lock( &connections_mutex );

#ifndef HAVE_WINSOCK
	c = &connections[s];

#else
	{
		ber_socket_t i;
		c = NULL;

		for( i=0; i < dtblsize; i++) {
			ber_socket_t	sd;

			if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
				assert( connections[i].c_sb == 0 );
				c = &connections[i];
				break;
			}

			sd = AC_SOCKET_INVALID;
			if (connections[i].c_sb != NULL) {
				ber_sockbuf_ctrl( connections[i].c_sb,
					LBER_SB_OPT_GET_FD, &sd );
			}

			if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
				assert( sd == AC_SOCKET_INVALID );
				c = &connections[i];
				break;
			}

			assert( connections[i].c_struct_state == SLAP_C_USED );
			assert( connections[i].c_conn_state != SLAP_C_INVALID );
			assert( sd != AC_SOCKET_INVALID );
		}

		if( c == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, INFO, 
				"connection_init(%d): connection table full "
				"(%d/%d)\n", s, i, dtblsize );
#else
			Debug( LDAP_DEBUG_ANY,
				"connection_init(%d): connection table full "
				"(%d/%d)\n", s, i, dtblsize);
#endif
			ldap_pvt_thread_mutex_unlock( &connections_mutex );
			return -1;
		}
	}
#endif

	assert( c != NULL );

	if( c->c_struct_state == SLAP_C_UNINITIALIZED ) {
		c->c_send_ldap_result = slap_send_ldap_result;
		c->c_send_search_entry = slap_send_search_entry;
		c->c_send_search_reference = slap_send_search_reference;
		c->c_send_ldap_extended = slap_send_ldap_extended;
#ifdef LDAP_RES_INTERMEDIATE
		c->c_send_ldap_intermediate = slap_send_ldap_intermediate;
#endif

		c->c_authmech.bv_val = NULL;
		c->c_authmech.bv_len = 0;
		c->c_dn.bv_val = NULL;
		c->c_dn.bv_len = 0;
		c->c_ndn.bv_val = NULL;
		c->c_ndn.bv_len = 0;

		c->c_listener = NULL;
		c->c_peer_domain.bv_val = NULL;
		c->c_peer_domain.bv_len = 0;
		c->c_peer_name.bv_val = NULL;
		c->c_peer_name.bv_len = 0;

		LDAP_STAILQ_INIT(&c->c_ops);
		LDAP_STAILQ_INIT(&c->c_pending_ops);

		c->c_sasl_bind_mech.bv_val = NULL;
		c->c_sasl_bind_mech.bv_len = 0;
		c->c_sasl_done = 0;
		c->c_sasl_authctx = NULL;
		c->c_sasl_sockctx = NULL;
		c->c_sasl_extra = NULL;
		c->c_sasl_bindop = NULL;

		c->c_sb = ber_sockbuf_alloc( );

		{
			ber_len_t max = sockbuf_max_incoming;
			ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
		}

		c->c_currentber = NULL;

		/* should check status of thread calls */
		ldap_pvt_thread_mutex_init( &c->c_mutex );
		ldap_pvt_thread_mutex_init( &c->c_write_mutex );
		ldap_pvt_thread_cond_init( &c->c_write_cv );

#ifdef LDAP_SLAPI
		if ( slapi_plugins_used ) {
			slapi_x_create_object_extensions( SLAPI_X_EXT_CONNECTION, c );
		}
#endif

		c->c_struct_state = SLAP_C_UNUSED;
	}

	ldap_pvt_thread_mutex_lock( &c->c_mutex );

	assert( c->c_struct_state == SLAP_C_UNUSED );
	assert( c->c_authmech.bv_val == NULL );
	assert( c->c_dn.bv_val == NULL );
	assert( c->c_ndn.bv_val == NULL );
	assert( c->c_listener == NULL );
	assert( c->c_peer_domain.bv_val == NULL );
	assert( c->c_peer_name.bv_val == NULL );
	assert( LDAP_STAILQ_EMPTY(&c->c_ops) );
	assert( LDAP_STAILQ_EMPTY(&c->c_pending_ops) );
	assert( c->c_sasl_bind_mech.bv_val == NULL );
	assert( c->c_sasl_done == 0 );
	assert( c->c_sasl_authctx == NULL );
	assert( c->c_sasl_sockctx == NULL );
	assert( c->c_sasl_extra == NULL );
	assert( c->c_sasl_bindop == NULL );
	assert( c->c_currentber == NULL );

	c->c_listener = listener;

	if ( flags == CONN_IS_CLIENT ) {
		c->c_conn_state = SLAP_C_CLIENT;
		c->c_struct_state = SLAP_C_USED;
		ldap_pvt_thread_mutex_unlock( &c->c_mutex );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );

		return 0;
	}

	ber_str2bv( dnsname, 0, 1, &c->c_peer_domain );
	ber_str2bv( peername, 0, 1, &c->c_peer_name );

	c->c_n_ops_received = 0;
	c->c_n_ops_executing = 0;
	c->c_n_ops_pending = 0;
	c->c_n_ops_completed = 0;

	c->c_n_get = 0;
	c->c_n_read = 0;
	c->c_n_write = 0;

	/* set to zero until bind, implies LDAP_VERSION3 */
	c->c_protocol = 0;

#ifdef SLAPD_MONITOR
	c->c_activitytime = c->c_starttime = slap_get_time();
#else
	if( global_idletimeout > 0 ) {
		c->c_activitytime = c->c_starttime = slap_get_time();
	}
#endif

#ifdef LDAP_CONNECTIONLESS
	c->c_is_udp = 0;
	if( flags == CONN_IS_UDP ) {
		c->c_is_udp = 1;
#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_PROVIDER, (void*)"udp_" );
#endif
		ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_udp,
			LBER_SBIOD_LEVEL_PROVIDER, (void *)&s );
		ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_readahead,
			LBER_SBIOD_LEVEL_PROVIDER, NULL );
	} else
#endif
	{
#ifdef LDAP_DEBUG
		ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
			LBER_SBIOD_LEVEL_PROVIDER, (void*)"tcp_" );
#endif
		ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_tcp,
			LBER_SBIOD_LEVEL_PROVIDER, (void *)&s );
	}

#ifdef LDAP_DEBUG
	ber_sockbuf_add_io( c->c_sb, &ber_sockbuf_io_debug,
		INT_MAX, (void*)"ldap_" );
#endif

	if( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_NONBLOCK,
		c /* non-NULL */ ) < 0 )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_init: conn %lu set nonblocking failed\n",
			c->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"connection_init(%d, %s): set nonblocking failed\n",
			s, c->c_peer_name.bv_val, 0 );
#endif
	}

	id = c->c_connid = conn_nextid++;

	c->c_conn_state = SLAP_C_INACTIVE;
	c->c_struct_state = SLAP_C_USED;

	c->c_ssf = c->c_transport_ssf = ssf;
	c->c_tls_ssf = 0;

#ifdef HAVE_TLS
	if ( flags == CONN_IS_TLS ) {
		c->c_is_tls = 1;
		c->c_needs_tls_accept = 1;
	} else {
		c->c_is_tls = 0;
		c->c_needs_tls_accept = 0;
	}
#endif

	slap_sasl_open( c, 0 );
	slap_sasl_external( c, ssf, authid );

	ldap_pvt_thread_mutex_unlock( &c->c_mutex );
	ldap_pvt_thread_mutex_unlock( &connections_mutex );

	backend_connection_init(c);

	return id;
}

void connection2anonymous( Connection *c )
{
	assert( connections != NULL );
	assert( c != NULL );

	{
		ber_len_t max = sockbuf_max_incoming;
		ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
	}

	if(c->c_authmech.bv_val != NULL ) {
		free(c->c_authmech.bv_val);
		c->c_authmech.bv_val = NULL;
	}
	c->c_authmech.bv_len = 0;

	if(c->c_dn.bv_val != NULL) {
		free(c->c_dn.bv_val);
		c->c_dn.bv_val = NULL;
	}
	c->c_dn.bv_len = 0;
	if(c->c_ndn.bv_val != NULL) {
		free(c->c_ndn.bv_val);
		c->c_ndn.bv_val = NULL;
	}
	c->c_ndn.bv_len = 0;

	c->c_authz_backend = NULL;
}

static void
connection_destroy( Connection *c )
{
	/* note: connections_mutex should be locked by caller */
	ber_socket_t	sd;
	unsigned long	connid;

	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state != SLAP_C_UNUSED );
	assert( c->c_conn_state != SLAP_C_INVALID );
	assert( LDAP_STAILQ_EMPTY(&c->c_ops) );

	/* only for stats (print -1 as "%lu" may give unexpected results ;) */
	connid = c->c_connid;

	backend_connection_destroy(c);

	c->c_protocol = 0;
	c->c_connid = -1;

	c->c_activitytime = c->c_starttime = 0;

	connection2anonymous( c );
	c->c_listener = NULL;

	if(c->c_peer_domain.bv_val != NULL) {
		free(c->c_peer_domain.bv_val);
		c->c_peer_domain.bv_val = NULL;
	}
	c->c_peer_domain.bv_len = 0;
	if(c->c_peer_name.bv_val != NULL) {
		free(c->c_peer_name.bv_val);
		c->c_peer_name.bv_val = NULL;
	}
	c->c_peer_name.bv_len = 0;

	c->c_sasl_bind_in_progress = 0;
	if(c->c_sasl_bind_mech.bv_val != NULL) {
		free(c->c_sasl_bind_mech.bv_val);
		c->c_sasl_bind_mech.bv_val = NULL;
	}
	c->c_sasl_bind_mech.bv_len = 0;

	slap_sasl_close( c );

	if ( c->c_currentber != NULL ) {
		ber_free( c->c_currentber, 1 );
		c->c_currentber = NULL;
	}

	ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_GET_FD, &sd );
	if ( sd != AC_SOCKET_INVALID ) {
		slapd_remove( sd, 1, 0 );

		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu fd=%ld closed\n",
			connid, (long) sd, 0, 0, 0 );
	}

	ber_sockbuf_free( c->c_sb );

	c->c_sb = ber_sockbuf_alloc( );

	{
		ber_len_t max = sockbuf_max_incoming;
		ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );
	}

	c->c_conn_state = SLAP_C_INVALID;
	c->c_struct_state = SLAP_C_UNUSED;

#ifdef LDAP_SLAPI
	/* call destructors, then constructors; avoids unnecessary allocation */
	if ( slapi_plugins_used ) {
		slapi_x_clear_object_extensions( SLAPI_X_EXT_CONNECTION, c );
	}
#endif
}

int connection_state_closing( Connection *c )
{
	/* c_mutex must be locked by caller */

	int state;
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );

	state = c->c_conn_state;

	assert( state != SLAP_C_INVALID );

	return state == SLAP_C_CLOSING;
}

static void connection_abandon( Connection *c )
{
	/* c_mutex must be locked by caller */

	Operation *o;

	LDAP_STAILQ_FOREACH(o, &c->c_ops, o_next) {
		o->o_abandon = 1;
	}

	/* remove pending operations */
	while ( (o = LDAP_STAILQ_FIRST( &c->c_pending_ops )) != NULL) {
		LDAP_STAILQ_REMOVE_HEAD( &c->c_pending_ops, o_next );
		LDAP_STAILQ_NEXT(o, o_next) = NULL;
		slap_op_free( o );
	}
}

void connection_closing( Connection *c )
{
	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );
	assert( c->c_conn_state != SLAP_C_INVALID );

	/* c_mutex must be locked by caller */

	if( c->c_conn_state != SLAP_C_CLOSING ) {
		ber_socket_t	sd;

		ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_GET_FD, &sd );
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, DETAIL1, 
			"connection_closing: conn %lu readying socket %d for close.\n",
			c->c_connid, sd, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"connection_closing: readying conn=%lu sd=%d for close\n",
			c->c_connid, sd, 0 );
#endif
		/* update state to closing */
		c->c_conn_state = SLAP_C_CLOSING;

		/* don't listen on this port anymore */
		slapd_clr_read( sd, 1 );

		/* abandon active operations */
		connection_abandon( c );

		/* wake write blocked operations */
		slapd_clr_write( sd, 1 );
		ldap_pvt_thread_cond_signal( &c->c_write_cv );
	}
}

static void connection_close( Connection *c )
{
	ber_socket_t	sd;

	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );
	assert( c->c_conn_state == SLAP_C_CLOSING );

	/* note: connections_mutex and c_mutex should be locked by caller */

	ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_GET_FD, &sd );
	if( !LDAP_STAILQ_EMPTY(&c->c_ops) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, DETAIL1, 
			"connection_close: conn %lu deferring sd %d\n",
				c->c_connid, sd, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"connection_close: deferring conn=%lu sd=%d\n",
			c->c_connid, sd, 0 );
#endif
		return;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONNECTION, RESULTS, 
		"connection_close: conn %lu sd %d\n", c->c_connid, sd, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "connection_close: conn=%lu sd=%d\n",
		c->c_connid, sd, 0 );
#endif
	connection_destroy( c );
}

unsigned long connections_nextid(void)
{
	unsigned long id;
	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	id = conn_nextid;

	ldap_pvt_thread_mutex_unlock( &connections_mutex );

	return id;
}

Connection* connection_first( ber_socket_t *index )
{
	assert( connections != NULL );
	assert( index != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	*index = 0;

	return connection_next(NULL, index);
}

Connection* connection_next( Connection *c, ber_socket_t *index )
{
	assert( connections != NULL );
	assert( index != NULL );
	assert( *index <= dtblsize );

	if( c != NULL ) {
		ldap_pvt_thread_mutex_unlock( &c->c_mutex );
	}

	c = NULL;

	for(; *index < dtblsize; (*index)++) {
		if( connections[*index].c_struct_state == SLAP_C_UNINITIALIZED ) {
			assert( connections[*index].c_conn_state == SLAP_C_INVALID );
#ifndef HAVE_WINSOCK
			continue;
#else
			break;
#endif
		}

		if( connections[*index].c_struct_state == SLAP_C_USED ) {
			assert( connections[*index].c_conn_state != SLAP_C_INVALID );
			c = &connections[(*index)++];
			break;
		}

		assert( connections[*index].c_struct_state == SLAP_C_UNUSED );
		assert( connections[*index].c_conn_state == SLAP_C_INVALID );
	}

	if( c != NULL ) {
		ldap_pvt_thread_mutex_lock( &c->c_mutex );
	}

	return c;
}

void connection_done( Connection *c )
{
	assert( connections != NULL );

	if( c != NULL ) {
		ldap_pvt_thread_mutex_unlock( &c->c_mutex );
	}

	ldap_pvt_thread_mutex_unlock( &connections_mutex );
}

/*
 * connection_activity - handle the request operation op on connection
 * conn.  This routine figures out what kind of operation it is and
 * calls the appropriate stub to handle it.
 */

#ifdef SLAPD_MONITOR
#define INCR_OP(var,index) \
	do { \
		ldap_pvt_thread_mutex_lock( &num_ops_mutex ); \
		(var)[(index)]++; \
		ldap_pvt_thread_mutex_unlock( &num_ops_mutex ); \
	} while (0)
#else /* !SLAPD_MONITOR */
#define INCR_OP(var,index) 
#endif /* !SLAPD_MONITOR */

static void *
connection_operation( void *ctx, void *arg_v )
{
	int rc = SLAPD_DISCONNECT;
	Operation *op = arg_v;
	SlapReply rs = {REP_RESULT};
	ber_tag_t tag = op->o_tag;
#ifdef SLAPD_MONITOR
	ber_tag_t oldtag = tag;
#endif /* SLAPD_MONITOR */
	Connection *conn = op->o_conn;
	void *memctx = NULL;
	void *memctx_null = NULL;
	ber_len_t memsiz;

	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_initiated++;
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );

	op->o_threadctx = ctx;

	if( conn->c_sasl_bind_in_progress && tag != LDAP_REQ_BIND ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_operation: conn %lu SASL bind in progress (tag=%ld).\n",
			conn->c_connid, (long)tag, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "connection_operation: "
			"error: SASL bind in progress (tag=%ld).\n",
			(long) tag, 0, 0 );
#endif
		send_ldap_error( op, &rs, LDAP_OPERATIONS_ERROR,
			"SASL bind in progress" );
		goto operations_error;
	}

	/* We can use Thread-Local storage for most mallocs. We can
	 * also use TL for ber parsing, but not on Add or Modify.
	 */
#define	SLAB_SIZE	1048576
#if 0
	memsiz = ber_len( op->o_ber ) * 64;
	if ( SLAB_SIZE > memsiz ) memsiz = SLAB_SIZE;
#endif
	memsiz = SLAB_SIZE;

	memctx = sl_mem_create( memsiz, ctx );
	op->o_tmpmemctx = memctx;
	op->o_tmpmfuncs = &sl_mfuncs;
	if ( tag != LDAP_REQ_ADD && tag != LDAP_REQ_MODIFY ) {
		/* Note - the ber and its buffer are already allocated from
		 * regular memory; this only affects subsequent mallocs that
		 * ber_scanf may invoke.
		 */
		ber_set_option( op->o_ber, LBER_OPT_BER_MEMCTX, &memctx );
	}

	switch ( tag ) {
	case LDAP_REQ_BIND:
		INCR_OP(num_ops_initiated_, SLAP_OP_BIND);
		rc = do_bind( op, &rs );
		break;

	case LDAP_REQ_UNBIND:
		INCR_OP(num_ops_initiated_, SLAP_OP_UNBIND);
		rc = do_unbind( op, &rs );
		break;

	case LDAP_REQ_ADD:
		INCR_OP(num_ops_initiated_, SLAP_OP_ADD);
		rc = do_add( op, &rs );
		break;

	case LDAP_REQ_DELETE:
		INCR_OP(num_ops_initiated_, SLAP_OP_DELETE);
		rc = do_delete( op, &rs );
		break;

	case LDAP_REQ_MODRDN:
		INCR_OP(num_ops_initiated_, SLAP_OP_MODRDN);
		rc = do_modrdn( op, &rs );
		break;

	case LDAP_REQ_MODIFY:
		INCR_OP(num_ops_initiated_, SLAP_OP_MODIFY);
		rc = do_modify( op, &rs );
		break;

	case LDAP_REQ_COMPARE:
		INCR_OP(num_ops_initiated_, SLAP_OP_COMPARE);
		rc = do_compare( op, &rs );
		break;

	case LDAP_REQ_SEARCH:
		INCR_OP(num_ops_initiated_, SLAP_OP_SEARCH);
		rc = do_search( op, &rs );
		break;

	case LDAP_REQ_ABANDON:
		INCR_OP(num_ops_initiated_, SLAP_OP_ABANDON);
		rc = do_abandon( op, &rs );
		break;

	case LDAP_REQ_EXTENDED:
		INCR_OP(num_ops_initiated_, SLAP_OP_EXTENDED);
		rc = do_extended( op, &rs );
		break;

	default:
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_operation: conn %lu unknown LDAP request 0x%lx\n",
			conn->c_connid, tag, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "unknown LDAP request 0x%lx\n",
			tag, 0, 0 );
#endif
		op->o_tag = LBER_ERROR;
		rs.sr_err = LDAP_PROTOCOL_ERROR;
		rs.sr_text = "unknown LDAP request";
		send_ldap_disconnect( op, &rs );
		rc = -1;
		break;
	}

#ifdef SLAPD_MONITOR
	oldtag = tag;
#endif /* SLAPD_MONITOR */
	if( rc == SLAPD_DISCONNECT ) tag = LBER_ERROR;

operations_error:
	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_completed++;
#ifdef SLAPD_MONITOR
	switch (oldtag) {
	case LDAP_REQ_BIND:
		num_ops_completed_[SLAP_OP_BIND]++;
		break;
	case LDAP_REQ_UNBIND:
		num_ops_completed_[SLAP_OP_UNBIND]++;
		break;
	case LDAP_REQ_ADD:
		num_ops_completed_[SLAP_OP_ADD]++;
		break;
	case LDAP_REQ_DELETE:
		num_ops_completed_[SLAP_OP_DELETE]++;
		break;
	case LDAP_REQ_MODRDN:
		num_ops_completed_[SLAP_OP_MODRDN]++;
		break;
	case LDAP_REQ_MODIFY:
		num_ops_completed_[SLAP_OP_MODIFY]++;
		break;
	case LDAP_REQ_COMPARE:
		num_ops_completed_[SLAP_OP_COMPARE]++;
		break;
	case LDAP_REQ_SEARCH:
		num_ops_completed_[SLAP_OP_SEARCH]++;
		break;
	case LDAP_REQ_ABANDON:
		num_ops_completed_[SLAP_OP_ABANDON]++;
		break;
	case LDAP_REQ_EXTENDED:
		num_ops_completed_[SLAP_OP_EXTENDED]++;
		break;
	}
#endif /* SLAPD_MONITOR */
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );

#ifdef LDAP_EXOP_X_CANCEL
	if ( op->o_cancel == SLAP_CANCEL_REQ ) {
		op->o_cancel = LDAP_TOO_LATE;
	}

	while ( op->o_cancel != SLAP_CANCEL_NONE &&
		op->o_cancel != SLAP_CANCEL_DONE )
	{
		ldap_pvt_thread_yield();
	}
#endif

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	ber_set_option( op->o_ber, LBER_OPT_BER_MEMCTX, &memctx_null );

	if ( op->o_cancel != SLAP_CANCEL_ACK &&
				( op->o_sync_mode & SLAP_SYNC_PERSIST ) ) {
		sl_mem_detach( ctx, memctx );
	} else if (( op->o_sync_slog_size != -1 )) {
		sl_mem_detach( ctx, memctx );
		LDAP_STAILQ_REMOVE( &conn->c_ops, op, slap_op, o_next);
		LDAP_STAILQ_NEXT(op, o_next) = NULL;
		conn->c_n_ops_executing--;
		conn->c_n_ops_completed++;
	} else {
		LDAP_STAILQ_REMOVE( &conn->c_ops, op, slap_op, o_next);
		LDAP_STAILQ_NEXT(op, o_next) = NULL;
		slap_op_free( op );
		conn->c_n_ops_executing--;
		conn->c_n_ops_completed++;
	}

no_co_op_free:

	switch( tag ) {
	case LBER_ERROR:
	case LDAP_REQ_UNBIND:
		/* c_mutex is locked */
		connection_closing( conn );
		break;

	case LDAP_REQ_BIND:
		conn->c_sasl_bind_in_progress =
			rc == LDAP_SASL_BIND_IN_PROGRESS ? 1 : 0;

		if( conn->c_conn_state == SLAP_C_BINDING) {
			conn->c_conn_state = SLAP_C_ACTIVE;
		}
	}

	connection_resched( conn );

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	return NULL;
}

int connection_client_setup(
	ber_socket_t s,
	Listener *l,
	ldap_pvt_thread_start_t *func,
	void *arg )
{
	Connection *c;

	if ( connection_init( s, l, "", "", CONN_IS_CLIENT, 0, "" ) < 0 ) {
		return -1;
	}

	c = connection_get( s );
	c->c_clientfunc = func;
	c->c_clientarg = arg;
	connection_return( c );
	slapd_add_internal( s, 0 );
	slapd_set_read( s, 1 );
	return 0;
}

void connection_client_enable(
	ber_socket_t s
)
{
	slapd_set_read( s, 1 );
}

void connection_client_stop(
	ber_socket_t s
)
{
	Connection *c;

	/* get (locked) connection */
	c = connection_get( s );
	
	assert( c->c_conn_state == SLAP_C_CLIENT );

	c->c_listener = NULL;
	c->c_conn_state = SLAP_C_INVALID;
	c->c_struct_state = SLAP_C_UNUSED;
	connection_return( c );
	slapd_remove( s, 0, 1 );
}

int connection_read(ber_socket_t s)
{
	int rc = 0;
	Connection *c;

	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	/* get (locked) connection */
	c = connection_get( s );

	if( c == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_read: sock %ld no connection\n", (long)s, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"connection_read(%ld): no connection!\n",
			(long) s, 0, 0 );
#endif
		slapd_remove(s, 1, 0);

		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_read++;

	if( c->c_conn_state == SLAP_C_CLOSING ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_read: conn %lu connection closing, ignoring input\n",
			c->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): closing, ignoring input for id=%lu\n",
			s, c->c_connid, 0 );
#endif
		connection_return( c );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}

	if ( c->c_conn_state == SLAP_C_CLIENT ) {
		slapd_clr_read( s, 0 );
		ldap_pvt_thread_pool_submit( &connection_pool,
			c->c_clientfunc, c->c_clientarg );
		connection_return( c );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONNECTION, DETAIL1, 
		"connection_read: conn %lu checking for input.\n", 
			c->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"connection_read(%d): checking for input on id=%lu\n",
		s, c->c_connid, 0 );
#endif

#ifdef HAVE_TLS
	if ( c->c_is_tls && c->c_needs_tls_accept ) {
		rc = ldap_pvt_tls_accept( c->c_sb, NULL );
		if ( rc < 0 ) {
#if 0 /* required by next #if 0 */
			struct timeval tv;
			fd_set rfd;
#endif

#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, ERR, 
				"connection_read: conn %lu TLS accept error, error %d\n",
				c->c_connid, rc, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"connection_read(%d): TLS accept error "
				"error=%d id=%lu, closing\n",
				s, rc, c->c_connid );
#endif
			c->c_needs_tls_accept = 0;
			/* connections_mutex and c_mutex are locked */
			connection_closing( c );

#if 0
			/* Drain input before close, to allow SSL error codes
			 * to propagate to client. */
			FD_ZERO(&rfd);
			FD_SET(s, &rfd);
			for (rc=1; rc>0;) {
				tv.tv_sec = 1;
				tv.tv_usec = 0;
				rc = select(s+1, &rfd, NULL, NULL, &tv);
				if (rc == 1) {
					ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_DRAIN, NULL);
				}
			}
#endif
			connection_close( c );

		} else if ( rc == 0 ) {
			void *ssl;
			struct berval authid = { 0, NULL };

			c->c_needs_tls_accept = 0;

			/* we need to let SASL know */
			ssl = ldap_pvt_tls_sb_ctx( c->c_sb );

			c->c_tls_ssf = (slap_ssf_t) ldap_pvt_tls_get_strength( ssl );
			if( c->c_tls_ssf > c->c_ssf ) {
				c->c_ssf = c->c_tls_ssf;
			}

			rc = dnX509peerNormalize( ssl, &authid );
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONNECTION, INFO, 
					"connection_read: conn %lu unable to get TLS client DN, "
					"error %d\n", c->c_connid, rc, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
				"connection_read(%d): unable to get TLS client DN "
				"error=%d id=%lu\n",
				s, rc, c->c_connid );
#endif
			}
			slap_sasl_external( c, c->c_tls_ssf, authid.bv_val );
			if ( authid.bv_val )	free( authid.bv_val );
		}

		/* if success and data is ready, fall thru to data input loop */
		if( rc != 0 ||
			!ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_DATA_READY, NULL ) )
		{
			connection_return( c );
			ldap_pvt_thread_mutex_unlock( &connections_mutex );
			return 0;
		}
	}
#endif

#ifdef HAVE_CYRUS_SASL
	if ( c->c_sasl_layers ) {
		/* If previous layer is not removed yet, give up for now */
		if ( !c->c_sasl_sockctx ) {
			connection_return( c );
			ldap_pvt_thread_mutex_unlock( &connections_mutex );
			return 0;
		}

		c->c_sasl_layers = 0;

		rc = ldap_pvt_sasl_install( c->c_sb, c->c_sasl_sockctx );

		if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, ERR, 
				"connection_read: conn %lu SASL install error %d, closing\n",
				c->c_connid, rc, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"connection_read(%d): SASL install error "
				"error=%d id=%lu, closing\n",
				s, rc, c->c_connid );
#endif
			/* connections_mutex and c_mutex are locked */
			connection_closing( c );
			connection_close( c );
			connection_return( c );
			ldap_pvt_thread_mutex_unlock( &connections_mutex );
			return 0;
		}
	}
#endif

#define CONNECTION_INPUT_LOOP 1
/* #define	DATA_READY_LOOP 1 */

	do
	{
		/* How do we do this without getting into a busy loop ? */
		rc = connection_input( c );
	}
#ifdef DATA_READY_LOOP
	while( !rc && ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_DATA_READY, NULL ) );
#elif CONNECTION_INPUT_LOOP
	while(!rc);
#else
	while(0);
#endif

	if( rc < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_read: conn %lu input error %d, closing.\n",
			c->c_connid, rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): input error=%d id=%lu, closing.\n",
			s, rc, c->c_connid );
#endif
		/* connections_mutex and c_mutex are locked */
		connection_closing( c );
		connection_close( c );
		connection_return( c );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}

	if ( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_NEEDS_READ, NULL ) ) {
		slapd_set_read( s, 1 );
	}

	if ( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_NEEDS_WRITE, NULL ) ) {
		slapd_set_write( s, 1 );
	}

	connection_return( c );
	ldap_pvt_thread_mutex_unlock( &connections_mutex );
	return 0;
}

static int
connection_input(
	Connection *conn
)
{
	Operation *op;
	ber_tag_t	tag;
	ber_len_t	len;
	ber_int_t	msgid;
	BerElement	*ber;
	int 		rc;
#ifdef LDAP_CONNECTIONLESS
	Sockaddr	peeraddr;
	char 		*cdn = NULL;
#endif

	if ( conn->c_currentber == NULL &&
		( conn->c_currentber = ber_alloc()) == NULL )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_input: conn %lu ber_alloc failed.\n", 
			conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
#endif
		return -1;
	}

	errno = 0;

#ifdef LDAP_CONNECTIONLESS
	if ( conn->c_is_udp ) {
		char	peername[sizeof("IP=255.255.255.255:65336")];
		len = ber_int_sb_read(conn->c_sb, &peeraddr,
			sizeof(struct sockaddr));
		if (len != sizeof(struct sockaddr))
			return 1;
		sprintf( peername, "IP=%s:%d",
			inet_ntoa( peeraddr.sa_in_addr.sin_addr ),
			(unsigned) ntohs( peeraddr.sa_in_addr.sin_port ) );
		Statslog( LDAP_DEBUG_STATS,
			"conn=%lu UDP request from %s (%s) accepted.\n",
			conn->c_connid, peername, conn->c_sock_name.bv_val, 0, 0 );
	}
#endif
	tag = ber_get_next( conn->c_sb, &len, conn->c_currentber );
	if ( tag != LDAP_TAG_MESSAGE ) {
		int err = errno;
		ber_socket_t	sd;

		ber_sockbuf_ctrl( conn->c_sb, LBER_SB_OPT_GET_FD, &sd );

#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_input: conn %lu ber_get_next failed, errno %d (%s).\n",
			conn->c_connid, err, sock_errstr(err) );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ber_get_next on fd %d failed errno=%d (%s)\n",
			sd, err, sock_errstr(err) );
#endif
		if ( err != EWOULDBLOCK && err != EAGAIN ) {
			/* log, close and send error */
			ber_free( conn->c_currentber, 1 );
			conn->c_currentber = NULL;

			return -2;
		}
		return 1;
	}

	ber = conn->c_currentber;
	conn->c_currentber = NULL;

	if ( (tag = ber_get_int( ber, &msgid )) != LDAP_TAG_MSGID ) {
		/* log, close and send error */
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_input: conn %lu ber_get_int returns 0x%lx.\n",
			conn->c_connid, tag, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_get_int returns 0x%lx\n",
			tag, 0, 0 );
#endif
		ber_free( ber, 1 );
		return -1;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error */
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_input: conn %lu ber_peek_tag returns 0x%lx.\n",
			conn->c_connid, tag, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "ber_peek_tag returns 0x%lx\n",
			tag, 0, 0 );
#endif
		ber_free( ber, 1 );

		return -1;
	}

#ifdef LDAP_CONNECTIONLESS
	if( conn->c_is_udp ) {
		if( tag == LBER_OCTETSTRING ) {
			ber_get_stringa( ber, &cdn );
			tag = ber_peek_tag(ber, &len);
		}
		if( tag != LDAP_REQ_ABANDON && tag != LDAP_REQ_SEARCH ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, ERR, 
				"connection_input: conn %lu invalid req for UDP 0x%lx.\n",
				conn->c_connid, tag, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "invalid req for UDP 0x%lx\n", tag, 0, 0 );
#endif
			ber_free( ber, 1 );
			return 0;
		}
	}
#endif
	if(tag == LDAP_REQ_BIND) {
		/* immediately abandon all exiting operations upon BIND */
		connection_abandon( conn );
	}

	op = slap_op_alloc( ber, msgid, tag, conn->c_n_ops_received++ );

	op->o_conn = conn;
	op->o_assertion = NULL;
	op->o_preread_attrs = NULL;
	op->o_postread_attrs = NULL;
	op->o_vrFilter = NULL;

#ifdef LDAP_CONTROL_PAGEDRESULTS
	op->o_pagedresults_state = conn->c_pagedresults_state;
#endif

	op->o_res_ber = NULL;

#ifdef LDAP_CONNECTIONLESS
	if (conn->c_is_udp) {
		if ( cdn ) {
			ber_str2bv( cdn, 0, 1, &op->o_dn );
			op->o_protocol = LDAP_VERSION2;
		}
		op->o_res_ber = ber_alloc_t( LBER_USE_DER );
		if (op->o_res_ber == NULL) return 1;

		rc = ber_write( op->o_res_ber, (char *)&peeraddr,
			sizeof(struct sockaddr), 0 );

		if (rc != sizeof(struct sockaddr)) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, INFO, 
				"connection_input: conn %lu ber_write failed\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "ber_write failed\n", 0, 0, 0 );
#endif
			return 1;
		}

		if (op->o_protocol == LDAP_VERSION2) {
			rc = ber_printf(op->o_res_ber, "{is{" /*}}*/, op->o_msgid, "");
			if (rc == -1) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONNECTION, INFO, 
					"connection_input: conn %lu put outer sequence failed\n",
					conn->c_connid, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "ber_write failed\n", 0, 0, 0 );
#endif
				return rc;
			}
		}
	}
#endif /* LDAP_CONNECTIONLESS */

	rc = 0;

	/* Don't process requests when the conn is in the middle of a
	 * Bind, or if it's closing. Also, don't let any single conn
	 * use up all the available threads, and don't execute if we're
	 * currently blocked on output. And don't execute if there are
	 * already pending ops, let them go first.
	 *
	 * But always allow Abandon through; it won't cost much.
	 */
	if ( tag != LDAP_REQ_ABANDON && (conn->c_conn_state == SLAP_C_BINDING
		|| conn->c_conn_state == SLAP_C_CLOSING
		|| conn->c_n_ops_executing >= connection_pool_max/2
		|| conn->c_n_ops_pending
		|| conn->c_writewaiter))
	{
		int max = conn->c_dn.bv_len
			? slap_conn_max_pending_auth
			: slap_conn_max_pending;

#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, INFO, 
			"connection_input: conn %lu deferring operation\n",
			conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"connection_input: conn=%lu deferring operation\n",
			conn->c_connid, 0, 0 );
#endif
		conn->c_n_ops_pending++;
		LDAP_STAILQ_INSERT_TAIL( &conn->c_pending_ops, op, o_next );
		if ( conn->c_n_ops_pending > max ) {
			rc = -1;
		} else {
			rc = 1;
		}
	} else {
		conn->c_n_ops_executing++;
		connection_op_activate( op );
	}

#ifdef NO_THREADS
	if ( conn->c_struct_state != SLAP_C_USED ) {
		/* connection must have got closed underneath us */
		return 1;
	}
#endif
	assert( conn->c_struct_state == SLAP_C_USED );

	return rc;
}

static int
connection_resched( Connection *conn )
{
	Operation *op;

	if( conn->c_conn_state == SLAP_C_CLOSING ) {
		int rc;
		ber_socket_t	sd;
		ber_sockbuf_ctrl( conn->c_sb, LBER_SB_OPT_GET_FD, &sd );

		/* us trylock to avoid possible deadlock */
		rc = ldap_pvt_thread_mutex_trylock( &connections_mutex );

		if( rc ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, DETAIL1, 
				"connection_resched: conn %lu reaquiring locks.\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"connection_resched: reaquiring locks conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
#endif
			/*
			 * reaquire locks in the right order...
			 * this may allow another thread to close this connection,
			 * so recheck state below.
			 */
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			ldap_pvt_thread_mutex_lock( &connections_mutex );
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
		}

		if( conn->c_conn_state != SLAP_C_CLOSING ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, INFO, 
				"connection_resched: conn %lu closed by other thread.\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "connection_resched: "
				"closed by other thread conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
#endif
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( CONNECTION, DETAIL1, 
				"connection_resched: conn %lu attempting closing.\n",
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "connection_resched: "
				"attempting closing conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
#endif
			connection_close( conn );
		}

		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}

	if( conn->c_conn_state != SLAP_C_ACTIVE || conn->c_writewaiter ) {
		/* other states need different handling */
		return 0;
	}

	while ((op = LDAP_STAILQ_FIRST( &conn->c_pending_ops )) != NULL) {
		if ( conn->c_n_ops_executing > connection_pool_max/2 ) {
			break;
		}
		LDAP_STAILQ_REMOVE_HEAD( &conn->c_pending_ops, o_next );
		LDAP_STAILQ_NEXT(op, o_next) = NULL;
		/* pending operations should not be marked for abandonment */
		assert(!op->o_abandon);

		conn->c_n_ops_pending--;
		conn->c_n_ops_executing++;

		connection_op_activate( op );

		if ( conn->c_conn_state == SLAP_C_BINDING ) {
			break;
		}
	}
	return 0;
}

static int connection_op_activate( Operation *op )
{
	int status;
	ber_tag_t tag = op->o_tag;

	if(tag == LDAP_REQ_BIND) {
		op->o_conn->c_conn_state = SLAP_C_BINDING;
	}

	if (!op->o_dn.bv_len) {
		op->o_authz = op->o_conn->c_authz;
		ber_dupbv( &op->o_dn, &op->o_conn->c_dn );
		ber_dupbv( &op->o_ndn, &op->o_conn->c_ndn );
	}
	op->o_authtype = op->o_conn->c_authtype;
	ber_dupbv( &op->o_authmech, &op->o_conn->c_authmech );
	
	if (!op->o_protocol) {
		op->o_protocol = op->o_conn->c_protocol
			? op->o_conn->c_protocol : LDAP_VERSION3;
	}
	if (op->o_conn->c_conn_state == SLAP_C_INACTIVE
		&& op->o_protocol > LDAP_VERSION2)
	{
		op->o_conn->c_conn_state = SLAP_C_ACTIVE;
	}

	op->o_connid = op->o_conn->c_connid;

	LDAP_STAILQ_INSERT_TAIL( &op->o_conn->c_ops, op, o_next );

	status = ldap_pvt_thread_pool_submit( &connection_pool,
		connection_operation, (void *) op );

	if ( status != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_op_activate: conn %lu	 thread pool submit failed.\n",
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"ldap_pvt_thread_pool_submit: failed (%d) for conn=%lu\n",
			status, op->o_connid, 0 );
#endif
		/* should move op to pending list */
	}

	return status;
}

int connection_write(ber_socket_t s)
{
	Connection *c;

	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	c = connection_get( s );

	slapd_clr_write( s, 0);

	if( c == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONNECTION, ERR, 
			"connection_write: sock %ld no connection!\n", (long)s, 0, 0);
#else
		Debug( LDAP_DEBUG_ANY,
			"connection_write(%ld): no connection!\n",
			(long)s, 0, 0 );
#endif
		slapd_remove(s, 1, 0);
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_write++;

#ifdef NEW_LOGGING
	LDAP_LOG( CONNECTION, DETAIL1, 
		"connection_write conn %lu waking output.\n", c->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"connection_write(%d): waking output for id=%lu\n",
		s, c->c_connid, 0 );
#endif
	ldap_pvt_thread_cond_signal( &c->c_write_cv );

	if ( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_NEEDS_READ, NULL ) ) {
		slapd_set_read( s, 1 );
	}
	if ( ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_NEEDS_WRITE, NULL ) ) {
		slapd_set_write( s, 1 );
	}
	connection_return( c );
	ldap_pvt_thread_mutex_unlock( &connections_mutex );
	return 0;
}

