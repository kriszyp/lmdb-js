/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <limits.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "lutil.h"
#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

/* protected by connections_mutex */
static ldap_pvt_thread_mutex_t connections_mutex;
static Connection *connections = NULL;

static ldap_pvt_thread_mutex_t conn_nextid_mutex;
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
	int i;

	assert( connections == NULL );

	if( connections != NULL) {
		Debug( LDAP_DEBUG_ANY, "connections_init: already initialized.\n",
			0, 0, 0 );
		return -1;
	}

	/* should check return of every call */
	ldap_pvt_thread_mutex_init( &connections_mutex );
	ldap_pvt_thread_mutex_init( &conn_nextid_mutex );

	connections = (Connection *) ch_calloc( dtblsize, sizeof(Connection) );

	if( connections == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"connections_init: allocation (%d*%ld) of connection array failed\n",
			dtblsize, (long) sizeof(Connection), 0 );
		return -1;
	}

	assert( connections[0].c_struct_state == SLAP_C_UNINITIALIZED );
	assert( connections[dtblsize-1].c_struct_state == SLAP_C_UNINITIALIZED );

	for (i=0; i<dtblsize; i++) connections[i].c_conn_idx = i;

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
		Debug( LDAP_DEBUG_ANY, "connections_destroy: nothing to destroy.\n",
			0, 0, 0 );
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
				slapi_int_free_object_extensions( SLAPI_X_EXT_CONNECTION, &connections[i] );
			}
#endif
		}
	}

	free( connections );
	connections = NULL;

	ldap_pvt_thread_mutex_destroy( &connections_mutex );
	ldap_pvt_thread_mutex_destroy( &conn_nextid_mutex );
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

	Debug( LDAP_DEBUG_ARGS,
		"connection_get(%ld)\n",
		(long) s, 0, 0 );

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

			Debug( LDAP_DEBUG_TRACE,
				"connection_get(%d): connection not used\n",
				s, 0, 0 );

			ldap_pvt_thread_mutex_unlock( &c->c_mutex );
			return NULL;
		}

		Debug( LDAP_DEBUG_TRACE,
			"connection_get(%d): got connid=%lu\n",
			s, c->c_connid, 0 );

		c->c_n_get++;

		assert( c->c_struct_state == SLAP_C_USED );
		assert( c->c_conn_state != SLAP_C_INVALID );
		assert( sd != AC_SOCKET_INVALID );

#ifndef SLAPD_MONITOR
		if ( global_idletimeout > 0 )
#endif /* ! SLAPD_MONITOR */
		{
			c->c_activitytime = slap_get_time();
		}
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
	struct berval *authid )
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
		Debug( LDAP_DEBUG_ANY,
			"connection_init: init of socket %ld invalid.\n", (long)s, 0, 0 );
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

			if( connections[i].c_conn_state == SLAP_C_CLIENT ) {
				continue;
			}

			assert( connections[i].c_struct_state == SLAP_C_USED );
			assert( connections[i].c_conn_state != SLAP_C_INVALID );
			assert( sd != AC_SOCKET_INVALID );
		}

		if( c == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"connection_init(%d): connection table full "
				"(%d/%d)\n", s, i, dtblsize);
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

		BER_BVZERO( &c->c_authmech );
		BER_BVZERO( &c->c_dn );
		BER_BVZERO( &c->c_ndn );

		c->c_listener = NULL;
		BER_BVZERO( &c->c_peer_domain );
		BER_BVZERO( &c->c_peer_name );

		LDAP_STAILQ_INIT(&c->c_ops);
		LDAP_STAILQ_INIT(&c->c_pending_ops);

		BER_BVZERO( &c->c_sasl_bind_mech );
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
			slapi_int_create_object_extensions( SLAPI_X_EXT_CONNECTION, c );
		}
#endif

		c->c_struct_state = SLAP_C_UNUSED;
	}

	ldap_pvt_thread_mutex_lock( &c->c_mutex );

	assert( c->c_struct_state == SLAP_C_UNUSED );
	assert( BER_BVISNULL( &c->c_authmech ) );
	assert( BER_BVISNULL( &c->c_dn ) );
	assert( BER_BVISNULL( &c->c_ndn ) );
	assert( c->c_listener == NULL );
	assert( BER_BVISNULL( &c->c_peer_domain ) );
	assert( BER_BVISNULL( &c->c_peer_name ) );
	assert( LDAP_STAILQ_EMPTY(&c->c_ops) );
	assert( LDAP_STAILQ_EMPTY(&c->c_pending_ops) );
	assert( BER_BVISNULL( &c->c_sasl_bind_mech ) );
	assert( c->c_sasl_done == 0 );
	assert( c->c_sasl_authctx == NULL );
	assert( c->c_sasl_sockctx == NULL );
	assert( c->c_sasl_extra == NULL );
	assert( c->c_sasl_bindop == NULL );
	assert( c->c_currentber == NULL );
	assert( c->c_writewaiter == 0);

	c->c_listener = listener;

	if ( flags == CONN_IS_CLIENT ) {
		c->c_conn_state = SLAP_C_CLIENT;
		c->c_struct_state = SLAP_C_USED;
		ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_FD, &s );
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

#ifndef SLAPD_MONITOR
	if ( global_idletimeout > 0 )
#endif /* ! SLAPD_MONITOR */
	{
		c->c_activitytime = c->c_starttime = slap_get_time();
	}

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
		Debug( LDAP_DEBUG_ANY,
			"connection_init(%d, %s): set nonblocking failed\n",
			s, c->c_peer_name.bv_val, 0 );
	}

	ldap_pvt_thread_mutex_lock( &conn_nextid_mutex );
	id = c->c_connid = conn_nextid++;
	ldap_pvt_thread_mutex_unlock( &conn_nextid_mutex );

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
	}
	BER_BVZERO( &c->c_authmech );

	if(c->c_dn.bv_val != NULL) {
		free(c->c_dn.bv_val);
	}
	BER_BVZERO( &c->c_dn );
	if(c->c_ndn.bv_val != NULL) {
		free(c->c_ndn.bv_val);
	}
	BER_BVZERO( &c->c_ndn );

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
	assert( c->c_writewaiter == 0);

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
	}
	BER_BVZERO( &c->c_peer_domain );
	if(c->c_peer_name.bv_val != NULL) {
		free(c->c_peer_name.bv_val);
	}
	BER_BVZERO( &c->c_peer_name );

	c->c_sasl_bind_in_progress = 0;
	if(c->c_sasl_bind_mech.bv_val != NULL) {
		free(c->c_sasl_bind_mech.bv_val);
	}
	BER_BVZERO( &c->c_sasl_bind_mech );

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
		slapi_int_clear_object_extensions( SLAPI_X_EXT_CONNECTION, c );
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
		Debug( LDAP_DEBUG_TRACE,
			"connection_closing: readying conn=%lu sd=%d for close\n",
			c->c_connid, sd, 0 );
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
		Debug( LDAP_DEBUG_TRACE,
			"connection_close: deferring conn=%lu sd=%d\n",
			c->c_connid, sd, 0 );
		return;
	}

	Debug( LDAP_DEBUG_TRACE, "connection_close: conn=%lu sd=%d\n",
		c->c_connid, sd, 0 );
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
/* FIXME: returns 0 in case of failure */
#define INCR_OP_INITIATED(index) \
	do { \
		ldap_pvt_thread_mutex_lock( &slap_counters.sc_ops_mutex ); \
		ldap_pvt_mp_add_ulong(slap_counters.sc_ops_initiated_[(index)], 1); \
		ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex ); \
	} while (0)
#define INCR_OP_COMPLETED(index) \
	do { \
		ldap_pvt_thread_mutex_lock( &slap_counters.sc_ops_mutex ); \
		ldap_pvt_mp_add_ulong(slap_counters.sc_ops_completed, 1); \
		ldap_pvt_mp_add_ulong(slap_counters.sc_ops_completed_[(index)], 1); \
		ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex ); \
	} while (0)
#else /* !SLAPD_MONITOR */
#define INCR_OP_INITIATED(index) 
#define INCR_OP_COMPLETED(index) 
#endif /* !SLAPD_MONITOR */

static void *
connection_operation( void *ctx, void *arg_v )
{
	int rc = LDAP_OTHER;
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

	ldap_pvt_thread_mutex_lock( &slap_counters.sc_ops_mutex );
	/* FIXME: returns 0 in case of failure */
	ldap_pvt_mp_add_ulong(slap_counters.sc_ops_initiated, 1);
	ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex );

	op->o_threadctx = ctx;

	switch ( tag ) {
	case LDAP_REQ_BIND:
	case LDAP_REQ_UNBIND:
	case LDAP_REQ_ADD:
	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODRDN:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_SEARCH:
	case LDAP_REQ_ABANDON:
	case LDAP_REQ_EXTENDED:
		break;
	default:
		Debug( LDAP_DEBUG_ANY, "connection_operation: "
			"conn %lu unknown LDAP request 0x%lx\n",
			conn->c_connid, tag, 0 );
		op->o_tag = LBER_ERROR;
		rs.sr_err = LDAP_PROTOCOL_ERROR;
		rs.sr_text = "unknown LDAP request";
		send_ldap_disconnect( op, &rs );
		rc = SLAPD_DISCONNECT;
		goto operations_error;
	}

	if( conn->c_sasl_bind_in_progress && tag != LDAP_REQ_BIND ) {
		Debug( LDAP_DEBUG_ANY, "connection_operation: "
			"error: SASL bind in progress (tag=%ld).\n",
			(long) tag, 0, 0 );
		send_ldap_error( op, &rs, LDAP_OPERATIONS_ERROR,
			"SASL bind in progress" );
		rc = LDAP_OPERATIONS_ERROR;
		goto operations_error;
	}

	/* We can use Thread-Local storage for most mallocs. We can
	 * also use TL for ber parsing, but not on Add or Modify.
	 */
#if 0
	memsiz = ber_len( op->o_ber ) * 64;
	if ( SLAP_SLAB_SIZE > memsiz ) memsiz = SLAP_SLAB_SIZE;
#endif
	memsiz = SLAP_SLAB_SIZE;

	memctx = slap_sl_mem_create( memsiz, ctx );
	op->o_tmpmemctx = memctx;
	op->o_tmpmfuncs = &slap_sl_mfuncs;
	if ( tag != LDAP_REQ_ADD && tag != LDAP_REQ_MODIFY ) {
		/* Note - the ber and its buffer are already allocated from
		 * regular memory; this only affects subsequent mallocs that
		 * ber_scanf may invoke.
		 */
		ber_set_option( op->o_ber, LBER_OPT_BER_MEMCTX, &memctx );
	}

	switch ( tag ) {
	case LDAP_REQ_BIND:
		INCR_OP_INITIATED(SLAP_OP_BIND);
		rc = do_bind( op, &rs );
		break;

	case LDAP_REQ_UNBIND:
		INCR_OP_INITIATED(SLAP_OP_UNBIND);
		rc = do_unbind( op, &rs );
		break;

	case LDAP_REQ_ADD:
		INCR_OP_INITIATED(SLAP_OP_ADD);
		rc = do_add( op, &rs );
		break;

	case LDAP_REQ_DELETE:
		INCR_OP_INITIATED(SLAP_OP_DELETE);
		rc = do_delete( op, &rs );
		break;

	case LDAP_REQ_MODRDN:
		INCR_OP_INITIATED(SLAP_OP_MODRDN);
		rc = do_modrdn( op, &rs );
		break;

	case LDAP_REQ_MODIFY:
		INCR_OP_INITIATED(SLAP_OP_MODIFY);
		rc = do_modify( op, &rs );
		break;

	case LDAP_REQ_COMPARE:
		INCR_OP_INITIATED(SLAP_OP_COMPARE);
		rc = do_compare( op, &rs );
		break;

	case LDAP_REQ_SEARCH:
		INCR_OP_INITIATED(SLAP_OP_SEARCH);
		rc = do_search( op, &rs );
		break;

	case LDAP_REQ_ABANDON:
		INCR_OP_INITIATED(SLAP_OP_ABANDON);
		rc = do_abandon( op, &rs );
		break;

	case LDAP_REQ_EXTENDED:
		INCR_OP_INITIATED(SLAP_OP_EXTENDED);
		rc = do_extended( op, &rs );
		break;

	default:
		/* not reachable */
		assert( 0 );
	}

operations_error:
	if( rc == SLAPD_DISCONNECT ) tag = LBER_ERROR;

#ifdef SLAPD_MONITOR
	switch (oldtag) {
	case LDAP_REQ_BIND:
		INCR_OP_COMPLETED(SLAP_OP_BIND);
		break;
	case LDAP_REQ_UNBIND:
		INCR_OP_COMPLETED(SLAP_OP_UNBIND);
		break;
	case LDAP_REQ_ADD:
		INCR_OP_COMPLETED(SLAP_OP_ADD);
		break;
	case LDAP_REQ_DELETE:
		INCR_OP_COMPLETED(SLAP_OP_DELETE);
		break;
	case LDAP_REQ_MODRDN:
		INCR_OP_COMPLETED(SLAP_OP_MODRDN);
		break;
	case LDAP_REQ_MODIFY:
		INCR_OP_COMPLETED(SLAP_OP_MODIFY);
		break;
	case LDAP_REQ_COMPARE:
		INCR_OP_COMPLETED(SLAP_OP_COMPARE);
		break;
	case LDAP_REQ_SEARCH:
		INCR_OP_COMPLETED(SLAP_OP_SEARCH);
		break;
	case LDAP_REQ_ABANDON:
		INCR_OP_COMPLETED(SLAP_OP_ABANDON);
		break;
	case LDAP_REQ_EXTENDED:
		INCR_OP_COMPLETED(SLAP_OP_EXTENDED);
		break;
	default:
		/* not reachable */
		assert( 0 );
	}
#endif /* SLAPD_MONITOR */
	ldap_pvt_thread_mutex_unlock( &slap_counters.sc_ops_mutex );

	if ( op->o_cancel == SLAP_CANCEL_REQ ) {
		op->o_cancel = LDAP_TOO_LATE;
	}
	while ( op->o_cancel != SLAP_CANCEL_NONE &&
		op->o_cancel != SLAP_CANCEL_DONE )
	{
		ldap_pvt_thread_yield();
	}

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	ber_set_option( op->o_ber, LBER_OPT_BER_MEMCTX, &memctx_null );

	if ( op->o_cancel != SLAP_CANCEL_ACK &&
		( op->o_sync_mode & SLAP_SYNC_PERSIST ) )
	{
		slap_sl_mem_detach( ctx, memctx );

	} else if ( op->o_sync_slog_size != -1 ) {
		slap_sl_mem_detach( ctx, memctx );
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

static const Listener dummy_list = { BER_BVC(""), BER_BVC("") };

int connection_client_setup(
	ber_socket_t s,
	ldap_pvt_thread_start_t *func,
	void *arg )
{
	int rc;
	Connection *c;

	rc = connection_init( s, (Listener *)&dummy_list, "", "",
		CONN_IS_CLIENT, 0, NULL );
	if ( rc < 0 ) return -1;

	c = connection_get( s );
	c->c_clientfunc = func;
	c->c_clientarg = arg;
	connection_return( c );
	slapd_add_internal( s, 0 );
	slapd_set_read( s, 1 );
	return 0;
}

void connection_client_enable(
	ber_socket_t s )
{
	slapd_set_read( s, 1 );
}

void connection_client_stop(
	ber_socket_t s )
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
		Debug( LDAP_DEBUG_ANY,
			"connection_read(%ld): no connection!\n",
			(long) s, 0, 0 );
		slapd_remove(s, 1, 0);

		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_read++;

	if( c->c_conn_state == SLAP_C_CLOSING ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): closing, ignoring input for id=%lu\n",
			s, c->c_connid, 0 );
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

	Debug( LDAP_DEBUG_TRACE,
		"connection_read(%d): checking for input on id=%lu\n",
		s, c->c_connid, 0 );

#ifdef HAVE_TLS
	if ( c->c_is_tls && c->c_needs_tls_accept ) {
		rc = ldap_pvt_tls_accept( c->c_sb, slap_tls_ctx );
		if ( rc < 0 ) {
#if 0 /* required by next #if 0 */
			struct timeval tv;
			fd_set rfd;
#endif

			Debug( LDAP_DEBUG_TRACE,
				"connection_read(%d): TLS accept error "
				"error=%d id=%lu, closing\n",
				s, rc, c->c_connid );
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
			struct berval authid = BER_BVNULL;

			c->c_needs_tls_accept = 0;

			/* we need to let SASL know */
			ssl = ldap_pvt_tls_sb_ctx( c->c_sb );

			c->c_tls_ssf = (slap_ssf_t) ldap_pvt_tls_get_strength( ssl );
			if( c->c_tls_ssf > c->c_ssf ) {
				c->c_ssf = c->c_tls_ssf;
			}

			rc = dnX509peerNormalize( ssl, &authid );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "connection_read(%d): "
					"unable to get TLS client DN, error=%d id=%lu\n",
					s, rc, c->c_connid );
			}
			slap_sasl_external( c, c->c_tls_ssf, &authid );
			if ( authid.bv_val ) free( authid.bv_val );
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
			Debug( LDAP_DEBUG_TRACE,
				"connection_read(%d): SASL install error "
				"error=%d id=%lu, closing\n",
				s, rc, c->c_connid );
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

	do {
		/* How do we do this without getting into a busy loop ? */
		rc = connection_input( c );
	}
#ifdef DATA_READY_LOOP
	while( !rc && ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_DATA_READY, NULL ));
#elif CONNECTION_INPUT_LOOP
	while(!rc);
#else
	while(0);
#endif

	if( rc < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): input error=%d id=%lu, closing.\n",
			s, rc, c->c_connid );
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
	Connection *conn )
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
	char *defer = NULL;

	if ( conn->c_currentber == NULL &&
		( conn->c_currentber = ber_alloc()) == NULL )
	{
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
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

		Debug( LDAP_DEBUG_TRACE,
			"ber_get_next on fd %d failed errno=%d (%s)\n",
			sd, err, sock_errstr(err) );
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
		Debug( LDAP_DEBUG_ANY, "ber_get_int returns 0x%lx\n",
			tag, 0, 0 );
		ber_free( ber, 1 );
		return -1;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error */
		Debug( LDAP_DEBUG_ANY, "ber_peek_tag returns 0x%lx\n",
			tag, 0, 0 );
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
			Debug( LDAP_DEBUG_ANY, "invalid req for UDP 0x%lx\n", tag, 0, 0 );
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
	/* clear state if the connection is being reused from inactive */
	if ( conn->c_conn_state == SLAP_C_INACTIVE ) {
		memset( &conn->c_pagedresults_state, 0, sizeof( conn->c_pagedresults_state ) );
	}
	op->o_pagedresults_state = conn->c_pagedresults_state;

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
			Debug( LDAP_DEBUG_ANY, "ber_write failed\n", 0, 0, 0 );
			return 1;
		}

		if (op->o_protocol == LDAP_VERSION2) {
			rc = ber_printf(op->o_res_ber, "{is{" /*}}*/, op->o_msgid, "");
			if (rc == -1) {
				Debug( LDAP_DEBUG_ANY, "ber_write failed\n", 0, 0, 0 );
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
	 * already pending ops, let them go first.  Abandon operations
	 * get exceptions to some, but not all, cases.
	 */
	if (tag != LDAP_REQ_ABANDON && conn->c_conn_state == SLAP_C_CLOSING) {
		defer = "closing";
	} else if (tag != LDAP_REQ_ABANDON && conn->c_writewaiter) {
		defer = "awaiting write";
	} else if (conn->c_n_ops_executing >= connection_pool_max/2) {
		defer = "too many executing";
	} else if (conn->c_conn_state == SLAP_C_BINDING) {
		defer = "binding";
	} else if (tag != LDAP_REQ_ABANDON && conn->c_n_ops_pending) {
		defer = "pending operations";
	}

	if( defer ) {
		int max = conn->c_dn.bv_len
			? slap_conn_max_pending_auth
			: slap_conn_max_pending;

		Debug( LDAP_DEBUG_ANY,
			"connection_input: conn=%lu deferring operation: %s\n",
			conn->c_connid, defer, 0 );
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
			Debug( LDAP_DEBUG_TRACE,
				"connection_resched: reaquiring locks conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
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
			Debug( LDAP_DEBUG_TRACE, "connection_resched: "
				"closed by other thread conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
		} else {
			Debug( LDAP_DEBUG_TRACE, "connection_resched: "
				"attempting closing conn=%lu sd=%d\n",
				conn->c_connid, sd, 0 );
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
		Debug( LDAP_DEBUG_ANY,
			"ldap_pvt_thread_pool_submit: failed (%d) for conn=%lu\n",
			status, op->o_connid, 0 );
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
		Debug( LDAP_DEBUG_ANY,
			"connection_write(%ld): no connection!\n",
			(long)s, 0, 0 );
		slapd_remove(s, 1, 0);
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_write++;

	Debug( LDAP_DEBUG_TRACE,
		"connection_write(%d): waking output for id=%lu\n",
		s, c->c_connid, 0 );
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

void
connection_fake_init(
	Connection *conn,
	Operation *op,
	void *ctx )
{
	conn->c_connid = -1;
	conn->c_send_ldap_result = slap_send_ldap_result;
	conn->c_send_search_entry = slap_send_search_entry;
	conn->c_send_search_reference = slap_send_search_reference;
	conn->c_listener = (Listener *)&dummy_list;
	conn->c_peer_domain = slap_empty_bv;
	conn->c_peer_name = slap_empty_bv;

	/* set memory context */
	op->o_tmpmemctx = slap_sl_mem_create( SLAP_SLAB_SIZE, ctx );
	op->o_tmpmfuncs = &slap_sl_mfuncs;
	op->o_threadctx = ctx;

	op->o_conn = conn;
	op->o_connid = op->o_conn->c_connid;

	op->o_time = slap_get_time();
}

void
connection_assign_nextid( Connection *conn )
{
	ldap_pvt_thread_mutex_lock( &conn_nextid_mutex );
	conn->c_connid = conn_nextid++;
	ldap_pvt_thread_mutex_unlock( &conn_nextid_mutex );
}

