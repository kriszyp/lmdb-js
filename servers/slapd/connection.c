/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"

/* we need LBER internals */
#include "../../libraries/liblber/lber-int.h"

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

const char *
connection_state2str( int state )
{
	switch( state ) {
	case SLAP_C_INVALID:	return "!";		
	case SLAP_C_INACTIVE:	return "|";		
	case SLAP_C_ACTIVE:		return "";			
	case SLAP_C_BINDING:	return "B";
	case SLAP_C_CLOSING:	return "C";			
	}

	return "?";
}

static Connection* connection_get( ber_socket_t s );

static int connection_input( Connection *c );
static void connection_close( Connection *c );

static int connection_op_activate( Connection *conn, Operation *op );
static int connection_resched( Connection *conn );
static void connection_abandon( Connection *conn );
static void connection_destroy( Connection *c );

struct co_arg {
	Connection	*co_conn;
	Operation	*co_op;
};

/*
 * Initialize connection management infrastructure.
 */
int connections_init(void)
{
	assert( connections == NULL );

	if( connections != NULL) {
		Debug( LDAP_DEBUG_ANY, "connections_init: already initialized.\n",
			0, 0, 0 );
		return -1;
	}

	/* should check return of every call */
	ldap_pvt_thread_mutex_init( &connections_mutex );

	connections = (Connection *) calloc( dtblsize, sizeof(Connection) );

	if( connections == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"connections_init: allocation (%d*%ld) of connection array failed\n",
			dtblsize, (long) sizeof(Connection), 0 );
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

	ldap_pvt_thread_mutex_lock( &connections_mutex );

 	for( c = connection_first( &connindex );
		c != NULL;
		c = connection_next( c, &connindex ) )
	{
		if( difftime( c->c_activitytime+global_idletimeout, now) < 0 ) {
			/* close it */
			connection_closing( c );
			connection_close( c );
			i++;
		}
	}
	connection_done( c );

	ldap_pvt_thread_mutex_unlock( &connections_mutex );

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
		ber_socket_t i;

		for(i=0; i<dtblsize; i++) {
			if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( connections[i].c_sb == 0 );
				break;
			}

			if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( !ber_pvt_sb_in_use( connections[i].c_sb ) );
				continue;
			}

			/* state can actually change from used -> unused by resched,
			 * so don't assert details here.
			 */

			if( ber_pvt_sb_get_desc( connections[i].c_sb ) == s ) {
				c = &connections[i];
				break;
			}
		}
	}
#endif

	if( c != NULL ) {
		ldap_pvt_thread_mutex_lock( &c->c_mutex );

		if( c->c_struct_state != SLAP_C_USED ) {
			/* connection must have been closed due to resched */

			assert( c->c_conn_state == SLAP_C_INVALID );
			assert( !ber_pvt_sb_in_use( c->c_sb ) );

			Debug( LDAP_DEBUG_TRACE,
				"connection_get(%d): connection not used\n",
				s, 0, 0 );

			ldap_pvt_thread_mutex_unlock( &c->c_mutex );
			return NULL;
		}

		Debug( LDAP_DEBUG_TRACE,
			"connection_get(%d): got connid=%ld\n",
			s, c->c_connid, 0 );

		c->c_n_get++;

		assert( c->c_struct_state == SLAP_C_USED );
		assert( c->c_conn_state != SLAP_C_INVALID );
		assert( ber_pvt_sb_in_use( c->c_sb ) );

    	c->c_activitytime = slap_get_time();
	}

	return c;
}

static void connection_return( Connection *c )
{
	ldap_pvt_thread_mutex_unlock( &c->c_mutex );
}

long connection_init(
	ber_socket_t s,
	const char* url,
	const char* dnsname,
	const char* peername,
	const char* sockname,
	int use_tls )
{
	unsigned long id;
	Connection *c;

	assert( connections != NULL );

	assert( dnsname != NULL );
	assert( peername != NULL );
	assert( sockname != NULL );

#ifndef HAVE_TLS
	assert( !use_tls );
#endif

	if( s == AC_SOCKET_INVALID ) {
        Debug( LDAP_DEBUG_ANY,
			"connection_init(%ld): invalid.\n",
			(long) s, 0, 0 );
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
		unsigned int i;

		c = NULL;

        for( i=0; i < dtblsize; i++) {
            if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
                assert( connections[i].c_sb == 0 );
                c = &connections[i];
                break;
            }

            if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
                assert( !ber_pvt_sb_in_use( connections[i].c_sb ));
                c = &connections[i];
                break;
            }

            assert( connections[i].c_struct_state == SLAP_C_USED );
            assert( connections[i].c_conn_state != SLAP_C_INVALID );
            assert( ber_pvt_sb_in_use( connections[i].c_sb ));
        }

        if( c == NULL ) {
        	Debug( LDAP_DEBUG_ANY,
				"connection_init(%d): connection table full (%d/%d)\n",
				s, i, dtblsize);
            ldap_pvt_thread_mutex_unlock( &connections_mutex );
            return -1;
        }
    }
#endif

    assert( c != NULL );

    if( c->c_struct_state == SLAP_C_UNINITIALIZED ) {
        c->c_dn = NULL;
        c->c_cdn = NULL;

		c->c_listener_url = NULL;
		c->c_peer_domain = NULL;
        c->c_peer_name = NULL;
        c->c_sock_name = NULL;

        c->c_ops = NULL;
        c->c_pending_ops = NULL;
		c->c_authmech = NULL;
		c->c_authstate = NULL;

#ifdef HAVE_CYRUS_SASL
		c->c_sasl_context = NULL;
#endif

        c->c_sb = ber_sockbuf_alloc( );
		c->c_currentber = NULL;

        /* should check status of thread calls */
        ldap_pvt_thread_mutex_init( &c->c_mutex );
        ldap_pvt_thread_mutex_init( &c->c_write_mutex );
        ldap_pvt_thread_cond_init( &c->c_write_cv );

        c->c_struct_state = SLAP_C_UNUSED;
    }

    ldap_pvt_thread_mutex_lock( &c->c_mutex );

    assert( c->c_struct_state == SLAP_C_UNUSED );
    assert(	c->c_dn == NULL );
    assert(	c->c_cdn == NULL );
    assert( c->c_listener_url == NULL );
    assert( c->c_peer_domain == NULL );
    assert( c->c_peer_name == NULL );
    assert( c->c_sock_name == NULL );
    assert( c->c_ops == NULL );
    assert( c->c_pending_ops == NULL );
	assert( c->c_authmech == NULL );
	assert( c->c_authstate == NULL );
#ifdef HAVE_CYRUS_SASL
	assert( c->c_sasl_context == NULL );
#endif
	assert( c->c_currentber == NULL );

	c->c_listener_url = ch_strdup( url  );
	c->c_peer_domain = ch_strdup( dnsname  );
    c->c_peer_name = ch_strdup( peername  );
    c->c_sock_name = ch_strdup( sockname );

    c->c_n_ops_received = 0;
    c->c_n_ops_executing = 0;
    c->c_n_ops_pending = 0;
    c->c_n_ops_completed = 0;

	c->c_n_get = 0;
	c->c_n_read = 0;
	c->c_n_write = 0;

	/* assume LDAPv3 until bind */
	c->c_protocol = LDAP_VERSION3;

    c->c_activitytime = c->c_starttime = slap_get_time();

    ber_pvt_sb_set_desc( c->c_sb, s );
    ber_pvt_sb_set_io( c->c_sb, &ber_pvt_sb_io_tcp, NULL );

    if( ber_pvt_sb_set_nonblock( c->c_sb, 1 ) < 0 ) {
        Debug( LDAP_DEBUG_ANY,
            "connection_init(%d, %s): set nonblocking failed\n",
            s, c->c_peer_name,0 );
    }

    id = c->c_connid = conn_nextid++;

    c->c_conn_state = SLAP_C_INACTIVE;
    c->c_struct_state = SLAP_C_USED;

#ifdef HAVE_TLS
    if ( use_tls ) {
	    c->c_is_tls = 1;
	    c->c_needs_tls_accept = 1;
    }
#endif

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    ldap_pvt_thread_mutex_unlock( &connections_mutex );

    backend_connection_init(c);

    return id;
}

static void
connection_destroy( Connection *c )
{
	/* note: connections_mutex should be locked by caller */

    assert( connections != NULL );
    assert( c != NULL );
    assert( c->c_struct_state != SLAP_C_UNUSED );
    assert( c->c_conn_state != SLAP_C_INVALID );
    assert( c->c_ops == NULL );

    backend_connection_destroy(c);

    c->c_protocol = 0;
    c->c_connid = -1;

    c->c_activitytime = c->c_starttime = 0;

    if(c->c_dn != NULL) {
        free(c->c_dn);
        c->c_dn = NULL;
    }
	if(c->c_cdn != NULL) {
		free(c->c_cdn);
		c->c_cdn = NULL;
	}
	if(c->c_listener_url != NULL) {
		free(c->c_listener_url);
		c->c_listener_url = NULL;
	}
	if(c->c_peer_domain != NULL) {
		free(c->c_peer_domain);
		c->c_peer_domain = NULL;
	}
	if(c->c_peer_name != NULL) {
		free(c->c_peer_name);
		c->c_peer_name = NULL;
	}
	if(c->c_sock_name != NULL) {
		free(c->c_sock_name);
		c->c_sock_name = NULL;
	}
	if(c->c_authmech != NULL ) {
		free(c->c_authmech);
		c->c_authmech = NULL;
	}
	if(c->c_authstate != NULL ) {
		free(c->c_authstate);
		c->c_authstate = NULL;
	}

#ifdef HAVE_CYRUS_SASL
	if(c->c_sasl_context != NULL ) {
		sasl_dispose( &c->c_sasl_context );
		c->c_sasl_context = NULL;
	}
#endif

	if ( c->c_currentber != NULL ) {
		ber_free( c->c_currentber, 1 );
		c->c_currentber = NULL;
	}

	if ( ber_pvt_sb_in_use(c->c_sb) ) {
		int sd = ber_pvt_sb_get_desc(c->c_sb);

		slapd_remove( sd, 0 );
	   	ber_pvt_sb_close( c->c_sb );

		Statslog( LDAP_DEBUG_STATS,
		    "conn=%ld fd=%d closed\n",
			c->c_connid, sd, 0, 0, 0 );
	}

   	ber_pvt_sb_destroy( c->c_sb );

    c->c_conn_state = SLAP_C_INVALID;
    c->c_struct_state = SLAP_C_UNUSED;
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

	for( o = c->c_ops; o != NULL; o = o->o_next ) {
		ldap_pvt_thread_mutex_lock( &o->o_abandonmutex );
		o->o_abandon = 1;
		ldap_pvt_thread_mutex_unlock( &o->o_abandonmutex );
	}

	/* remove pending operations */
	for( o = slap_op_pop( &c->c_pending_ops );
		o != NULL;
		o = slap_op_pop( &c->c_pending_ops ) )
	{
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

		Debug( LDAP_DEBUG_TRACE,
			"connection_closing: readying conn=%ld sd=%d for close\n",
			c->c_connid, ber_pvt_sb_get_desc( c->c_sb ), 0 );

		/* update state to closing */
		c->c_conn_state = SLAP_C_CLOSING;

		/* don't listen on this port anymore */
		slapd_clr_read( ber_pvt_sb_get_desc( c->c_sb ), 1 );

		/* shutdown I/O -- not yet implemented */

		/* abandon active operations */
		connection_abandon( c );

		/* wake write blocked operations */
		slapd_clr_write( ber_pvt_sb_get_desc(c->c_sb), 1 );
		ldap_pvt_thread_cond_signal( &c->c_write_cv );
	}
}

static void connection_close( Connection *c )
{
	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );
	assert( c->c_conn_state == SLAP_C_CLOSING );

	/* note: connections_mutex and c_mutex should be locked by caller */

	if( c->c_ops != NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_close: deferring conn=%ld sd=%d\n",
			c->c_connid, ber_pvt_sb_get_desc( c->c_sb ), 0 );

		return;
	}

	Debug( LDAP_DEBUG_TRACE, "connection_close: conn=%ld sd=%d\n",
		c->c_connid, ber_pvt_sb_get_desc( c->c_sb ), 0 );

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

static void *
connection_operation( void *arg_v )
{
	int rc;
	struct co_arg	*arg = arg_v;
	ber_tag_t tag = arg->co_op->o_tag;
	Connection *conn = arg->co_conn;

	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_initiated++;
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );

	switch ( tag ) {
	case LDAP_REQ_BIND:
		rc = do_bind( conn, arg->co_op );
		break;

	case LDAP_REQ_UNBIND:
		rc = do_unbind( conn, arg->co_op );
		break;

	case LDAP_REQ_ADD:
		rc = do_add( conn, arg->co_op );
		break;

	case LDAP_REQ_DELETE:
		rc = do_delete( conn, arg->co_op );
		break;

	case LDAP_REQ_MODRDN:
		rc = do_modrdn( conn, arg->co_op );
		break;

	case LDAP_REQ_MODIFY:
		rc = do_modify( conn, arg->co_op );
		break;

	case LDAP_REQ_COMPARE:
		rc = do_compare( conn, arg->co_op );
		break;

	case LDAP_REQ_SEARCH:
		rc = do_search( conn, arg->co_op );
		break;

	case LDAP_REQ_ABANDON:
		rc = do_abandon( conn, arg->co_op );
		break;

	case LDAP_REQ_EXTENDED:
		rc = do_extended( conn, arg->co_op );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "unknown LDAP request 0x%lx\n",
		    tag, 0, 0 );
		arg->co_op->o_tag = LBER_ERROR;
		send_ldap_disconnect( conn, arg->co_op,
			LDAP_PROTOCOL_ERROR, "unknown LDAP request" );
		rc = -1;
		break;
	}

	if( rc == -1 ) tag = LBER_ERROR;

	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_completed++;
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	conn->c_n_ops_executing--;
	conn->c_n_ops_completed++;

	slap_op_remove( &conn->c_ops, arg->co_op );
	slap_op_free( arg->co_op );
	arg->co_op = NULL;
	arg->co_conn = NULL;
	free( (char *) arg );
	arg = NULL;

	switch( tag ) {
	case LBER_ERROR:
	case LDAP_REQ_UNBIND:
		/* c_mutex is locked */
		connection_closing( conn );
		break;

	case LDAP_REQ_BIND:
		if( conn->c_conn_state == SLAP_C_BINDING) {
			conn->c_conn_state = SLAP_C_ACTIVE;
		}
		conn->c_bind_in_progress = ( rc == LDAP_SASL_BIND_IN_PROGRESS );
	}

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	active_threads--;
	if( active_threads < 1 ) {
		ldap_pvt_thread_cond_signal(&active_threads_cond);
	}
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	connection_resched( conn );

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	return NULL;
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

		slapd_remove(s, 0);

		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_read++;

	if( c->c_conn_state == SLAP_C_CLOSING ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): closing, ignoring input for id=%ld\n",
			s, c->c_connid, 0 );

		connection_return( c );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}

	Debug( LDAP_DEBUG_TRACE,
		"connection_read(%d): checking for input on id=%ld\n",
		s, c->c_connid, 0 );

#ifdef HAVE_TLS
	if ( c->c_is_tls && c->c_needs_tls_accept ) {
		rc = ldap_pvt_tls_accept( c->c_sb, NULL );
		if ( rc < 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			       "connection_read(%d): TLS accept error error=%d id=%ld, closing\n",
			       s, rc, c->c_connid );

			c->c_needs_tls_accept = 0;
			/* connections_mutex and c_mutex are locked */
			connection_closing( c );
			connection_close( c );
		} else if ( rc == 0 ) {
			c->c_needs_tls_accept = 0;
		}
		connection_return( c );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return 0;
	}
#endif

#define CONNECTION_INPUT_LOOP 1

#ifdef DATA_READY_LOOP
	while(!rc && ber_pvt_sb_data_ready(&c->c_sb))
#elif CONNECTION_INPUT_LOOP
	while(!rc)
#endif
	{
		/* How do we do this without getting into a busy loop ? */
		rc = connection_input( c );
	}

	if( rc < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): input error=%d id=%ld, closing.\n",
			s, rc, c->c_connid );

		/* connections_mutex and c_mutex are locked */
		connection_closing( c );
		connection_close( c );
	}

	if ( ber_pvt_sb_needs_read( c->c_sb ) )
		slapd_set_read( s, 1 );
	if ( ber_pvt_sb_needs_write( c->c_sb ) )
		slapd_set_write( s, 1 );
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

	if ( conn->c_currentber == NULL && (conn->c_currentber = ber_alloc())
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		return -1;
	}

	errno = 0;
	if ( (tag = ber_get_next( conn->c_sb, &len, conn->c_currentber ))
	    != LDAP_TAG_MESSAGE )
	{
		int err = errno;

		Debug( LDAP_DEBUG_TRACE,
			"ber_get_next on fd %d failed errno=%d (%s)\n",
			ber_pvt_sb_get_desc( conn->c_sb ), err, STRERROR(err) );
		Debug( LDAP_DEBUG_TRACE,
			"\t*** got %ld of %lu so far\n",
			(long) ( conn->c_currentber->ber_buf
				?  conn->c_currentber->ber_rwptr - conn->c_currentber->ber_buf
				: 0 ),
			(long) conn->c_currentber->ber_len, 0 );

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
		Debug( LDAP_DEBUG_ANY, "ber_get_int returns 0x%lx\n", tag, 0,
		    0 );
		ber_free( ber, 1 );
		return -1;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error */
		Debug( LDAP_DEBUG_ANY, "ber_peek_tag returns 0x%lx\n", tag, 0,
		    0 );
		ber_free( ber, 1 );

		return -1;
	}

	if(tag == LDAP_REQ_BIND) {
		/* immediately abandon all exiting operations upon BIND */
		connection_abandon( conn );
	}

	op = slap_op_alloc( ber, msgid, tag, conn->c_n_ops_received++ );

	if ( conn->c_conn_state == SLAP_C_BINDING
		|| conn->c_conn_state == SLAP_C_CLOSING )
	{
		Debug( LDAP_DEBUG_ANY, "deferring operation\n", 0, 0, 0 );
		conn->c_n_ops_pending++;
		slap_op_add( &conn->c_pending_ops, op );

	} else {
		conn->c_n_ops_executing++;
		connection_op_activate( conn, op );
	}

#ifdef NO_THREADS
	if ( conn->c_struct_state != SLAP_C_USED ) {
		/* connection must have got closed underneath us */
		return 1;
	}
#endif
	assert( conn->c_struct_state == SLAP_C_USED );

	return 0;
}

static int
connection_resched( Connection *conn )
{
	Operation *op;

	if( conn->c_conn_state == SLAP_C_CLOSING ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_resched: attempting closing conn=%ld sd=%d\n",
			conn->c_connid, ber_pvt_sb_get_desc( conn->c_sb ), 0 );

		connection_close( conn );
		return 0;
	}

	if( conn->c_conn_state != SLAP_C_ACTIVE ) {
		/* other states need different handling */
		return 0;
	}

	for( op = slap_op_pop( &conn->c_pending_ops );
		op != NULL;
		op = slap_op_pop( &conn->c_pending_ops ) )
	{
		/* pending operations should not be marked for abandonment */
		assert(!op->o_abandon);

		conn->c_n_ops_pending--;
		conn->c_n_ops_executing++;

		connection_op_activate( conn, op );

		if ( conn->c_conn_state == SLAP_C_BINDING ) {
			break;
		}
	}
	return 0;
}

static int connection_op_activate( Connection *conn, Operation *op )
{
	struct co_arg *arg;
	char *tmpdn;
	int status;
	ber_tag_t tag = op->o_tag;

	if(tag == LDAP_REQ_BIND) {
		conn->c_conn_state = SLAP_C_BINDING;
	}

	if ( conn->c_dn != NULL ) {
		tmpdn = ch_strdup( conn->c_dn );
	} else {
		tmpdn = NULL;
	}

	arg = (struct co_arg *) ch_malloc( sizeof(struct co_arg) );
	arg->co_conn = conn;
	arg->co_op = op;

	arg->co_op->o_bind_in_progress = conn->c_bind_in_progress;

	arg->co_op->o_dn = ch_strdup( tmpdn != NULL ? tmpdn : "" );
	arg->co_op->o_ndn = ch_strdup( arg->co_op->o_dn );
	(void) dn_normalize( arg->co_op->o_ndn );

	arg->co_op->o_protocol = conn->c_protocol;
	arg->co_op->o_connid = conn->c_connid;

	arg->co_op->o_authtype = conn->c_authtype;
	arg->co_op->o_authmech = conn->c_authmech != NULL
		?  ch_strdup( conn->c_authmech ) : NULL;
	
	slap_op_add( &conn->c_ops, arg->co_op );

	if( tmpdn != NULL ) {
		free( tmpdn );
	}

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	active_threads++;
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	status = ldap_pvt_thread_create( &arg->co_op->o_tid, 1,
					 connection_operation, (void *) arg );

	if ( status != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		"ldap_pvt_thread_create failed (%d)\n", status, 0, 0 );

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
			(long) s, 0, 0 );
		slapd_remove(s, 0);
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	c->c_n_write++;

	Debug( LDAP_DEBUG_TRACE,
		"connection_write(%d): waking output for id=%ld\n",
		s, c->c_connid, 0 );

	ldap_pvt_thread_cond_signal( &c->c_write_cv );

	if ( ber_pvt_sb_needs_read( c->c_sb ) )
		slapd_set_read( s, 1 );
	if ( ber_pvt_sb_needs_write( c->c_sb ) )
		slapd_set_write( s, 1 );
	connection_return( c );
	ldap_pvt_thread_mutex_unlock( &connections_mutex );
	return 0;
}
