#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"

#ifdef HAVE_WINSOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

/* protected by connections_mutex */
static ldap_pvt_thread_mutex_t connections_mutex;
static Connection *connections = NULL;
static int conn_index = -1;
static long conn_nextid = 0;

/* structure state (protected by connections_mutex) */
#define SLAP_C_UNINITIALIZED	0x0	/* MUST BE ZERO (0) */
#define SLAP_C_UNUSED			0x1
#define SLAP_C_USED				0x2

/* connection state (protected by c_mutex ) */
#define SLAP_C_INVALID			0x0	/* MUST BE ZERO (0) */
#define SLAP_C_INACTIVE			0x1	/* zero threads */
#define SLAP_C_ACTIVE			0x2 /* one or more threads */
#define SLAP_C_BINDING			0x3	/* binding */
#define SLAP_C_CLOSING			0x4	/* closing */

void slapd_remove(int s);
static Connection* connection_get( int s );

static int connection_input( Connection *c );

static int connection_op_activate( Connection *conn, Operation *op );
static int connection_resched( Connection *conn );

struct co_arg {
	Connection	*co_conn;
	Operation	*co_op;
};

/*
 * Initialize connection management infrastructure.
 */
int connections_init(void)
{
	int i;

	assert( connections == NULL );

	if( connections != NULL) { /* probably should assert this */
		Debug( LDAP_DEBUG_ANY, "connections_init: already initialized.\n",
			0, 0, 0 );
		return -1;
	}

	/* should check return of every call */
	ldap_pvt_thread_mutex_init( &connections_mutex );

	connections = (Connection *) calloc( dtblsize, sizeof(Connection) );

	if( connections == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"connections_init: allocation (%d*%ld) of connection array failed.\n",
			dtblsize, (long) sizeof(Connection), 0 );
		return -1;
	}

	for ( i = 0; i < dtblsize; i++ )
		memset( &connections[i], 0, sizeof(Connection) );

	/*
	 * per entry initialization of the Connection array initialization
	 * will be done by connection_init()
	 */ 

	return 0;
}

static Connection* connection_get( int s )
{
	Connection *c = NULL;

	assert( connections != NULL );

	if(s < 0) {
		return NULL;
	}

#ifndef HAVE_WINSOCK
	assert( connections[s].c_struct_state == SLAP_C_USED );
	assert( connections[s].c_conn_state != SLAP_C_INVALID );
	assert( connections[s].c_sb.sb_sd != -1 );

	c = &connections[s];
#else
	{
		int i;

		for(i=0; i<dtblsize; i++) {
			if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( connections[i].c_sb.sb_sd == 0 );
				break;
			}

			if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
				assert( connections[i].c_conn_state == SLAP_C_INVALID );
				assert( connections[i].c_sb.sb_sd == -1 );
				continue;
			}

			assert( connections[i].c_struct_state == SLAP_C_USED );
			assert( connections[i].c_conn_state != SLAP_C_INVALID );
			assert( connections[i].c_sb.sb_sd != -1 );

			if( connections[i].c_sb.sb_sd == s ) {
				c = &connections[i];
				break;
			}
		}
	}
#endif

	if( c != NULL ) {
		/* we do this BEFORE locking to aid in debugging */
		Debug( LDAP_DEBUG_TRACE,
			"connection_get(%d): got connid=%ld\n",
			s, c->c_connid, 0 );

		ldap_pvt_thread_mutex_lock( &c->c_mutex );
	}
	return c;
}

static void connection_return( Connection *c )
{
	ldap_pvt_thread_mutex_unlock( &c->c_mutex );
}

long connection_init(
	int s,
	const char* name,
	const char* addr)
{
	long id;
	Connection *c;
	assert( connections != NULL );

	if( s < 0 ) {
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
		int i;

        for( i=0; i < dtblsize; i++) {
            if( connections[i].c_struct_state == SLAP_C_UNINITIALIZED ) {
                assert( connections[i].c_sb.sb_sd == 0 );
                c = &connections[i];
                break;
            }

            if( connections[i].c_struct_state == SLAP_C_UNUSED ) {
                assert( connections[i].c_sb.sb_sd == -1 );
                c = &connections[i];
                break;
            }

            assert( connections[i].c_struct_state == SLAP_C_USED );
            assert( connections[i].c_conn_state != SLAP_C_INVALID );
            assert( connections[i].c_sb.sb_sd != -1 );
        }

        if( c == NULL ) {
            ldap_pvt_thread_mutex_unlock( &connections_mutex );
            return -1;
        }
    }
#endif

    assert( c != NULL );
    assert( c->c_struct_state != SLAP_C_USED );
    assert( c->c_conn_state == SLAP_C_INVALID );

    if( c->c_struct_state == SLAP_C_UNINITIALIZED ) {
        c->c_dn = NULL;
        c->c_cdn = NULL;
        c->c_client_name = NULL;
        c->c_client_addr = NULL;
        c->c_ops = NULL;
        c->c_pending_ops = NULL;

        lber_pvt_sb_init( &c->c_sb );

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
    assert( c->c_client_name == NULL );
    assert( c->c_client_addr == NULL );
    assert( c->c_ops == NULL );
    assert( c->c_pending_ops == NULL );

    c->c_client_name = ch_strdup( name == NULL ? "" : name );
    c->c_client_addr = ch_strdup( addr );

    c->c_n_ops_received = 0;
#ifdef LDAP_COUNTERS
    c->c_n_ops_executing = 0;
    c->c_n_ops_pending = 0;
    c->c_n_ops_completed = 0;
#endif

    c->c_starttime = slap_get_time();

    lber_pvt_sb_set_desc( &c->c_sb, s );
    lber_pvt_sb_set_io( &c->c_sb, &lber_pvt_sb_io_tcp, NULL );

    if( lber_pvt_sb_set_nonblock( &c->c_sb, 1 ) < 0 ) {
        Debug( LDAP_DEBUG_ANY,
            "connection_init(%d, %s, %s): set nonblocking failed\n",
            s, c->c_client_name, c->c_client_addr);
    }

    id = c->c_connid = conn_nextid++;

    c->c_conn_state = SLAP_C_INACTIVE;
    c->c_struct_state = SLAP_C_USED;

    ldap_pvt_thread_mutex_unlock( &c->c_mutex );
    ldap_pvt_thread_mutex_unlock( &connections_mutex );

    return id;
}

static void
connection_destroy( Connection *c )
{
    assert( connections != NULL );
    assert( c != NULL );
    assert( c->c_struct_state != SLAP_C_UNUSED );
    assert( c->c_conn_state != SLAP_C_INVALID );
    assert( c->c_ops == NULL );

    c->c_struct_state = SLAP_C_UNUSED;
    c->c_conn_state = SLAP_C_INVALID;

    c->c_version = 0;
    c->c_protocol = 0;

    c->c_starttime = 0;

    if(c->c_dn != NULL) {
        free(c->c_dn);
        c->c_dn = NULL;
    }
	if(c->c_cdn != NULL) {
		free(c->c_cdn);
		c->c_cdn = NULL;
	}
	if(c->c_client_name != NULL) {
		free(c->c_client_name);
		c->c_client_name = NULL;
	}
	if(c->c_client_addr != NULL) {
		free(c->c_client_addr);
		c->c_client_addr = NULL;
	}

	if ( lber_pvt_sb_in_use(&c->c_sb) ) {
		int sd = lber_pvt_sb_get_desc(&c->c_sb);

		slapd_remove( sd );
	   	lber_pvt_sb_close( &c->c_sb );

		Statslog( LDAP_DEBUG_STATS,
		    "conn=%d fd=%d closed.\n",
			c->c_connid, sd, 0, 0, 0 );
	}

   	lber_pvt_sb_destroy( &c->c_sb );
}

void connection_closing( Connection *c )
{
	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );
	assert( c->c_conn_state != SLAP_C_INVALID );

	if( c->c_conn_state != SLAP_C_CLOSING ) {
		/* don't listen on this port anymore */
		slapd_clr_read( c->c_sb.sb_sd, 1 );
		c->c_conn_state = SLAP_C_CLOSING;
	}
}

static void connection_close( Connection *c )
{
	assert( connections != NULL );
	assert( c != NULL );
	assert( c->c_struct_state == SLAP_C_USED );
	assert( c->c_conn_state == SLAP_C_CLOSING );

	if( c->c_ops != NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_close: deferring conn=%ld sd=%d.\n",
			c->c_connid, c->c_sb.sb_sd, 0 );

		return;
	}

	Debug( LDAP_DEBUG_TRACE, "connection_close: conn=%ld sd=%d.\n",
		c->c_connid, c->c_sb.sb_sd, 0 );

	connection_destroy( c );
}

long connections_nextid(void)
{
	long id;
	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	id = conn_nextid;

	ldap_pvt_thread_mutex_unlock( &connections_mutex );

	return id;
}

Connection* connection_first(void)
{
	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	assert( conn_index == -1 );
	conn_index = 0;

	return connection_next(NULL);
}

Connection* connection_next(Connection *c)
{
	assert( connections != NULL );
	assert( conn_index != -1 );
	assert( conn_index <= dtblsize );

	if( c != NULL ) {
		ldap_pvt_thread_mutex_unlock( &c->c_mutex );
	}

	c = NULL;

	for(; conn_index < dtblsize; conn_index++) {
		if( connections[conn_index].c_struct_state == SLAP_C_UNINITIALIZED ) {
			assert( connections[conn_index].c_conn_state == SLAP_C_INVALID );
#ifndef HAVE_WINSOCK
			continue;
#else
			break;
#endif
		}

		if( connections[conn_index].c_struct_state == SLAP_C_USED ) {
			assert( connections[conn_index].c_conn_state != SLAP_C_INVALID );
			c = &connections[conn_index++];
			break;
		}

		assert( connections[conn_index].c_struct_state == SLAP_C_UNUSED );
		assert( connections[conn_index].c_conn_state == SLAP_C_INVALID );
	}

	if( c != NULL ) {
		ldap_pvt_thread_mutex_lock( &c->c_mutex );
	}

	return c;
}

void connection_done(Connection *c)
{
	assert( connections != NULL );
	assert( conn_index != -1 );
	assert( conn_index <= dtblsize );

	if( c != NULL ) {
		ldap_pvt_thread_mutex_unlock( &c->c_mutex );
	}

	conn_index = -1;
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
	struct co_arg	*arg = arg_v;
	int tag = arg->co_op->o_tag;
	Connection *conn = arg->co_conn;

#ifdef LDAP_COUNTERS
	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_initiated++;
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );
#endif

	switch ( tag ) {
	case LDAP_REQ_BIND:
		do_bind( conn, arg->co_op );
		break;

#ifdef LDAP_COMPAT30
	case LDAP_REQ_UNBIND_30:
#endif
	case LDAP_REQ_UNBIND:
		do_unbind( conn, arg->co_op );
		break;

	case LDAP_REQ_ADD:
		do_add( conn, arg->co_op );
		break;

#ifdef LDAP_COMPAT30
	case LDAP_REQ_DELETE_30:
#endif
	case LDAP_REQ_DELETE:
		do_delete( conn, arg->co_op );
		break;

	case LDAP_REQ_MODRDN:
		do_modrdn( conn, arg->co_op );
		break;

	case LDAP_REQ_MODIFY:
		do_modify( conn, arg->co_op );
		break;

	case LDAP_REQ_COMPARE:
		do_compare( conn, arg->co_op );
		break;

	case LDAP_REQ_SEARCH:
		do_search( conn, arg->co_op );
		break;

#ifdef LDAP_COMPAT30
	case LDAP_REQ_ABANDON_30:
#endif
	case LDAP_REQ_ABANDON:
		do_abandon( conn, arg->co_op );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "unknown request 0x%lx\n",
		    arg->co_op->o_tag, 0, 0 );
		break;
	}

#ifdef LDAP_COUNTERS
	ldap_pvt_thread_mutex_lock( &num_ops_mutex );
	num_ops_completed++;
	ldap_pvt_thread_mutex_unlock( &num_ops_mutex );
#endif

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

#ifdef LDAP_COUNTERS
	conn->c_n_ops_completed++;
#endif

	slap_op_remove( &conn->c_ops, arg->co_op );
	slap_op_free( arg->co_op );
	arg->co_op = NULL;
	arg->co_conn = NULL;
	free( (char *) arg );
	arg = NULL;

	switch( tag ) {
#ifdef LDAP_COMPAT30
	case LDAP_REQ_UNBIND_30:
#endif
	case LDAP_REQ_UNBIND:
		connection_closing( conn );
		break;

	case LDAP_REQ_BIND:
		if( conn->c_conn_state == SLAP_C_BINDING) {
			conn->c_conn_state = SLAP_C_ACTIVE;
		}
	}

	if( conn->c_conn_state == SLAP_C_CLOSING ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_operation: attempting closing conn=%ld sd=%d.\n",
			conn->c_connid, conn->c_sb.sb_sd, 0 );

		connection_close( conn );
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

int connection_read(int s)
{
	int rc = 0;
	Connection *c;
	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	c = connection_get( s );
	if( c == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"connection_read(%d): no connection!\n",
			s, 0, 0 );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

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

#define CONNECTION_INPUT_LOOP 1

#ifdef DATA_READY_LOOP
	while(!rc && lber_pvt_sb_data_ready(&c->c_sb))
#elif CONNECTION_INPUT_LOOP
	while(!rc)
#endif
	{
		rc = connection_input( c );
	}

	if( rc < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"connection_read(%d): input error=%d id=%ld, closing.\n",
			s, rc, c->c_connid );

		connection_closing( c );
		connection_close( c );
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
	unsigned long	tag, len;
	long		msgid;
	BerElement	*ber;

	if ( conn->c_currentber == NULL && (conn->c_currentber = ber_alloc())
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ber_alloc failed\n", 0, 0, 0 );
		return -1;
	}

	errno = 0;
	if ( (tag = ber_get_next( &conn->c_sb, &len, conn->c_currentber ))
	    != LDAP_TAG_MESSAGE )
	{
		int err = errno;

		Debug( LDAP_DEBUG_TRACE,
			"ber_get_next on fd %d failed errno %d (%s)\n",
			lber_pvt_sb_get_desc(&conn->c_sb), err,
			err > -1 && err < sys_nerr ?  sys_errlist[err] : "unknown" );
		Debug( LDAP_DEBUG_TRACE,
			"\t*** got %ld of %lu so far\n",
			(long)(conn->c_currentber->ber_rwptr - conn->c_currentber->ber_buf),
			conn->c_currentber->ber_len, 0 );

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

#ifdef LDAP_COMPAT30
	if ( conn->c_version == 30 ) {
		(void) ber_skip_tag( ber, &len );
	}
#endif

	op = slap_op_alloc( ber, msgid, tag, conn->c_n_ops_received++ );

	if ( conn->c_conn_state == SLAP_C_BINDING
		|| conn->c_conn_state == SLAP_C_CLOSING )
	{
		Debug( LDAP_DEBUG_ANY, "deferring operation\n", 0, 0, 0 );
		slap_op_add( &conn->c_pending_ops, op );

	} else {
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

	if( conn->c_conn_state != SLAP_C_ACTIVE ) {
		/* other states need different handling */
		return 0;
	}

	for( op = slap_op_pop( &conn->c_pending_ops );
		op != NULL;
		op = slap_op_pop( &conn->c_pending_ops ) )
	{
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
	unsigned long tag = op->o_tag;

	if ( conn->c_dn != NULL ) {
		tmpdn = ch_strdup( conn->c_dn );
	} else {
		tmpdn = NULL;
	}

	arg = (struct co_arg *) ch_malloc( sizeof(struct co_arg) );
	arg->co_conn = conn;
	arg->co_op = op;

	arg->co_op->o_dn = ch_strdup( tmpdn != NULL ? tmpdn : "" );
	arg->co_op->o_ndn = dn_normalize_case( ch_strdup( arg->co_op->o_dn ) );

	slap_op_add( &conn->c_ops, arg->co_op );

	if(tag == LDAP_REQ_BIND) {
		conn->c_conn_state = SLAP_C_BINDING;
	}

	if ( tmpdn != NULL ) {
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

int connection_write(int s)
{
	Connection *c;
	assert( connections != NULL );

	ldap_pvt_thread_mutex_lock( &connections_mutex );

	c = connection_get( s );
	if( c == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"connection_write(%d): no connection!\n",
			s, 0, 0 );
		ldap_pvt_thread_mutex_unlock( &connections_mutex );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE,
		"connection_write(%d): waking output for id=%ld\n",
		s, c->c_connid, 0 );

	ldap_pvt_thread_cond_signal( &c->c_write_cv );

	connection_return( c );
	ldap_pvt_thread_mutex_unlock( &connections_mutex );
	return 0;
}
