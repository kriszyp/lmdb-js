#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"

static int connection_op_activate( Connection *conn, Operation *op );
static int connection_resched( Connection *conn );

struct co_arg {
	Connection	*co_conn;
	Operation	*co_op;
};

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

	ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );
	conn->c_ops_received++;
	ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );

	ldap_pvt_thread_mutex_lock( &ops_mutex );
	ops_initiated++;
	ldap_pvt_thread_mutex_unlock( &ops_mutex );

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

	ldap_pvt_thread_mutex_lock( &ops_mutex );
	ops_completed++;
	ldap_pvt_thread_mutex_unlock( &ops_mutex );

	ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );
	conn->c_ops_completed++;

	slap_op_remove( &conn->c_ops, arg->co_op );
	slap_op_free( arg->co_op );
	arg->co_op = NULL;
	arg->co_conn = NULL;
	free( (char *) arg );
	arg = NULL;

	if((tag == LDAP_REQ_BIND) && (conn->c_state == SLAP_C_BINDING)) {
		conn->c_state = SLAP_C_ACTIVE;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	active_threads--;
	if( active_threads < 1 ) {
		ldap_pvt_thread_cond_signal(&active_threads_cond);
	}
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	connection_resched( conn );

	return NULL;
}

void
connection_activity(
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
		return;
	}

	errno = 0;
	if ( (tag = ber_get_next( &conn->c_sb, &len, conn->c_currentber ))
	    != LDAP_TAG_MESSAGE ) {
		Debug( LDAP_DEBUG_TRACE,
		    "ber_get_next on fd %d failed errno %d (%s)\n",
		    lber_pvt_sb_get_desc(&conn->c_sb), errno, errno > -1 && errno < sys_nerr ?
		    sys_errlist[errno] : "unknown" );
		Debug( LDAP_DEBUG_TRACE, "*** got %ld of %lu so far\n",
		    (long)(conn->c_currentber->ber_rwptr - conn->c_currentber->ber_buf),
		    conn->c_currentber->ber_len, 0 );

		if ( errno != EWOULDBLOCK && errno != EAGAIN ) {
			/* log, close and send error */
			ber_free( conn->c_currentber, 1 );
			conn->c_currentber = NULL;

			close_connection( conn, conn->c_connid, -1 );
		}

		return;
	}
	ber = conn->c_currentber;
	conn->c_currentber = NULL;

	if ( (tag = ber_get_int( ber, &msgid )) != LDAP_TAG_MSGID ) {
		/* log, close and send error */
		Debug( LDAP_DEBUG_ANY, "ber_get_int returns 0x%lx\n", tag, 0,
		    0 );
		ber_free( ber, 1 );

		close_connection( conn, conn->c_connid, -1 );
		return;
	}

	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error */
		Debug( LDAP_DEBUG_ANY, "ber_peek_tag returns 0x%lx\n", tag, 0,
		    0 );
		ber_free( ber, 1 );

		close_connection( conn, conn->c_connid, -1 );
		return;
	}

#ifdef LDAP_COMPAT30
	if ( conn->c_version == 30 ) {
		(void) ber_skip_tag( ber, &len );
	}
#endif

	op = slap_op_alloc( ber, msgid, tag,
	   	conn->c_ops_received, conn->c_connid );

	if ( conn->c_state == SLAP_C_BINDING ) {
		/* connection is binding to a dn, make 'em wait */
		ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );
		slap_op_add( &conn->c_pending_ops, op );

		Debug( LDAP_DEBUG_ANY, "deferring operation\n", 0, 0, 0 );

		ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );

		return;
	}

	connection_op_activate( conn, op );
}

static int
connection_resched( Connection *conn )
{
	Operation *op;

	if( conn->c_state != SLAP_C_ACTIVE ) {
		/* other states need different handling */
		return;
	}

	ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );

	for( op = slap_op_pop( &conn->c_pending_ops );
		op != NULL;
		op = slap_op_pop( &conn->c_pending_ops ) )
	{
		ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );

		connection_op_activate( conn, op );

		ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );

		if ( conn->c_state == SLAP_C_BINDING ) {
			break;
		}
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );
}

static int connection_op_activate( Connection *conn, Operation *op )
{
	struct co_arg *arg;
	char *tmpdn;
	int status;
	unsigned long tag = op->o_tag;

	ldap_pvt_thread_mutex_lock( &conn->c_dnmutex );
	if ( conn->c_dn != NULL ) {
		tmpdn = ch_strdup( conn->c_dn );
	} else {
		tmpdn = NULL;
	}
	ldap_pvt_thread_mutex_unlock( &conn->c_dnmutex );

	arg = (struct co_arg *) ch_malloc( sizeof(struct co_arg) );
	arg->co_conn = conn;
	arg->co_op = op;

	arg->co_op->o_dn = ch_strdup( tmpdn != NULL ? tmpdn : "" );
	arg->co_op->o_ndn = dn_normalize_case( ch_strdup( arg->co_op->o_dn ) );

	ldap_pvt_thread_mutex_lock( &conn->c_opsmutex );

	slap_op_add( &conn->c_ops, arg->co_op );

	if(tag == LDAP_REQ_BIND) {
		conn->c_state = SLAP_C_BINDING;
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_opsmutex );

	if ( tmpdn != NULL ) {
		free( tmpdn );
	}

	ldap_pvt_thread_mutex_lock( &active_threads_mutex );
	active_threads++;
	ldap_pvt_thread_mutex_unlock( &active_threads_mutex );

	status = ldap_pvt_thread_create( &arg->co_op->o_tid, 1,
					 connection_operation, (void *) arg );

	if ( status != 0 ) {
		Debug( LDAP_DEBUG_ANY, "ldap_pvt_thread_create failed (%d)\n", status, 0, 0 );
	}

	return status;
}
