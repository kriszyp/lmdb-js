/* operation.c - routines to deal with pending ldap operations */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"


void
slap_op_free( Operation *op )
{
#ifdef LDAP_DEBUG
	assert( op->o_next == NULL );
#endif

	ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );

	if ( op->o_ber != NULL ) {
		ber_free( op->o_ber, 1 );
	}
	if ( op->o_dn != NULL ) {
		free( op->o_dn );
	}
	if ( op->o_ndn != NULL ) {
		free( op->o_ndn );
	}

	ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
	ldap_pvt_thread_mutex_destroy( &op->o_abandonmutex );
	free( (char *) op );
}

Operation *
slap_op_alloc(
    BerElement		*ber,
    unsigned long	msgid,
    unsigned long	tag,
    int				id,
    int				connid
)
{
	Operation	*op;

	op = (Operation *) ch_calloc( 1, sizeof(Operation) );

	ldap_pvt_thread_mutex_init( &op->o_abandonmutex );
	op->o_ber = ber;
	op->o_msgid = msgid;
	op->o_tag = tag;
	op->o_abandon = 0;

	op->o_dn = NULL;
	op->o_ndn = NULL;

	ldap_pvt_thread_mutex_lock( &currenttime_mutex );
	op->o_time = currenttime;
	ldap_pvt_thread_mutex_unlock( &currenttime_mutex );
	op->o_opid = id;
	op->o_connid = connid;
	op->o_next = NULL;

	return( op );
}

int slap_op_add(
    Operation		**olist,
	Operation		*op
)
{
	Operation	**tmp;

	for ( tmp = olist; *tmp != NULL; tmp = &(*tmp)->o_next )
		;	/* NULL */

	*tmp = op;

	return 0;
}

int
slap_op_remove( Operation **olist, Operation *op )
{
	Operation	**tmp;

	for ( tmp = olist; *tmp != NULL && *tmp != op; tmp = &(*tmp)->o_next )
		;	/* NULL */

	if ( *tmp == NULL ) {
		Debug( LDAP_DEBUG_ANY, "op_delete: can't find op %ld\n",
		    op->o_msgid, 0, 0 );
		return -1; 
	}

	*tmp = (*tmp)->o_next;
	op->o_next = NULL;

	return 0;
}

Operation * slap_op_pop( Operation **olist )
{
	Operation *tmp = *olist;

	if(tmp != NULL) {
		*olist = tmp->o_next;
		tmp->o_next = NULL;
	}

	return tmp;
}

