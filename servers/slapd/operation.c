/* operation.c - routines to deal with pending ldap operations */

#include "portable.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

extern time_t		currenttime;
extern pthread_mutex_t	currenttime_mutex;

void
op_free( Operation *op )
{
	if ( op->o_ber != NULL )
		ber_free( op->o_ber, 1 );
	if ( op->o_dn != NULL ) {
		free( op->o_dn );
	}
	/* pthread_mutex_destroy( &op->o_abandonmutex ); */
	free( (char *) op );
}

Operation *
op_add(
    Operation		**olist,
    BerElement		*ber,
    unsigned long	msgid,
    unsigned long	tag,
    char			*dn,
    int				id,
    int				connid
)
{
	Operation	**tmp;

	for ( tmp = olist; *tmp != NULL; tmp = &(*tmp)->o_next )
		;	/* NULL */

	*tmp = (Operation *) calloc( 1, sizeof(Operation) );
	pthread_mutex_init( &(*tmp)->o_abandonmutex,
	    pthread_mutexattr_default );
	(*tmp)->o_ber = ber;
	(*tmp)->o_msgid = msgid;
	(*tmp)->o_tag = tag;
	(*tmp)->o_abandon = 0;
	(*tmp)->o_dn = strdup( dn != NULL ? dn : "" );
	pthread_mutex_lock( &currenttime_mutex );
	(*tmp)->o_time = currenttime;
	pthread_mutex_unlock( &currenttime_mutex );
	(*tmp)->o_opid = id;
	(*tmp)->o_connid = connid;
	(*tmp)->o_next = NULL;

	return( *tmp );
}

void
op_delete( Operation **olist, Operation *op )
{
	Operation	**tmp;

	for ( tmp = olist; *tmp != NULL && *tmp != op; tmp = &(*tmp)->o_next )
		;	/* NULL */

	if ( *tmp == NULL ) {
		Debug( LDAP_DEBUG_ANY, "op_delete: can't find op %d\n",
		    op->o_msgid, 0, 0 );
		return; 
	}

	*tmp = (*tmp)->o_next;
	op_free( op );
}
