/* add.c - shell backend add function */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

int
shell_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	int			len;

	if ( si->si_add == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "add not implemented", NULL, NULL );
		return( -1 );
	}

	if ( (op->o_private = (void *) forkandexec( si->si_add, &rfp, &wfp )) == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec", NULL, NULL );
		return( -1 );
	}

	/* write out the request to the add process */
	fprintf( wfp, "ADD\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	fprintf( wfp, "%s", entry2str( e, &len ) );
	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );
	fclose( wfp );

	/* read in the result and send it along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );

	fclose( rfp );
	return( 0 );
}
