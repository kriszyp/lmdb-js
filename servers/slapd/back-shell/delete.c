/* delete.c - shell backend delete function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

void
shell_back_delete(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;

	if ( si->si_delete == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "delete not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_delete, &rfp, &wfp ))
	    == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the delete process */
	fprintf( wfp, "DELETE\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );
	fclose( rfp );
}
