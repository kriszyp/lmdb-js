/* compare.c - shell backend compare function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

void
shell_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    Ava		*ava
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;

	if ( si->si_compare == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "compare not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_compare, &rfp, &wfp ))
	    == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the compare process */
	fprintf( wfp, "COMPARE\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	fprintf( wfp, "%s: %s\n", ava->ava_type, ava->ava_value.bv_val );
	fclose( wfp );

	/* read in the result and send it along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );

	fclose( rfp );
}
