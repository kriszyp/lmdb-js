/* unbind.c - shell backend unbind function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

void
shell_back_unbind(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    char		*dn,
    int			method,
    struct berval	*cred
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;

	if ( si->si_unbind == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "unbind not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_unbind, &rfp, &wfp ))
	    == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the unbind process */
	fprintf( wfp, "UNBIND\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	fclose( wfp );

	/* no response to unbind */
	fclose( rfp );
}
