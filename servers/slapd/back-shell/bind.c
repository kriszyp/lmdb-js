/* bind.c - shell backend bind function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

int
shell_back_bind(
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
	int			rc;

	if ( si->si_bind == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "bind not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_bind, &rfp, &wfp ))
	    == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the bind process */
	fprintf( wfp, "BIND\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	fprintf( wfp, "method: %d\n", method );
	fprintf( wfp, "credlen: %d\n", cred->bv_len );
	fprintf( wfp, "cred: %s\n", cred->bv_val ); /* XXX */
	fclose( wfp );

	/* read in the results and send them along */
	rc = read_and_send_results( be, conn, op, rfp, NULL, 0 );
	fclose( rfp );

	return( rc );
}
