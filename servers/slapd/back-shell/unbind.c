/* unbind.c - shell backend unbind function */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "shell.h"

int
shell_back_unbind(
    Backend		*be,
    Connection		*conn,
    Operation		*op
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;

	if ( si->si_unbind == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "unbind not implemented", NULL, NULL );
		return 0;
	}

	if ( (op->o_private = (void *) forkandexec( si->si_unbind, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec", NULL, NULL );
		return 0;
	}

	/* write out the request to the unbind process */
	fprintf( wfp, "UNBIND\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", (conn->c_dn ? conn->c_dn : "") );
	fclose( wfp );

	/* no response to unbind */
	fclose( rfp );

	return 0;
}
