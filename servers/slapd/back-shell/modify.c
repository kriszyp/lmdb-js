/* modify.c - shell backend modify function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

void
shell_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    LDAPMod	*mods
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	int			i;

	if ( si->si_modify == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "modify not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_modify, &rfp, &wfp ))
	    == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the modify process */
	fprintf( wfp, "MODIFY\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	for ( ; mods != NULL; mods = mods->mod_next ) {
		switch ( mods->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
			fprintf( wfp, "add: %s", mods->mod_type );
			break;

		case LDAP_MOD_DELETE:
			fprintf( wfp, "delete: %s", mods->mod_type );
			break;

		case LDAP_MOD_REPLACE:
			fprintf( wfp, "replace: %s", mods->mod_type );
			break;
		}

		for ( i = 0; mods->mod_bvalues != NULL && mods->mod_bvalues[i]
		    != NULL; i++ ) {
			fprintf( wfp, "%s: %s\n", mods->mod_type,
			    mods->mod_bvalues[i]->bv_val );
		}
	}
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );
	fclose( rfp );
}
