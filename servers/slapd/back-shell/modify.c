/* modify.c - shell backend modify function */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

int
shell_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
    LDAPModList	*ml
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	int			i;

	if ( si->si_modify == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "modify not implemented", NULL, NULL );
		return( -1 );
	}

	if ( (op->o_private = (void *) forkandexec( si->si_modify, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec", NULL, NULL );
		return( -1 );
	}

	/* write out the request to the modify process */
	fprintf( wfp, "MODIFY\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn );
	for ( ; ml != NULL; ml = ml->ml_next ) {
		switch ( ml->ml_op ) {
		case LDAP_MOD_ADD:
			fprintf( wfp, "add: %s\n", ml->ml_type );
			break;

		case LDAP_MOD_DELETE:
			fprintf( wfp, "delete: %s\n", ml->ml_type );
			break;

		case LDAP_MOD_REPLACE:
			fprintf( wfp, "replace: %s\n", ml->ml_type );
			break;
		}

		for ( i = 0; ml->ml_bvalues != NULL && ml->ml_bvalues[i]
		    != NULL; i++ ) {
			fprintf( wfp, "%s: %s\n", ml->ml_type,
			    ml->ml_bvalues[i]->bv_val );
		}
	}
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );
	fclose( rfp );
	return( 0 );
}
