/* modify.c - shell backend modify function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

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
    struct berval *dn,
    struct berval *ndn,
    Modifications	*ml
)
{
	Modification *mod;
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Entry e;
	FILE			*rfp, *wfp;
	int			i;

	if ( si->si_modify == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "modify not implemented", NULL, NULL );
		return( -1 );
	}

	e.e_id = NOID;
	e.e_name = *dn;
	e.e_nname = *ndn;
	e.e_attrs = NULL;
	e.e_ocflags = 0;
	e.e_bv.bv_len = 0;
	e.e_bv.bv_val = NULL;
	e.e_private = NULL;

	if ( ! access_allowed( be, conn, op, &e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		return -1;
	}

	if ( (op->o_private = (void *) forkandexec( si->si_modify, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OTHER, NULL,
		    "could not fork/exec", NULL, NULL );
		return( -1 );
	}

	/* write out the request to the modify process */
	fprintf( wfp, "MODIFY\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn->bv_val );
	for ( ; ml != NULL; ml = ml->sml_next ) {
		mod = &ml->sml_mod;

		/* FIXME: should use LDIF routines to deal with binary data */

		switch ( mod->sm_op ) {
		case LDAP_MOD_ADD:
			fprintf( wfp, "add: %s\n", mod->sm_desc->ad_cname.bv_val );
			break;

		case LDAP_MOD_DELETE:
			fprintf( wfp, "delete: %s\n", mod->sm_desc->ad_cname.bv_val );
			break;

		case LDAP_MOD_REPLACE:
			fprintf( wfp, "replace: %s\n", mod->sm_desc->ad_cname.bv_val );
			break;
		}

		if( mod->sm_bvalues != NULL ) {
			for ( i = 0; mod->sm_bvalues[i].bv_val != NULL; i++ ) {
				fprintf( wfp, "%s: %s\n", mod->sm_desc->ad_cname.bv_val,
					mod->sm_bvalues[i].bv_val /* binary! */ );
			}
		}

		fprintf( wfp, "-\n" );
	}
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );
	fclose( rfp );
	return( 0 );
}
