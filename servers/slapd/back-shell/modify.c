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
    Operation	*op,
    SlapReply	*rs )
{
	Modification *mod;
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Modifications *ml  = op->oq_modify.rs_modlist;
	Entry e;
	FILE			*rfp, *wfp;
	int			i;

	if ( si->si_modify == NULL ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
		    "modify not implemented" );
		return( -1 );
	}

	e.e_id = NOID;
	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;
	e.e_attrs = NULL;
	e.e_ocflags = 0;
	e.e_bv.bv_len = 0;
	e.e_bv.bv_val = NULL;
	e.e_private = NULL;

	if ( ! access_allowed( op, &e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( (op->o_private = (void *) forkandexec( si->si_modify, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not fork/exec" );
		return( -1 );
	}

	/* write out the request to the modify process */
	fprintf( wfp, "MODIFY\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, op->o_bd );
	fprintf( wfp, "dn: %s\n", op->o_req_dn.bv_val );
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
	read_and_send_results( op, rs, rfp );
	fclose( rfp );
	return( 0 );
}
