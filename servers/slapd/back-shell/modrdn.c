/* modrdn.c - shell backend modrdn function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * LDAP v3 newSuperior support.
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "shell.h"

int
shell_back_modrdn(
    Operation	*op,
    SlapReply	*rs )
{
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Entry e;
	FILE			*rfp, *wfp;

	if ( si->si_modrdn == NULL ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
		    "modrdn not implemented" );
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

	if ( (op->o_private = (void *) forkandexec( si->si_modrdn, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not fork/exec" );
		return( -1 );
	}

	/* write out the request to the modrdn process */
	fprintf( wfp, "MODRDN\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, op->o_bd );
	fprintf( wfp, "dn: %s\n", op->o_req_dn.bv_val );
	fprintf( wfp, "newrdn: %s\n", op->oq_modrdn.rs_newrdn.bv_val );
	fprintf( wfp, "deleteoldrdn: %d\n", op->oq_modrdn.rs_deleteoldrdn ? 1 : 0 );
	if (op->oq_modrdn.rs_newSup != NULL) {
		fprintf( wfp, "newSuperior: %s\n", op->oq_modrdn.rs_newSup->bv_val );
	}
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( op, rs, rfp );
	fclose( rfp );
	return( 0 );
}
