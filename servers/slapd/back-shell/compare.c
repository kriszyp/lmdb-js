/* compare.c - shell backend compare function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

int
shell_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval *dn,
    struct berval *ndn,
    AttributeAssertion *ava
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	Entry e;
	FILE			*rfp, *wfp;

	if ( IS_NULLCMD( si->si_compare ) ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "compare not implemented", NULL, NULL );
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
		entry, NULL, ACL_READ, NULL ) )
	{
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		return -1;
	}

	if ( (op->o_private = (void *) forkandexec( si->si_compare, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OTHER, NULL,
		    "could not fork/exec", NULL, NULL );
		return( -1 );
	}

	/*
	 * FIX ME:  This should use LDIF routines so that binary
	 *	values are properly dealt with
	 */

	/* write out the request to the compare process */
	fprintf( wfp, "COMPARE\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "dn: %s\n", dn->bv_val );
	fprintf( wfp, "%s: %s\n",
		ava->aa_desc->ad_cname.bv_val,
		ava->aa_value.bv_val /* could be binary! */ );
	fclose( wfp );

	/* read in the result and send it along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );

	fclose( rfp );
	return( 0 );
}
