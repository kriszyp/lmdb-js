/* referral.c - LDBM backend referral handler */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"
#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_referrals(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    const char *dn,
    const char *ndn,
	const char **text )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc = LDAP_SUCCESS;
	Entry *e, *matched;

	if( op->o_tag == LDAP_REQ_SEARCH ) {
		/* let search take care of itself */
		return rc;
	}

	if( get_manageDSAit( op ) ) {
		/* let op take care of DSA management */
		return rc;
	} 

	/* fetch entry */
	rc = dn2entry_r( be, NULL, ndn, &e, &matched );

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
		    NULL, "internal error", NULL, NULL );
		return rc;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = default_referral;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

			Debug( LDAP_DEBUG_TRACE,
				"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
				op->o_tag, dn, matched_dn );

			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;

			bdb_entry_return( be, matched );
		}

		if( refs != NULL ) {
			/* send referrals */
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				matched_dn, NULL, refs, NULL );
		}

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return rc;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE,
			"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			op->o_tag, dn, e->e_dn );

		if( refs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
		    	e->e_dn, NULL, refs, NULL );
		}

		ber_bvecfree( refs );
	}

	bdb_entry_return( be, e );
	return rc;
}
