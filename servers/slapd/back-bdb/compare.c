/* compare.c - bdb backend compare routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_compare(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn,
	AttributeAssertion *ava
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	Entry		*matched;
	Entry		*e;
	Attribute	*a;
	int			rc; 
	const char	*text = NULL;
	int		manageDSAit = get_manageDSAit( op );

	/* get entry */
	rc = bdb_dn2entry( be, NULL, ndn, &e, &matched, 0 );

	switch( rc ) {
	case DB_NOTFOUND:
	case 0:
		break;
	default:
		rc = LDAP_OTHER;
		text = "internal error";
		goto return_results;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		BVarray refs;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			bdb_entry_return( be, matched );
			matched = NULL;

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		bvarray_free( refs );
		free( matched_dn );

		goto done;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		BVarray refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			e->e_dn, NULL, refs, NULL );

		bvarray_free( refs );
		goto done;
	}

	if ( ! access_allowed( be, conn, op, e,
		ava->aa_desc, &ava->aa_value, ACL_COMPARE ) )
	{
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto return_results;
	}

	rc = LDAP_NO_SUCH_ATTRIBUTE;

	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, ava->aa_desc ))
	{
		rc = LDAP_COMPARE_FALSE;

		if ( value_find( ava->aa_desc, a->a_vals, &ava->aa_value ) == 0 ) {
			rc = LDAP_COMPARE_TRUE;
			break;
		}

	}

	if( rc != LDAP_NO_SUCH_ATTRIBUTE ) {
		rc = LDAP_SUCCESS;
	}


return_results:
	send_ldap_result( conn, op, LDAP_SUCCESS,
		NULL, text, NULL, NULL );

done:
	/* free entry */
	if( e != NULL ) {
		bdb_entry_return( be, e );
	}

	return rc;
}
