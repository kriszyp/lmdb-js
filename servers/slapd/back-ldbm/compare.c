/* compare.c - ldbm backend compare routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeAssertion *ava
#else
    Ava		*ava
#endif
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Entry		*matched;
	Entry		*e;
	Attribute	*a;
	int		rc;
	int		manageDSAit = get_manageDSAit( op );

	/* get entry with reader lock */
	if ( (e = dn2entry_r( be, ndn, &matched )) == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );
			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, LDAP_REFERRAL,
			matched_dn, NULL, refs, NULL );

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return( 1 );
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    e->e_dn, NULL, refs, NULL );

		ber_bvecfree( refs );

		rc = 1;
		goto return_results;
	}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	if ( ! access_allowed( be, conn, op, e,
		ava->aa_desc, ava->aa_value, ACL_COMPARE ) )
#else
	if ( ! access_allowed( be, conn, op, e,
		ava->ava_type, &ava->ava_value, ACL_COMPARE ) )
#endif
	{
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS,
			NULL, NULL, NULL, NULL );
		rc = 1;
		goto return_results;
	}

	rc = LDAP_NO_SUCH_ATTRIBUTE;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a, ava->aa_desc ))
#else
	if ((a = attr_find( e->e_attrs, ava->ava_type )) != NULL )
#endif
	{
		rc = LDAP_COMPARE_FALSE;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		if ( value_find( a->a_vals, &ava->ava_value, a->a_syntax, 1 ) == 0 )
#endif
		{
			rc = LDAP_COMPARE_TRUE;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			break;
#endif
		}

	}

	send_ldap_result( conn, op, rc,
		NULL, NULL, NULL, NULL );

	if( rc != LDAP_NO_SUCH_ATTRIBUTE ) {
		rc = 0;
	}


return_results:;
	cache_return_entry_r( &li->li_cache, e );
	return( rc );
}
