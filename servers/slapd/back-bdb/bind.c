/* bind.c - bdb backend bind routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/krb.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "back-bdb.h"
#include "external.h"

int
bdb_bind(
	Backend		*be,
	Connection		*conn,
	Operation		*op,
	const char		*dn,
	const char		*ndn,
	int			method,
	struct berval	*cred,
	char**	edn
)
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	Entry		*e;
	Attribute	*a;
	int		rc;
	Entry		*matched;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	char		krbname[MAX_K_NAME_SZ + 1];
	AttributeDescription *krbattr = slap_schema.si_ad_krbName;
	AUTH_DAT	ad;
#endif

	AttributeDescription *password = slap_schema.si_ad_userPassword;

	Debug( LDAP_DEBUG_ARGS, "==> bdb_bind: dn: %s\n", dn, 0, 0);

	*edn = NULL;

	/* get entry */
	rc = bdb_dn2entry( be, NULL, ndn, &e, &matched, 0 );

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		return rc;
	}

	/* get entry with reader lock */
	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;

			bdb_entry_return( be, matched );
			matched = NULL;

		} else {
			refs = default_referral;
		}

		/* allow noauth binds */
		rc = 1;
		if ( method == LDAP_AUTH_SIMPLE ) {
			if ( be_isroot_pw( be, conn, ndn, cred ) ) {
				*edn = ch_strdup( be_root_dn( be ) );
				rc = LDAP_SUCCESS; /* front end will send result */

			} else if ( refs != NULL ) {
				send_ldap_result( conn, op, rc = LDAP_REFERRAL,
					matched_dn, NULL, refs, NULL );

			} else {
				send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
					NULL, NULL, NULL, NULL );
			}

		} else if ( refs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				matched_dn, NULL, refs, NULL );

		} else {
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
		}

		if ( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return rc;
	}

	*edn = ch_strdup( e->e_dn );

	/* check for deleted */

	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0,
			0, 0 );

		send_ldap_result( conn, op, rc = LDAP_ALIAS_PROBLEM,
			NULL, "entry is alias", NULL, NULL );

		goto done;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral, don't allow bind */
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );

		if( refs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				e->e_dn, NULL, refs, NULL );

		} else {
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
		}

		ber_bvecfree( refs );

		goto done;
	}

	switch ( method ) {
	case LDAP_AUTH_SIMPLE:
		/* check for root dn/passwd */
		if ( be_isroot_pw( be, conn, dn, cred ) ) {
			/* front end will send result */
			if(*edn != NULL) free( *edn );
			*edn = ch_strdup( be_root_dn( be ) );
			rc = LDAP_SUCCESS;
			goto done;
		}

		if ( ! access_allowed( be, conn, op, e,
			password, NULL, ACL_AUTH ) )
		{
			send_ldap_result( conn, op, rc = LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		if ( (a = attr_find( e->e_attrs, password )) == NULL ) {
			send_ldap_result( conn, op, rc = LDAP_INAPPROPRIATE_AUTH,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		if ( slap_passwd_check( conn, a, cred ) != 0 ) {
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		rc = 0;
		break;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( be, cred, &ad ) != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		if ( ! access_allowed( be, conn, op, e,
			krbattr, NULL, ACL_AUTH ) )
		{
			send_ldap_result( conn, op, rc = LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
			: "", ad.pinst, ad.prealm );

		if ( (a = attr_find( e->e_attrs, krbattr )) == NULL ) {
			/*
			 * no krbname values present:  check against DN
			 */
			if ( strcasecmp( dn, krbname ) == 0 ) {
				rc = 0;
				break;
			}
			send_ldap_result( conn, op, rc = LDAP_INAPPROPRIATE_AUTH,
				NULL, NULL, NULL, NULL );
			goto done;

		} else {	/* look for krbname match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_desc, a->a_vals, &krbval ) != 0 ) {
				send_ldap_result( conn, op,
					rc = LDAP_INVALID_CREDENTIALS,
					NULL, NULL, NULL, NULL );
				goto done;
			}
		}
		rc = 0;
		break;

	case LDAP_AUTH_KRBV42:
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "Kerberos bind step 2 not supported",
			NULL, NULL );
		goto done;
#endif

	default:
		send_ldap_result( conn, op, rc = LDAP_STRONG_AUTH_NOT_SUPPORTED,
			NULL, "authentication method not supported", NULL, NULL );
		goto done;
	}

done:
	/* free entry and reader lock */
	if( e != NULL ) {
		bdb_entry_return( be, e );
	}

	/* front end with send result on success (rc==0) */
	return rc;
}
