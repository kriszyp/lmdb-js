/* bind.c - bdb backend bind routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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
	struct berval		*dn,
	struct berval		*ndn,
	int			method,
	struct berval	*cred,
	struct berval	*edn
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

	u_int32_t	locker;
	DB_LOCK		lock;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "==> bdb_bind: dn: %s\n", dn->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "==> bdb_bind: dn: %s\n", dn->bv_val, 0, 0);
#endif

	rc = LOCK_ID(bdb->bi_dbenv, &locker);
	switch(rc) {
	case 0:
		break;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		return rc;
	}

dn2entry_retry:
	/* get entry */
	rc = bdb_dn2entry_r( be, NULL, ndn, &e, &matched, 0, locker, &lock );

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		send_ldap_result( conn, op, LDAP_BUSY,
			NULL, "ldap server busy", NULL, NULL );
		LOCK_ID_FREE(bdb->bi_dbenv, locker);
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		LOCK_ID_FREE(bdb->bi_dbenv, locker);
		return rc;
	}

	/* get entry with reader lock */
	if ( e == NULL ) {
		char *matched_dn = NULL;
		BerVarray refs;

		if( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;

			bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, matched, &lock );
			matched = NULL;

		} else {
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		/* allow noauth binds */
		rc = 1;
		if ( method == LDAP_AUTH_SIMPLE ) {
			if ( be_isroot_pw( be, conn, ndn, cred ) ) {
				ber_dupbv( edn, be_root_dn( be ) );
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

		LOCK_ID_FREE(bdb->bi_dbenv, locker);

		ber_bvarray_free( refs );
		free( matched_dn );

		return rc;
	}

	ber_dupbv( edn, &e->e_name );

	/* check for deleted */
#ifdef BDB_SUBENTRIES
	if ( is_entry_subentry( e ) ) {
		/* entry is an subentry, don't allow bind */
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_bind: entry is subentry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is subentry\n", 0,
			0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
			NULL, NULL, NULL, NULL );

		goto done;
	}
#endif

#ifdef BDB_ALIASES
	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "bdb_bind: entry is alias\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0,
			0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_ALIAS_PROBLEM,
			NULL, "entry is alias", NULL, NULL );

		goto done;
	}
#endif

	if ( is_entry_referral( e ) ) {
		/* entry is a referral, don't allow bind */
		BerVarray refs = get_entry_referrals( be,
			conn, op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_bind: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );
#endif

		if( refs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				e->e_dn, NULL, refs, NULL );

		} else {
			send_ldap_result( conn, op, rc = LDAP_INVALID_CREDENTIALS,
				NULL, NULL, NULL, NULL );
		}

		ber_bvarray_free( refs );

		goto done;
	}

	switch ( method ) {
	case LDAP_AUTH_SIMPLE:
		/* check for root dn/passwd */
		if ( be_isroot_pw( be, conn, ndn, cred ) ) {
			/* front end will send result */
			if(edn->bv_val != NULL) free( edn->bv_val );
			ber_dupbv( edn, be_root_dn( be ) );
			rc = LDAP_SUCCESS;
			goto done;
		}

		rc = access_allowed( be, conn, op, e,
			password, NULL, ACL_AUTH, NULL );
		if ( ! rc ) {
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

		rc = access_allowed( be, conn, op, e,
			krbattr, NULL, ACL_AUTH, NULL );
		if ( ! rc ) {
			send_ldap_result( conn, op, rc = LDAP_INSUFFICIENT_ACCESS,
				NULL, NULL, NULL, NULL );
			goto done;
		}

		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
			: "", ad.pinst, ad.prealm );

		if ( (a = attr_find( e->e_attrs, krbattr )) == NULL ) {
			/*
			 * no krbname values present: check against DN
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
		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
	}

	LOCK_ID_FREE(bdb->bi_dbenv, locker);

	/* front end with send result on success (rc==0) */
	return rc;
}
