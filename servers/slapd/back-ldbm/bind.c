/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
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

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, 
		"ldbm_back_bind: dn: %s.\n", op->o_req_dn.bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_bind: dn: %s\n", op->o_req_dn.bv_val, 0, 0);
#endif

	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op ) ) {
		ber_dupbv( &op->oq_bind.rb_edn, be_root_dn( op->o_bd ) );
		/* front end will send result */
		return LDAP_SUCCESS;
	}

	/* grab giant lock for reading */
	ldap_pvt_thread_rdwr_rlock(&li->li_giant_rwlock);

	/* get entry with reader lock */
	if ( (e = dn2entry_r( op->o_bd, &op->o_req_ndn, &matched )) == NULL ) {
		if( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );

			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;

			cache_return_entry_r( &li->li_cache, matched );

		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		/* allow noauth binds */
		rc = 1;
		if ( rs->sr_ref != NULL ) {
			rs->sr_err = LDAP_REFERRAL;
		} else {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
		}
		send_ldap_result( op, rs );

		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		if ( rs->sr_matched ) free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		return rs->sr_err;
	}

	ber_dupbv( &op->oq_bind.rb_edn, &e->e_name );

	/* check for deleted */
#ifdef LDBM_SUBENTRIES
	if ( is_entry_subentry( e ) ) {
		/* entry is an subentry, don't allow bind */
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1,
				"bdb_bind: entry is subentry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
				"entry is subentry\n", 0, 0, 0 );
#endif
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );
		rc = LDAP_INVALID_CREDENTIALS;
		goto return_results;
	}
#endif

	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_bind: entry (%s) is an alias.\n", e->e_name.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0,
		    0, 0 );
#endif


		send_ldap_error( op, rs, LDAP_ALIAS_PROBLEM,
		    "entry is alias" );

		rc = LDAP_ALIAS_PROBLEM;
		goto return_results;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral, don't allow bind */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			   "ldbm_back_bind: entry(%s) is a referral.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif


		if( rs->sr_ref != NULL ) {
			rs->sr_err = LDAP_REFERRAL;
			rs->sr_matched = e->e_name.bv_val;

		} else {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
		}
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		rs->sr_matched = NULL;
		rs->sr_ref = NULL;
		rc = rs->sr_err;
		goto return_results;
	}

	switch ( op->oq_bind.rb_method ) {
	case LDAP_AUTH_SIMPLE:
		if ( ! access_allowed( op, e,
			password, NULL, ACL_AUTH, NULL ) )
		{
			send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		if ( (a = attr_find( e->e_attrs, password )) == NULL ) {
			send_ldap_error( op, rs, LDAP_INAPPROPRIATE_AUTH, NULL );

			/* stop front end from sending result */
			rc = LDAP_INAPPROPRIATE_AUTH;
			goto return_results;
		}

		if ( slap_passwd_check( op->o_conn, a, &op->oq_bind.rb_cred, &rs->sr_text ) != 0 ) {
			send_ldap_error( op, rs, LDAP_INVALID_CREDENTIALS, NULL );
			/* stop front end from sending result */
			rc = LDAP_INVALID_CREDENTIALS;
			goto return_results;
		}

		rc = 0;
		break;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( op->o_bd, &op->oq_bind.rb_cred, &ad ) != LDAP_SUCCESS ) {
			send_ldap_error( op, rs, LDAP_INVALID_CREDENTIALS, NULL );
			rc = LDAP_INVALID_CREDENTIALS;
			goto return_results;
		}

		if ( ! access_allowed( op, e,
			krbattr, NULL, ACL_AUTH, NULL ) )
		{
			send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
				NULL );
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		sprintf( krbname, "%s%s%s@%s", ad.pname, *ad.pinst ? "."
		    : "", ad.pinst, ad.prealm );

		if ( (a = attr_find( e->e_attrs, krbattr )) == NULL ) {
			/*
			 * no krbname values present:  check against DN
			 */
			if ( strcasecmp( op->o_req_dn.bv_val, krbname ) == 0 ) {
				rc = 0;
				break;
			}
			send_ldap_error( op, rs, LDAP_INAPPROPRIATE_AUTH, NULL );
			rc = LDAP_INAPPROPRIATE_AUTH;
			goto return_results;

		} else {	/* look for krbname match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_desc, a->a_vals, &krbval ) != 0 ) {
				send_ldap_error( op, rs,
				    LDAP_INVALID_CREDENTIALS, NULL );
				rc = LDAP_INVALID_CREDENTIALS;
				goto return_results;
			}
		}
		rc = 0;
		break;

	case LDAP_AUTH_KRBV42:
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"Kerberos bind step 2 not supported" );
		/* stop front end from sending result */
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto return_results;
#endif

	default:
		send_ldap_error( op, rs, LDAP_STRONG_AUTH_NOT_SUPPORTED,
		    "authentication method not supported" );
		rc = LDAP_STRONG_AUTH_NOT_SUPPORTED;
		goto return_results;
	}

return_results:;
	/* free entry and reader lock */
	cache_return_entry_r( &li->li_cache, e );
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	/* front end will send result on success (rc==0) */
	return( rc );
}

