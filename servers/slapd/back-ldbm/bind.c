/* bind.c - ldbm backend bind and unbind routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

	Debug(LDAP_DEBUG_ARGS,
		"==> ldbm_back_bind: dn: %s\n", op->o_req_dn.bv_val, 0, 0);

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
			cache_return_entry_r( &li->li_cache, matched );
		}
		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		/* allow noauth binds */
		rc = 1;
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/* check for deleted */
#ifdef LDBM_SUBENTRIES
	if ( is_entry_subentry( e ) ) {
		/* entry is an subentry, don't allow bind */
		Debug( LDAP_DEBUG_TRACE,
				"entry is subentry\n", 0, 0, 0 );
		rc = LDAP_INVALID_CREDENTIALS;
		goto return_results;
	}
#endif

	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0, 0, 0 );

#if 1
		rc = LDAP_INVALID_CREDENTIALS;
#else
		rs->sr_text = "entry is alias";
		rc = LDAP_ALIAS_PROBLEM;
#endif
		goto return_results;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0, 0, 0 );

		rc = LDAP_INVALID_CREDENTIALS;
		goto return_results;
	}

	switch ( op->oq_bind.rb_method ) {
	case LDAP_AUTH_SIMPLE:
		if ( (a = attr_find( e->e_attrs, password )) == NULL ) {
			/* stop front end from sending result */
			rc = LDAP_INVALID_CREDENTIALS;
			goto return_results;
		}

		if ( slap_passwd_check( op, e, a, &op->oq_bind.rb_cred,
					&rs->sr_text ) != 0 )
		{
			/* failure; stop front end from sending result */
			rc = LDAP_INVALID_CREDENTIALS;
			goto return_results;
		}

		rc = 0;
		break;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( op->o_bd, &op->oq_bind.rb_cred, &ad )
			!= LDAP_SUCCESS )
		{
			rc = LDAP_INVALID_CREDENTIALS;
			goto return_results;
		}

		if ( ! access_allowed( op, e,
			krbattr, NULL, ACL_AUTH, NULL ) )
		{
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
			rc = LDAP_INAPPROPRIATE_AUTH;
			goto return_results;

		} else {	/* look for krbname match */
			struct berval	krbval;

			krbval.bv_val = krbname;
			krbval.bv_len = strlen( krbname );

			if ( value_find( a->a_desc, a->a_vals, &krbval ) != 0 ) {
				rc = LDAP_INVALID_CREDENTIALS;
				goto return_results;
			}
		}
		rc = 0;
		break;
#endif

	default:
		assert( 0 ); /* should not be reachable */
		rs->sr_text = "authentication method not supported";
		rc = LDAP_STRONG_AUTH_NOT_SUPPORTED;
		goto return_results;
	}

	ber_dupbv( &op->oq_bind.rb_edn, &e->e_name );

return_results:;
	/* free entry and reader lock */
	cache_return_entry_r( &li->li_cache, e );
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	if ( rc ) {
		rs->sr_err = rc;
		send_ldap_result( op, rs );
		if ( rs->sr_ref ) {
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		}
	}

	/* front end will send result on success (rc==0) */
	return( rc );
}

