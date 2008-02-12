/* bind.c - bdb backend bind routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2008 The OpenLDAP Foundation.
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
#include <ac/string.h>
#include <ac/unistd.h>

#include "back-bdb.h"

int
bdb_bind( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry		*e;
	Attribute	*a;
	EntryInfo	*ei;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	char		krbname[MAX_K_NAME_SZ + 1];
	AttributeDescription *krbattr = slap_schema.si_ad_krbName;
	struct berval	krbval;
	AUTH_DAT	ad;
#endif

	AttributeDescription *password = slap_schema.si_ad_userPassword;

	u_int32_t	locker;
	DB_LOCK		lock;

	Debug( LDAP_DEBUG_ARGS,
		"==> " LDAP_XSTRING(bdb_bind) ": dn: %s\n",
		op->o_req_dn.bv_val, 0, 0);

	/* allow noauth binds */
	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op )) {
		ber_dupbv( &op->oq_bind.rb_edn, be_root_dn( op->o_bd ) );
		/* front end will send result */
		return LDAP_SUCCESS;
	}

	rs->sr_err = LOCK_ID(bdb->bi_dbenv, &locker);
	switch(rs->sr_err) {
	case 0:
		break;
	default:
		rs->sr_text = "internal error";
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

dn2entry_retry:
	/* get entry with reader lock */
	rs->sr_err = bdb_dn2entry( op, NULL, &op->o_req_ndn, &ei, 1,
		locker, &lock );

	switch(rs->sr_err) {
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		send_ldap_error( op, rs, LDAP_BUSY, "ldap_server_busy" );
		LOCK_ID_FREE(bdb->bi_dbenv, locker);
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		LOCK_ID_FREE(bdb->bi_dbenv, locker);
		return rs->sr_err;
	}

	e = ei->bei_e;
	if ( rs->sr_err == DB_NOTFOUND ) {
		if( e != NULL ) {
			bdb_cache_return_entry_r( bdb->bi_dbenv,
				&bdb->bi_cache, e, &lock );
			e = NULL;
		}

		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );

		LOCK_ID_FREE(bdb->bi_dbenv, locker);

		return rs->sr_err;
	}

	ber_dupbv( &op->oq_bind.rb_edn, &e->e_name );

	/* check for deleted */
	if ( is_entry_subentry( e ) ) {
		/* entry is an subentry, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is subentry\n", 0,
			0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	if ( is_entry_alias( e ) ) {
		/* entry is an alias, don't allow bind */
		Debug( LDAP_DEBUG_TRACE, "entry is alias\n", 0, 0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	if ( is_entry_referral( e ) ) {
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto done;
	}

	switch ( op->oq_bind.rb_method ) {
	case LDAP_AUTH_SIMPLE:
		a = attr_find( e->e_attrs, password );
		if ( a == NULL ) {
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			goto done;
		}

		if ( slap_passwd_check( op, e, a, &op->oq_bind.rb_cred,
					&rs->sr_text ) != 0 )
		{
			/* failure; stop front end from sending result */
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			goto done;
		}
			
		rs->sr_err = 0;
		break;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
	case LDAP_AUTH_KRBV41:
		if ( krbv4_ldap_auth( op->o_bd, &op->oq_bind.rb_cred, &ad )
			!= LDAP_SUCCESS )
		{
			rs->sr_err = LDAP_INVALID_CREDENTIALS,
			goto done;
		}

		rs->sr_err = access_allowed( op, e,
			krbattr, NULL, ACL_AUTH, NULL );
		if ( ! rs->sr_err ) {
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS,
			goto done;
		}

		krbval.bv_len = sprintf( krbname, "%s%s%s@%s", ad.pname,
			*ad.pinst ? "." : "", ad.pinst, ad.prealm );

		if ( (a = attr_find( e->e_attrs, krbattr )) == NULL ) {
			/*
			 * no krbname values present: check against DN
			 */
			if ( strcasecmp( op->o_req_dn.bv_val, krbname ) == 0 ) {
				rs->sr_err = 0;
				break;
			}
			rs->sr_err = LDAP_INAPPROPRIATE_AUTH,
			goto done;

		} else {	/* look for krbname match */
			krbval.bv_val = krbname;

			if ( value_find( a->a_desc, a->a_vals, &krbval ) != 0 ) {
				rs->sr_err = LDAP_INVALID_CREDENTIALS;
				goto done;
			}
		}
		rs->sr_err = 0;
		break;
#endif

	default:
		assert( 0 ); /* should not be unreachable */
		rs->sr_err = LDAP_STRONG_AUTH_NOT_SUPPORTED;
		rs->sr_text = "authentication method not supported";
	}

done:
	/* free entry and reader lock */
	if( e != NULL ) {
		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
	}

	LOCK_ID_FREE(bdb->bi_dbenv, locker);

	if ( rs->sr_err ) {
		send_ldap_result( op, rs );
		if ( rs->sr_ref ) {
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		}
	}
	/* front end will send result on success (rs->sr_err==0) */
	return rs->sr_err;
}
