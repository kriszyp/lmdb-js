/* referral.c - BDB backend referral handler */
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
#include <ac/string.h>

#include "back-bdb.h"

int
bdb_referrals( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry *e = NULL;
	EntryInfo *ei;
	int rc = LDAP_SUCCESS;

	u_int32_t	locker;
	DB_LOCK		lock;

	if( op->o_tag == LDAP_REQ_SEARCH ) {
		/* let search take care of itself */
		return rc;
	}

	if( get_manageDSAit( op ) ) {
		/* let op take care of DSA management */
		return rc;
	} 

	rc = LOCK_ID(bdb->bi_dbenv, &locker);
	switch(rc) {
	case 0:
		break;
	default:
		return LDAP_OTHER;
	}

dn2entry_retry:
	/* get entry */
	rc = bdb_dn2entry( op, NULL, &op->o_req_ndn, &ei, 1, locker, &lock );

	/* bdb_dn2entry() may legally leave ei == NULL
	 * if rc != 0 and rc != DB_NOTFOUND
	 */
	if ( ei ) {
		e = ei->bei_e;
	}

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		send_ldap_error( op, rs, LDAP_BUSY, "ldap server busy" );
		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_referrals)
			": dn2entry failed: %s (%d)\n",
			db_strerror(rc), rc, 0 ); 
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		return rs->sr_err;
	}

	if ( rc == DB_NOTFOUND ) {
		rc = 0;
		rs->sr_matched = NULL;
		if ( e != NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				LDAP_XSTRING(bdb_referrals)
				": op=%ld target=\"%s\" matched=\"%s\"\n",
				(long) op->o_tag, op->o_req_dn.bv_val, e->e_name.bv_val );

			if( is_entry_referral( e ) ) {
				BerVarray ref = get_entry_referrals( op, e );
				rc = LDAP_OTHER;
				rs->sr_ref = referral_rewrite( ref, NULL,
					&op->o_req_dn, LDAP_SCOPE_DEFAULT );
				ber_bvarray_free( ref );
				if ( rs->sr_ref ) {
					rs->sr_matched = ber_strdup_x(
					e->e_name.bv_val, op->o_tmpmemctx );
				}
			}

			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
			e = NULL;
		} else if ( !be_issuffix( op->o_bd, &op->o_req_ndn ) && default_referral != NULL ) {
			rc = LDAP_OTHER;
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		if( rs->sr_ref != NULL ) {
			/* send referrals */
			rc = rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		} else if ( rc != LDAP_SUCCESS ) {
			rs->sr_err = rc;
			rs->sr_text = rs->sr_matched ? "bad referral object" : NULL;
			send_ldap_result( op, rs );
		}

		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		if (rs->sr_matched) {
			op->o_tmpfree( (char *)rs->sr_matched, op->o_tmpmemctx );
			rs->sr_matched = NULL;
		}
		return rc;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral */
		BerVarray refs = get_entry_referrals( op, e );
		rs->sr_ref = referral_rewrite(
			refs, &e->e_name, &op->o_req_dn, LDAP_SCOPE_DEFAULT );

		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(bdb_referrals)
			": op=%ld target=\"%s\" matched=\"%s\"\n",
			(long) op->o_tag, op->o_req_dn.bv_val, e->e_name.bv_val );

		rs->sr_matched = e->e_name.bv_val;
		if( rs->sr_ref != NULL ) {
			rc = rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		} else {
			send_ldap_error( op, rs, LDAP_OTHER, "bad referral object" );
			rc = rs->sr_err;
		}

		rs->sr_matched = NULL;
		ber_bvarray_free( refs );
	}

	bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
	LOCK_ID_FREE ( bdb->bi_dbenv, locker );
	return rc;
}
