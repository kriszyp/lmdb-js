/* referral.c - BDB backend referral handler */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2002 The OpenLDAP Foundation, All Rights Reserved.
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
	struct berval *dn,
	struct berval *ndn,
	const char **text )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int rc = LDAP_SUCCESS;
	Entry *e = NULL;
	Entry *matched = NULL;

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

	/* XXYYZ: need to check return value */
	LOCK_ID ( bdb->bi_dbenv, &locker );

dn2entry_retry:
	/* get entry */
	rc = bdb_dn2entry_r( be, NULL, ndn, &e, &matched, 0, locker, &lock );

	switch(rc) {
	case DB_NOTFOUND:
		rc = 0;
	case 0:
		break;
	case LDAP_BUSY:
		if (e != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
		}
		if (matched != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
		}
		send_ldap_result( conn, op, LDAP_BUSY,
			NULL, "ldap server busy", NULL, NULL );
		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"bdb_referrals: dn2entry failed: %s (%d)\n", 
			db_strerror(rc), rc, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_referrals: dn2entry failed: %s (%d)\n",
			db_strerror(rc), rc, 0 ); 
#endif
		if (e != NULL) {
                        bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
		}
                if (matched != NULL) {
                        bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
		}
		send_ldap_result( conn, op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		return rc;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		BerVarray refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			(long) op->o_tag, dn->bv_val, matched_dn );
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
				(long) op->o_tag, dn->bv_val, matched_dn );
#endif

			if( is_entry_referral( matched ) ) {
				rc = LDAP_OTHER;
				refs = get_entry_referrals( be, conn, op, matched );
			}

			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
			matched = NULL;
		} else if ( default_referral != NULL ) {
			rc = LDAP_OTHER;
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		if( refs != NULL ) {
			/* send referrals */
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				matched_dn, NULL, refs, NULL );
			ber_bvarray_free( refs );
		} else if ( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, matched_dn,
				matched_dn ? "bad referral object" : NULL,
				NULL, NULL );
		}

		LOCK_ID_FREE ( bdb->bi_dbenv, locker );
		free( matched_dn );
		return rc;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral */
		BerVarray refs = get_entry_referrals( be, conn, op, e );
		BerVarray rrefs = referral_rewrite(
			refs, &e->e_name, dn, LDAP_SCOPE_DEFAULT );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			(long) op->o_tag, dn->bv_val, e->e_dn );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			(long) op->o_tag, dn->bv_val, e->e_dn );
#endif

		if( rrefs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				e->e_dn, NULL, rrefs, NULL );
			ber_bvarray_free( rrefs );
		} else {
			send_ldap_result( conn, op, rc = LDAP_OTHER, e->e_dn,
				"bad referral object", NULL, NULL );
		}

		ber_bvarray_free( refs );
	}

	bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
	LOCK_ID_FREE ( bdb->bi_dbenv, locker );
	return rc;
}
