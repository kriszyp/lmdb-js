/* referral.c - LDBM backend referral handler */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
ldbm_back_referrals(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval *dn,
    struct berval *ndn,
	const char **text )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
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

	/* grab giant lock for reading */
	ldap_pvt_thread_rdwr_rlock(&li->li_giant_rwlock);

	/* get entry with reader lock */
	e = dn2entry_r( be, ndn, &matched );
	if ( e == NULL ) {
		char *matched_dn = NULL;
		BerVarray refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, DETAIL1,
				"ldbm_back_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
				op->o_tag, dn->bv_val, matched_dn );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
				op->o_tag, dn->bv_val, matched_dn );
#endif

			if( is_entry_referral( matched ) ) {
				rc = LDAP_OTHER;
				refs = get_entry_referrals( be, conn, op, matched );
			}

			cache_return_entry_r( &li->li_cache, matched );

		} else if ( default_referral != NULL ) {
			rc = LDAP_OTHER;
			refs = referral_rewrite( default_referral,
				NULL, dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		if( refs != NULL ) {
			/* send referrals */
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				matched_dn, NULL, refs, NULL );
			ber_bvarray_free( refs );

		} else if ( rc != LDAP_SUCCESS ) {
			send_ldap_result( conn, op, rc, matched_dn,
				matched_dn ? "bad referral object" : "bad default referral",
				NULL, NULL );
		}

		if ( matched_dn ) free( matched_dn );
		return rc;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral */
		BerVarray refs = get_entry_referrals( be, conn, op, e );
		BerVarray rrefs = referral_rewrite(
			refs, &e->e_name, dn, LDAP_SCOPE_DEFAULT );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, DETAIL1,
			"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			op->o_tag, dn->bv_val, e->e_dn );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			op->o_tag, dn->bv_val, e->e_dn );
#endif

		if( rrefs != NULL ) {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL,
				e->e_dn, NULL, rrefs, NULL );

			ber_bvarray_free( rrefs );

		} else {
			send_ldap_result( conn, op, rc = LDAP_OTHER, e->e_dn,
				"bad referral object", NULL, NULL );
		}

		if( refs != NULL ) ber_bvarray_free( refs );
	}

	cache_return_entry_r( &li->li_cache, e );
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	return rc;
}
