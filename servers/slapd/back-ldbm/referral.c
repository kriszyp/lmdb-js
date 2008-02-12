/* referral.c - LDBM backend referral handler */
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

int
ldbm_back_referrals(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	Entry		*e, *matched;
	int		rc = LDAP_SUCCESS;

	if( op->o_tag == LDAP_REQ_SEARCH ) {
		/* let search take care of itself */
		return LDAP_SUCCESS;
	}

	if( get_manageDSAit( op ) ) {
		/* let op take care of DSA management */
		return LDAP_SUCCESS;
	} 

	/* grab giant lock for reading */
	ldap_pvt_thread_rdwr_rlock(&li->li_giant_rwlock);

	/* get entry with reader lock */
	e = dn2entry_r( op->o_bd, &op->o_req_ndn, &matched );
	if ( e == NULL ) {
		if ( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );

			Debug( LDAP_DEBUG_TRACE,
				"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
				op->o_tag, op->o_req_dn.bv_val, rs->sr_matched );

			if ( is_entry_referral( matched ) ) {
				rc = rs->sr_err = LDAP_OTHER;
				rs->sr_ref = get_entry_referrals( op, matched );
			}

			cache_return_entry_r( &li->li_cache, matched );

		} else if ( !be_issuffix( op->o_bd, &op->o_req_ndn ) && default_referral != NULL ) {
			rc = rs->sr_err = LDAP_OTHER;
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		if ( rs->sr_ref != NULL ) {
			/* send referrals */
			rc = rs->sr_err = LDAP_REFERRAL;

		} else {
			rs->sr_text = rs->sr_matched ? "bad referral object" : "bad default referral";
		}

		if ( rc != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
		}

		if ( rs->sr_matched ) free( (char *)rs->sr_matched );
		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		rs->sr_text = NULL;
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		return rc;
	}

	if ( is_entry_referral( e ) ) {
		/* entry is a referral */
		BerVarray refs = get_entry_referrals( op, e );
		rs->sr_ref = referral_rewrite(
			refs, &e->e_name, &op->o_req_dn, LDAP_SCOPE_DEFAULT );

		Debug( LDAP_DEBUG_TRACE,
			"ldbm_referrals: op=%ld target=\"%s\" matched=\"%s\"\n",
			op->o_tag, op->o_req_dn.bv_val, e->e_dn );

		rs->sr_matched = e->e_name.bv_val;
		if( rs->sr_ref != NULL ) {
			rc = rs->sr_err = LDAP_REFERRAL;
			rs->sr_text = NULL;

		} else {
			rc = rs->sr_err = LDAP_OTHER;
			rs->sr_text = "bad referral object";
		}
		send_ldap_result( op, rs );

		if ( refs != NULL ) ber_bvarray_free( refs );
		rs->sr_err = rc;
		rs->sr_ref = NULL;
		rs->sr_text = NULL;
		rs->sr_matched = NULL;
	}

	cache_return_entry_r( &li->li_cache, e );
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	return rc;
}
