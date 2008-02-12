/* compare.c - ldbm backend compare routine */
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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
ldbm_back_compare(
	Operation	*op,
	SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	Entry		*matched;
	Entry		*e;
	Attribute	*a;
	int		manageDSAit = get_manageDSAit( op );

	rs->sr_matched = NULL;
	rs->sr_ref = NULL;

	/* grab giant lock for reading */
	ldap_pvt_thread_rdwr_rlock(&li->li_giant_rwlock);

	/* get entry with reader lock */
	e = dn2entry_r( op->o_bd, &op->o_req_ndn, &matched );
	if ( e == NULL ) {
		if ( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );
		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		rs->sr_err = LDAP_REFERRAL;
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		struct berval	bv;

		/* entry is a referral, don't allow add */
		rs->sr_ref = get_entry_referrals( op, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );


		rs->sr_err = LDAP_REFERRAL;
		ber_dupbv_x( &bv, &e->e_name, op->o_tmpmemctx );
		rs->sr_matched = bv.bv_val;

		goto return_results;
	}

	if ( ! access_allowed( op, e,
		op->oq_compare.rs_ava->aa_desc, &op->oq_compare.rs_ava->aa_value, ACL_COMPARE, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
			NULL );
		goto return_results;
	}

	rs->sr_err = LDAP_NO_SUCH_ATTRIBUTE;

	for(a = attrs_find( e->e_attrs, op->oq_compare.rs_ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, op->oq_compare.rs_ava->aa_desc ))
	{
		rs->sr_err = LDAP_COMPARE_FALSE;

		if ( value_find_ex( op->oq_compare.rs_ava->aa_desc,
			SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
				SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
			a->a_nvals, &op->oq_compare.rs_ava->aa_value,
			op->o_tmpmemctx ) == 0 )
		{
			rs->sr_err = LDAP_COMPARE_TRUE;
			break;
		}
	}

return_results:;
	if ( e ) cache_return_entry_r( &li->li_cache, e );
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	send_ldap_result( op, rs );

	switch ( rs->sr_err ) {
	case LDAP_COMPARE_FALSE:
	case LDAP_COMPARE_TRUE:
		rs->sr_err = LDAP_SUCCESS;
		break;
	}

	if ( rs->sr_ref != NULL ) {
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
	}

	if ( rs->sr_matched != NULL ) {
		op->o_tmpfree( (char *)rs->sr_matched, op->o_tmpmemctx );
		rs->sr_matched = NULL;
	}

	return rs->sr_err;
}
