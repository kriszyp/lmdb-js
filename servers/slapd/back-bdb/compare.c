/* compare.c - bdb backend compare routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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
#include "external.h"

int
bdb_compare( Operation *op, SlapReply *rs )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	Entry		*e = NULL;
	EntryInfo	*ei;
	Attribute	*a;
	int		manageDSAit = get_manageDSAit( op );

	u_int32_t	locker;
	DB_LOCK		lock;

	rs->sr_err = LOCK_ID(bdb->bi_dbenv, &locker);
	switch(rs->sr_err) {
	case 0:
		break;
	default:
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return rs->sr_err;
	}

dn2entry_retry:
	/* get entry */
	rs->sr_err = bdb_dn2entry( op, NULL, &op->o_req_ndn, &ei, 1, locker, &lock );

	switch( rs->sr_err ) {
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		rs->sr_text = "ldap server busy";
		goto return_results;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "internal error";
		goto return_results;
	}

	e = ei->bei_e;
	if ( rs->sr_err == DB_NOTFOUND ) {
		if ( e != NULL ) {
			rs->sr_matched = ch_strdup( e->e_dn );
			rs->sr_ref = is_entry_referral( e )
				? get_entry_referrals( op, e )
				: NULL;
			bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
			e = NULL;

		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
		}

		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;

		goto done;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"bdb_compare: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
			0, 0 );
#endif

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		goto done;
	}

	if ( get_assert( op ) &&
		( test_filter( op, e, get_assertion( op )) != LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		goto return_results;
	}

	rs->sr_err = access_allowed( op, e, op->oq_compare.rs_ava->aa_desc,
		&op->oq_compare.rs_ava->aa_value, ACL_COMPARE, NULL );
	if ( ! rs->sr_err ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
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
			a->a_nvals, &op->oq_compare.rs_ava->aa_value, op->o_tmpmemctx ) == 0 )
		{
			rs->sr_err = LDAP_COMPARE_TRUE;
			break;
		}
	}

return_results:
	send_ldap_result( op, rs );

	if( rs->sr_err == LDAP_COMPARE_FALSE || rs->sr_err == LDAP_COMPARE_TRUE ) {
		rs->sr_err = LDAP_SUCCESS;
	}

done:
	/* free entry */
	if( e != NULL ) {
		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
	}

	LOCK_ID_FREE ( bdb->bi_dbenv, locker );

	return rs->sr_err;
}
