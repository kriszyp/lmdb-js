/* delete.c - ldbm backend delete routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
#include "proto-back-ldbm.h"

int
ldbm_back_delete(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	Entry	*matched;
	struct berval	pdn;
	Entry	*e, *p = NULL;
	int	rc = -1;
	int		manageDSAit = get_manageDSAit( op );
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDBM, ENTRY, "ldbm_back_delete: %s\n", op->o_req_dn.bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_delete: %s\n", op->o_req_dn.bv_val, 0, 0);
#endif

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	/* get entry with writer lock */
	e = dn2entry_w( op->o_bd, &op->o_req_ndn, &matched );

	/* FIXME : dn2entry() should return non-glue entry */
	if ( e == NULL || ( !manageDSAit && is_entry_glue( e ))) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_delete: no such object %s\n", op->o_req_dn.bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: no such object %s\n",
			op->o_req_dn.bv_val, 0, 0);
#endif

		if ( matched != NULL ) {
			rs->sr_matched = ch_strdup( matched->e_dn );
			rs->sr_ref = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;
			cache_return_entry_r( &li->li_cache, matched );

		} else {
			BerVarray deref = NULL;
			if ( !LDAP_STAILQ_EMPTY( &op->o_bd->be_syncinfo )) {
				syncinfo_t *si;
				LDAP_STAILQ_FOREACH( si, &op->o_bd->be_syncinfo, si_next ) {
					struct berval tmpbv;
					ber_dupbv( &tmpbv, &si->si_provideruri_bv[0] );
					ber_bvarray_add( &deref, &tmpbv );
				}
			} else {
				deref = default_referral;
			}
			rs->sr_ref = referral_rewrite( deref, NULL, &op->o_req_dn,
								LDAP_SCOPE_DEFAULT );
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		rs->sr_err = LDAP_REFERRAL;
		send_ldap_result( op, rs );

		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		free( (char *)rs->sr_matched );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		return( -1 );
	}

	/* check entry for "entry" acl */
	if ( ! access_allowed( op, e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: no write access to entry of (%s)\n", 
			op->o_req_dn.bv_val, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"<=- ldbm_back_delete: no write access to entry\n", 0,
			0, 0 );
#endif

		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
			"no write access to entry" );

		rc = LDAP_INSUFFICIENT_ACCESS;
		goto return_results;
	}

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* parent is a referral, don't allow add */
		/* parent is an alias, don't allow add */
		rs->sr_ref = get_entry_referrals( op, e );

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, INFO, 
			"ldbm_back_delete: entry (%s) is a referral.\n", e->e_dn, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );
#endif

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = e->e_name.bv_val;
		send_ldap_result( op, rs );

		if ( rs->sr_ref ) ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		rc = LDAP_REFERRAL;
		goto return_results;
	}

	if ( has_children( op->o_bd, e ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			   "ldbm_back_delete: (%s) is a non-leaf node.\n", op->o_req_dn.bv_val, 0,0);
#else
		Debug(LDAP_DEBUG_ARGS, "<=- ldbm_back_delete: non leaf %s\n",
			op->o_req_dn.bv_val, 0, 0);
#endif

		send_ldap_error( op, rs, LDAP_NOT_ALLOWED_ON_NONLEAF,
			"subtree delete not supported" );
		goto return_results;
	}

	/* delete from parent's id2children entry */
	if( !be_issuffix( op->o_bd, &e->e_nname ) && (dnParent( &e->e_nname, &pdn ),
		pdn.bv_len) ) {
		if( (p = dn2entry_w( op->o_bd, &pdn, NULL )) == NULL) {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_delete: parent of (%s) does not exist\n", op->o_req_dn, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: parent does not exist\n",
				0, 0, 0);
#endif

			send_ldap_error( op, rs, LDAP_OTHER,
				"could not locate parent of entry" );
			goto return_results;
		}

		/* check parent for "children" acl */
		if ( ! access_allowed( op, p,
			children, NULL, ACL_WRITE, NULL ) )
		{
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDBM, ERR, 
				"ldbm_back_delete: no access to parent of (%s)\n", 
				op->o_req_dn.bv_val, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"<=- ldbm_back_delete: no access to parent\n", 0,
				0, 0 );
#endif

			send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
				"no write access to parent" );
			goto return_results;
		}

	} else {
		/* no parent, must be root to delete */
		if( ! be_isroot( op ) ) {
			if ( be_issuffix( op->o_bd, (struct berval *)&slap_empty_bv )
				|| be_shadow_update( op ) ) {
				p = (Entry *)&slap_entry_root;
				
				rc = access_allowed( op, p,
					children, NULL, ACL_WRITE, NULL );
				p = NULL;
								
				/* check parent for "children" acl */
				if ( ! rc ) {
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDBM, ERR,
						"ldbm_back_delete: no access "
						"to parent of ("")\n", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"<=- ldbm_back_delete: no "
						"access to parent\n", 0, 0, 0 );
#endif

					send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
						"no write access to parent" );
					goto return_results;
				}

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDBM, ERR, 
					"ldbm_back_delete: (%s) has no "
					"parent & not a root.\n", op->o_ndn, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"<=- ldbm_back_delete: no parent & "
					"not root\n", 0, 0, 0);
#endif

				send_ldap_error( op, rs,
					LDAP_INSUFFICIENT_ACCESS,
					NULL );
				goto return_results;
			}
		}
	}

	/* delete from dn2id mapping */
	if ( dn2id_delete( op->o_bd, &e->e_nname, e->e_id ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: (%s) operations error\n", op->o_req_dn.bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			op->o_req_dn.bv_val, 0, 0);
#endif

		send_ldap_error( op, rs, LDAP_OTHER,
			"DN index delete failed" );
		goto return_results;
	}

	/* delete from disk and cache */
	if ( id2entry_delete( op->o_bd, e ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDBM, ERR, 
			"ldbm_back_delete: (%s) operations error\n", op->o_req_dn.bv_val, 0, 0 );
#else
		Debug(LDAP_DEBUG_ARGS,
			"<=- ldbm_back_delete: operations error %s\n",
			op->o_req_dn.bv_val, 0, 0);
#endif

		send_ldap_error( op, rs, LDAP_OTHER,
			"entry delete failed" );
		goto return_results;
	}

	/* delete attribute indices */
	(void) index_entry_del( op, e );

	rs->sr_err = LDAP_SUCCESS;
	send_ldap_result( op, rs );
	rc = LDAP_SUCCESS;

return_results:;
	if( p != NULL ) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p );
	}

	/* free entry and writer lock */
	cache_return_entry_w( &li->li_cache, e );

	ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

	return rc;
}
