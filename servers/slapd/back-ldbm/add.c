/* add.c - ldap ldbm back-end add routine */
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

static int
ldbm_csn_cb(
	Operation *op,
	SlapReply *rs )
{
	op->o_callback = op->o_callback->sc_next;
	slap_graduate_commit_csn( op );
	return SLAP_CB_CONTINUE;
}

int
ldbm_back_add(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	struct berval	pdn;
	Entry		*p = NULL;
	ID               id = NOID;
	AttributeDescription *children = slap_schema.si_ad_children;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	slap_callback cb = { NULL };
#ifdef LDBM_SUBENTRIES
	int subentry;
#endif

	Debug(LDAP_DEBUG_ARGS, "==> ldbm_back_add: %s\n",
		op->o_req_dn.bv_val, 0, 0);
	
	rs->sr_err = slap_add_opattrs( op, &rs->sr_text, textbuf, textlen, 1 );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"entry failed op attrs add: %s (%d)\n",
			rs->sr_text, rs->sr_err, 0 );
		goto return_results;
	}

	cb.sc_cleanup = ldbm_csn_cb;
	cb.sc_next = op->o_callback;
	op->o_callback = &cb;

	rs->sr_err = entry_schema_check( op, op->oq_add.rs_e, NULL,
		get_manageDIT(op), &rs->sr_text, textbuf, textlen );

	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "entry failed schema check: %s\n",
			rs->sr_text, 0, 0 );

		send_ldap_result( op, rs );
		return rs->sr_err;
	}
	rs->sr_text = NULL;

#ifdef LDBM_SUBENTRIES
	subentry = is_entry_subentry( op->oq_add.rs_e );
#endif

	if ( !access_allowed( op, op->oq_add.rs_e,
				entry, NULL, ACL_WADD, NULL ) )
	{
		Debug( LDAP_DEBUG_TRACE, "no write access to entry\n", 0,
		    0, 0 );

		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
		    "no write access to entry" );

		return LDAP_INSUFFICIENT_ACCESS;
	}

	/* grab giant lock for writing */
	ldap_pvt_thread_rdwr_wlock(&li->li_giant_rwlock);

	rs->sr_err = dn2id( op->o_bd, &op->o_req_ndn, &id );
	if ( rs->sr_err || id != NOID )	{
		/* if (rs->sr_err) something bad happened to ldbm cache */
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
		rs->sr_err = rs->sr_err ? LDAP_OTHER : LDAP_ALREADY_EXISTS;
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 * If the parent does not exist, only allow the "root" user to
	 * add the entry.
	 */

	if ( be_issuffix( op->o_bd, &op->o_req_ndn ) ) {
		pdn = slap_empty_bv;
	} else {
		dnParent( &op->o_req_ndn, &pdn );
	}

	if( pdn.bv_len ) {
		Entry *matched = NULL;

		/* get parent with writer lock */
		if ( (p = dn2entry_w( op->o_bd, &pdn, &matched )) == NULL ) {
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

			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

			Debug( LDAP_DEBUG_TRACE, "parent does not exist\n",
				0, 0, 0 );

			rs->sr_text = rs->sr_ref
				? "parent is referral" : "parent does not exist";
			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			ber_bvarray_free( rs->sr_ref );
			free( (char *)rs->sr_matched );
			rs->sr_ref = NULL;
			rs->sr_matched = NULL;
			return rs->sr_err;
		}

		if ( ! access_allowed( op, p, children, NULL, ACL_WADD, NULL ) ) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

			Debug( LDAP_DEBUG_TRACE, "no write access to parent\n", 0,
			    0, 0 );

			send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS,
			    "no write access to parent" );

			return LDAP_INSUFFICIENT_ACCESS;
		}

#ifdef LDBM_SUBENTRIES
		if ( is_entry_subentry( p )) {
			Debug( LDAP_DEBUG_TRACE, "bdb_add: parent is subentry\n",
				0, 0, 0 );
			rs->sr_err = LDAP_OBJECT_CLASS_VIOLATION;
			rs->sr_text = "parent is a subentry";
			goto return_results;
		}
#endif

		if ( is_entry_alias( p ) ) {
			/* parent is an alias, don't allow add */

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

			Debug( LDAP_DEBUG_TRACE, "parent is alias\n", 0,
			    0, 0 );

			send_ldap_error( op, rs, LDAP_ALIAS_PROBLEM,
			    "parent is an alias" );

			return LDAP_ALIAS_PROBLEM;
		}

		if ( is_entry_referral( p ) ) {
			/* parent is a referral, don't allow add */
			rs->sr_matched = ch_strdup( p->e_dn );
			rs->sr_ref = is_entry_referral( p )
				? get_entry_referrals( op, p )
				: NULL;

			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p );
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

			Debug( LDAP_DEBUG_TRACE, "parent is referral\n", 0,
			    0, 0 );
			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			ber_bvarray_free( rs->sr_ref );
			free( (char *)rs->sr_matched );
			rs->sr_ref = NULL;
			rs->sr_matched = NULL;
			return rs->sr_err;
		}

#ifdef LDBM_SUBENTRIES
		if ( subentry ) {
			/* FIXME: */
			/* parent must be an administrative point of the required kind */
		}
#endif

	} else {
		assert( pdn.bv_val == NULL || *pdn.bv_val == '\0' );

		if (( !be_isroot(op) && !be_shadow_update(op) )
			&& !is_entry_glue( op->oq_add.rs_e ))
		{
			ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

			Debug( LDAP_DEBUG_TRACE, "%s add denied\n",
				pdn.bv_val == NULL ? "suffix" : "entry at root", 0, 0 );

			send_ldap_error( op, rs, LDAP_NO_SUCH_OBJECT, NULL );
			return LDAP_NO_SUCH_OBJECT;
		}
	}

	if ( next_id( op->o_bd, &op->oq_add.rs_e->e_id ) ) {
		if( p != NULL) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		Debug( LDAP_DEBUG_ANY, "ldbm_add: next_id failed\n",
			0, 0, 0 );

		send_ldap_error( op, rs, LDAP_OTHER,
			"next_id add failed" );

		return LDAP_OTHER;
	}

	/*
	 * Try to add the entry to the cache, assign it a new dnid.
	 */
	rs->sr_err = cache_add_entry_rw( &li->li_cache, op->oq_add.rs_e,
		CACHE_WRITE_LOCK );

	if ( rs->sr_err != 0 ) {
		if( p != NULL) {
			/* free parent and writer lock */
			cache_return_entry_w( &li->li_cache, p ); 
		}

		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);

		Debug( LDAP_DEBUG_ANY, "cache_add_entry_lock failed\n", 0, 0,
		    0 );

		rs->sr_text = rs->sr_err > 0 ? NULL : "cache add failed";
		rs->sr_err = rs->sr_err > 0 ? LDAP_ALREADY_EXISTS : LDAP_OTHER;
		send_ldap_result( op, rs );

		return rs->sr_err;
	}

	rs->sr_err = -1;

	/* attribute indexes */
	if ( index_entry_add( op, op->oq_add.rs_e ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "index_entry_add failed\n", 0,
		    0, 0 );
		
		send_ldap_error( op, rs, LDAP_OTHER,
			"index generation failed" );

		goto return_results;
	}

	/* dn2id index */
	if ( dn2id_add( op->o_bd, &op->oq_add.rs_e->e_nname,
		op->oq_add.rs_e->e_id ) != 0 )
	{
		Debug( LDAP_DEBUG_TRACE, "dn2id_add failed\n", 0,
		    0, 0 );
		/* FIXME: delete attr indices? */

		send_ldap_error( op, rs, LDAP_OTHER,
			"DN index generation failed" );

		goto return_results;
	}

	/* id2entry index */
	if ( id2entry_add( op->o_bd, op->oq_add.rs_e ) != 0 ) {
		Debug( LDAP_DEBUG_TRACE, "id2entry_add failed\n", 0,
		    0, 0 );

		/* FIXME: delete attr indices? */
		(void) dn2id_delete( op->o_bd, &op->oq_add.rs_e->e_nname,
			op->oq_add.rs_e->e_id );
		
		send_ldap_error( op, rs, LDAP_OTHER,
			"entry store failed" );

		goto return_results;
	}

	rs->sr_err = LDAP_SUCCESS;
	rs->sr_text = NULL;
	send_ldap_result( op, rs );

	/* marks the entry as committed, so it is added to the cache;
	 * otherwise it is removed from the cache, but not destroyed;
	 * it will be destroyed by the caller */
	cache_entry_commit( op->oq_add.rs_e );

return_results:;
	if (p != NULL) {
		/* free parent and writer lock */
		cache_return_entry_w( &li->li_cache, p ); 
	}

	if ( rs->sr_err ) {
		/*
		 * in case of error, writer lock is freed 
		 * and entry's private data is destroyed.
		 * otherwise, this is done when entry is released
		 */
		cache_return_entry_w( &li->li_cache, op->oq_add.rs_e );
		ldap_pvt_thread_rdwr_wunlock(&li->li_giant_rwlock);
	}

	return( rs->sr_err );
}
