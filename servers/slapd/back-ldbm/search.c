/* search.c - ldbm backend search function */
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
#include "proto-back-ldbm.h"

static ID_BLOCK	*base_candidate(
	Backend *be, Entry *e );

static ID_BLOCK	*search_candidates(
	Operation *op, Entry *e, Filter *filter,
	int scope, int deref, int manageDSAit );


int
ldbm_back_search(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldbminfo	*li = (struct ldbminfo *) op->o_bd->be_private;
	int		rc;
	time_t		stoptime;
	ID_BLOCK		*candidates;
	ID		id, cursor;
	Entry		*e;
	Entry	*matched = NULL;
	struct berval	realbase = BER_BVNULL;
	int		manageDSAit = get_manageDSAit( op );
#ifdef SLAP_ACL_HONOR_DISCLOSE
	slap_mask_t	mask;
#endif

	Debug(LDAP_DEBUG_TRACE, "=> ldbm_back_search\n", 0, 0, 0);

	/* grab giant lock for reading */
	ldap_pvt_thread_rdwr_rlock(&li->li_giant_rwlock);

	if ( op->o_req_ndn.bv_len == 0 ) {
		/* DIT root special case */
		e = (Entry *) &slap_entry_root;

		/* need normalized dn below */
		ber_dupbv( &realbase, &e->e_nname );

		candidates = search_candidates( op, e, op->ors_filter,
			op->ors_scope, op->ors_deref,
			manageDSAit || get_domainScope(op) );

		goto searchit;
		
	} else if ( op->ors_deref & LDAP_DEREF_FINDING ) {
		/* deref dn and get entry with reader lock */
		e = deref_dn_r( op->o_bd, &op->o_req_ndn,
			&rs->sr_err, &matched, &rs->sr_text );

		if( rs->sr_err == LDAP_NO_SUCH_OBJECT ) rs->sr_err = LDAP_REFERRAL;

	} else {
		/* get entry with reader lock */
		e = dn2entry_r( op->o_bd, &op->o_req_ndn, &matched );
		rs->sr_err = e != NULL ? LDAP_SUCCESS : LDAP_REFERRAL;
		rs->sr_text = NULL;
	}

	if ( e == NULL ) {
		struct berval matched_dn = BER_BVNULL;

		if ( matched != NULL ) {
			BerVarray erefs = NULL;

#ifdef SLAP_ACL_HONOR_DISCLOSE
			if ( ! access_allowed( op, matched,
						slap_schema.si_ad_entry,
						NULL, ACL_DISCLOSE, NULL ) )
			{
				rs->sr_err = LDAP_NO_SUCH_OBJECT;

			} else
#endif /* SLAP_ACL_HONOR_DISCLOSE */
			{
				ber_dupbv( &matched_dn, &matched->e_name );

				erefs = is_entry_referral( matched )
					? get_entry_referrals( op, matched )
					: NULL;
			}

			cache_return_entry_r( &li->li_cache, matched );

			if ( erefs ) {
				rs->sr_ref = referral_rewrite( erefs, &matched_dn,
					&op->o_req_dn, op->ors_scope );

				ber_bvarray_free( erefs );
			}

		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, op->ors_scope );
		}

		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( op, rs );

		ber_bvarray_free( rs->sr_ref );
		ber_memfree( matched_dn.bv_val );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		return rs->sr_err;
	}

#ifdef SLAP_ACL_HONOR_DISCLOSE
	/* NOTE: __NEW__ "search" access is required
	 * on searchBase object */
	if ( ! access_allowed_mask( op, e, slap_schema.si_ad_entry,
				NULL, ACL_SEARCH, NULL, &mask ) )
	{
		if ( !ACL_GRANT( mask, ACL_DISCLOSE ) ) {
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
		} else {
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		}

		cache_return_entry_r( &li->li_cache, e );
		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		send_ldap_result( op, rs );
		return rs->sr_err;
	}
#endif /* SLAP_ACL_HONOR_DISCLOSE */

	if ( !manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval	matched_dn = BER_BVNULL;
		BerVarray	erefs = NULL;

		rs->sr_ref = NULL;
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "bad referral object";

		ber_dupbv( &matched_dn, &e->e_name );
		erefs = get_entry_referrals( op, e );

		cache_return_entry_r( &li->li_cache, e );
		ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

		Debug( LDAP_DEBUG_TRACE,
			"ldbm_search: entry is referral\n",
			0, 0, 0 );

		if ( erefs ) {
			rs->sr_ref = referral_rewrite( erefs, &matched_dn,
				&op->o_req_dn, op->ors_scope );

			ber_bvarray_free( erefs );
			
			if ( rs->sr_ref ) {
				rs->sr_err = LDAP_REFERRAL;
				rs->sr_text = NULL;
			}
		}

		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( op, rs );
		ber_bvarray_free( rs->sr_ref );
		ber_memfree( matched_dn.bv_val );
		rs->sr_ref = NULL;
		rs->sr_matched = NULL;
		return rs->sr_err;
	}

	if ( is_entry_alias( e ) ) {
		/* don't deref */
		op->ors_deref = LDAP_DEREF_NEVER;
	}

	if ( op->ors_scope == LDAP_SCOPE_BASE ) {
		candidates = base_candidate( op->o_bd, e );

	} else {
		candidates = search_candidates( op, e, op->ors_filter,
		    op->ors_scope, op->ors_deref, manageDSAit );
	}

	/* need normalized dn below */
	ber_dupbv( &realbase, &e->e_nname );

	cache_return_entry_r( &li->li_cache, e );

searchit:
	if ( candidates == NULL ) {
		/* no candidates */
		Debug( LDAP_DEBUG_TRACE, "ldbm_search: no candidates\n",
			0, 0, 0 );

		rs->sr_err = LDAP_SUCCESS;
		send_ldap_result( op, rs );

		rc = LDAP_SUCCESS;
		goto done;
	}

	/* if candidates exceed to-be-checked entries, abort */
	if ( op->ors_limit	/* isroot == FALSE */
			&& op->ors_limit->lms_s_unchecked != -1
			&& ID_BLOCK_NIDS( candidates ) > (unsigned) op->ors_limit->lms_s_unchecked )
	{
		send_ldap_error( op, rs, LDAP_ADMINLIMIT_EXCEEDED, NULL );
		rc = LDAP_SUCCESS;
		goto done;
	}
	
	/* compute it anyway; root does not use it */
	stoptime = op->o_time + op->ors_tlimit;
	rs->sr_attrs = op->ors_attrs;

	for ( id = idl_firstid( candidates, &cursor ); id != NOID;
	    id = idl_nextid( candidates, &cursor ) )
	{
		int scopeok = 0;
		int result = 0;

		/* check for abandon */
		if ( op->o_abandon ) {
			rc = SLAPD_ABANDON;
			goto done;
		}

		/* check time limit */
		if ( op->ors_tlimit != SLAP_NO_LIMIT
				&& slap_get_time() > stoptime )
		{
			rs->sr_err = LDAP_TIMELIMIT_EXCEEDED;
			send_ldap_result( op, rs );
			rc = LDAP_SUCCESS;
			goto done;
		}

		/* get the entry with reader lock */
		e = id2entry_r( op->o_bd, id );

		if ( e == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_search: candidate %ld not found\n",
				id, 0, 0 );

			goto loop_continue;
		}

		rs->sr_entry = e;

#ifdef LDBM_SUBENTRIES
		if ( is_entry_subentry( e ) ) {
			if( op->ors_scope != LDAP_SCOPE_BASE ) {
				if(!get_subentries_visibility( op )) {
					/* only subentries are visible */
					goto loop_continue;
				}
			} else if ( get_subentries( op ) &&
				!get_subentries_visibility( op ))
			{
				/* only subentries are visible */
				goto loop_continue;
			}
		} else if ( get_subentries_visibility( op )) {
			/* only subentries are visible */
			goto loop_continue;
		}
#endif

		if ( op->ors_deref & LDAP_DEREF_SEARCHING &&
			is_entry_alias( e ) )
		{
			Entry *matched;
			int err;
			const char *text;
			
			e = deref_entry_r( op->o_bd, e, &err, &matched, &text );

			if( e == NULL ) {
				e = matched;
				goto loop_continue;
			}

			if( e->e_id == id ) {
				/* circular loop */
				goto loop_continue;
			}

			/* need to skip alias which deref into scope */
			if( op->ors_scope == LDAP_SCOPE_ONELEVEL ) {
				struct berval pdn;
				dnParent( &e->e_nname, &pdn );
				if ( ber_bvcmp( &pdn, &realbase ) ) {
					goto loop_continue;
				}

			} else if ( dnIsSuffix( &e->e_nname, &realbase ) ) {
				/* alias is within scope */
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: alias \"%s\" in subtree\n",
					e->e_dn, 0, 0 );

				goto loop_continue;
			}

			rs->sr_entry = e;

			scopeok = 1;
		}

		/*
		 * If it's a referral, add it to the list of referrals.
		 * Only do this for non-base searches, and don't check
		 * the filter explicitly here since it's only a candidate
		 * anyway.
		 */
		if ( !manageDSAit && op->ors_scope != LDAP_SCOPE_BASE &&
			is_entry_referral( e ) )
		{
			struct berval	dn;

			/* check scope */
			if ( !scopeok && op->ors_scope == LDAP_SCOPE_ONELEVEL ) {
				if ( !be_issuffix( op->o_bd, &e->e_nname ) ) {
					dnParent( &e->e_nname, &dn );
					scopeok = dn_match( &dn, &realbase );
				} else {
					scopeok = (realbase.bv_len == 0);
				}

			} else if ( !scopeok
				&& op->ors_scope == LDAP_SCOPE_SUBTREE )
			{
				scopeok = dnIsSuffix( &e->e_nname, &realbase );

#ifdef LDAP_SCOPE_SUBORDINATE
			} else if ( !scopeok
				&& op->ors_scope == LDAP_SCOPE_SUBORDINATE )
			{
				scopeok = !dn_match( &e->e_nname, &realbase )
					&& dnIsSuffix( &e->e_nname, &realbase );
#endif

			} else {
				scopeok = 1;
			}

			if( scopeok ) {
				BerVarray erefs = get_entry_referrals( op, e );
				rs->sr_ref = referral_rewrite( erefs,
					&e->e_name, NULL,
					op->ors_scope == LDAP_SCOPE_ONELEVEL
						? LDAP_SCOPE_BASE
						: LDAP_SCOPE_SUBTREE );

				ber_bvarray_free( erefs );

				send_search_reference( op, rs );

				ber_bvarray_free( rs->sr_ref );
				rs->sr_ref = NULL;

			} else {
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: candidate referral %ld scope not okay\n",
					id, 0, 0 );
			}

			goto loop_continue;
		}

		if ( !manageDSAit && is_entry_glue( e )) {
			goto loop_continue;
		}

		/* if it matches the filter and scope, send it */
		result = test_filter( op, e, op->ors_filter );

		if ( result == LDAP_COMPARE_TRUE ) {
			struct berval	dn;

			/* check scope */
			if ( !scopeok && op->ors_scope == LDAP_SCOPE_ONELEVEL ) {
				if ( !be_issuffix( op->o_bd, &e->e_nname ) ) {
					dnParent( &e->e_nname, &dn );
					scopeok = dn_match( &dn, &realbase );
				} else {
					scopeok = (realbase.bv_len == 0);
				}

			} else if ( !scopeok &&
				op->ors_scope == LDAP_SCOPE_SUBTREE )
			{
				scopeok = dnIsSuffix( &e->e_nname, &realbase );

			} else if ( !scopeok &&
				op->ors_scope == LDAP_SCOPE_SUBORDINATE )
			{
				scopeok = !dn_match( &e->e_nname, &realbase )
					&& dnIsSuffix( &e->e_nname, &realbase );

			} else {
				scopeok = 1;
			}

			if ( scopeok ) {
				if (e) {
					rs->sr_flags = 0;
					rs->sr_err = send_search_entry( op, rs );

					switch ( rs->sr_err ) {
					case LDAP_UNAVAILABLE:	/* connection closed */
						cache_return_entry_r( &li->li_cache, e );
						rc = LDAP_SUCCESS;
						goto done;
					case LDAP_SIZELIMIT_EXCEEDED:
						cache_return_entry_r( &li->li_cache, e );
						rc = rs->sr_err;
						rs->sr_entry = NULL;
						send_ldap_result( op, rs );
						rc = LDAP_SUCCESS;
						goto done;
					}
				}

			} else {
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: candidate entry %ld scope not okay\n",
					id, 0, 0 );
			}

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_search: candidate entry %ld does not match filter\n",
				id, 0, 0 );
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			cache_return_entry_r( &li->li_cache, e );
		}

		ldap_pvt_thread_yield();
	}

	rs->sr_err = rs->sr_v2ref ? LDAP_REFERRAL : LDAP_SUCCESS;
	rs->sr_ref = rs->sr_v2ref;
	send_ldap_result( op, rs );

	rc = LDAP_SUCCESS;

done:
	ldap_pvt_thread_rdwr_runlock(&li->li_giant_rwlock);

	if( candidates != NULL )
		idl_free( candidates );

	if( rs->sr_v2ref ) ber_bvarray_free( rs->sr_v2ref );
	if( realbase.bv_val ) free( realbase.bv_val );

	return rc;
}

static ID_BLOCK *
base_candidate(
    Backend	*be,
	Entry	*e )
{
	ID_BLOCK		*idl;

	Debug(LDAP_DEBUG_TRACE, "base_candidates: base: \"%s\"\n",
		e->e_dn, 0, 0);


	idl = idl_alloc( 1 );
	idl_insert( &idl, e->e_id, 1 );

	return( idl );
}

static ID_BLOCK *
search_candidates(
    Operation	*op,
    Entry	*e,
    Filter	*filter,
    int		scope,
	int		deref,
	int		manageDSAit )
{
	ID_BLOCK		*candidates;
	Filter		f, fand, rf, af, xf;
    AttributeAssertion aa_ref, aa_alias;
	struct berval bv_ref = { sizeof("referral")-1, "referral" };
	struct berval bv_alias = { sizeof("alias")-1, "alias" };
#ifdef LDBM_SUBENTRIES
	Filter  sf;
	AttributeAssertion aa_subentry;
#endif

	Debug(LDAP_DEBUG_TRACE,
		"search_candidates: base=\"%s\" s=%d d=%d\n",
		e->e_ndn, scope, deref );


	xf.f_or = filter;
	xf.f_choice = LDAP_FILTER_OR;
	xf.f_next = NULL;

	if( !manageDSAit ) {
		/* match referrals */
		rf.f_choice = LDAP_FILTER_EQUALITY;
		rf.f_ava = &aa_ref;
		rf.f_av_desc = slap_schema.si_ad_objectClass;
		rf.f_av_value = bv_ref;
		rf.f_next = xf.f_or;
		xf.f_or = &rf;
	}

	if( deref & LDAP_DEREF_SEARCHING ) {
		/* match aliases */
		af.f_choice = LDAP_FILTER_EQUALITY;
		af.f_ava = &aa_alias;
		af.f_av_desc = slap_schema.si_ad_objectClass;
		af.f_av_value = bv_alias;
		af.f_next = xf.f_or;
		xf.f_or = &af;
	}

	f.f_next = NULL;
	f.f_choice = LDAP_FILTER_AND;
	f.f_and = &fand;
	fand.f_choice = scope == LDAP_SCOPE_ONELEVEL
		? SLAPD_FILTER_DN_ONE
		: SLAPD_FILTER_DN_SUBTREE;
	fand.f_dn = &e->e_nname;
	fand.f_next = xf.f_or == filter ? filter : &xf ;

#ifdef LDBM_SUBENTRIES
	if ( get_subentries_visibility( op )) {
		struct berval bv_subentry = { sizeof("SUBENTRY")-1, "SUBENTRY" };
		sf.f_choice = LDAP_FILTER_EQUALITY;
		sf.f_ava = &aa_subentry;
		sf.f_av_desc = slap_schema.si_ad_objectClass;
		sf.f_av_value = bv_subentry;
		sf.f_next = fand.f_next;
		fand.f_next = &sf;
	}
#endif

	candidates = filter_candidates( op, &f );
	return( candidates );
}
