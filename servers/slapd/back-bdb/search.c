/* search.c - search operation */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "idl.h"
#include "external.h"

static int base_candidate(
	BackendDB	*be,
	Entry	*e,
	ID		*ids );
static int search_candidates(
	Operation *stackop,	/* op with the current threadctx/slab cache */
	Operation *sop,		/* search op */
	Entry *e,
	ID	*ids );
static void send_pagerequest_response( 
	Operation *op,
	SlapReply *rs,
	ID  lastid,
	int tentries );			

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
#define IS_BDB_REPLACE(type) (( type == LDAP_PSEARCH_BY_DELETE ) || \
			( type == LDAP_PSEARCH_BY_SCOPEOUT ))

#define IS_PSEARCH (op != sop)

int
bdb_abandon( Operation *op, SlapReply *rs )
{
	Operation	*ps_list;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;

	LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
		if ( ps_list->o_connid == op->o_connid ) {
			if ( ps_list->o_msgid == op->oq_abandon.rs_msgid ) {
				ps_list->o_abandon = 1;
				LDAP_LIST_REMOVE( ps_list, o_ps_link );
				slap_op_free ( ps_list );
				return LDAP_SUCCESS;
			}
		}
	}
	return LDAP_UNAVAILABLE;
}

int
bdb_cancel( Operation *op, SlapReply *rs )
{
	Operation	*ps_list;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;

	LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
		if ( ps_list->o_connid == op->o_connid ) {
			if ( ps_list->o_msgid == op->oq_cancel.rs_msgid ) {
				ps_list->o_cancel = SLAP_CANCEL_DONE;
				LDAP_LIST_REMOVE( ps_list, o_ps_link );

#if 0
				bdb_build_sync_done_ctrl( conn, ps_list, ps_list->ctrls, 1, &latest_entrycsn_bv );
				send_ldap_result( conn, ps_list, LDAP_CANCELLED,
						NULL, NULL, NULL, ps_list->ctrls, ps_list->nentries);
#endif
				rs->sr_err = LDAP_CANCELLED;
				send_ldap_result( ps_list, rs );

				slap_op_free ( ps_list );
				return LDAP_SUCCESS;
			}
		}
	}
	return LDAP_UNAVAILABLE;
}

int bdb_search( Operation *op, SlapReply *rs )
{
	return bdb_do_search( op, rs, op, NULL, 0 );
}

/* For persistent searches, op is the currently executing operation,
 * sop is the persistent search. For regular searches, sop = op.
 */
int
bdb_do_search( Operation *op, SlapReply *rs, Operation *sop, Entry *ps_e, int ps_type )
#else
int bdb_search( Operation *op, SlapReply *rs )
#define	sop	op
#define	IS_PSEARCH	0
#endif
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	time_t		stoptime;
	ID		id, cursor;
	ID		candidates[BDB_IDL_UM_SIZE];
	Entry		*e = NULL;
	Entry	*matched = NULL;
	struct berval	realbase = { 0, NULL };
	int		manageDSAit;
	int		tentries = 0;
	ID		lastid = NOID;
	AttributeName	*attrs;

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
	Filter 		cookief, csnfnot, csnfeq, csnfand, csnfge;
	AttributeAssertion aa_ge, aa_eq;
	int		entry_count = 0;
	struct berval	entrycsn_bv = { 0, NULL };
	struct berval	latest_entrycsn_bv = { 0, NULL };
	LDAPControl	*ctrls[SLAP_SEARCH_MAX_CTRLS];
	int		num_ctrls = 0;
	AttributeName	uuid_attr[2];
#ifdef LDAP_SYNC
	int		rc_sync = 0;
	int		entry_sync_state = -1;
	AttributeName	null_attr;
#endif
#endif
	struct slap_limits_set *limit = NULL;
	int isroot = 0;

	u_int32_t	locker = 0;
	DB_LOCK		lock;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_back_search\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_back_search\n",
		0, 0, 0);
#endif
	attrs = sop->oq_search.rs_attrs;

#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
#ifdef LDAP_CLIENT_UPDATE
	if ( !IS_PSEARCH && sop->o_clientupdate_type & SLAP_LCUP_PERSIST ) {
		sop->o_ps_protocol = LDAP_CLIENT_UPDATE;
		LDAP_LIST_INSERT_HEAD( &bdb->bi_psearch_list, sop, o_ps_link );
		return LDAP_SUCCESS;
	}
#endif
#ifdef LDAP_SYNC
	/* psearch needs to be registered before refresh begins */
	/* psearch and refresh transmission is serialized in send_ldap_ber() */
	if ( !IS_PSEARCH && sop->o_sync_mode & SLAP_SYNC_PERSIST ) {
		sop->o_ps_protocol = LDAP_SYNC;
		LDAP_LIST_INSERT_HEAD( &bdb->bi_psearch_list, sop, o_ps_link );
	}
	null_attr.an_desc = NULL;
	null_attr.an_oc = NULL;
	null_attr.an_name.bv_len = 0;
	null_attr.an_name.bv_val = NULL;
#endif

	for ( num_ctrls = 0; num_ctrls < SLAP_SEARCH_MAX_CTRLS; num_ctrls++ )
		ctrls[num_ctrls] = NULL;
	num_ctrls = 0;

	if ( IS_PSEARCH && IS_BDB_REPLACE(ps_type)) {
#ifdef LDAP_CLIENT_UPDATE
		if ( sop->o_ps_protocol == LDAP_CLIENT_UPDATE ) {
			attrs = uuid_attr;
			attrs[0].an_desc = slap_schema.si_ad_entryUUID;
			attrs[0].an_oc = NULL;
			attrs[0].an_name =  attrs[0].an_desc->ad_cname;
			attrs[1].an_desc = NULL;
			attrs[1].an_oc = NULL;
			attrs[1].an_name.bv_len = 0;
			attrs[1].an_name.bv_val = NULL;
		} else
#endif
#ifdef LDAP_SYNC
		if (sop->o_ps_protocol == LDAP_SYNC ) {
			attrs = uuid_attr;
			attrs[0].an_desc = NULL;
			attrs[0].an_oc = NULL;
			attrs[0].an_name.bv_len = 0;
			attrs[0].an_name.bv_val = NULL;
		} else
#endif
		{
			rs->sr_err = 1;
			goto done;
		}
	}
#endif
	manageDSAit = get_manageDSAit( sop );

	rs->sr_err = LOCK_ID (bdb->bi_dbenv, &locker );

	switch(rs->sr_err) {
	case 0:
		break;
	default:
		send_ldap_error( sop, rs, LDAP_OTHER, "internal error" );
		return rs->sr_err;
	}

	if ( sop->o_req_ndn.bv_len == 0 ) {
		/* DIT root special case */
		e = (Entry *) &slap_entry_root;
		rs->sr_err = 0;
	} else						
#ifdef BDB_ALIASES
	/* get entry with reader lock */
	if ( deref & LDAP_DEREF_FINDING ) {
		e = deref_dn_r( op->o_bd, &sop->o_req_ndn, &rs->sr_err, &matched, &rs->sr_text );

	} else
#endif
	{
dn2entry_retry:
		rs->sr_err = bdb_dn2entry_r( op->o_bd, NULL, &sop->o_req_ndn, &e, &matched, 0, locker, &lock );
	}

	switch(rs->sr_err) {
	case DB_NOTFOUND:
	case 0:
		break;
	case LDAP_BUSY:
		if (e != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
		}
		if (matched != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
		}
		send_ldap_error( sop, rs, LDAP_BUSY, "ldap server busy" );
		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		if (e != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
		}
		if (matched != NULL) {
			bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
		}
		send_ldap_error( sop, rs, LDAP_OTHER, "internal error" );
		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		return rs->sr_err;
	}

	if ( e == NULL ) {
		struct berval matched_dn = { 0, NULL };

		if ( matched != NULL ) {
			BerVarray erefs;
			ber_dupbv( &matched_dn, &matched->e_name );

			erefs = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;

			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
			matched = NULL;

			if( erefs ) {
				rs->sr_ref = referral_rewrite( erefs, &matched_dn,
					&sop->o_req_dn, sop->oq_search.rs_scope );
				ber_bvarray_free( erefs );
			}

		} else {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &sop->o_req_dn, sop->oq_search.rs_scope );
		}

		rs->sr_err=LDAP_REFERRAL;
		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( sop, rs );

		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		if ( rs->sr_ref ) {
			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
		}
		if ( matched_dn.bv_val ) {
			ber_memfree( matched_dn.bv_val );
			rs->sr_matched = NULL;
		}
		return rs->sr_err;
	}

	if (!manageDSAit && e != &slap_entry_root && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval matched_dn;
		BerVarray erefs;
		
		ber_dupbv( &matched_dn, &e->e_name );
		erefs = get_entry_referrals( op, e );

		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
		e = NULL;

		if( erefs ) {
			rs->sr_ref = referral_rewrite( erefs, &matched_dn,
				&sop->o_req_dn, sop->oq_search.rs_scope );
			ber_bvarray_free( erefs );
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_search: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_search: entry is referral\n",
			0, 0, 0 );
#endif

		if (!rs->sr_ref) rs->sr_text = "bad_referral object";
		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( sop, rs );

		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		ber_memfree( matched_dn.bv_val );
		rs->sr_matched = NULL;
		return 1;
	}

	/* if not root, get appropriate limits */
	if ( be_isroot( op->o_bd, &sop->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( op->o_bd, &sop->o_ndn, &limit );
	}

	/* The time/size limits come first because they require very little
	 * effort, so there's no chance the candidates are selected and then 
	 * the request is not honored only because of time/size constraints */

	/* if no time limit requested, use soft limit (unless root!) */
	if ( isroot ) {
		if ( sop->oq_search.rs_tlimit == 0 ) {
			sop->oq_search.rs_tlimit = -1;	/* allow root to set no limit */
		}

		if ( sop->oq_search.rs_slimit == 0 ) {
			sop->oq_search.rs_slimit = -1;
		}

	} else {
		/* if no limit is required, use soft limit */
		if ( sop->oq_search.rs_tlimit <= 0 ) {
			sop->oq_search.rs_tlimit = limit->lms_t_soft;

		/* if requested limit higher than hard limit, abort */
		} else if ( sop->oq_search.rs_tlimit > limit->lms_t_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_t_hard == 0
					&& limit->lms_t_soft > -1
					&& sop->oq_search.rs_tlimit > limit->lms_t_soft ) {
				sop->oq_search.rs_tlimit = limit->lms_t_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_t_hard > 0 ) {
				rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
				send_ldap_result( sop, rs );
				rs->sr_err = 0;
				goto done;
			}
		
			/* negative hard limit means no limit */
		}
		
		/* if no limit is required, use soft limit */
		if ( sop->oq_search.rs_slimit <= 0 ) {
			if ( get_pagedresults(sop) && limit->lms_s_pr != 0 ) {
				sop->oq_search.rs_slimit = limit->lms_s_pr;
			} else {
				sop->oq_search.rs_slimit = limit->lms_s_soft;
			}

		/* if requested limit higher than hard limit, abort */
		} else if ( sop->oq_search.rs_slimit > limit->lms_s_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_s_hard == 0
					&& limit->lms_s_soft > -1
					&& sop->oq_search.rs_slimit > limit->lms_s_soft ) {
				sop->oq_search.rs_slimit = limit->lms_s_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_s_hard > 0 ) {
				rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
				send_ldap_result( sop, rs );
				rs->sr_err = 0;	
				goto done;
			}
			
			/* negative hard limit means no limit */
		}
	}

	/* compute it anyway; root does not use it */
	stoptime = op->o_time + sop->oq_search.rs_tlimit;

	/* select candidates */
	if ( sop->oq_search.rs_scope == LDAP_SCOPE_BASE ) {
		rs->sr_err = base_candidate( op->o_bd, e, candidates );

	} else {
		BDB_IDL_ALL( bdb, candidates );
		rs->sr_err = search_candidates( op, sop, e, candidates );
	}

	/* start cursor at beginning of candidates.
	 */
	cursor = 0;
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
	if (IS_PSEARCH) {
		if ( !BDB_IDL_IS_RANGE( candidates ) ) {
			cursor = bdb_idl_search( candidates, ps_e->e_id );
			if ( candidates[cursor] != ps_e->e_id ) {
			   	rs->sr_err = LDAP_SUCCESS;
			   	goto done;
			}
		} else {
			if ( ps_e->e_id < BDB_IDL_RANGE_FIRST(candidates)
			   || ps_e->e_id > BDB_IDL_RANGE_LAST(candidates)){
			   	rs->sr_err = LDAP_SUCCESS;
			   	goto done;
			}
		}
		candidates[0] = 1;
		candidates[1] = ps_e->e_id;
	}
#endif

	/* need normalized dn below */
	ber_dupbv( &realbase, &e->e_nname );

	if ( e != &slap_entry_root ) {
		bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
	}
	e = NULL;

	if ( candidates[0] == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS,
			"bdb_search: no candidates\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_search: no candidates\n",
			0, 0, 0 );
#endif

		rs->sr_err = LDAP_SUCCESS;
		send_ldap_result( sop, rs );
		rs->sr_err = 1;
		goto done;
	}

	/* if not root and candidates exceed to-be-checked entries, abort */
	if ( !isroot && limit->lms_s_unchecked != -1 ) {
		if ( BDB_IDL_N(candidates) > (unsigned) limit->lms_s_unchecked ) {
			rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
			send_ldap_result( sop, rs );
			rs->sr_err = 1;
			goto done;
		}
	}

	if ( isroot || !limit->lms_s_pr_hide ) {
		tentries = BDB_IDL_N(candidates);
	}

#ifdef LDAP_CONTROL_PAGEDRESULTS
	if ( get_pagedresults(sop) ) {
		if ( sop->o_pagedresults_state.ps_cookie == 0 ) {
			id = 0;
		} else {
			if ( sop->o_pagedresults_size == 0 ) {
				rs->sr_err = LDAP_SUCCESS;
				rs->sr_text = "search abandoned by pagedResult size=0";
				send_ldap_result( sop, rs );
				goto done;
			}
			for ( id = bdb_idl_first( candidates, &cursor );
				id != NOID && id <= (ID)( sop->o_pagedresults_state.ps_cookie );
				id = bdb_idl_next( candidates, &cursor ) );
		}
		if ( cursor == NOID ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, RESULTS, 
				"bdb_search: no paged results candidates\n", 
			0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, 
				"bdb_search: no paged results candidates\n",
				0, 0, 0 );
#endif
			send_pagerequest_response( sop, rs, lastid, 0 );

			rs->sr_err = 1;
			goto done;
		}
		goto loop_begin;
	}
#endif

#ifdef LDAP_CLIENT_UPDATE
	if ( (sop->o_clientupdate_type & SLAP_LCUP_SYNC) ||
	    (IS_PSEARCH && sop->o_ps_protocol == LDAP_CLIENT_UPDATE )) {
		cookief.f_choice = LDAP_FILTER_AND;
		cookief.f_and = &csnfnot;
		cookief.f_next = NULL;

		csnfnot.f_choice = LDAP_FILTER_NOT;
		csnfnot.f_not = &csnfeq;
		csnfnot.f_next = &csnfand;

		csnfeq.f_choice = LDAP_FILTER_EQUALITY;
		csnfeq.f_ava = &aa_eq;
		csnfeq.f_av_desc = slap_schema.si_ad_entryCSN;
		csnfeq.f_av_value = sop->o_clientupdate_state;

		csnfand.f_choice = LDAP_FILTER_AND;
		csnfand.f_and = &csnfge;
		csnfand.f_next = NULL;

		csnfge.f_choice = LDAP_FILTER_GE;
		csnfge.f_ava = &aa_ge;
		csnfge.f_av_desc = slap_schema.si_ad_entryCSN;
		csnfge.f_av_value = sop->o_clientupdate_state;
		csnfge.f_next = sop->oq_search.rs_filter;
	}
#endif
#if defined(LDAP_CLIENT_UPDATE) && defined(LDAP_SYNC)
	else
#endif
#ifdef LDAP_SYNC
	if ( (sop->o_sync_mode & SLAP_SYNC_REFRESH) ||
		( IS_PSEARCH && sop->o_ps_protocol == LDAP_SYNC )) {
		cookief.f_choice = LDAP_FILTER_AND;
		cookief.f_and = &csnfnot;
		cookief.f_next = NULL;

		csnfnot.f_choice = LDAP_FILTER_NOT;
		csnfnot.f_not = &csnfeq;
		csnfnot.f_next = &csnfand;

		csnfeq.f_choice = LDAP_FILTER_EQUALITY;
		csnfeq.f_ava = &aa_eq;
		csnfeq.f_av_desc = slap_schema.si_ad_entryCSN;
		csnfeq.f_av_value = sop->o_sync_state;

		csnfand.f_choice = LDAP_FILTER_AND;
		csnfand.f_and = &csnfge;
		csnfand.f_next = NULL;

		csnfge.f_choice = LDAP_FILTER_GE;
		csnfge.f_ava = &aa_ge;
		csnfge.f_av_desc = slap_schema.si_ad_entryCSN;
		csnfge.f_av_value = sop->o_sync_state;
		csnfge.f_next = sop->oq_search.rs_filter;
	}
#endif

	for ( id = bdb_idl_first( candidates, &cursor );
		id != NOID;
		id = bdb_idl_next( candidates, &cursor ) )
	{

		int		scopeok = 0;

loop_begin:
		/* check for abandon */
		if ( sop->o_abandon ) {
			rs->sr_err = 0;
			goto done;
		}

#ifdef LDAP_EXOP_X_CANCEL
		if ( sop->o_cancel ) {
			assert( sop->o_cancel == SLAP_CANCEL_REQ );
			rs->sr_err = LDAP_CANCELLED;
			send_ldap_result( sop, rs );
			sop->o_cancel = SLAP_CANCEL_ACK;
			rs->sr_err = 0;
			goto done;
		}
#endif

		/* check time limit */
		if ( sop->oq_search.rs_tlimit != -1 && slap_get_time() > stoptime ) {
			rs->sr_err = LDAP_TIMELIMIT_EXCEEDED;
			rs->sr_ref = rs->sr_v2ref;
			send_ldap_result( sop, rs );
			goto done;
		}


#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
		if (!IS_PSEARCH) {
#endif
id2entry_retry:
			/* get the entry with reader lock */
			rs->sr_err = bdb_id2entry_r( op->o_bd, NULL, id, &e, locker, &lock );

			if (rs->sr_err == LDAP_BUSY) {
				rs->sr_text = "ldap server busy";
				send_ldap_result( sop, rs );
				goto done;

			} else if ( rs->sr_err == DB_LOCK_DEADLOCK || rs->sr_err == DB_LOCK_NOTGRANTED ) {
				goto id2entry_retry;	
			}

			if ( e == NULL ) {
				if( !BDB_IDL_IS_RANGE(candidates) ) {
					/* only complain for non-range IDLs */
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, RESULTS,
						"bdb_search: candidate %ld not found\n", (long) id, 0, 0);
#else
					Debug( LDAP_DEBUG_TRACE,
						"bdb_search: candidate %ld not found\n",
						(long) id, 0, 0 );
#endif
				}

				goto loop_continue;
			}
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
		} else {
			e = ps_e;
		}
#endif

		rs->sr_entry = e;
#ifdef BDB_SUBENTRIES
		if ( is_entry_subentry( e ) ) {
			if( sop->oq_search.rs_scope != LDAP_SCOPE_BASE ) {
				if(!get_subentries_visibility( sop )) {
					/* only subentries are visible */
					goto loop_continue;
				}

			} else if ( get_subentries( sop ) &&
				!get_subentries_visibility( sop ))
			{
				/* only subentries are visible */
				goto loop_continue;
			}

		} else if ( get_subentries_visibility( sop )) {
			/* only subentries are visible */
			goto loop_continue;
		}
#endif

#ifdef BDB_ALIASES
		if ( sop->oq_search.rs_deref & LDAP_DEREF_SEARCHING && is_entry_alias( e ) ) {
			Entry *matched;
			int err;
			const char *text;
			
			e = deref_entry_r( op->o_bd, e, &rs->sr_err, &matched, &rs->sr_text );

			if( e == NULL ) {
				e = matched;
				goto loop_continue;
			}

			if( e->e_id == id ) {
				/* circular loop */
				goto loop_continue;
			}

			/* need to skip alias which deref into scope */
			if( sop->oq_search.rs_scope & LDAP_SCOPE_ONELEVEL ) {
				struct berval	pdn;
				
				dnParent( &e->e_nname, &pdn ):
				if ( ber_bvcmp( pdn, &realbase ) ) {
					goto loop_continue;
				}

			} else if ( dnIsSuffix( &e->e_nname, &realbase ) ) {
				/* alias is within scope */
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, RESULTS,
					"bdb_search: \"%s\" in subtree\n", e->edn, 0, 0);
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_search: \"%s\" in subtree\n",
					e->e_dn, 0, 0 );
#endif
				goto loop_continue;
			}

			scopeok = 1;
		}
#endif

		/*
		 * if it's a referral, add it to the list of referrals. only do
		 * this for non-base searches, and don't check the filter
		 * explicitly here since it's only a candidate anyway.
		 */
		if ( !manageDSAit && sop->oq_search.rs_scope != LDAP_SCOPE_BASE &&
			is_entry_referral( e ) )
		{
			struct berval	dn;

			/* check scope */
			if ( !scopeok && sop->oq_search.rs_scope == LDAP_SCOPE_ONELEVEL ) {
				if ( !be_issuffix( op->o_bd, &e->e_nname ) ) {
					dnParent( &e->e_nname, &dn );
					scopeok = dn_match( &dn, &realbase );
				} else {
					scopeok = (realbase.bv_len == 0);
				}

			} else if ( !scopeok && sop->oq_search.rs_scope == LDAP_SCOPE_SUBTREE ) {
				scopeok = dnIsSuffix( &e->e_nname, &realbase );

			} else {
				scopeok = 1;
			}

			if( scopeok ) {
				BerVarray erefs = get_entry_referrals( sop, e );
				rs->sr_ref = referral_rewrite( erefs,
					&e->e_name, NULL,
					sop->oq_search.rs_scope == LDAP_SCOPE_SUBTREE
						? LDAP_SCOPE_SUBTREE
						: LDAP_SCOPE_BASE );

				send_search_reference( sop, rs );

				ber_bvarray_free( rs->sr_ref );
				ber_bvarray_free( erefs );
				rs->sr_ref = NULL;

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG(OPERATION, DETAIL2, 
					"bdb_search: candidate referral %ld scope not okay\n",
					id, 0, 0 );
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_search: candidate referral %ld scope not okay\n",
					id, 0, 0 );
#endif
			}

			goto loop_continue;
		}

		/* if it matches the filter and scope, send it */
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
		if (IS_PSEARCH) {
			if (ps_type != LDAP_PSEARCH_BY_SCOPEOUT) {
				rs->sr_err = test_filter( sop, rs->sr_entry, &cookief );
			} else {
				rs->sr_err = LDAP_COMPARE_TRUE;
			}
		} else {
#ifdef LDAP_CLIENT_UPDATE
			if ( sop->o_clientupdate_type & SLAP_LCUP_SYNC ) {
				rs->sr_err = test_filter( sop, rs->sr_entry, &cookief );
			} else
#endif
#ifdef LDAP_SYNC
			if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
				rc_sync = test_filter( sop, rs->sr_entry, &cookief );
				rs->sr_err      = test_filter( sop, rs->sr_entry, sop->oq_search.rs_filter );
				if ( rs->sr_err == LDAP_COMPARE_TRUE ) {
					if ( rc_sync == LDAP_COMPARE_TRUE ) {
						entry_sync_state = LDAP_SYNC_ADD;
					} else {
						entry_sync_state = LDAP_SYNC_PRESENT;
					}
				}
			} else
#endif
#endif
			{
				rs->sr_err = test_filter( sop, rs->sr_entry, sop->oq_search.rs_filter );
			}
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
		}
#endif

		if ( rs->sr_err == LDAP_COMPARE_TRUE ) {
			struct berval	dn;

			/* check scope */
			if ( !scopeok && sop->oq_search.rs_scope == LDAP_SCOPE_ONELEVEL ) {
				if ( be_issuffix( op->o_bd, &e->e_nname ) ) {
					scopeok = (realbase.bv_len == 0);
				} else {
					dnParent( &e->e_nname, &dn );
					scopeok = dn_match( &dn, &realbase );
				}

			} else if ( !scopeok && sop->oq_search.rs_scope == LDAP_SCOPE_SUBTREE ) {
				scopeok = dnIsSuffix( &e->e_nname, &realbase );

			} else {
				scopeok = 1;
			}

			if ( scopeok ) {
				/* check size limit */
				if ( --sop->oq_search.rs_slimit == -1 ) {
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
					if (!IS_PSEARCH)
#endif
					bdb_cache_return_entry_r( bdb->bi_dbenv,
						&bdb->bi_cache, e, &lock );
					e = NULL;
					rs->sr_entry = NULL;
					rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
					rs->sr_ref = rs->sr_v2ref;
					send_ldap_result( sop, rs );
					goto done;
				}

#ifdef LDAP_CONTROL_PAGEDRESULTS
				if ( get_pagedresults(sop) ) {
					if ( rs->sr_nentries >= sop->o_pagedresults_size ) {
						send_pagerequest_response( sop, rs,
							lastid, tentries );
						goto done;
					}
					lastid = id;
				}
#endif

				if (e) {
					int result;
					
#if 0	/* noop is masked SLAP_CTRL_UPDATE */
					if( op->o_noop ) {
						result = 0;
					} else
#endif
#if defined(LDAP_CLIENT_UPDATE) || defined(LDAP_SYNC)
					if (IS_PSEARCH) {
#ifdef LDAP_SYNC
						int premodify_found = 0;
						int entry_sync_state;
#endif

						if ( ps_type == LDAP_PSEARCH_BY_ADD ||
							 ps_type == LDAP_PSEARCH_BY_DELETE ||
							 ps_type == LDAP_PSEARCH_BY_MODIFY ||
							 ps_type == LDAP_PSEARCH_BY_SCOPEOUT )
						{
							if ( ps_type == LDAP_PSEARCH_BY_MODIFY ) {
								struct psid_entry* psid_e;
								LDAP_LIST_FOREACH( psid_e, &op->o_pm_list, ps_link)
								{
									if( psid_e->ps_op == sop )
									{
#ifdef LDAP_SYNC
										premodify_found = 1;
#endif
										LDAP_LIST_REMOVE(psid_e, ps_link);
										break;
									}
								}
								if (psid_e != NULL) free (psid_e);
							}
#ifdef LDAP_SYNC
							if ( ps_type == LDAP_PSEARCH_BY_ADD )
								entry_sync_state = LDAP_SYNC_ADD;
							else if ( ps_type == LDAP_PSEARCH_BY_DELETE )
								entry_sync_state = LDAP_SYNC_DELETE;
							else if ( ps_type == LDAP_PSEARCH_BY_MODIFY ) {
								if ( premodify_found )
									entry_sync_state = LDAP_SYNC_MODIFY;
								else
									entry_sync_state = LDAP_SYNC_ADD;
							} else if ( ps_type == LDAP_PSEARCH_BY_SCOPEOUT )
								entry_sync_state = LDAP_SYNC_DELETE;
							else {
								rs->sr_err = 1;
								goto done;
							}
#endif

#ifdef LDAP_CLIENT_UPDATE
						if ( sop->o_ps_protocol == LDAP_CLIENT_UPDATE ) {
							int entry_count = ++sop->o_ps_entries;
							if ( IS_BDB_REPLACE(ps_type) ) {
								rs->sr_err = bdb_build_lcup_update_ctrl( sop, rs, e, entry_count, ctrls,
										num_ctrls++, &latest_entrycsn_bv, SLAP_LCUP_ENTRY_DELETED_TRUE );
							} else {
								rs->sr_err = bdb_build_lcup_update_ctrl( sop, rs, e, entry_count, ctrls,
										num_ctrls++, &latest_entrycsn_bv, SLAP_LCUP_ENTRY_DELETED_FALSE );
							}
							if ( rs->sr_err != LDAP_SUCCESS )
								goto done;
							rs->sr_attrs = attrs;
							rs->sr_ctrls = ctrls;
							result = send_search_entry( sop, rs );
							if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
								ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
							ch_free( ctrls[--num_ctrls] );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;
						} else
#endif
#ifdef LDAP_SYNC
						if ( sop->o_ps_protocol == LDAP_SYNC ) {
							rs->sr_err = bdb_build_sync_state_ctrl( sop, rs, e, entry_sync_state, ctrls,
											num_ctrls++, 1, &latest_entrycsn_bv );
							if ( rs->sr_err != LDAP_SUCCESS )
								goto done;
							rs->sr_attrs = attrs;
							rs->sr_ctrls = ctrls;
							result = send_search_entry( sop, rs );
							if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
								ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
							ch_free( ctrls[--num_ctrls] );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;
						} else
#endif
						{
							rs->sr_err = 1;
							goto done;
						}

					} else if ( ps_type == LDAP_PSEARCH_BY_PREMODIFY ) {
						struct psid_entry* psid_e;
						psid_e = (struct psid_entry *) calloc (1,
							sizeof(struct psid_entry));
						psid_e->ps_op = sop;
						LDAP_LIST_INSERT_HEAD( &op->o_pm_list, psid_e, ps_link );

					} else {
						printf("Error !\n");
					}
				} else {
#ifdef LDAP_CLIENT_UPDATE
						if ( sop->o_clientupdate_type & SLAP_LCUP_SYNC ) {
							rs->sr_err = bdb_build_lcup_update_ctrl( sop, rs, e, ++entry_count, ctrls,
									num_ctrls++, &latest_entrycsn_bv, SLAP_LCUP_ENTRY_DELETED_FALSE );
							if ( rs->sr_err != LDAP_SUCCESS )
								goto done;
							rs->sr_ctrls = ctrls;
							rs->sr_attrs = sop->oq_search.rs_attrs;
							result = send_search_entry( sop, rs );

							if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
								ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
							ch_free( ctrls[--num_ctrls] );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;
						} else
#endif
#ifdef LDAP_SYNC
						if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
							rs->sr_err = bdb_build_sync_state_ctrl( sop, rs, e, entry_sync_state, ctrls,
									num_ctrls++, 0, &latest_entrycsn_bv );
							if ( rs->sr_err != LDAP_SUCCESS )
								goto done;

							rs->sr_ctrls = ctrls;
							if ( rc_sync == LDAP_COMPARE_TRUE ) { /* ADD */
								rs->sr_attrs = sop->oq_search.rs_attrs;
							} else { /* PRESENT */
								rs->sr_attrs = &null_attr;
							}
							result = send_search_entry( sop, rs );

							if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
								ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
							ch_free( ctrls[--num_ctrls] );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;
						} else
#endif
#endif
						{
							rs->sr_attrs = sop->oq_search.rs_attrs;
							rs->sr_ctrls = NULL;
							result = send_search_entry( sop, rs );
						}
					}

					switch (result) {
					case 0:		/* entry sent ok */
						break;
					case 1:		/* entry not sent */
						break;
					case -1:	/* connection closed */
						if (!IS_PSEARCH)
						bdb_cache_return_entry_r(bdb->bi_dbenv,
							&bdb->bi_cache, e, &lock);
						e = NULL;
						rs->sr_entry = NULL;
						rs->sr_err = LDAP_OTHER;
						goto done;
					}
				}
			} else {
#ifdef NEW_LOGGING
				LDAP_LOG ( OPERATION, RESULTS,
					"bdb_search: %ld scope not okay\n", (long) id, 0, 0);
#else
				Debug( LDAP_DEBUG_TRACE,
					"bdb_search: %ld scope not okay\n",
					(long) id, 0, 0 );
#endif
			}
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, RESULTS,
				"bdb_search: %ld does not match filter\n", (long) id, 0, 0);
#else
			Debug( LDAP_DEBUG_TRACE,
				"bdb_search: %ld does not match filter\n",
				(long) id, 0, 0 );
#endif
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			if (!IS_PSEARCH)
			bdb_cache_return_entry_r( bdb->bi_dbenv,
				&bdb->bi_cache, e , &lock);
			e = NULL;
			rs->sr_entry = NULL;
		}

		ldap_pvt_thread_yield();
	}

	if (!IS_PSEARCH) {
#ifdef LDAP_CLIENT_UPDATE
	if ( sop->o_clientupdate_type & SLAP_LCUP_SYNC ) {
		bdb_build_lcup_done_ctrl( sop, rs, ctrls, num_ctrls++, &latest_entrycsn_bv );

		rs->sr_ctrls = ctrls;
		rs->sr_ref = rs->sr_v2ref;
		rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS : LDAP_REFERRAL;
		send_ldap_result( sop, rs );

		ch_free( latest_entrycsn_bv.bv_val );
		latest_entrycsn_bv.bv_val = NULL;

		if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
				ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
		ch_free( ctrls[--num_ctrls] );
		ctrls[num_ctrls] = NULL;
	} else
#endif
#ifdef LDAP_SYNC
	if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
		if ( sop->o_sync_mode & SLAP_SYNC_PERSIST ) {
			/* refreshAndPersist mode */
			rs->sr_err = LDAP_SUCCESS;
			rs->sr_rspoid = LDAP_SYNC_INFO;
			rs->sr_ctrls = NULL;
			bdb_send_ldap_intermediate( sop, rs,
				LDAP_SYNC_REFRESH_DONE, &latest_entrycsn_bv );
		} else {
			/* refreshOnly mode */
			bdb_build_sync_done_ctrl( sop, rs, ctrls, num_ctrls++, 1, &latest_entrycsn_bv );
			rs->sr_ctrls = ctrls;
			rs->sr_ref = rs->sr_v2ref;
			rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS : LDAP_REFERRAL;
			send_ldap_result( sop, rs );
			if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL )
				ch_free( ctrls[num_ctrls-1]->ldctl_value.bv_val );
			ch_free( ctrls[--num_ctrls] );
			ctrls[num_ctrls] = NULL;
		}

		ch_free( latest_entrycsn_bv.bv_val );
		latest_entrycsn_bv.bv_val = NULL;
	} else
#endif
	{
		rs->sr_ctrls = NULL;
		rs->sr_ref = rs->sr_v2ref;
		rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS : LDAP_REFERRAL;
		send_ldap_result( sop, rs );
	}
	}

	rs->sr_err = LDAP_SUCCESS;

done:
	if( !IS_PSEARCH && e != NULL ) {
		/* free reader lock */
		bdb_cache_return_entry_r ( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
	}

	LOCK_ID_FREE (bdb->bi_dbenv, locker );

	if( rs->sr_v2ref ) {
		ber_bvarray_free( rs->sr_v2ref );
		rs->sr_v2ref = NULL;
	}
	if( realbase.bv_val ) ch_free( realbase.bv_val );

	return rs->sr_err;
}


static int base_candidate(
	BackendDB	*be,
	Entry	*e,
	ID		*ids )
{
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY,
		"base_candidate: base: \"%s\" (0x%08lx)\n", e->e_dn, (long) e->e_id, 0);
#else
	Debug(LDAP_DEBUG_ARGS, "base_candidates: base: \"%s\" (0x%08lx)\n",
		e->e_dn, (long) e->e_id, 0);
#endif

	ids[0] = 1;
	ids[1] = e->e_id;
	return 0;
}

/* Look for "objectClass Present" in this filter.
 * Also count depth of filter tree while we're at it.
 */
static int oc_filter(
	Filter *f,
	int cur,
	int *max
)
{
	int rc = 0;

	if( cur > *max ) *max = cur;

	switch(f->f_choice) {
	case LDAP_FILTER_PRESENT:
		if (f->f_desc == slap_schema.si_ad_objectClass) {
			rc = 1;
		}
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
		cur++;
		for (f=f->f_and; f; f=f->f_next) {
			(void) oc_filter(f, cur, max);
		}
		break;

	default:
		break;
	}
	return rc;
}

static void search_stack_free( void *key, void *data)
{
	ch_free(data);
}

static void *search_stack(
	Operation *op
)
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	void *ret = NULL;

	if ( op->o_threadctx ) {
		ldap_pvt_thread_pool_getkey( op->o_threadctx, search_stack,
			&ret, NULL );
	} else {
		ret = bdb->bi_search_stack;
	}

	if ( !ret ) {
		ret = ch_malloc( bdb->bi_search_stack_depth * BDB_IDL_UM_SIZE * sizeof( ID ) );
		if ( op->o_threadctx ) {
			ldap_pvt_thread_pool_setkey( op->o_threadctx, search_stack,
				ret, search_stack_free );
		} else {
			bdb->bi_search_stack = ret;
		}
	}
	return ret;
}

static int search_candidates(
	Operation *stackop,
	Operation *op,
	Entry *e,
	ID	*ids )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	int rc, depth = 1;
	Filter		f, scopef, rf, xf;
	ID		*stack;
	AttributeAssertion aa_ref;
#ifdef BDB_SUBENTRIES
	Filter	sf;
	AttributeAssertion aa_subentry;
#endif
#ifdef BDB_ALIASES
	Filter	af;
	AttributeAssertion aa_alias;
#endif

	/*
	 * This routine takes as input a filter (user-filter)
	 * and rewrites it as follows:
	 *	(&(scope=DN)[(objectClass=subentry)]
	 *		(|[(objectClass=referral)(objectClass=alias)](user-filter))
	 */

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY,
		"search_candidates: base=\"%s\" (0x%08lx) scope=%d\n", 
		e->e_dn, (long) e->e_id, op->oq_search.rs_scope);
#else
	Debug(LDAP_DEBUG_TRACE,
		"search_candidates: base=\"%s\" (0x%08lx) scope=%d\n",
		e->e_dn, (long) e->e_id, op->oq_search.rs_scope );
#endif

	xf.f_or = op->oq_search.rs_filter;
	xf.f_choice = LDAP_FILTER_OR;
	xf.f_next = NULL;

	/* If the user's filter uses objectClass=*,
	 * these clauses are redundant.
	 */
	if (!oc_filter(op->oq_search.rs_filter, 1, &depth) && !get_subentries_visibility(op) ) {
		if( !get_manageDSAit(op) && !get_domainScope(op) ) {
			/* match referral objects */
			struct berval bv_ref = { sizeof("referral")-1, "referral" };
			rf.f_choice = LDAP_FILTER_EQUALITY;
			rf.f_ava = &aa_ref;
			rf.f_av_desc = slap_schema.si_ad_objectClass;
			rf.f_av_value = bv_ref;
			rf.f_next = xf.f_or;
			xf.f_or = &rf;
		}

#ifdef BDB_ALIASES
		if( op->oq_search.rs_deref & LDAP_DEREF_SEARCHING ) {
			/* match alias objects */
			struct berval bv_alias = { sizeof("alias")-1, "alias" };
			af.f_choice = LDAP_FILTER_EQUALITY;
			af.f_ava = &aa_alias;
			af.f_av_desc = slap_schema.si_ad_objectClass;
			af.f_av_value = bv_alias;
			af.f_next = xf.f_or;
			xf.f_or = &af;
		}
#endif
		/* We added one of these clauses, filter depth increased */
		if( xf.f_or != op->oq_search.rs_filter ) depth++;
	}

	f.f_next = NULL;
	f.f_choice = LDAP_FILTER_AND;
	f.f_and = &scopef;
	scopef.f_choice = op->oq_search.rs_scope == LDAP_SCOPE_SUBTREE
		? SLAPD_FILTER_DN_SUBTREE
		: SLAPD_FILTER_DN_ONE;
	scopef.f_dn = &e->e_nname;
	scopef.f_next = xf.f_or == op->oq_search.rs_filter ? op->oq_search.rs_filter : &xf ;
	/* Filter depth increased again, adding scope clause */
	depth++;

#ifdef BDB_SUBENTRIES
	if( get_subentries_visibility( op ) ) {
		struct berval bv_subentry = { sizeof("SUBENTRY")-1, "SUBENTRY" };
		sf.f_choice = LDAP_FILTER_EQUALITY;
		sf.f_ava = &aa_subentry;
		sf.f_av_desc = slap_schema.si_ad_objectClass;
		sf.f_av_value = bv_subentry;
		sf.f_next = scopef.f_next;
		scopef.f_next = &sf;
	}
#endif

	/* Allocate IDL stack, plus 1 more for former tmp */
	if ( depth+1 > bdb->bi_search_stack_depth ) {
		stack = ch_malloc( (depth + 1) * BDB_IDL_UM_SIZE * sizeof( ID ) );
	} else {
		stack = search_stack( stackop );
	}

	rc = bdb_filter_candidates( op->o_bd, &f, ids, stack, stack+BDB_IDL_UM_SIZE );

	if ( depth+1 > bdb->bi_search_stack_depth ) {
		ch_free( stack );
	}

	if( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1,
			"bdb_search_candidates: failed (rc=%d)\n", rc, 0, 0  );
#else
		Debug(LDAP_DEBUG_TRACE,
			"bdb_search_candidates: failed (rc=%d)\n",
			rc, NULL, NULL );
#endif

	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1,
			"bdb_search_candidates: id=%ld first=%ld last=%ld\n",
			(long) ids[0], (long) BDB_IDL_FIRST(ids), 
			(long) BDB_IDL_LAST(ids));
#else
		Debug(LDAP_DEBUG_TRACE,
			"bdb_search_candidates: id=%ld first=%ld last=%ld\n",
			(long) ids[0],
			(long) BDB_IDL_FIRST(ids),
			(long) BDB_IDL_LAST(ids) );
#endif
	}

	return rc;
}

#ifdef LDAP_CONTROL_PAGEDRESULTS
static void
send_pagerequest_response( 
	Operation	*op,
	SlapReply	*rs,
	ID		lastid,
	int		tentries )
{
	LDAPControl	ctrl, *ctrls[2];
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement	*ber = (BerElement *)berbuf;
	struct berval	cookie = { 0, NULL };
	PagedResultsCookie respcookie;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY,
		"send_pagerequest_response: lastid: (0x%08lx) "
		"nentries: (0x%081x)\n", 
		lastid, rs->sr_nentries, NULL );
#else
	Debug(LDAP_DEBUG_ARGS, "send_pagerequest_response: lastid: (0x%08lx) "
			"nentries: (0x%081x)\n", lastid, rs->sr_nentries, NULL );
#endif

	ctrl.ldctl_value.bv_val = NULL;
	ctrls[0] = &ctrl;
	ctrls[1] = NULL;

	ber_init2( ber, NULL, LBER_USE_DER );

	respcookie = ( PagedResultsCookie )lastid;
	op->o_conn->c_pagedresults_state.ps_cookie = respcookie;
	cookie.bv_len = sizeof( respcookie );
	cookie.bv_val = (char *)&respcookie;

	/*
	 * FIXME: we should consider sending an estimate of the entries
	 * left, after appropriate security check is done
	 */
	ber_printf( ber, "{iO}", tentries, &cookie ); 

	if ( ber_flatten2( ber, &ctrls[0]->ldctl_value, 0 ) == -1 ) {
		goto done;
	}

	ctrls[0]->ldctl_oid = LDAP_CONTROL_PAGEDRESULTS;
	ctrls[0]->ldctl_iscritical = 0;

	rs->sr_ctrls = ctrls;
	rs->sr_err = LDAP_SUCCESS;
	send_ldap_result( op, rs );

done:
	(void) ber_free_buf( ber );
}			
#endif

#ifdef LDAP_CLIENT_UPDATE
int
bdb_build_lcup_update_ctrl(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	int		entry_count,
	LDAPControl	**ctrls,
	int		num_ctrls,
	struct berval	*latest_entrycsn_bv,
	int		isdeleted	)
{
	Attribute* a;
	int ret;
	int res;
	int rc;
	const char *text = NULL;

	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement *ber = (BerElement *)berbuf;

	struct berval entrycsn_bv = { 0, NULL };

	ber_init2( ber, 0, LBER_USE_DER );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		AttributeDescription *desc = a->a_desc;
		if ( desc == slap_schema.si_ad_entryCSN ) {
			ber_dupbv( &entrycsn_bv, &a->a_vals[0] );
			if ( latest_entrycsn_bv->bv_val == NULL ) {
				ber_dupbv( latest_entrycsn_bv, &entrycsn_bv );
			} else {
				res = value_match( &ret, desc,
					desc->ad_type->sat_ordering, 0,
					&entrycsn_bv, latest_entrycsn_bv, &text );
				if ( res != LDAP_SUCCESS ) {
					ret = 0;
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, RESULTS, 
						"bdb_search: value_match failed\n",
						0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
						"bdb_search: value_match failed\n",
						0, 0, 0 );
#endif
				}

				if ( ret > 0 ) {
					ch_free( latest_entrycsn_bv->bv_val );
					latest_entrycsn_bv->bv_val = NULL;
					ber_dupbv( latest_entrycsn_bv, &entrycsn_bv );
				}
			}
		}
	}

	if ( entry_count % op->o_clientupdate_interval == 0 )
		ber_printf( ber,
			"{bb{sON}N}",
			SLAP_LCUP_STATE_UPDATE_FALSE,
			isdeleted,
			LDAP_CUP_COOKIE_OID, &entrycsn_bv );
	else /* Do not send cookie */
		ber_printf( ber,
			"{bbN}",
			SLAP_LCUP_STATE_UPDATE_FALSE,
			isdeleted );

	ch_free( entrycsn_bv.bv_val );
	entrycsn_bv.bv_val = NULL;

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_ENTRY_UPDATE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_clientupdate;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_build_lcup_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_build_lcup_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

int
bdb_build_lcup_done_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	**ctrls,
	int		num_ctrls,
	struct berval	*latest_entrycsn_bv	)
{
	int ret, rc;
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement *ber = (BerElement *)berbuf;

	ber_init2( ber, NULL, LBER_USE_DER );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	ber_printf( ber, "{sO", LDAP_CUP_COOKIE_OID, latest_entrycsn_bv );
	ber_printf( ber, "N}" );

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_CLIENT_UPDATE_DONE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_clientupdate;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_build_lcup_done_ctrl: ber_flatten2 failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_build_lcup_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}
#endif

#ifdef LDAP_SYNC
int
bdb_build_sync_state_ctrl(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	int		entry_sync_state,
	LDAPControl	**ctrls,
	int		num_ctrls,
	int		send_cookie,
	struct berval	*latest_entrycsn_bv	)
{
	Attribute* a;
	int ret;
	int res;
	int rc;
	const char *text = NULL;

	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement *ber = (BerElement *)berbuf;

	struct berval entryuuid_bv	= { 0, NULL };
	struct berval entrycsn_bv	= { 0, NULL };

	ber_init2( ber, 0, LBER_USE_DER );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		AttributeDescription *desc = a->a_desc;
		if ( desc == slap_schema.si_ad_entryCSN ) {
			ber_dupbv( &entrycsn_bv, &a->a_vals[0] );
			if ( latest_entrycsn_bv->bv_val == NULL ) {
				ber_dupbv( latest_entrycsn_bv, &entrycsn_bv );
			} else {
				res = value_match( &ret, desc,
						desc->ad_type->sat_ordering, 0,
						&entrycsn_bv, latest_entrycsn_bv, &text );
				if ( res != LDAP_SUCCESS ) {
					ret = 0;
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, RESULTS,
							"bdb_search: value_match failed\n",
							0, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
							"bdb_search: value_match failed\n",
							0, 0, 0 );
#endif
				}
				if ( ret > 0 ) {
					ch_free( latest_entrycsn_bv->bv_val );
					latest_entrycsn_bv->bv_val = NULL;
					ber_dupbv( latest_entrycsn_bv, &entrycsn_bv );
				}
			}
		} else if ( desc == slap_schema.si_ad_entryUUID ) {
			ber_dupbv( &entryuuid_bv, &a->a_vals[0] );
		}
	}

	if ( send_cookie )
		ber_printf( ber, "{eOON}", entry_sync_state, &entryuuid_bv, &entrycsn_bv );
	else
		ber_printf( ber, "{eON}", entry_sync_state, &entryuuid_bv );

	ch_free( entrycsn_bv.bv_val );
	entrycsn_bv.bv_val = NULL;
	ch_free( entryuuid_bv.bv_val );
	entryuuid_bv.bv_val = NULL;

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_STATE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_sync;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

int
bdb_build_sync_done_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	**ctrls,
	int		num_ctrls,
	int		send_cookie,
	struct berval	*latest_entrycsn_bv	)
{
	int ret,rc;
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement *ber = (BerElement *)berbuf;

	ber_init2( ber, NULL, LBER_USE_DER );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	if ( send_cookie ) {
		ber_printf( ber, "{ON}", latest_entrycsn_bv );
	} else {
		ber_printf( ber, "{N}" );
	}

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_DONE;
	ctrls[num_ctrls]->ldctl_iscritical = op->o_sync;
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_build_lcup_done_ctrl: ber_flatten2 failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_build_lcup_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

int
bdb_send_ldap_intermediate(
	Operation   *op,
	SlapReply   *rs,
	int	    state,
	struct berval *cookie )
{
	char berbuf[LBER_ELEMENT_SIZEOF];
	BerElement *ber = (BerElement *)berbuf;
	struct berval rspdata;

	int ret, rc;

	ber_init2( ber, NULL, LBER_USE_DER );

	if ( cookie == NULL )
		ber_printf( ber, "{eN}", state );
	else
		ber_printf( ber, "{eON}", state, cookie );

	ret = ber_flatten2( ber, &rspdata, 0 );

	if ( ret < 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_build_lcup_done_ctrl: ber_flatten2 failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_build_lcup_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
#endif
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	rs->sr_rspdata = &rspdata;
	send_ldap_intermediate_resp( op, rs );
	rs->sr_rspdata = NULL;
	ber_free_buf( ber );

	return LDAP_SUCCESS;
}
#endif
