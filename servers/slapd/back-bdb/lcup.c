/* lcup.c - lcup operations */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include "back-bdb.h"
#include "idl.h"
#include "external.h"

#ifdef LDAP_CLIENT_UPDATE

int
bdb_abandon(
	BackendDB	*be,
	Connection	*conn,
	ber_int_t	id )
{
	Operation	*ps_list;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	LDAP_LIST_FOREACH ( ps_list, &bdb->psearch_list, link ) {
		if ( ps_list->o_connid == conn->c_connid ) {
			if ( ps_list->o_msgid == id ) {
				ps_list->o_abandon = 1;
				LDAP_LIST_REMOVE( ps_list, link );
				slap_op_free ( ps_list );
				return LDAP_SUCCESS;
			}
		}
	}
	return LDAP_UNAVAILABLE;
}

int
bdb_add_psearch_spec(
	BackendDB       *be,
	Connection      *conn,
	Operation       *op,
	struct berval   *base,
	struct berval   *nbase,
	int             scope,
	int             deref,
	int             slimit,
	int             tlimit,
	Filter		*filter,
	struct berval	*fstr,
	AttributeName   *attrs,
	int             attrsonly )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	LDAP_LIST_FIRST(&op->psearch_spec) = (struct lcup_search_spec *)
			calloc ( 1, sizeof ( struct lcup_search_spec ) );

	LDAP_LIST_FIRST(&op->psearch_spec)->op = op;

	LDAP_LIST_FIRST(&op->psearch_spec)->base = ber_dupbv(NULL, base);
	LDAP_LIST_FIRST(&op->psearch_spec)->nbase = ber_dupbv(NULL, nbase);

	LDAP_LIST_FIRST(&op->psearch_spec)->scope = scope;
	LDAP_LIST_FIRST(&op->psearch_spec)->deref = deref;
	LDAP_LIST_FIRST(&op->psearch_spec)->slimit = slimit;
	LDAP_LIST_FIRST(&op->psearch_spec)->tlimit = tlimit;

	LDAP_LIST_FIRST(&op->psearch_spec)->filter = filter;
	LDAP_LIST_FIRST(&op->psearch_spec)->filterstr = ber_dupbv(NULL, fstr);
	LDAP_LIST_FIRST(&op->psearch_spec)->attrs = attrs;

	LDAP_LIST_FIRST(&op->psearch_spec)->attrsonly = attrsonly;

	LDAP_LIST_FIRST(&op->psearch_spec)->entry_count = 0;

	LDAP_LIST_INSERT_HEAD( &bdb->psearch_list, op, link );
}

int
bdb_psearch(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	Operation	*ps_op,
	Entry		*entry,
	int		psearch_type )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int		rc;
	const char *text = NULL;
	time_t		stoptime;
	unsigned	cursor;
	ID		id;
	ID		candidates[BDB_IDL_UM_SIZE];
	Entry		*e = NULL;
	BerVarray v2refs = NULL;
	Entry	*matched = NULL;
	struct berval	realbase = { 0, NULL };
	int		nentries = 0;
	int		manageDSAit;

	Filter lcupf, csnfnot, csnfeq, csnfand, csnfge;
	AttributeAssertion aa_ge, aa_eq;
	struct berval entrycsn_bv = { 0, NULL };
	struct berval latest_entrycsn_bv = { 0, NULL };

	struct slap_limits_set *limit = NULL;
	int isroot = 0;
	int scopeok = 0;

#ifdef SLAP_X_FILTER_HASSUBORDINATES
	int		filter_hasSubordinates = 0;
	Attribute	*hasSubordinates = NULL;
#endif /* SLAP_X_FILTER_HASSUBORDINATES */

	u_int32_t	locker;
	DB_LOCK		lock;

	Connection	*ps_conn   = ps_op->o_conn;
	struct berval	*base      = LDAP_LIST_FIRST(&ps_op->psearch_spec)->base;
	struct berval	*nbase     = LDAP_LIST_FIRST(&ps_op->psearch_spec)->nbase;
	int		scope      = LDAP_LIST_FIRST(&ps_op->psearch_spec)->scope;
	int		deref      = LDAP_LIST_FIRST(&ps_op->psearch_spec)->deref;
	int		slimit     = LDAP_LIST_FIRST(&ps_op->psearch_spec)->slimit;
	int		tlimit     = LDAP_LIST_FIRST(&ps_op->psearch_spec)->tlimit;
	Filter		*filter    = LDAP_LIST_FIRST(&ps_op->psearch_spec)->filter;
	struct berval	*filterstr = LDAP_LIST_FIRST(&ps_op->psearch_spec)->filterstr;
	int		attrsonly  = LDAP_LIST_FIRST(&ps_op->psearch_spec)->attrsonly;
	AttributeName	*attrs;

	if ( psearch_type != LCUP_PSEARCH_BY_DELETE &&
				psearch_type != LCUP_PSEARCH_BY_SCOPEOUT ) {
		attrs     = LDAP_LIST_FIRST(&ps_op->psearch_spec)->attrs;
	} else {
		attrs     = uuid_attr;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "bdb_back_search\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "=> bdb_back_search\n",
		0, 0, 0);
#endif

	manageDSAit = get_manageDSAit( ps_op );

	rc = LOCK_ID (bdb->bi_dbenv, &locker );
	switch(rc) {
	case 0:
		break;
	default:
		send_ldap_result( ps_conn, ps_op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		return rc;
	}

	if ( nbase->bv_len == 0 ) {
		/* DIT root special case */
		e = (Entry *) &slap_entry_root;
		rc = 0;
	} else						
#ifdef BDB_ALIASES
	/* get entry with reader lock */
	if ( deref & LDAP_DEREF_FINDING ) {
		e = deref_dn_r( be, nbase-, &err, &matched, &text );

	} else
#endif
	{
dn2entry_retry:
		rc = bdb_dn2entry_r( be, NULL, nbase, &e, &matched, 0, locker, &lock );
	}

	switch(rc) {
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
		send_ldap_result( ps_conn, ps_op, LDAP_BUSY,
			NULL, "ldap server busy", NULL, NULL );
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
		send_ldap_result( ps_conn, ps_op, rc=LDAP_OTHER,
			NULL, "internal error", NULL, NULL );
		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		return rc;
	}

	if ( e == NULL ) {
		struct berval matched_dn = { 0, NULL };
		BerVarray refs = NULL;

		if ( matched != NULL ) {
			BerVarray erefs;
			ber_dupbv( &matched_dn, &matched->e_name );

			erefs = is_entry_referral( matched )
				? get_entry_referrals( be, ps_conn, ps_op, matched )
				: NULL;

			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache, matched, &lock);
			matched = NULL;

			if( erefs ) {
				refs = referral_rewrite( erefs, &matched_dn,
					base, scope );
				ber_bvarray_free( erefs );
			}

		} else {
			refs = referral_rewrite( default_referral,
				NULL, base, scope );
		}

		send_ldap_result( ps_conn, ps_op,	rc=LDAP_REFERRAL ,
			matched_dn.bv_val, text, refs, NULL );

		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		if ( refs ) ber_bvarray_free( refs );
		if ( matched_dn.bv_val ) ber_memfree( matched_dn.bv_val );
		return rc;
	}

	if (!manageDSAit && e != &slap_entry_root && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		struct berval matched_dn;
		BerVarray erefs, refs;
		
		ber_dupbv( &matched_dn, &e->e_name );
		erefs = get_entry_referrals( be, ps_conn, ps_op, e );
		refs = NULL;

		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
		e = NULL;

		if( erefs ) {
			refs = referral_rewrite( erefs, &matched_dn,
				base, scope );
			ber_bvarray_free( erefs );
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"bdb_search: entry is referral\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "bdb_search: entry is referral\n",
			0, 0, 0 );
#endif

		send_ldap_result( ps_conn, ps_op, LDAP_REFERRAL,
			matched_dn.bv_val,
			refs ? NULL : "bad referral object",
			refs, NULL );

		LOCK_ID_FREE (bdb->bi_dbenv, locker );
		ber_bvarray_free( refs );
		ber_memfree( matched_dn.bv_val );
		return 1;
	}

	/* if not root, get appropriate limits */
	if ( be_isroot( be, &ps_op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, &ps_op->o_ndn, &limit );
	}

	/* The time/size limits come first because they require very little
	 * effort, so there's no chance the candidates are selected and then 
	 * the request is not honored only because of time/size constraints */

	/* if no time limit requested, use soft limit (unless root!) */
	if ( isroot ) {
		if ( tlimit == 0 ) {
			tlimit = -1;	/* allow root to set no limit */
		}

		if ( slimit == 0 ) {
			slimit = -1;
		}

	} else {
		/* if no limit is required, use soft limit */
		if ( tlimit <= 0 ) {
			tlimit = limit->lms_t_soft;

		/* if requested limit higher than hard limit, abort */
		} else if ( tlimit > limit->lms_t_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_t_hard == 0 && tlimit > limit->lms_t_soft ) {
				tlimit = limit->lms_t_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_t_hard > 0 ) {
				send_search_result( ps_conn, ps_op, 
						LDAP_UNWILLING_TO_PERFORM,
						NULL, NULL, NULL, NULL, 0 );
				rc = 0;
				goto done;
			}
		
			/* negative hard limit means no limit */
		}
		
		/* if no limit is required, use soft limit */
		if ( slimit <= 0 ) {
			slimit = limit->lms_s_soft;

		/* if requested limit higher than hard limit, abort */
		} else if ( slimit > limit->lms_s_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_s_hard == 0 && slimit > limit->lms_s_soft ) {
				slimit = limit->lms_s_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_s_hard > 0 ) {
				send_search_result( ps_conn, ps_op, 
						LDAP_UNWILLING_TO_PERFORM,
						NULL, NULL, NULL, NULL, 0 );
				rc = 0;	
				goto done;
			}
			
			/* negative hard limit means no limit */
		}
	}

	/* compute it anyway; root does not use it */
	stoptime = ps_op->o_time + tlimit;

	/* candidates = { e } */
	candidates[0] = 1;
	candidates[1] = entry->e_id;

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

		send_search_result( ps_conn, ps_op,
			LDAP_SUCCESS,
			NULL, NULL, NULL, NULL, 0 );

		rc = 1;
		goto done;
	}

	/* if not root and candidates exceed to-be-checked entries, abort */
	if ( !isroot && limit->lms_s_unchecked != -1 ) {
		if ( BDB_IDL_N(candidates) > (unsigned) limit->lms_s_unchecked ) {
			send_search_result( ps_conn, ps_op, 
					LDAP_ADMINLIMIT_EXCEEDED,
					NULL, NULL, NULL, NULL, 0 );
			rc = 1;
			goto done;
		}
	}

#ifdef SLAP_X_FILTER_HASSUBORDINATES
	/*
	 * is hasSubordinates used in the filter ?
	 * FIXME: we may compute this directly when parsing the filter
	 */
	filter_hasSubordinates = filter_has_subordinates( filter );
#endif /* SLAP_X_FILTER_HASSUBORDINATES */

	lcupf.f_choice = LDAP_FILTER_AND;
	lcupf.f_and = &csnfnot;
	lcupf.f_next = NULL;

	csnfnot.f_choice = LDAP_FILTER_NOT;
	csnfnot.f_not = &csnfeq;
	csnfnot.f_next = &csnfand;

	csnfeq.f_choice = LDAP_FILTER_EQUALITY;
	csnfeq.f_ava = &aa_eq;
	csnfeq.f_av_desc = slap_schema.si_ad_entryCSN;
	ber_dupbv( &csnfeq.f_av_value, &ps_op->o_clientupdate_state );

	csnfand.f_choice = LDAP_FILTER_AND;
	csnfand.f_and = &csnfge;
	csnfand.f_next = NULL;

	csnfge.f_choice = LDAP_FILTER_GE;
	csnfge.f_ava = &aa_ge;
	csnfge.f_av_desc = slap_schema.si_ad_entryCSN;
	ber_dupbv( &csnfge.f_av_value, &ps_op->o_clientupdate_state );
	csnfge.f_next = filter;

	if ( !BDB_IDL_IS_RANGE( candidates ) ) {
		cursor = bdb_idl_search( candidates, entry->e_id );
		if ( candidates[cursor] != entry->e_id ) {
			rc = LDAP_SUCCESS;
			goto done;
		}
	} else {
		if ( entry->e_id < BDB_IDL_RANGE_FIRST(candidates) &&
		     entry->e_id > BDB_IDL_RANGE_LAST(candidates) ) {
			rc = LDAP_SUCCESS;
			goto done;
		}
	}

	id = entry->e_id;

	/* check for abandon */
	if ( ps_op->o_abandon ) {
		rc = 0;
		goto done;
	}

	/* check time limit */
	if ( tlimit != -1 && slap_get_time() > stoptime ) {
		send_search_result( ps_conn, ps_op, rc = LDAP_TIMELIMIT_EXCEEDED,
			NULL, NULL, v2refs, NULL, nentries );
		goto done;
	}

	e = entry;

#ifdef BDB_SUBENTRIES
	if ( is_entry_subentry( e ) ) {
		if( scope != LDAP_SCOPE_BASE ) {
			if(!get_subentries_visibility( ps_op )) {
				/* only subentries are visible */
				goto test_done;
			}

		} else if ( get_subentries( ps_op ) &&
			!get_subentries_visibility( ps_op ))
		{
			/* only subentries are visible */
			goto test_done;
		}

	} else if ( get_subentries_visibility( ps_op )) {
		/* only subentries are visible */
		goto test_done;
	}
#endif

#ifdef BDB_ALIASES
	if ( deref & LDAP_DEREF_SEARCHING && is_entry_alias( e ) ) {
		Entry *matched;
		int err;
		const char *text;
		
		e = deref_entry_r( be, e, &err, &matched, &text );

		if( e == NULL ) {
			e = matched;
			goto test_done;
		}

		if( e->e_id == id ) {
			/* circular loop */
			goto test_done;
		}

		/* need to skip alias which deref into scope */
		if( scope & LDAP_SCOPE_ONELEVEL ) {
			struct berval	pdn;
			
			dnParent( &e->e_nname, &pdn ):
			if ( ber_bvcmp( pdn, &realbase ) ) {
				goto test_done;
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
			goto test_done;
		}

		scopeok = 1;
	}
#endif

	/*
	 * if it's a referral, add it to the list of referrals. only do
	 * this for non-base searches, and don't check the filter
	 * explicitly here since it's only a candidate anyway.
	 */
	if ( !manageDSAit && scope != LDAP_SCOPE_BASE &&
		is_entry_referral( e ) )
	{
		struct berval	dn;

		/* check scope */
		if ( !scopeok && scope == LDAP_SCOPE_ONELEVEL ) {
			if ( !be_issuffix( be, &e->e_nname ) ) {
				dnParent( &e->e_nname, &dn );
				scopeok = dn_match( &dn, &realbase );
			} else {
				scopeok = (realbase.bv_len == 0);
			}

		} else if ( !scopeok && scope == LDAP_SCOPE_SUBTREE ) {
			scopeok = dnIsSuffix( &e->e_nname, &realbase );

		} else {
			scopeok = 1;
		}

		if( scopeok ) {
			BerVarray erefs = get_entry_referrals(
				be, ps_conn, ps_op, e );
			BerVarray refs = referral_rewrite( erefs,
				&e->e_name, NULL,
				scope == LDAP_SCOPE_SUBTREE
					? LDAP_SCOPE_SUBTREE
					: LDAP_SCOPE_BASE );

			send_search_reference( be, ps_conn, ps_op,
				e, refs, NULL, &v2refs );

			ber_bvarray_free( refs );

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

		goto test_done;
	}

#ifdef SLAP_X_FILTER_HASSUBORDINATES
	/*
	 * if hasSubordinates is used in the filter,
	 * append it to the entry's attributes
	 */
	if ( filter_hasSubordinates ) {
		int	hs;

		rc = bdb_hasSubordinates( be, ps_conn, ps_op, e, &hs);
		if ( rc != LDAP_SUCCESS ) {
			goto test_done;
		}

		hasSubordinates = slap_operational_hasSubordinate(
			hs == LDAP_COMPARE_TRUE );

		if ( hasSubordinates == NULL ) {
			goto test_done;
		}

		hasSubordinates->a_next = e->e_attrs;
		e->e_attrs = hasSubordinates;
	}
#endif /* SLAP_X_FILTER_HASSUBORDINATES */

	if ( psearch_type != LCUP_PSEARCH_BY_SCOPEOUT ) {
		rc = test_filter( be, ps_conn, ps_op, e, &lcupf );
	} else {
		rc = LDAP_COMPARE_TRUE;
	}

#ifdef SLAP_X_FILTER_HASSUBORDINATES
	if ( hasSubordinates ) {
		/*
		 * FIXME: this is fairly inefficient, because 
		 * if hasSubordinates is among the required
		 * attrs, it will be added again later;
		 * maybe we should leave it and check
		 * check later if it's already present,
		 * if required
		 */
		e->e_attrs = e->e_attrs->a_next;
		attr_free( hasSubordinates );
	}
#endif /* SLAP_X_FILTER_HASSUBORDINATES */

	if ( rc == LDAP_COMPARE_TRUE ) {
		struct berval	dn;

		/* check scope */
		if ( !scopeok && scope == LDAP_SCOPE_ONELEVEL ) {
			if ( be_issuffix( be, &e->e_nname ) ) {
				scopeok = (realbase.bv_len == 0);
			} else {
				dnParent( &e->e_nname, &dn );
				scopeok = dn_match( &dn, &realbase );
			}

		} else if ( !scopeok && scope == LDAP_SCOPE_SUBTREE ) {
			scopeok = dnIsSuffix( &e->e_nname, &realbase );

		} else {
			scopeok = 1;
		}

		if ( scopeok ) {
			/* check size limit */
			if ( --slimit == -1 ) {
				send_search_result( ps_conn, ps_op,
					rc = LDAP_SIZELIMIT_EXCEEDED, NULL, NULL,
					v2refs, NULL, nentries );
				goto done;
			}

			if (e) {
				int result;
				
#if 0	/* noop is masked SLAP_CTRL_UPDATE */
				if( ps_op->o_noop ) {
					result = 0;
				} else
#endif
				{
					if ( psearch_type == LCUP_PSEARCH_BY_ADD ||
					     psearch_type == LCUP_PSEARCH_BY_DELETE ||
					     psearch_type == LCUP_PSEARCH_BY_MODIFY ||
					     psearch_type == LCUP_PSEARCH_BY_SCOPEOUT ) {
						Attribute* a;
						int ret;
						int res;
						const char *text = NULL;
						LDAPControl *ctrls[2];
						struct berval *bv;

						BerElement *ber = ber_alloc_t( LBER_USE_DER );

						if ( ber == NULL ) {
#ifdef NEW_LOGGING
							LDAP_LOG ( OPERATION, RESULTS, 
								"bdb_search: ber_alloc_t failed\n",
								0, 0, 0 );
#else
							Debug( LDAP_DEBUG_TRACE,
								"bdb_search: ber_alloc_t failed\n",
								0, 0, 0 );
#endif
							send_ldap_result( ps_conn, ps_op, rc=LDAP_OTHER,
								NULL, "internal error", NULL, NULL );
							goto done;
						}

						LDAP_LIST_FIRST(&ps_op->psearch_spec)->entry_count++;

						ctrls[0] = ch_malloc ( sizeof ( LDAPControl ) );
						ctrls[1] = NULL;

						if ( LDAP_LIST_FIRST(&ps_op->psearch_spec)->entry_count % ps_op->o_clientupdate_interval == 0 ) {
							/* Send cookie */
							for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
								AttributeDescription *desc = a->a_desc;
								if ( desc == slap_schema.si_ad_entryCSN ) {
									ber_dupbv( &entrycsn_bv, &a->a_vals[0] );
									if ( latest_entrycsn_bv.bv_val == NULL ) {
										ber_dupbv( &latest_entrycsn_bv, &entrycsn_bv );
									} else {
										res = value_match( &ret, desc,
											desc->ad_type->sat_ordering,
											SLAP_MR_ASSERTION_SYNTAX_MATCH,
											&entrycsn_bv, &latest_entrycsn_bv, &text );
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
											ch_free( latest_entrycsn_bv.bv_val );
											latest_entrycsn_bv.bv_val = NULL;
											ber_dupbv( &latest_entrycsn_bv,
												&entrycsn_bv );
										}
									}
								}
							}

							if ( psearch_type != LCUP_PSEARCH_BY_DELETE || psearch_type != LCUP_PSEARCH_BY_SCOPEOUT ) {
								ber_printf( ber,
									"{bb{sON}N}",
									SLAP_LCUP_STATE_UPDATE_FALSE,
									SLAP_LCUP_ENTRY_DELETED_FALSE,
									LCUP_COOKIE_OID, &entrycsn_bv );
							} else {
								ber_printf( ber,
									"{bb{sON}N}",
									SLAP_LCUP_STATE_UPDATE_FALSE,
									SLAP_LCUP_ENTRY_DELETED_TRUE,
									LCUP_COOKIE_OID, &entrycsn_bv );
							}

							ch_free( entrycsn_bv.bv_val );
							entrycsn_bv.bv_val = NULL;

						} else {
							/* Do not send cookie */
							if ( psearch_type != LCUP_PSEARCH_BY_DELETE || psearch_type != LCUP_PSEARCH_BY_SCOPEOUT ) {
								ber_printf( ber,
									"{bbN}",
									SLAP_LCUP_STATE_UPDATE_FALSE,
									SLAP_LCUP_ENTRY_DELETED_FALSE );
							} else {
								ber_printf( ber,
									"{bbN}",
									SLAP_LCUP_STATE_UPDATE_FALSE,
									SLAP_LCUP_ENTRY_DELETED_TRUE );
							}
						}

						ctrls[0]->ldctl_oid = LDAP_CONTROL_ENTRY_UPDATE;
						ctrls[0]->ldctl_iscritical = ps_op->o_clientupdate;
						ret = ber_flatten( ber, &bv );

						if ( ret < 0 ) {
#ifdef NEW_LOGGING
							LDAP_LOG ( OPERATION, RESULTS, 
								"bdb_search: ber_flatten failed\n",
								0, 0, 0 );
#else
							Debug( LDAP_DEBUG_TRACE,
								"bdb_search: ber_flatten failed\n",
								0, 0, 0 );
#endif
							send_ldap_result( ps_conn, ps_op, rc=LDAP_OTHER,
								NULL, "internal error", NULL, NULL );
							goto done;
						}

						ber_dupbv( &ctrls[0]->ldctl_value, bv );
						
						result = send_search_entry( be, ps_conn, ps_op,
							e, attrs, attrsonly, ctrls);

						ch_free( ctrls[0]->ldctl_value.bv_val );
						ch_free( ctrls[0] );
						ber_free( ber, 1 );
						ber_bvfree( bv );

						if ( psearch_type == LCUP_PSEARCH_BY_MODIFY ) {
							struct psid_entry* psid_e;
							LDAP_LIST_FOREACH( psid_e, &op->premodify_list, link) {
								if (psid_e->ps == LDAP_LIST_FIRST(&ps_op->psearch_spec)) {
									LDAP_LIST_REMOVE(psid_e, link);
									break;
								}
							}
							if (psid_e != NULL) 
								free (psid_e);
						}
					} else if ( psearch_type == LCUP_PSEARCH_BY_PREMODIFY ) {
						struct psid_entry* psid_e;
						psid_e = (struct psid_entry *) calloc (1, sizeof (struct psid_entry));
						psid_e->ps = LDAP_LIST_FIRST(&ps_op->psearch_spec);
						LDAP_LIST_INSERT_HEAD( &op->premodify_list, psid_e, link );
					}
					else
					{
						printf("Error !\n");
					}
				}

				switch (result) {
				case 0:		/* entry sent ok */
					nentries++;
					break;
				case 1:		/* entry not sent */
					break;
				case -1:	/* connection closed */
					rc = LDAP_OTHER;
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
			"bdb_search: %ld does match filter\n", (long) id, 0, 0);
#else
		Debug( LDAP_DEBUG_TRACE,
			"bdb_search: %ld does match filter\n",
			(long) id, 0, 0 );
#endif
	}

test_done:
	rc = LDAP_SUCCESS;

done:
	if ( csnfeq.f_ava != NULL && csnfeq.f_av_value.bv_val != NULL ) {
		ch_free( csnfeq.f_av_value.bv_val );
	}
	
	if ( csnfge.f_ava != NULL && csnfge.f_av_value.bv_val != NULL ) {
		ch_free( csnfge.f_av_value.bv_val );
	}

	LOCK_ID_FREE (bdb->bi_dbenv, locker );

	if( v2refs ) ber_bvarray_free( v2refs );
	if( realbase.bv_val ) ch_free( realbase.bv_val );

	return rc;
}

#endif /* LDAP_CLIENT_UPDATE */
