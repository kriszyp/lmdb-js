/* search.c - ldbm backend search function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
	Backend *be, Entry *e, Filter *filter,
	int scope, int deref, int manageDSAit );


int
ldbm_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*base,
    const char	*nbase,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    const char	*filterstr,
    char	**attrs,
    int		attrsonly )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int		rc, err;
	const char *text = NULL;
	time_t		stoptime;
	ID_BLOCK		*candidates;
	ID		id, cursor;
	Entry		*e;
	struct berval **v2refs = NULL;
	Entry	*matched = NULL;
	char	*realbase = NULL;
	int		nentries = 0;
	int		manageDSAit = get_manageDSAit( op );
	int		cscope = LDAP_SCOPE_DEFAULT;

	struct slap_limits_set *limit = NULL;
	int isroot = 0;
		
#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "ldbm_back_search: enter\n" ));
#else
	Debug(LDAP_DEBUG_TRACE, "=> ldbm_back_search\n", 0, 0, 0);
#endif


	if ( *nbase == '\0' ) {
		/* DIT root special case */
		static const Entry root = { NOID, "", "", NULL, NULL };
		e = (Entry *) &root;

		/* need normalized dn below */
		realbase = ch_strdup( e->e_ndn );

		candidates = search_candidates( be, e, filter,
		    scope, deref, manageDSAit );

		goto searchit;
		
	} else if ( deref & LDAP_DEREF_FINDING ) {
		/* deref dn and get entry with reader lock */
		e = deref_dn_r( be, nbase, &err, &matched, &text );

		if( err == LDAP_NO_SUCH_OBJECT ) err = LDAP_REFERRAL;

	} else {
		/* get entry with reader lock */
		e = dn2entry_r( be, nbase, &matched );
		err = e != NULL ? LDAP_SUCCESS : LDAP_REFERRAL;
		text = NULL;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			struct berval **erefs;
			matched_dn = ch_strdup( matched->e_dn );

			erefs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched,
					base, scope )
				: NULL;

			cache_return_entry_r( &li->li_cache, matched );

			if( erefs ) {
				refs = referral_rewrite( erefs, matched_dn,
					base, scope );

				ber_bvecfree( erefs );
			}

		} else {
			refs = referral_rewrite( default_referral,
				NULL, base, scope );
		}

		send_ldap_result( conn, op, err,
			matched_dn, text, refs, NULL );

		ber_bvecfree( refs );
		free( matched_dn );
		return 1;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		char *matched_dn = ch_strdup( e->e_dn );
		struct berval **erefs = get_entry_referrals( be,
			conn, op, e, base, scope );
		struct berval **refs = NULL;

		cache_return_entry_r( &li->li_cache, e );

#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			"ldbm_search: entry (%s) is a referral.\n",
			e->e_dn ));
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldbm_search: entry is referral\n",
			0, 0, 0 );
#endif

		if( erefs ) {
			refs = referral_rewrite( erefs, matched_dn,
				base, scope );

			ber_bvecfree( erefs );
		}

		if( refs ) {
			send_ldap_result( conn, op, LDAP_REFERRAL,
				matched_dn, NULL, refs, NULL );
			ber_bvecfree( refs );

		} else {
			send_ldap_result( conn, op, LDAP_OTHER, matched_dn,
				"bad referral object", NULL, NULL );
		}

		free( matched_dn );
		return 1;
	}

	if ( is_entry_alias( e ) ) {
		/* don't deref */
		deref = LDAP_DEREF_NEVER;
	}

	if ( scope == LDAP_SCOPE_BASE ) {
		cscope = LDAP_SCOPE_BASE;
		candidates = base_candidate( be, e );

	} else {
		cscope = ( scope != LDAP_SCOPE_SUBTREE )
			? LDAP_SCOPE_BASE : LDAP_SCOPE_SUBTREE;
		candidates = search_candidates( be, e, filter,
		    scope, deref, manageDSAit );
	}

	/* need normalized dn below */
	realbase = ch_strdup( e->e_ndn );

	cache_return_entry_r( &li->li_cache, e );

searchit:
	if ( candidates == NULL ) {
		/* no candidates */
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
			"ldbm_search: no candidates\n" ));
#else
		Debug( LDAP_DEBUG_TRACE, "ldbm_search: no candidates\n",
			0, 0, 0 );
#endif

		send_search_result( conn, op,
			LDAP_SUCCESS,
			NULL, NULL, NULL, NULL, 0 );

		rc = 1;
		goto done;
	}

	/* if not root, get appropriate limits */
	if ( be_isroot( be, op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, op->o_ndn, &limit );
	}

	/* if candidates exceed to-be-checked entries, abort */
	if ( !isroot && limit->lms_s_unchecked != -1 ) {
		if ( ID_BLOCK_NIDS( candidates ) > limit->lms_s_unchecked ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto done;
		}
	}
	
	/* if no time limit requested, use soft limit (unless root!) */
	if ( tlimit <= 0 ) {
		if ( isroot ) {
			tlimit = -1;	/* allow root to set no limit */
		} else {
			tlimit = limit->lms_t_soft;
		}
		
	/* if requested limit higher than hard limit, abort */
	} else if ( tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0 ) {
			tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0; 
			goto done;
		}

		/* negative hard limit means no limit */
	}

	/* compute it anyway; root does not use it */
	stoptime = op->o_time + tlimit;

	/* if no size limit requested, use soft limit (unless root!) */
	if ( slimit == 0 ) {
		if ( isroot ) {
			slimit = -1;	/* allow root to set no limit */
		} else {
			slimit = limit->lms_s_soft;
		}
	
	/* if requested limit higher than hard limit, abort */
	} else if ( slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0 ) {
			slimit = limit->lms_s_soft;

		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto done;
		}

		/* negative hard limit means no limit */
	}

	for ( id = idl_firstid( candidates, &cursor ); id != NOID;
	    id = idl_nextid( candidates, &cursor ) )
	{
		int scopeok = 0;

		/* check for abandon */
		ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );

		if ( op->o_abandon ) {
			ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );
			rc = 0;
			goto done;
		}

		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

		/* check time limit */
		if ( tlimit != -1 && slap_get_time() > stoptime ) {
			send_search_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			rc = 0;
			goto done;
		}

		/* get the entry with reader lock */
		e = id2entry_r( be, id );

		if ( e == NULL ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_INFO,
				"ldbm_search: candidate %ld not found.\n", id ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_search: candidate %ld not found\n",
				id, 0, 0 );
#endif

			goto loop_continue;
		}

		if ( deref & LDAP_DEREF_SEARCHING && is_entry_alias( e ) ) {
			Entry *matched;
			int err;
			const char *text;
			
			e = deref_entry_r( be, e, &err, &matched, &text );

			if( e == NULL ) {
				e = matched;
				goto loop_continue;
			}

			if( e->e_id == id ) {
				/* circular loop */
				goto loop_continue;
			}

			/* need to skip alias which deref into scope */
			if( scope & LDAP_SCOPE_ONELEVEL ) {
				char *pdn = dn_parent( NULL, e->e_ndn );
				if ( pdn != NULL ) {
					if( strcmp( pdn, realbase ) ) {
						free( pdn );
						goto loop_continue;
					}
					free(pdn);
				}

			} else if ( dn_issuffix( e->e_ndn, realbase ) ) {
				/* alias is within scope */
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
					"ldbm_search: alias \"%s\" in subtree\n", e->e_dn ));
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: alias \"%s\" in subtree\n",
					e->e_dn, 0, 0 );
#endif

				goto loop_continue;
			}

			scopeok = 1;
		}

		/*
		 * if it's a referral, add it to the list of referrals. only do
		 * this for non-base searches, and don't check the filter
		 * explicitly here since it's only a candidate anyway.
		 */
		if ( !manageDSAit && scope != LDAP_SCOPE_BASE &&
			is_entry_referral( e ) )
		{
			char	*dn;

			/* check scope */
			if ( !scopeok && scope == LDAP_SCOPE_ONELEVEL ) {
				if ( (dn = dn_parent( be, e->e_ndn )) != NULL ) {
					(void) dn_normalize( dn );
					scopeok = (dn == realbase)
						? 1
						: (strcmp( dn, realbase ) ? 0 : 1 );
					free( dn );

				} else {
					scopeok = (realbase == NULL || *realbase == '\0');
				}

			} else if ( !scopeok && scope == LDAP_SCOPE_SUBTREE ) {
				dn = ch_strdup( e->e_ndn );
				scopeok = dn_issuffix( dn, realbase );
				free( dn );

			} else {
				scopeok = 1;
			}

			if( scopeok ) {
				struct berval **erefs = get_entry_referrals(
					be, conn, op, e, NULL, cscope );
				struct berval **refs = referral_rewrite( erefs, e->e_dn,
					NULL, scope );

				send_search_reference( be, conn, op,
					e, refs, NULL, &v2refs );

				ber_bvecfree( refs );

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL2,
					"ldbm_search: candidate referral %ld scope not okay\n",
					id ));
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: candidate referral %ld scope not okay\n",
					id, 0, 0 );
#endif
			}

			goto loop_continue;
		}

		/* if it matches the filter and scope, send it */
		if ( test_filter( be, conn, op, e, filter ) == LDAP_COMPARE_TRUE ) {
			char	*dn;

			/* check scope */
			if ( !scopeok && scope == LDAP_SCOPE_ONELEVEL ) {
				if ( (dn = dn_parent( be, e->e_ndn )) != NULL ) {
					(void) dn_normalize( dn );
					scopeok = (dn == realbase)
						? 1
						: (strcmp( dn, realbase ) ? 0 : 1 );
					free( dn );

				} else {
					scopeok = (realbase == NULL || *realbase == '\0');
				}

			} else if ( !scopeok && scope == LDAP_SCOPE_SUBTREE ) {
				dn = ch_strdup( e->e_ndn );
				scopeok = dn_issuffix( dn, realbase );
				free( dn );

			} else {
				scopeok = 1;
			}

			if ( scopeok ) {
				/* check size limit */
				if ( --slimit == -1 ) {
					cache_return_entry_r( &li->li_cache, e );
					send_search_result( conn, op,
						LDAP_SIZELIMIT_EXCEEDED, NULL, NULL,
						v2refs, NULL, nentries );
					rc = 0;
					goto done;
				}

				if (e) {
					int result = send_search_entry(be, conn, op,
						e, attrs, attrsonly, NULL);

					switch (result) {
					case 0:		/* entry sent ok */
						nentries++;
						break;
					case 1:		/* entry not sent */
						break;
					case -1:	/* connection closed */
						cache_return_entry_r( &li->li_cache, e );
						rc = 0;
						goto done;
					}
				}
			} else {
#ifdef NEW_LOGGING
				LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL2,
					"ldbm_search: candidate entry %ld scope not okay\n", id ));
#else
				Debug( LDAP_DEBUG_TRACE,
					"ldbm_search: candidate entry %ld scope not okay\n",
					id, 0, 0 );
#endif
			}

		} else {
#ifdef NEW_LOGGING
			LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL2,
				"ldbm_search: candidate entry %ld does not match filter\n", id ));
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldbm_search: candidate entry %ld does not match filter\n",
				id, 0, 0 );
#endif
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			cache_return_entry_r( &li->li_cache, e );
		}

		ldap_pvt_thread_yield();
	}

	send_search_result( conn, op,
		v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
		NULL, NULL, v2refs, NULL, nentries );

	rc = 0;

done:
	if( candidates != NULL )
		idl_free( candidates );

	ber_bvecfree( v2refs );
	if( realbase ) free( realbase );

	return rc;
}

static ID_BLOCK *
base_candidate(
    Backend	*be,
	Entry	*e )
{
	ID_BLOCK		*idl;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "base_candidate: base (%s)\n", e->e_dn ));
#else
	Debug(LDAP_DEBUG_TRACE, "base_candidates: base: \"%s\"\n",
		e->e_dn, 0, 0);
#endif


	idl = idl_alloc( 1 );
	idl_insert( &idl, e->e_id, 1 );

	return( idl );
}

static ID_BLOCK *
search_candidates(
    Backend	*be,
    Entry	*e,
    Filter	*filter,
    int		scope,
	int		deref,
	int		manageDSAit )
{
	ID_BLOCK		*candidates;
	Filter		f, fand, rf, af, xf;
    AttributeAssertion aa_ref, aa_alias;
	static struct berval bv_ref = { sizeof("REFERRAL")-1, "REFERRAL" };
	static struct berval bv_alias = { sizeof("ALIAS")-1, "ALIAS" };

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
		   "search_candidates: base (%s) scope %d deref %d\n",
		   e->e_ndn, scope, deref ));
#else
	Debug(LDAP_DEBUG_TRACE,
		"search_candidates: base=\"%s\" s=%d d=%d\n",
		e->e_ndn, scope, deref );
#endif


	xf.f_or = filter;
	xf.f_choice = LDAP_FILTER_OR;
	xf.f_next = NULL;

	if( !manageDSAit ) {
		/* match referrals */
		rf.f_choice = LDAP_FILTER_EQUALITY;
		rf.f_ava = &aa_ref;
		rf.f_av_desc = slap_schema.si_ad_objectClass;
		rf.f_av_value = &bv_ref;
		rf.f_next = xf.f_or;
		xf.f_or = &rf;
	}

	if( deref & LDAP_DEREF_SEARCHING ) {
		/* match aliases */
		af.f_choice = LDAP_FILTER_EQUALITY;
		af.f_ava = &aa_alias;
		af.f_av_desc = slap_schema.si_ad_objectClass;
		af.f_av_value = &bv_alias;
		af.f_next = xf.f_or;
		xf.f_or = &af;
	}

	f.f_next = NULL;
	f.f_choice = LDAP_FILTER_AND;
	f.f_and = &fand;
	fand.f_choice = scope == LDAP_SCOPE_SUBTREE
		? SLAPD_FILTER_DN_SUBTREE
		: SLAPD_FILTER_DN_ONE;
	fand.f_dn = e->e_ndn;
	fand.f_next = xf.f_or == filter ? filter : &xf ;

	candidates = filter_candidates( be, &f );

	return( candidates );
}
