/* search.c - bdb2 backend search function */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"

static ID_BLOCK *base_candidate(
	Backend *be, Entry *e );

static ID_BLOCK *search_candidates(
	Backend *be, Entry *e, Filter *filter,
	int scope, int deref, int manageDSAit );

static int
bdb2i_back_search_internal(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*base,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    char	*filterstr,
    char	**attrs,
    int		attrsonly
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int		rc, err;
	char *text;
	time_t		stoptime;
	ID_BLOCK		*candidates;
	ID		id, cursor;
	Entry		*e;
	struct berval **v2refs = NULL;
	Entry	*matched = NULL;
	char	*realbase = NULL;
	int		nentries = 0;
	int		manageDSAit = get_manageDSAit( op );

	Debug(LDAP_DEBUG_TRACE, "=> bdb2_back_search\n", 0, 0, 0);

	/* get entry with reader lock */
	if ( deref & LDAP_DEREF_FINDING ) {
		e = deref_dn_r( be, base, &err, &matched, &text );

	} else {
		e = bdb2i_dn2entry_r( be, base, &matched );
		err = e != NULL ? LDAP_SUCCESS : LDAP_REFERRAL;
		text = NULL;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;

			bdb2i_cache_return_entry_r( &li->li_cache, matched );
		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op, err,
			matched_dn, text, refs, NULL );

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
		}

		return 1;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		char *matched_dn = ch_strdup( e->e_dn );
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		bdb2i_cache_return_entry_r( &li->li_cache, e );

		Debug( LDAP_DEBUG_TRACE, "entry is referral\n", 0,
		    0, 0 );

		send_ldap_result( conn, op, LDAP_REFERRAL,
		    matched_dn, NULL, refs, NULL );

		ber_bvecfree( refs );
		free( matched_dn );

		return 1;
	}

	if ( tlimit == 0 && be_isroot( be, op->o_ndn ) ) {
		tlimit = -1;	/* allow root to set no limit */
	} else {
		tlimit = (tlimit > be->be_timelimit || tlimit < 1) ?
		    be->be_timelimit : tlimit;
		stoptime = op->o_time + tlimit;
	}

	if ( slimit == 0 && be_isroot( be, op->o_ndn ) ) {
		slimit = -1;	/* allow root to set no limit */
	} else {
		slimit = (slimit > be->be_sizelimit || slimit < 1) ?
		    be->be_sizelimit : slimit;
	}

	if ( scope == LDAP_SCOPE_BASE) {
		candidates = base_candidate( be, e );

	} else {
		candidates = search_candidates( be, e, filter,
		    scope, deref, manageDSAit );
	}

	/* need normalized dn below */
	realbase = ch_strdup( e->e_ndn );
	bdb2i_cache_return_entry_r( &li->li_cache, e );

	if ( candidates == NULL ) {
		/* no candidates */
		Debug( LDAP_DEBUG_TRACE, "no candidates\n", 0,
		    0, 0 );

		send_search_result( conn, op,
			LDAP_SUCCESS,
			NULL, NULL, NULL, NULL, 0 );

		rc = 1;
		goto done;
	}

	for ( id = bdb2i_idl_firstid( candidates, &cursor ); id != NOID;
	    id = bdb2i_idl_nextid( candidates, &cursor ) )
	{
		int		scopeok = 0;

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
		e = bdb2i_id2entry_r( be, id );

		if ( e == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "search: candidate %ld not found\n",
				id, 0, 0 );

			goto loop_continue;
		}

		if ( deref & LDAP_DEREF_SEARCHING && is_entry_alias( e ) ) {
			Entry *matched;
			int err;
			char *text;
			
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
				Debug( LDAP_DEBUG_ARGS, "search: \"%s\" in subtree\n",
					e->e_dn, 0, 0 );
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
			struct berval **refs = get_entry_referrals(
				be, conn, op, e );

			send_search_reference( be, conn, op,
				e, refs, scope, NULL, &v2refs );

			ber_bvecfree( refs );

			goto loop_continue;
		}

		/* if it matches the filter and scope, send it */
		if ( test_filter( be, conn, op, e, filter ) == 0 ) {
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
					bdb2i_cache_return_entry_r( &li->li_cache, e );
					send_search_result( conn, op,
						LDAP_SIZELIMIT_EXCEEDED, NULL, NULL,
						v2refs, NULL, nentries );
					rc = 0;
					goto done;
				}

				if (e) {
					switch ( send_search_entry( be, conn, op, e,
						attrs, attrsonly, NULL ) ) {
					case 0:		/* entry sent ok */
						nentries++;
						break;
					case 1:		/* entry not sent */
						break;
					case -1:	/* connection closed */
						bdb2i_cache_return_entry_r( &li->li_cache, e );
						rc = 0;
						goto done;
					}
				}
			} else {
				Debug( LDAP_DEBUG_TRACE, "candidate %ld scope not okay\n",
					id, 0, 0 );
			}
		} else {
			Debug( LDAP_DEBUG_TRACE, "candidate %ld does match filter\n",
				id, 0, 0 );
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			bdb2i_cache_return_entry_r( &li->li_cache, e );
		}

		ldap_pvt_thread_yield();
	}
	send_search_result( conn, op,
		v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
		NULL, NULL, v2refs, NULL, nentries );

	rc = 0;

done:
	bdb2i_idl_free( candidates );

	ber_bvecfree( v2refs );
	if( realbase ) free( realbase );

	return rc;
}


int
bdb2_back_search(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    char	*base,
    char	*nbase,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    char	*filterstr,
    char	**attrs,
    int		attrsonly
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_r( &lock ) != 0 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
			NULL, NULL, NULL, NULL );
		return( -1 );

	}

	ret = bdb2i_back_search_internal( be, conn, op, nbase, scope, deref,
					slimit, tlimit, filter, filterstr, attrs, attrsonly );

	(void) bdb2i_leave_backend_r( lock );
	bdb2i_stop_timing( be->bd_info, time1, "SRCH", conn, op );

	return( ret );
}


static ID_BLOCK *
base_candidate(
    Backend	*be,
	Entry	*e
)
{
	ID_BLOCK		*idl;

	Debug(LDAP_DEBUG_TRACE, "base_candidates: base: \"%s\"\n",
		e->e_dn, 0, 0);

	idl = bdb2i_idl_alloc( 1 );
	bdb2i_idl_insert( &idl, e->e_id, 1 );

	return( idl );
}

static ID_BLOCK *
search_candidates(
    Backend	*be,
    Entry	*e,
    Filter	*filter,
    int		scope,
	int		deref,
	int		manageDSAit
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID_BLOCK		*candidates;
	Filter		*f, *rf, *af, *lf;

	Debug(LDAP_DEBUG_TRACE, "search_candidates: base=\"%s\" s=%d d=%d\n",
		e->e_ndn, scope, deref );

	f = NULL;

	if( !manageDSAit ) {
		/* match referrals */
		rf = (Filter *) ch_malloc( sizeof(Filter) );
		rf->f_next = NULL;
		rf->f_choice = LDAP_FILTER_OR;
		rf->f_or = (Filter *) ch_malloc( sizeof(Filter) );
		rf->f_or->f_choice = LDAP_FILTER_EQUALITY;
		rf->f_or->f_avtype = ch_strdup( "objectclass" );
		rf->f_or->f_avvalue.bv_val = ch_strdup( "REFERRAL" );
		rf->f_or->f_avvalue.bv_len = sizeof("REFERRAL")-1;
		rf->f_or->f_next = filter;
		f = rf;
	} else {
		rf = NULL;
		f = filter;
	}

	if( deref & LDAP_DEREF_SEARCHING ) {
		/* match aliases */
		af = (Filter *) ch_malloc( sizeof(Filter) );
		af->f_next = NULL;
		af->f_choice = LDAP_FILTER_OR;
		af->f_or = (Filter *) ch_malloc( sizeof(Filter) );
		af->f_or->f_choice = LDAP_FILTER_EQUALITY;
		af->f_or->f_avtype = ch_strdup( "objectclass" );
		af->f_or->f_avvalue.bv_val = ch_strdup( "ALIAS" );
		af->f_or->f_avvalue.bv_len = sizeof("ALIAS")-1;
		af->f_or->f_next = f;
		f = af;
	} else {
		af = NULL;
	}

	if ( scope == LDAP_SCOPE_SUBTREE ) {
		lf = (Filter *) ch_malloc( sizeof(Filter) );
		lf->f_next = NULL;
		lf->f_choice = LDAP_FILTER_AND;
		lf->f_and = (Filter *) ch_malloc( sizeof(Filter) );

		lf->f_and->f_choice = SLAPD_FILTER_DN_SUBTREE;
		lf->f_and->f_dn = e->e_ndn;

		lf->f_and->f_next = f;
		f = lf;

	} else if ( scope == LDAP_SCOPE_ONELEVEL ) {
		lf = (Filter *) ch_malloc( sizeof(Filter) );
		lf->f_next = NULL;
		lf->f_choice = LDAP_FILTER_AND;
		lf->f_and = (Filter *) ch_malloc( sizeof(Filter) );

		lf->f_and->f_choice = SLAPD_FILTER_DN_ONE;
		lf->f_and->f_dn = e->e_ndn;

		lf->f_and->f_next = f;
		f = lf;

	} else {
		lf = NULL;
	}

	candidates = bdb2i_filter_candidates( be, f );

	/* free up filter additions we allocated above */
	if( lf != NULL ) {
		free( lf->f_and );
		free( lf );
	}

	if( af != NULL ) {
		af->f_or->f_next = NULL;
		filter_free( af );
	}

	if( rf != NULL ) {
		rf->f_or->f_next = NULL;
		filter_free( rf );
	}

	return( candidates );
}
