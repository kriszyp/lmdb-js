/* search.c - search operation */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

static int base_candidate(
    BackendDB	*be,
	Entry	*e,
	ID		*ids );
static int search_candidates(
	BackendDB *be,
	Entry *e,
	Filter *filter,
    int scope,
	int deref,
	int manageDSAit,
	ID	*ids );

static ID idl_first( ID *ids, ID *cursor );
static ID idl_next( ID *ids, ID *cursor );

int
bdb_search(
    BackendDB	*be,
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
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	int		 abandon;
	int		rc;
	const char *text = NULL;
	time_t		stoptime;
	ID		id, cursor;
	ID		candidates[BDB_IDL_SIZE];
	Entry		*e = NULL;
	struct berval **v2refs = NULL;
	Entry	*matched = NULL;
	char	*realbase = NULL;
	int		nentries = 0;
	int		manageDSAit;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_back_search\n",
		0, 0, 0);

	manageDSAit = get_manageDSAit( op );

#ifdef BDB_ALIASES
	/* get entry with reader lock */
	if ( deref & LDAP_DEREF_FINDING ) {
		e = deref_dn_r( be, nbase, &err, &matched, &text );

	} else
#endif
	{
		/* obtain entry */
		rc = dn2entry_r( be, NULL, nbase, &e, &matched );
	}

	switch(rc) {
	case DB_NOTFOUND:
	case 0:
		break;
	default:
		send_ldap_result( conn, op, rc=LDAP_OTHER,
		    NULL, "internal error", NULL, NULL );
		return rc;
	}

	if ( e == NULL ) {
		char *matched_dn = NULL;
		struct berval **refs = NULL;

		if ( matched != NULL ) {
			matched_dn = ch_strdup( matched->e_dn );

			refs = is_entry_referral( matched )
				? get_entry_referrals( be, conn, op, matched )
				: NULL;

		} else {
			refs = default_referral;
		}

		send_ldap_result( conn, op,	rc=LDAP_REFERRAL ,
			matched_dn, text, refs, NULL );

		if( matched != NULL ) {
			ber_bvecfree( refs );
			free( matched_dn );
			bdb_entry_return( be, matched );
		}

		return rc;
	}

	if (!manageDSAit && is_entry_referral( e ) ) {
		/* entry is a referral, don't allow add */
		char *matched_dn = ch_strdup( e->e_dn );
		struct berval **refs = get_entry_referrals( be,
			conn, op, e );

		bdb_entry_return( be, e );

		Debug( LDAP_DEBUG_TRACE, "bdb_search: entry is referral\n",
			0, 0, 0 );

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

	if ( scope == LDAP_SCOPE_BASE ) {
		rc = base_candidate( be, e, candidates );

	} else {
		rc = search_candidates( be, e, filter,
		    scope, deref, manageDSAit, candidates );
	}

	/* need normalized dn below */
	realbase = ch_strdup( e->e_ndn );

	/* start cursor at base entry's id */
	cursor = e->e_id;

	bdb_entry_return( be, e );

	if ( candidates[0] == 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb_search: no candidates\n",
			0, 0, 0 );

		send_search_result( conn, op,
			LDAP_SUCCESS,
			NULL, NULL, NULL, NULL, 0 );

		rc = 1;
		goto done;
	}

	for ( id = idl_first( candidates, &cursor );
		id != NOID;
	    id = idl_next( candidates, &cursor ) )
	{
		int		scopeok = 0;

		/* check for abandon */
		ldap_pvt_thread_mutex_lock( &op->o_abandonmutex );
		abandon = op->o_abandon;
		ldap_pvt_thread_mutex_unlock( &op->o_abandonmutex );

		if ( abandon ) {
			rc = 0;
			goto done;
		}

		/* check time limit */
		if ( tlimit != -1 && slap_get_time() > stoptime ) {
			send_search_result( conn, op, rc = LDAP_TIMELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			goto done;
		}

		/* get the entry with reader lock */
		rc = bdb_id2entry( be, NULL, id, &e );

		if ( e == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_search: candidate %ld not found\n",
				id, 0, 0 );

			goto loop_continue;
		}

#ifdef BDB_ALIASES
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
				Debug( LDAP_DEBUG_TRACE,
					"bdb_search: \"%s\" in subtree\n",
					e->e_dn, 0, 0 );
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
		rc = test_filter( be, conn, op, e, filter );
		if ( rc == LDAP_COMPARE_TRUE ) {
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
					bdb_entry_return( be, e );
					send_search_result( conn, op,
						rc = LDAP_SIZELIMIT_EXCEEDED, NULL, NULL,
						v2refs, NULL, nentries );
					goto done;
				}

				if (e) {
					int result = send_search_entry( be, conn, op,
						e, attrs, attrsonly, NULL);

					switch (result) {
					case 0:		/* entry sent ok */
						nentries++;
						break;
					case 1:		/* entry not sent */
						break;
					case -1:	/* connection closed */
						bdb_entry_return( be, e );
						rc = LDAP_OTHER;
						goto done;
					}
				}
			} else {
				Debug( LDAP_DEBUG_TRACE,
					"bdb_search: %ld scope not okay\n",
					id, 0, 0 );
			}
		} else {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_search: %ld does match filter\n",
				id, 0, 0 );
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			bdb_entry_return( be, e );
		}

		ldap_pvt_thread_yield();
	}
	send_search_result( conn, op,
		v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
		NULL, NULL, v2refs, NULL, nentries );

	rc = 0;

done:
	ber_bvecfree( v2refs );
	if( realbase ) ch_free( realbase );

	return rc;
}


static int base_candidate(
    BackendDB	*be,
	Entry	*e,
	ID		*ids )
{
	Debug(LDAP_DEBUG_ARGS, "base_candidates: base: \"%s\" (0x%08lx)\n",
		e->e_dn, (long) e->e_id, 0);

	ids[0] = 1;
	ids[1] = e->e_id;
	return 0;
}

static int search_candidates(
	BackendDB *be,
	Entry *e,
	Filter *filter,
    int scope,
	int deref,
	int manageDSAit,
	ID	*ids )
{
	Debug(LDAP_DEBUG_TRACE, "subtree_candidates: base: \"%s\" (0x%08lx)\n",
		e->e_dn, (long) e->e_id, 0);

	ids[0] = NOID;
	return 0;
}

static ID idl_first( ID *ids, ID *cursor )
{
	ID pos;

	if ( ids[0] == 0 ) {
		*cursor = NOID;
		return NOID;
	}

	if ( BDB_IS_ALLIDS( ids ) ) {
		/* XXYYZ: quick hack for testing */
		ids[1] = 100;
		return *cursor;
	}

	pos = bdb_idl_search( ids, *cursor );

	if( pos > ids[0] ) {
		return NOID;
	}

	*cursor = pos;
	return ids[pos];
}

static ID idl_next( ID *ids, ID *cursor )
{
	if ( BDB_IS_ALLIDS( ids ) ) {
		if( ++(*cursor) <= ids[1] ) {
			return *cursor;
		}
		return NOID;
	}

	if ( *cursor < ids[0] ) {
		return ids[(*cursor)++];
	}

	return NOID;
}

