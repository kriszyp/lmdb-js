/* search.c - search operation */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2004 The OpenLDAP Foundation.
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
#include "idl.h"

static int base_candidate(
	BackendDB	*be,
	Entry	*e,
	ID		*ids );

static int search_candidates(
	Operation *stackop,	/* op with the current threadctx/slab cache */
	Operation *sop,		/* search op */
	SlapReply *rs,
	Entry *e,
	u_int32_t locker,
	ID	*ids,
	ID	*scopes );

static int parse_paged_cookie( Operation *op, SlapReply *rs );

static void send_paged_response( 
	Operation *op,
	SlapReply *rs,
	ID  *lastid,
	int tentries );

static int bdb_pfid_cmp( const void *v_id1, const void *v_id2 );
static ID* bdb_id_dup( Operation *op, ID *id );

/* Dereference aliases for a single alias entry. Return the final
 * dereferenced entry on success, NULL on any failure.
 */
static Entry * deref_base (
	Operation *op,
	SlapReply *rs,
	Entry *e,
	Entry **matched,
	u_int32_t locker,
	DB_LOCK *lock,
	ID	*tmp,
	ID	*visited )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	struct berval ndn;
	EntryInfo *ei;
	DB_LOCK lockr;

	rs->sr_err = LDAP_ALIAS_DEREF_PROBLEM;
	rs->sr_text = "maximum deref depth exceeded";

	while (BDB_IDL_N(tmp) < op->o_bd->be_max_deref_depth) {
		/* Remember the last entry we looked at, so we can
		 * report broken links
		 */
		*matched = e;

		/* If this is part of a subtree or onelevel search,
		 * have we seen this ID before? If so, quit.
		 */
		if ( visited && bdb_idl_insert( visited, e->e_id ) ) {
			e = NULL;
			break;
		}

		/* If we've seen this ID during this deref iteration,
		 * we've hit a loop.
		 */
		if ( bdb_idl_insert( tmp, e->e_id ) ) {
			rs->sr_err = LDAP_ALIAS_PROBLEM;
			rs->sr_text = "circular alias";
			e = NULL;
			break;
		}

		/* If there was a problem getting the aliasedObjectName,
		 * get_alias_dn will have set the error status.
		 */
		if ( get_alias_dn(e, &ndn, &rs->sr_err, &rs->sr_text) ) {
			e = NULL;
			break;
		}

		rs->sr_err = bdb_dn2entry( op, NULL, &ndn, &ei,
			0, locker, &lockr );

		if ( ei ) {
			e = ei->bei_e;
		} else {
			e = NULL;
		}

		if (!e) {
			rs->sr_err = LDAP_ALIAS_PROBLEM;
			rs->sr_text = "aliasedObject not found";
			break;
		}

		/* Free the previous entry, continue to work with the
		 * one we just retrieved.
		 */
		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache,
			*matched, lock);
		*lock = lockr;

		/* We found a regular entry. Return this to the caller. The
		 * entry is still locked for Read.
		 */
		if (!is_entry_alias(e)) {
			rs->sr_err = LDAP_SUCCESS;
			rs->sr_text = NULL;
			break;
		}
	}
	return e;
}

/* Look for and dereference all aliases within the search scope. Adds
 * the dereferenced entries to the "ids" list. Requires "stack" to be
 * able to hold 8 levels of DB_SIZE IDLs. Of course we're hardcoded to
 * require a minimum of 8 UM_SIZE IDLs so this is never a problem.
 */
static int search_aliases(
	Operation *op,
	SlapReply *rs,
	Entry *e,
	u_int32_t locker,
	ID *ids,
	ID *scopes,
	ID *stack )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	ID *aliases, *curscop, *subscop, *visited, *newsubs, *oldsubs, *tmp;
	ID cursora, ida, cursoro, ido, *subscop2;
	Entry *matched, *a;
	EntryInfo *ei;
	struct berval bv_alias = BER_BVC( "alias" );
	AttributeAssertion aa_alias;
	Filter	af;
	DB_LOCK locka, lockr;
	int first = 1;

	aliases = stack;	/* IDL of all aliases in the database */
	curscop = aliases + BDB_IDL_DB_SIZE;	/* Aliases in the current scope */
	subscop = curscop + BDB_IDL_DB_SIZE;	/* The current scope */
	visited = subscop + BDB_IDL_DB_SIZE;	/* IDs we've seen in this search */
	newsubs = visited + BDB_IDL_DB_SIZE;	/* New subtrees we've added */
	oldsubs = newsubs + BDB_IDL_DB_SIZE;	/* Subtrees added previously */
	tmp = oldsubs + BDB_IDL_DB_SIZE;	/* Scratch space for deref_base() */

	/* A copy of subscop, because subscop gets clobbered by
	 * the bdb_idl_union/intersection routines
	 */
	subscop2 = tmp + BDB_IDL_DB_SIZE;

	af.f_choice = LDAP_FILTER_EQUALITY;
	af.f_ava = &aa_alias;
	af.f_av_desc = slap_schema.si_ad_objectClass;
	af.f_av_value = bv_alias;
	af.f_next = NULL;

	/* Find all aliases in database */
	BDB_IDL_ZERO( aliases );
	rs->sr_err = bdb_filter_candidates( op, &af, aliases,
		curscop, visited );
	if (rs->sr_err != LDAP_SUCCESS) {
		return rs->sr_err;
	}
	oldsubs[0] = 1;
	oldsubs[1] = e->e_id;

	BDB_IDL_ZERO( ids );
	BDB_IDL_ZERO( visited );
	BDB_IDL_ZERO( newsubs );

	cursoro = 0;
	ido = bdb_idl_first( oldsubs, &cursoro );

	for (;;) {
		/* Set curscop to only the aliases in the current scope. Start with
		 * all the aliases, obtain the IDL for the current scope, and then
		 * get the intersection of these two IDLs. Add the current scope
		 * to the cumulative list of candidates.
		 */
		BDB_IDL_CPY( curscop, aliases );
		rs->sr_err = bdb_dn2idl( op, e, subscop,
			subscop2+BDB_IDL_DB_SIZE );
		if (first) {
			first = 0;
		} else {
			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache, e, &locka);
		}
		BDB_IDL_CPY(subscop2, subscop);
		rs->sr_err = bdb_idl_intersection(curscop, subscop);
		bdb_idl_union( ids, subscop2 );

		/* Dereference all of the aliases in the current scope. */
		cursora = 0;
		for (ida = bdb_idl_first(curscop, &cursora); ida != NOID;
			ida = bdb_idl_next(curscop, &cursora))
		{
			ei = NULL;
retry1:
			rs->sr_err = bdb_cache_find_id(op, NULL,
				ida, &ei, 0, locker, &lockr );
			if (rs->sr_err != LDAP_SUCCESS) {
				if ( rs->sr_err == DB_LOCK_DEADLOCK ||
					rs->sr_err == DB_LOCK_NOTGRANTED ) goto retry1;
				continue;
			}
			a = ei->bei_e;

			/* This should only happen if the curscop IDL has maxed out and
			 * turned into a range that spans IDs indiscriminately
			 */
			if (!is_entry_alias(a)) {
				bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache,
					a, &lockr);
				continue;
			}

			/* Actually dereference the alias */
			BDB_IDL_ZERO(tmp);
			a = deref_base( op, rs, a, &matched, locker, &lockr,
				tmp, visited );
			if (a) {
				/* If the target was not already in our current candidates,
				 * make note of it in the newsubs list. Also
				 * set it in the scopes list so that bdb_search
				 * can check it.
				 */
				if (bdb_idl_insert(ids, a->e_id) == 0) {
					bdb_idl_insert(newsubs, a->e_id);
					bdb_idl_insert(scopes, a->e_id);
				}
				bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache,
					a, &lockr);

			} else if (matched) {
				/* Alias could not be dereferenced, or it deref'd to
				 * an ID we've already seen. Ignore it.
				 */
				bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache,
					matched, &lockr );
				rs->sr_text = NULL;
			}
		}
		/* If this is a OneLevel search, we're done; oldsubs only had one
		 * ID in it. For a Subtree search, oldsubs may be a list of scope IDs.
		 */
		if ( op->ors_scope == LDAP_SCOPE_ONELEVEL ) break;
nextido:
		ido = bdb_idl_next( oldsubs, &cursoro );
		
		/* If we're done processing the old scopes, did we add any new
		 * scopes in this iteration? If so, go back and do those now.
		 */
		if (ido == NOID) {
			if (BDB_IDL_IS_ZERO(newsubs)) break;
			BDB_IDL_CPY(oldsubs, newsubs);
			BDB_IDL_ZERO(newsubs);
			cursoro = 0;
			ido = bdb_idl_first( oldsubs, &cursoro );
		}

		/* Find the entry corresponding to the next scope. If it can't
		 * be found, ignore it and move on. This should never happen;
		 * we should never see the ID of an entry that doesn't exist.
		 * Set the name so that the scope's IDL can be retrieved.
		 */
		ei = NULL;
sameido:
		rs->sr_err = bdb_cache_find_id(op, NULL, ido, &ei,
			0, locker, &locka );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			if ( rs->sr_err == DB_LOCK_DEADLOCK ||
				rs->sr_err == DB_LOCK_NOTGRANTED )
				goto sameido;
			goto nextido;
		}
		e = ei->bei_e;
	}
	return rs->sr_err;
}

#define is_sync_protocol(op)	\
	((op)->o_sync_mode & SLAP_SYNC_REFRESH_AND_PERSIST)

#define IS_BDB_REPLACE(type) (( type == LDAP_PSEARCH_BY_DELETE ) || \
	( type == LDAP_PSEARCH_BY_SCOPEOUT ))
#define IS_PSEARCH (op != sop)
#define IS_POST_SEARCH ( op->ors_post_search_id != NOID )

static Operation *
bdb_drop_psearch( Operation *op, ber_int_t msgid )
{
	Operation	*ps_list;
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;

	LDAP_LIST_FOREACH ( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
		if ( ps_list->o_connid == op->o_connid ) {
			if ( ps_list->o_msgid == msgid ) {
				ps_list->o_abandon = 1;
				LDAP_LIST_REMOVE( ps_list, o_ps_link );
				ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
				LDAP_STAILQ_REMOVE( &op->o_conn->c_ops, ps_list,
					slap_op, o_next );
				LDAP_STAILQ_NEXT( ps_list, o_next ) = NULL;
				op->o_conn->c_n_ops_executing--;
				op->o_conn->c_n_ops_completed++;
				ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );
				return ps_list;
			}
		}
	}

	return NULL;
}

int
bdb_abandon( Operation *op, SlapReply *rs )
{
	Operation	*ps;
	void		*saved_tmpmemctx;

	ps = bdb_drop_psearch( op, op->oq_abandon.rs_msgid );
	if ( ps ) {
		saved_tmpmemctx = ps->o_tmpmemctx;

		if (!BER_BVISNULL(&ps->o_req_dn)) {
			slap_sl_free(ps->o_req_dn.bv_val, ps->o_tmpmemctx );
		}
		if (!BER_BVISNULL(&ps->o_req_ndn)) {
			slap_sl_free(ps->o_req_ndn.bv_val, ps->o_tmpmemctx );
		}
		if (!BER_BVISNULL(&ps->ors_filterstr)) {
			ps->o_tmpfree(ps->ors_filterstr.bv_val, ps->o_tmpmemctx);
		}
		if (ps->ors_filter != NULL) {
			filter_free_x(ps, ps->ors_filter);
		}
		if (ps->ors_attrs != NULL) {
			ps->o_tmpfree(ps->ors_attrs, ps->o_tmpmemctx);
		}

		slap_op_free ( ps );

		if ( saved_tmpmemctx ) {
			slap_sl_mem_destroy( NULL, saved_tmpmemctx );
		}

		return LDAP_SUCCESS;
	}
	return LDAP_UNAVAILABLE;
}

int
bdb_cancel( Operation *op, SlapReply *rs )
{
	Operation	*ps;
	void		*saved_tmpmemctx;

	ps = bdb_drop_psearch( op, op->oq_cancel.rs_msgid );
	if ( ps ) {
		saved_tmpmemctx = ps->o_tmpmemctx;

		rs->sr_err = LDAP_CANCELLED;
		send_ldap_result( ps, rs );

		if (!BER_BVISNULL(&ps->o_req_dn)) {
			slap_sl_free(ps->o_req_dn.bv_val, ps->o_tmpmemctx );
		}
		if (!BER_BVISNULL(&ps->o_req_ndn)) {
			slap_sl_free(ps->o_req_ndn.bv_val, ps->o_tmpmemctx );
		}
		if (!BER_BVISNULL(&ps->ors_filterstr)) {
			ps->o_tmpfree(ps->ors_filterstr.bv_val, ps->o_tmpmemctx);
		}
		if (ps->ors_filter != NULL) {
			filter_free_x(ps, ps->ors_filter);
		}
		if (ps->ors_attrs != NULL) {
			ps->o_tmpfree(ps->ors_attrs, ps->o_tmpmemctx);
		}

		slap_op_free ( ps );

		if ( saved_tmpmemctx ) {
			slap_sl_mem_destroy( NULL, saved_tmpmemctx );
		}

		return LDAP_SUCCESS;
	}
	return LDAP_UNAVAILABLE;
}

int bdb_search( Operation *op, SlapReply *rs )
{
	int rc;
	struct pc_entry *pce = NULL;
	struct pc_entry *tmp_pce = NULL;
	Entry ps_e = {0};
	Attribute *a;

	ps_e.e_private = NULL;
	ldap_pvt_thread_mutex_init( &op->o_pcmutex );
	LDAP_TAILQ_INIT( &op->o_ps_pre_candidates );
	LDAP_TAILQ_INIT( &op->o_ps_post_candidates );

	op->ors_post_search_id = NOID;
	rc = bdb_do_search( op, rs, op, NULL, 0 );

	ldap_pvt_thread_mutex_lock( &op->o_pcmutex );
	pce = LDAP_TAILQ_FIRST( &op->o_ps_post_candidates );
	ldap_pvt_thread_mutex_unlock( &op->o_pcmutex );

	while ( rc == LDAP_SUCCESS && pce &&
			op->o_sync_mode & SLAP_SYNC_REFRESH_AND_PERSIST ) {

		ps_e.e_id = op->ors_post_search_id = pce->pc_id;
		if ( op->o_sync_csn.bv_val ) {
			ch_free( op->o_sync_csn.bv_val );
			op->o_sync_csn.bv_val = NULL;
		}
		ber_dupbv( &op->o_sync_csn, &pce->pc_csn );
		ber_dupbv( &ps_e.e_name, &pce->pc_ename );
		ber_dupbv( &ps_e.e_nname, &pce->pc_enname );
		a = ch_calloc( 1, sizeof( Attribute ));
		a->a_desc = slap_schema.si_ad_entryUUID;
		a->a_vals = ch_calloc( 2, sizeof( struct berval ));
		ber_dupbv( &a->a_vals[0], &pce->pc_entryUUID );
		a->a_nvals = a->a_vals;
		a->a_next = NULL;
		ps_e.e_attrs = a;

		rc = bdb_do_search( op, rs, op, &ps_e, 0 );

		tmp_pce = pce;
		ldap_pvt_thread_mutex_lock( &op->o_pcmutex );
		pce = LDAP_TAILQ_NEXT( pce, pc_link );
		LDAP_TAILQ_REMOVE( &op->o_ps_post_candidates, tmp_pce, pc_link );
		ldap_pvt_thread_mutex_unlock( &op->o_pcmutex );

		ch_free( tmp_pce->pc_csn.bv_val );
		ch_free( tmp_pce->pc_entryUUID.bv_val );
		ch_free( tmp_pce->pc_ename.bv_val );
		ch_free( tmp_pce->pc_enname.bv_val );
		ch_free( tmp_pce );	
		entry_clean( &ps_e );
	}
	return rc;
}

#define BDB_PSEARCH_MAX_WAIT 3
int bdb_psearch( Operation *op, SlapReply *rs, Operation *sop,
	Entry *ps_e, int ps_type )
{
	int	rc;
	struct pc_entry *pce = NULL;
	struct pc_entry *p = NULL;
	int num_retries = 0;

	op->ors_post_search_id = NOID;

	switch (ps_type) {
	case LDAP_PSEARCH_BY_PREMODIFY:
	case LDAP_PSEARCH_BY_PREDELETE:

		if ( !op->o_ps_send_wait ) {
			if ( sop->o_refresh_in_progress ) {
				pce = (struct pc_entry *) ch_calloc(
							1, sizeof( struct pc_entry ));
				pce->pc_id = ps_e->e_id;
				ldap_pvt_thread_mutex_lock( &sop->o_pcmutex );
				if ( LDAP_TAILQ_EMPTY( &sop->o_ps_pre_candidates )) {
					LDAP_TAILQ_INSERT_HEAD(
							&sop->o_ps_pre_candidates, pce, pc_link );
				} else {
					LDAP_TAILQ_FOREACH( p,
							&sop->o_ps_pre_candidates, pc_link ) {
						if ( p->pc_id > pce->pc_id )
							break;
					}

					if ( p ) {
						LDAP_TAILQ_INSERT_BEFORE( p, pce, pc_link );
					} else {
						LDAP_TAILQ_INSERT_TAIL(
								&sop->o_ps_pre_candidates,
								pce, pc_link );
					}
				}
				ldap_pvt_thread_mutex_unlock( &sop->o_pcmutex );
			} else {
				rc = bdb_do_search( op, rs, sop, ps_e, ps_type );
				return rc;
			}
		} else {
			pce = op->o_ps_send_wait;
		}

		/* Wait until refresh search send the entry */
		while ( !pce->pc_sent ) {
			if ( sop->o_refresh_in_progress ) {
				if ( num_retries == BDB_PSEARCH_MAX_WAIT ) {
					op->o_ps_send_wait = pce;
					return LDAP_BUSY;
				}
				ldap_pvt_thread_yield();
				bdb_trans_backoff( ++num_retries );
			} else {
				break;
			}
		}

		op->o_ps_send_wait = NULL;

		if ( !sop->o_refresh_in_progress && !pce->pc_sent ) {
			/* refresh ended without processing pce */
			/* need to perform psearch for ps_e */
			ldap_pvt_thread_mutex_lock( &sop->o_pcmutex );
			LDAP_TAILQ_REMOVE( &sop->o_ps_pre_candidates, pce, pc_link );
			ldap_pvt_thread_mutex_unlock( &sop->o_pcmutex );
			ch_free( pce );
			rc = bdb_do_search( op, rs, sop, ps_e, ps_type );
			return rc;
		} else {
			/* the pce entry was sent in the refresh phase */
			if ( ps_type == LDAP_PSEARCH_BY_PREMODIFY ) {
				struct psid_entry* psid_e;
				psid_e = (struct psid_entry *) ch_calloc(1,
							sizeof(struct psid_entry));
				psid_e->ps_op = sop;
				LDAP_LIST_INSERT_HEAD( &op->o_pm_list, psid_e, ps_link );
			}

			ldap_pvt_thread_mutex_lock( &sop->o_pcmutex );
			LDAP_TAILQ_REMOVE( &sop->o_ps_pre_candidates, pce, pc_link );
			ldap_pvt_thread_mutex_unlock( &sop->o_pcmutex );
			ch_free( pce );
			return LDAP_SUCCESS;
		} 
		break;
	case LDAP_PSEARCH_BY_DELETE:
	case LDAP_PSEARCH_BY_SCOPEOUT:
	case LDAP_PSEARCH_BY_ADD:
	case LDAP_PSEARCH_BY_MODIFY:
		ldap_pvt_thread_mutex_lock( &op->o_pcmutex );
		if ( sop->o_refresh_in_progress ||
				!LDAP_TAILQ_EMPTY( &sop->o_ps_post_candidates )) {
			pce = (struct pc_entry *) ch_calloc( 1, sizeof( struct pc_entry ));
			pce->pc_id = ps_e->e_id;
			ber_dupbv( &pce->pc_csn, &op->o_sync_csn );
			if ( ps_type == LDAP_PSEARCH_BY_DELETE ) {
				Attribute *a;
				for ( a = ps_e->e_attrs; a != NULL; a = a->a_next ) {
					AttributeDescription *desc = a->a_desc;
					if ( desc == slap_schema.si_ad_entryUUID ) {
						ber_dupbv( &pce->pc_entryUUID, &a->a_nvals[0] );
					}
				}
			}	
			ber_dupbv( &pce->pc_ename, &ps_e->e_name ); 
			ber_dupbv( &pce->pc_enname, &ps_e->e_nname ); 
			LDAP_TAILQ_INSERT_TAIL( &sop->o_ps_post_candidates, pce, pc_link );
			ldap_pvt_thread_mutex_unlock( &op->o_pcmutex );
		} else {
			ldap_pvt_thread_mutex_unlock( &op->o_pcmutex );
			rc = bdb_do_search( op, rs, sop, ps_e, ps_type );
			return rc;
		}
		break;
	default:
		Debug( LDAP_DEBUG_TRACE, "do_psearch: invalid psearch type\n",
				0, 0, 0 );
		return LDAP_OTHER;
	}
}

/* For persistent searches, op is the currently executing operation,
 * sop is the persistent search. For regular searches, sop = op.
 */
int
bdb_do_search( Operation *op, SlapReply *rs, Operation *sop,
	Entry *ps_e, int ps_type )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	time_t		stoptime;
	ID		id, cursor;
	ID		candidates[BDB_IDL_UM_SIZE];
	ID		scopes[BDB_IDL_DB_SIZE];
	Entry		*e = NULL, base, e_root = {0};
	Entry		*matched = NULL;
	EntryInfo	*ei, ei_root = {0};
	struct berval	realbase = BER_BVNULL;
	int		manageDSAit;
	int		tentries = 0;
	ID		lastid = NOID;
	AttributeName	*attrs;

	Filter		contextcsnand, contextcsnle, cookief, csnfnot,
			csnfeq, csnfand, csnfge;
	AttributeAssertion aa_ge, aa_eq, aa_le;
	struct berval	*search_context_csn = NULL;
	DB_LOCK		ctxcsn_lock;
	LDAPControl	*ctrls[SLAP_MAX_RESPONSE_CONTROLS];
	int		num_ctrls = 0;
	AttributeName	uuid_attr[2];
	int		rc_sync = 0;
	int		entry_sync_state = -1;
	AttributeName	null_attr;
	int		no_sync_state_change = 0;

	u_int32_t	locker = 0;
	DB_LOCK		lock;

	Operation	*ps_list;
	int			sync_send_present_mode = 1;
	int			match;
	MatchingRule *mr;
	const char *text;
	int			slog_found = 0;

	struct pc_entry *pce = NULL;
	BerVarray	syncUUID_set = NULL;
	int			syncUUID_set_cnt = 0;

	struct	bdb_op_info	*opinfo = NULL;
	DB_TXN			*ltid = NULL;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_search\n", 0, 0, 0);
	attrs = sop->oq_search.rs_attrs;

	opinfo = (struct bdb_op_info *) op->o_private;

	if ( !IS_POST_SEARCH && !IS_PSEARCH &&
			sop->o_sync_mode & SLAP_SYNC_REFRESH_AND_PERSIST ) {
		struct slap_session_entry *sent;
		if ( sop->o_sync_state.sid >= 0 ) {
			LDAP_LIST_FOREACH( sent, &bdb->bi_session_list, se_link ) {
				if ( sent->se_id == sop->o_sync_state.sid ) {
					sop->o_sync_slog_size = sent->se_size;
					break;
				}
			}
		}
	}

	/* psearch needs to be registered before refresh begins */
	if ( !IS_POST_SEARCH && !IS_PSEARCH &&
			sop->o_sync_mode & SLAP_SYNC_PERSIST ) {
		sop->o_refresh_in_progress = 1;
		ldap_pvt_thread_rdwr_wlock( &bdb->bi_pslist_rwlock );
		LDAP_LIST_INSERT_HEAD( &bdb->bi_psearch_list, sop, o_ps_link );
		ldap_pvt_thread_rdwr_wunlock( &bdb->bi_pslist_rwlock );

	} else if ( !IS_POST_SEARCH && !IS_PSEARCH &&
				sop->o_sync_mode & SLAP_SYNC_REFRESH_AND_PERSIST
				&& sop->o_sync_slog_size >= 0 )
	{
		ldap_pvt_thread_rdwr_wlock( &bdb->bi_pslist_rwlock );
		LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list, o_ps_link ) {
			if ( ps_list->o_sync_slog_size >= 0 ) {
				if ( ps_list->o_sync_state.sid == sop->o_sync_state.sid ) {
					slog_found = 1;
					break;
				}
			}
		}

		if ( slog_found ) {
			if ( ps_list->o_sync_slog_omitcsn.bv_len != 0 ) {
				mr = slap_schema.si_ad_entryCSN->ad_type->sat_ordering;
				if ( sop->o_sync_state.ctxcsn &&
					sop->o_sync_state.ctxcsn->bv_val != NULL )
				{
					value_match( &match, slap_schema.si_ad_entryCSN, mr,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						sop->o_sync_state.ctxcsn,
						&ps_list->o_sync_slog_omitcsn,
						&text );
				} else {
					match = -1;
				}
				if ( match >= 0 ) {
					sync_send_present_mode = 0;
				}
			} else {
				sync_send_present_mode = 0;
			}
		} else if ( sop->o_sync_slog_size >= 0 ) {
			LDAP_LIST_INSERT_HEAD( &bdb->bi_psearch_list, sop, o_ps_link );
		} else {
			sop->o_sync_state.sid = -1;
		}
		ldap_pvt_thread_rdwr_wunlock( &bdb->bi_pslist_rwlock );
	}

	null_attr.an_desc = NULL;
	null_attr.an_oc = NULL;
	null_attr.an_oc_exclude = 0;
	BER_BVZERO( &null_attr.an_name );

	for( num_ctrls = 0; num_ctrls < SLAP_MAX_RESPONSE_CONTROLS; num_ctrls++ ) {
		ctrls[num_ctrls] = NULL;
	}
	num_ctrls = 0;

	if ( IS_PSEARCH && IS_BDB_REPLACE(ps_type)) {
		attrs = uuid_attr;
		attrs[0].an_desc = NULL;
		attrs[0].an_oc = NULL;
		attrs[0].an_oc_exclude = 0;
		BER_BVZERO( &attrs[0].an_name );
	}

	manageDSAit = get_manageDSAit( sop );

	/* Sync control overrides manageDSAit */
	if ( !IS_PSEARCH && sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
		if ( manageDSAit == SLAP_NO_CONTROL ) {
			manageDSAit = SLAP_CRITICAL_CONTROL;
		}
	} else if ( IS_PSEARCH ) {
		if ( manageDSAit == SLAP_NO_CONTROL ) {
			manageDSAit = SLAP_CRITICAL_CONTROL;
		}
	}

	if ( opinfo && opinfo->boi_txn ) {
		ltid = opinfo->boi_txn;
		locker = TXN_ID( ltid );
	} else {
		rs->sr_err = LOCK_ID( bdb->bi_dbenv, &locker );

		switch(rs->sr_err) {
		case 0:
			break;
		default:
			send_ldap_error( sop, rs, LDAP_OTHER, "internal error" );
			return rs->sr_err;
		}
	}

	if ( IS_POST_SEARCH ) {
		cursor = 0;
		candidates[0] = 1;
		candidates[1] = op->ors_post_search_id;
		search_context_csn = ber_dupbv( NULL, &op->o_sync_csn );	
		goto loop_start;
	}

	if ( sop->o_req_ndn.bv_len == 0 ) {
		/* DIT root special case */
		ei_root.bei_e = &e_root;
		ei_root.bei_parent = &ei_root;
		e_root.e_private = &ei_root;
		e_root.e_id = 0;
		BER_BVSTR( &e_root.e_nname, "" );
		BER_BVSTR( &e_root.e_name, "" );
		ei = &ei_root;
		rs->sr_err = LDAP_SUCCESS;
	} else {
dn2entry_retry:
		/* get entry with reader lock */
		rs->sr_err = bdb_dn2entry( op, ltid, &sop->o_req_ndn, &ei,
			1, locker, &lock );
	}

	switch(rs->sr_err) {
	case DB_NOTFOUND:
		matched = ei->bei_e;
		break;
	case 0:
		e = ei->bei_e;
		break;
	case LDAP_BUSY:
		send_ldap_error( sop, rs, LDAP_BUSY, "ldap server busy" );
		if ( !opinfo )
			LOCK_ID_FREE (bdb->bi_dbenv, locker );
		return LDAP_BUSY;
	case DB_LOCK_DEADLOCK:
	case DB_LOCK_NOTGRANTED:
		goto dn2entry_retry;
	default:
		send_ldap_error( sop, rs, LDAP_OTHER, "internal error" );
		if ( !opinfo )
			LOCK_ID_FREE (bdb->bi_dbenv, locker );
		return rs->sr_err;
	}

	if ( e && (op->ors_deref & LDAP_DEREF_FINDING) && is_entry_alias(e) ) {
		BDB_IDL_ZERO(candidates);
		e = deref_base( op, rs, e, &matched, locker, &lock,
			candidates, NULL );
	}

	if ( e == NULL ) {
		struct berval matched_dn = BER_BVNULL;

		if ( matched != NULL ) {
			BerVarray erefs;
			ber_dupbv( &matched_dn, &matched->e_name );

			erefs = is_entry_referral( matched )
				? get_entry_referrals( op, matched )
				: NULL;

			bdb_cache_return_entry_r (bdb->bi_dbenv, &bdb->bi_cache,
				matched, &lock);
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

		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( sop, rs );

		if ( !opinfo )
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

	if ( !manageDSAit && e != &e_root && is_entry_referral( e ) ) {
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

		Debug( LDAP_DEBUG_TRACE, "bdb_search: entry is referral\n",
			0, 0, 0 );

		if (!rs->sr_ref) rs->sr_text = "bad_referral object";
		rs->sr_err = LDAP_REFERRAL;
		rs->sr_matched = matched_dn.bv_val;
		send_ldap_result( sop, rs );

		if ( !opinfo )
			LOCK_ID_FREE (bdb->bi_dbenv, locker );
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
		ber_memfree( matched_dn.bv_val );
		rs->sr_matched = NULL;
		return 1;
	}

	if ( get_assert( op ) &&
		( test_filter( op, e, get_assertion( op )) != LDAP_COMPARE_TRUE ))
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		send_ldap_result( sop, rs );
		return 1;
	}

	/* compute it anyway; root does not use it */
	stoptime = op->o_time + sop->ors_tlimit;

	/* need normalized dn below */
	ber_dupbv( &realbase, &e->e_nname );

	/* Copy info to base, must free entry before accessing the database
	 * in search_candidates, to avoid deadlocks.
	 */
	base.e_private = e->e_private;
	base.e_nname = realbase;
	base.e_id = e->e_id;

	if ( e != &e_root ) {
		bdb_cache_return_entry_r(bdb->bi_dbenv, &bdb->bi_cache, e, &lock);
	}
	e = NULL;

	if ( !IS_PSEARCH ) {
		rs->sr_err = bdb_get_commit_csn( sop, rs, &search_context_csn,
			locker, &ctxcsn_lock );

		if ( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_error( sop, rs, rs->sr_err,
				"error in csn management in search" );
			goto done;
		}

		if ( sop->o_sync_mode != SLAP_SYNC_NONE &&
			sop->o_sync_state.ctxcsn &&
			sop->o_sync_state.ctxcsn->bv_val &&
			ber_bvcmp( &sop->o_sync_state.ctxcsn[0], search_context_csn ) == 0 )
		{
			bdb_cache_entry_db_unlock( bdb->bi_dbenv, &ctxcsn_lock );
			goto nochange;
		}
	} else {
		search_context_csn = ber_dupbv( NULL, &op->o_sync_csn );	
	}

	/* select candidates */
	if ( sop->oq_search.rs_scope == LDAP_SCOPE_BASE ) {
		rs->sr_err = base_candidate( op->o_bd, &base, candidates );

	} else {
		BDB_IDL_ZERO( candidates );
		BDB_IDL_ZERO( scopes );
		rs->sr_err = search_candidates( op, sop, rs, &base,
			locker, candidates, scopes );
	}

	if ( !IS_PSEARCH && sop->o_sync_mode != SLAP_SYNC_NONE ) {
		bdb_cache_entry_db_unlock( bdb->bi_dbenv, &ctxcsn_lock );
	}

	/* start cursor at beginning of candidates.
	 */
	cursor = 0;
	if (IS_PSEARCH) {
		if ( !BDB_IDL_IS_RANGE( candidates ) ) {
			cursor = bdb_idl_search( candidates, ps_e->e_id );
			if ( candidates[cursor] != ps_e->e_id ) {
			   	rs->sr_err = LDAP_SUCCESS;
			   	goto done;
			}
		} else if ( ps_e->e_id < BDB_IDL_RANGE_FIRST( candidates ) ||
			ps_e->e_id > BDB_IDL_RANGE_LAST( candidates ))
		{
			rs->sr_err = LDAP_SUCCESS;
			goto done;
		}
		candidates[0] = 1;
		candidates[1] = ps_e->e_id;
	}

	if ( candidates[0] == 0 ) {
		Debug( LDAP_DEBUG_TRACE, "bdb_search: no candidates\n",
			0, 0, 0 );

		goto nochange;
	}

	/* if not root and candidates exceed to-be-checked entries, abort */
	if ( sop->ors_limit	/* isroot == FALSE */ &&
		sop->ors_limit->lms_s_unchecked != -1 &&
		BDB_IDL_N(candidates) > (unsigned) sop->ors_limit->lms_s_unchecked )
	{
		rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
		send_ldap_result( sop, rs );
		rs->sr_err = LDAP_SUCCESS;
		goto done;
	}

	if ( sop->ors_limit == NULL	/* isroot == TRUE */ ||
		!sop->ors_limit->lms_s_pr_hide )
	{
		tentries = BDB_IDL_N(candidates);
	}

	if ( get_pagedresults( sop ) > SLAP_NO_CONTROL ) {
		/* deferred cookie parsing */
		rs->sr_err = parse_paged_cookie( sop, rs );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( sop, rs );
			goto done;
		}

		if ( (ID)( sop->o_pagedresults_state.ps_cookie ) == 0 ) {
			id = bdb_idl_first( candidates, &cursor );

		} else {
			if ( sop->o_pagedresults_size == 0 ) {
				rs->sr_err = LDAP_SUCCESS;
				rs->sr_text = "search abandoned by pagedResult size=0";
				send_ldap_result( sop, rs );
				goto done;
			}
			for ( id = bdb_idl_first( candidates, &cursor );
				id != NOID &&
					id <= (ID)( sop->o_pagedresults_state.ps_cookie );
				id = bdb_idl_next( candidates, &cursor ) )
			{
				/* empty */;
			}
		}

		if ( cursor == NOID ) {
			Debug( LDAP_DEBUG_TRACE, 
				"bdb_search: no paged results candidates\n",
				0, 0, 0 );
			send_paged_response( sop, rs, &lastid, 0 );

			rs->sr_err = LDAP_OTHER;
			goto done;
		}
		goto loop_begin;
	}

	if (( sop->o_sync_mode & SLAP_SYNC_REFRESH ) || IS_PSEARCH ) {
		int match;

		cookief.f_choice = LDAP_FILTER_AND;
		cookief.f_and = &csnfnot;
		cookief.f_next = NULL;

		csnfnot.f_choice = LDAP_FILTER_NOT;
		csnfnot.f_not = &csnfeq;
		csnfnot.f_next = &csnfand;

		csnfeq.f_choice = LDAP_FILTER_EQUALITY;
		csnfeq.f_ava = &aa_eq;
		csnfeq.f_av_desc = slap_schema.si_ad_entryCSN;
		if ( sop->o_sync_state.ctxcsn != NULL ) {
			csnfeq.f_av_value = *sop->o_sync_state.ctxcsn;
		} else {
			csnfeq.f_av_value = slap_empty_bv;
		}

		csnfand.f_choice = LDAP_FILTER_AND;
		csnfand.f_and = &csnfge;
		csnfand.f_next = NULL;

		csnfge.f_choice = LDAP_FILTER_GE;
		csnfge.f_ava = &aa_ge;
		csnfge.f_av_desc = slap_schema.si_ad_entryCSN;
		if ( sop->o_sync_state.ctxcsn != NULL ) {
			csnfge.f_av_value = *sop->o_sync_state.ctxcsn;
		} else {
			csnfge.f_av_value = slap_empty_bv;
		}

		if ( search_context_csn && !IS_PSEARCH ) {
			csnfge.f_next = &contextcsnand;

			contextcsnand.f_choice = LDAP_FILTER_AND;
			contextcsnand.f_and = &contextcsnle;
			contextcsnand.f_next = NULL;
	
			contextcsnle.f_choice = LDAP_FILTER_LE;
			contextcsnle.f_ava = &aa_le;
			contextcsnle.f_av_desc = slap_schema.si_ad_entryCSN;
			contextcsnle.f_av_value = *search_context_csn;
			contextcsnle.f_next = sop->oq_search.rs_filter;

			mr = slap_schema.si_ad_entryCSN->ad_type->sat_ordering;
			if ( sop->o_sync_state.ctxcsn &&
				sop->o_sync_state.ctxcsn->bv_val != NULL )
			{
				value_match( &match, slap_schema.si_ad_entryCSN, mr,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						&sop->o_sync_state.ctxcsn[0], search_context_csn,
						&text );
			} else {
				match = -1;
			}
			no_sync_state_change = ( match >= 0 );
		} else {
			csnfge.f_next = sop->oq_search.rs_filter;
		}
	}

loop_start:

	for ( id = bdb_idl_first( candidates, &cursor );
		  id != NOID && !no_sync_state_change;
		id = bdb_idl_next( candidates, &cursor ) )
	{
		int scopeok = 0;
		ID* idhole = NULL;

loop_begin:

		if ( !IS_POST_SEARCH ) {
			idhole = (ID*) avl_find( sop->o_psearch_finished,
									 (caddr_t)&id, bdb_pfid_cmp );
			if ( idhole ) {
				avl_delete( &sop->o_psearch_finished,
							(caddr_t)idhole, bdb_pfid_cmp );
				sop->o_tmpfree( idhole, sop->o_tmpmemctx );
				goto loop_continue;
			}

			if ( sop->o_refresh_in_progress ) {
				ldap_pvt_thread_mutex_lock( &sop->o_pcmutex );
				pce = LDAP_TAILQ_FIRST( &sop->o_ps_pre_candidates );	
				while ( pce && pce->pc_sent ) {
					pce = LDAP_TAILQ_NEXT( pce, pc_link );
				}
				ldap_pvt_thread_mutex_unlock( &sop->o_pcmutex );
				if ( pce ) {
					ID pos;
					if ( BDB_IDL_IS_RANGE( candidates ) ) {
						if ( pce->pc_id >= candidates[1] &&
							 pce->pc_id <= candidates[2] &&
							 pce->pc_id > cursor-1 ) {
							id = pce->pc_id;
							cursor--;
							avl_insert( &sop->o_psearch_finished,
										(caddr_t)bdb_id_dup( sop, &pce->pc_id ),
										bdb_pfid_cmp, avl_dup_error );
						} else {
							pce->pc_sent = 1;
						}
					} else {
						pos = bdb_idl_search(candidates, pce->pc_id);
						if ( pos > cursor-1 && pos <= candidates[0] ) {
							id = pce->pc_id;
							cursor--;
							avl_insert( &sop->o_psearch_finished,
										(caddr_t)bdb_id_dup( sop, &pce->pc_id ),
										bdb_pfid_cmp, avl_dup_error );
						} else {
							pce->pc_sent = 1;
						}
					}
				}
			}
		}

		/* check for abandon */
		if ( sop->o_abandon ) {
			if ( sop != op ) {
				bdb_drop_psearch( sop, sop->o_msgid );
			}
			rs->sr_err = LDAP_SUCCESS;
			goto done;
		}

		if ( sop->o_cancel ) {
			assert( sop->o_cancel == SLAP_CANCEL_REQ );
			rs->sr_err = LDAP_CANCELLED;
			send_ldap_result( sop, rs );
			sop->o_cancel = SLAP_CANCEL_ACK;
			rs->sr_err = LDAP_SUCCESS;
			goto done;
		}

		/* check time limit */
		if ( sop->ors_tlimit != SLAP_NO_LIMIT
				&& slap_get_time() > stoptime )
		{
			rs->sr_err = LDAP_TIMELIMIT_EXCEEDED;
			rs->sr_ref = rs->sr_v2ref;
			send_ldap_result( sop, rs );
			rs->sr_err = LDAP_SUCCESS;
			goto done;
		}

		if (!IS_PSEARCH) {
id2entry_retry:
			/* get the entry with reader lock */
			ei = NULL;
			rs->sr_err = bdb_cache_find_id( op, ltid,
				id, &ei, 0, locker, &lock );

			if (rs->sr_err == LDAP_BUSY) {
				rs->sr_text = "ldap server busy";
				send_ldap_result( sop, rs );
				goto done;

			} else if ( rs->sr_err == DB_LOCK_DEADLOCK
				|| rs->sr_err == DB_LOCK_NOTGRANTED )
			{
				goto id2entry_retry;	
			}

			if ( ei && rs->sr_err == LDAP_SUCCESS ) {
				e = ei->bei_e;
			} else {
				e = NULL;
			}

			if ( e == NULL ) {
				if ( IS_POST_SEARCH ) {
					/* send LDAP_SYNC_DELETE */
					rs->sr_entry = e = ps_e;
					goto post_search_no_entry;
				} else if( !BDB_IDL_IS_RANGE(candidates) ) {
					/* only complain for non-range IDLs */
					Debug( LDAP_DEBUG_TRACE,
						"bdb_search: candidate %ld not found\n",
						(long) id, 0, 0 );
				}

				goto loop_continue;
			}
		} else {
			e = ps_e;
		}

		rs->sr_entry = e;

#ifdef BDB_SUBENTRIES
		/* FIXME: send all but syncrepl */
#if 0
		if ( !is_sync_protocol( sop ) )
#endif
		{
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
		}
#endif /* BDB_SUBENTRIES */

		/* Does this candidate actually satisfy the search scope?
		 *
		 * Note that we don't lock access to the bei_parent pointer.
		 * Since only leaf nodes can be deleted, the parent of any
		 * node will always be a valid node. Also since we have
		 * a Read lock on the data, it cannot be renamed out of the
		 * scope while we are looking at it, and unless we're using
		 * BDB_HIER, its parents cannot be moved either.
		 */
		switch( sop->ors_scope ) {
		case LDAP_SCOPE_BASE:
			/* This is always true, yes? */
			if ( id == base.e_id ) scopeok = 1;
			break;

		case LDAP_SCOPE_ONELEVEL:
			if ( ei->bei_parent->bei_id == base.e_id ) scopeok = 1;
			break;

#ifdef LDAP_SCOPE_CHILDREN
		case LDAP_SCOPE_CHILDREN:
			if ( id == base.e_id ) break;
			/* Fall-thru */
#endif
		case LDAP_SCOPE_SUBTREE: {
			EntryInfo *tmp;
			for ( tmp = BEI(e); tmp; tmp = tmp->bei_parent ) {
				if ( tmp->bei_id == base.e_id ) {
					scopeok = 1;
					break;
				}
			}
			} break;
		}

		/* aliases were already dereferenced in candidate list */
		if ( sop->ors_deref & LDAP_DEREF_SEARCHING ) {
			/* but if the search base is an alias, and we didn't
			 * deref it when finding, return it.
			 */
			if ( is_entry_alias(e) &&
				((sop->ors_deref & LDAP_DEREF_FINDING) ||
					!bvmatch(&e->e_nname, &op->o_req_ndn)))
			{
				goto loop_continue;
			}

			/* scopes is only non-empty for onelevel or subtree */
			if ( !scopeok && BDB_IDL_N(scopes) ) {
				unsigned x;
				if ( sop->ors_scope == LDAP_SCOPE_ONELEVEL ) {
					x = bdb_idl_search( scopes, e->e_id );
					if ( scopes[x] == e->e_id ) scopeok = 1;
				} else {
					/* subtree, walk up the tree */
					EntryInfo *tmp = BEI(e);
					for (;tmp->bei_parent; tmp=tmp->bei_parent) {
						x = bdb_idl_search( scopes, tmp->bei_id );
						if ( scopes[x] == tmp->bei_id ) {
							scopeok = 1;
							break;
						}
					}
				}
			}
		}

		/* Not in scope, ignore it */
		if ( !IS_POST_SEARCH && !scopeok ) {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_search: %ld scope not okay\n",
				(long) id, 0, 0 );
			goto loop_continue;
		}

		/*
		 * if it's a referral, add it to the list of referrals. only do
		 * this for non-base searches, and don't check the filter
		 * explicitly here since it's only a candidate anyway.
		 */
		if ( !manageDSAit && sop->oq_search.rs_scope != LDAP_SCOPE_BASE
			&& is_entry_referral( e ) )
		{
			BerVarray erefs = get_entry_referrals( sop, e );
			rs->sr_ref = referral_rewrite( erefs, &e->e_name, NULL,
				sop->oq_search.rs_scope == LDAP_SCOPE_ONELEVEL
					? LDAP_SCOPE_BASE : LDAP_SCOPE_SUBTREE );

			send_search_reference( sop, rs );

			ber_bvarray_free( rs->sr_ref );
			ber_bvarray_free( erefs );
			rs->sr_ref = NULL;

			goto loop_continue;
		}

		if ( !manageDSAit && is_entry_glue( e )) {
			goto loop_continue;
		}

		/* if it matches the filter and scope, send it */
		if (IS_PSEARCH) {
			if (ps_type != LDAP_PSEARCH_BY_SCOPEOUT) {
				rs->sr_err = test_filter( sop, rs->sr_entry, &cookief );
			} else {
				rs->sr_err = LDAP_COMPARE_TRUE;
			}

		} else {
			if ( !IS_POST_SEARCH ) {
				if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
					rc_sync = test_filter( sop, rs->sr_entry, &cookief );
					rs->sr_err = test_filter( sop, rs->sr_entry,
										&contextcsnand );
					if ( rs->sr_err == LDAP_COMPARE_TRUE ) {
						if ( rc_sync == LDAP_COMPARE_TRUE ) {
							if ( no_sync_state_change ) {
								Debug( LDAP_DEBUG_TRACE,
									"bdb_search: "
									"error in context csn management\n",
									0, 0, 0 );
							}
							entry_sync_state = LDAP_SYNC_ADD;

						} else {
							if ( no_sync_state_change ) {
								goto loop_continue;
							}
							entry_sync_state = LDAP_SYNC_PRESENT;
						}
					}
				} else {
					rs->sr_err = test_filter( sop,
						rs->sr_entry, sop->oq_search.rs_filter );
				}
			} else {
				if ( scopeok ) {
					rs->sr_err = test_filter( sop,
						rs->sr_entry, sop->oq_search.rs_filter );
				} else {
					rs->sr_err = LDAP_COMPARE_TRUE;
				}
			}
		}

		if ( rs->sr_err == LDAP_COMPARE_TRUE ) {
			/* check size limit */
			if ( --sop->ors_slimit == -1 &&
				sop->o_sync_slog_size == -1 )
			{
				if (!IS_PSEARCH) {
					bdb_cache_return_entry_r( bdb->bi_dbenv,
						&bdb->bi_cache, e, &lock );
				}
				e = NULL;
				rs->sr_entry = NULL;
				rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
				rs->sr_ref = rs->sr_v2ref;
				send_ldap_result( sop, rs );
				rs->sr_err = LDAP_SUCCESS;
				goto done;
			}

			if ( get_pagedresults(sop) > SLAP_NO_CONTROL ) {
				if ( rs->sr_nentries >= sop->o_pagedresults_size ) {
					send_paged_response( sop, rs, &lastid, tentries );
					goto done;
				}
				lastid = id;
			}

			if (e) {
				/* safe default */
				int result = -1;
				
				if (IS_PSEARCH || IS_POST_SEARCH) {
					int premodify_found = 0;

					if ( IS_POST_SEARCH ||
						 ps_type == LDAP_PSEARCH_BY_ADD ||
						 ps_type == LDAP_PSEARCH_BY_DELETE ||
						 ps_type == LDAP_PSEARCH_BY_MODIFY ||
						 ps_type == LDAP_PSEARCH_BY_SCOPEOUT )
					{
						if ( !IS_POST_SEARCH &&
							 ps_type == LDAP_PSEARCH_BY_MODIFY ) {
							struct psid_entry* psid_e;
							LDAP_LIST_FOREACH( psid_e,
								&op->o_pm_list, ps_link)
							{
								if( psid_e->ps_op == sop ) {
									premodify_found = 1;
									LDAP_LIST_REMOVE(psid_e, ps_link);
									break;
								}
							}
							if (psid_e != NULL) free (psid_e);
						}

						if ( IS_POST_SEARCH ) {
							if ( scopeok ) {
								entry_sync_state = LDAP_SYNC_ADD;
							} else {
post_search_no_entry:
								entry_sync_state = LDAP_SYNC_DELETE;
							}
						} else if ( ps_type == LDAP_PSEARCH_BY_ADD ) {
							entry_sync_state = LDAP_SYNC_ADD;
						} else if ( ps_type == LDAP_PSEARCH_BY_DELETE ) {
							entry_sync_state = LDAP_SYNC_DELETE;
						} else if ( ps_type == LDAP_PSEARCH_BY_MODIFY ) {
							if ( premodify_found ) {
								entry_sync_state = LDAP_SYNC_MODIFY;
							} else {
								entry_sync_state = LDAP_SYNC_ADD;
							}
						} else if ( ps_type == LDAP_PSEARCH_BY_SCOPEOUT ) {
							entry_sync_state = LDAP_SYNC_DELETE;
						} else {
							rs->sr_err = LDAP_OTHER;
							goto done;
						}

						if ( sop->o_sync_slog_size != -1 ) {
							if ( entry_sync_state == LDAP_SYNC_DELETE ) {
								result = slap_add_session_log( op, sop, e );
							} else {
								result = 1;
							}
						} else {
							struct berval cookie;
							slap_compose_sync_cookie( sop, &cookie,
								search_context_csn,
								sop->o_sync_state.sid,
								sop->o_sync_state.rid );
							rs->sr_err = slap_build_sync_state_ctrl(
								sop, rs, e, entry_sync_state, ctrls,
								num_ctrls++, 1, &cookie );
							if ( rs->sr_err != LDAP_SUCCESS ) goto done;
							if (!(IS_POST_SEARCH &&
								entry_sync_state == LDAP_SYNC_DELETE)) {
								rs->sr_attrs = attrs;
							} else {
								rs->sr_attrs = NULL;
							}
							rs->sr_operational_attrs = NULL;
							rs->sr_ctrls = ctrls;
							rs->sr_flags = 0;
							result = send_search_entry( sop, rs );
							if ( cookie.bv_val ) ch_free( cookie.bv_val );	
							slap_sl_free(
								ctrls[num_ctrls-1]->ldctl_value.bv_val,
								sop->o_tmpmemctx );
							slap_sl_free( ctrls[--num_ctrls],
								sop->o_tmpmemctx );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;
						}

					} else if ( ps_type == LDAP_PSEARCH_BY_PREMODIFY ) {
						struct psid_entry* psid_e;
						psid_e = (struct psid_entry *) ch_calloc(1,
							sizeof(struct psid_entry));
						psid_e->ps_op = sop;
						LDAP_LIST_INSERT_HEAD( &op->o_pm_list,
							psid_e, ps_link );

					} else {
						Debug( LDAP_DEBUG_TRACE,
							"bdb_search: invalid ps_type (%d) \n",
							ps_type, 0, 0);
					}

				} else {
					if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
						if ( rc_sync == LDAP_COMPARE_TRUE ) { /* ADD */
							rs->sr_err = slap_build_sync_state_ctrl(
								sop, rs, e, entry_sync_state, ctrls,
								num_ctrls++, 0, NULL );
							if ( rs->sr_err != LDAP_SUCCESS ) goto done;
							rs->sr_ctrls = ctrls;
							rs->sr_attrs = sop->oq_search.rs_attrs;
							rs->sr_operational_attrs = NULL;
							rs->sr_flags = 0;
							result = send_search_entry( sop, rs );
							slap_sl_free(
								ctrls[num_ctrls-1]->ldctl_value.bv_val,
								sop->o_tmpmemctx );
							slap_sl_free( ctrls[--num_ctrls],
								sop->o_tmpmemctx );
							ctrls[num_ctrls] = NULL;
							rs->sr_ctrls = NULL;

						} else { /* PRESENT */
							if ( sync_send_present_mode ) {
								result = slap_build_syncUUID_set( sop,
									&syncUUID_set, e );
								if ( result <= 0 ) {
									result = -1;	
								} else {
									syncUUID_set_cnt++;
									if ( syncUUID_set_cnt ==
										SLAP_SYNCUUID_SET_SIZE )
									{
										rs->sr_err = LDAP_SUCCESS;
										rs->sr_rspoid = LDAP_SYNC_INFO;
										rs->sr_ctrls = NULL;
										result = slap_send_syncinfo( sop, rs,
											LDAP_TAG_SYNC_ID_SET,
											NULL, 0, syncUUID_set, 0 );
										if ( result != LDAP_SUCCESS ) {
											result = -1;
										}
										ber_bvarray_free_x( syncUUID_set,
											sop->o_tmpmemctx );
										syncUUID_set = NULL;
										syncUUID_set_cnt = 0;
									}
								}

							} else {
								result = 1;
							}
						}

					} else {
						rs->sr_attrs = sop->oq_search.rs_attrs;
						rs->sr_operational_attrs = NULL;
						rs->sr_ctrls = NULL;
						rs->sr_flags = 0;
						rs->sr_err = LDAP_SUCCESS;
						result = send_search_entry( sop, rs );
					}
				}

				switch (result) {
				case 0:		/* entry sent ok */
					break;
				case 1:		/* entry not sent */
					break;
				case -1:	/* connection closed */
					if (!IS_PSEARCH) {
						bdb_cache_return_entry_r(bdb->bi_dbenv,
							&bdb->bi_cache, e, &lock);
					}
					e = NULL;
					rs->sr_entry = NULL;
					rs->sr_err = LDAP_OTHER;
					goto done;
				}
			}

		} else {
			Debug( LDAP_DEBUG_TRACE,
				"bdb_search: %ld does not match filter\n",
				(long) id, 0, 0 );
		}

loop_continue:
		if( e != NULL ) {
			/* free reader lock */
			if (!IS_PSEARCH) {
				if (!(IS_POST_SEARCH &&
						 entry_sync_state == LDAP_SYNC_DELETE)) {
					bdb_cache_return_entry_r( bdb->bi_dbenv,
						&bdb->bi_cache, e , &lock );
					if ( sop->o_nocaching ) {
						bdb_cache_delete_entry( bdb, ei, locker, &lock );
					}
				}
			}
			e = NULL;
			rs->sr_entry = NULL;
		}
		
		if ( sop->o_refresh_in_progress ) {
			if ( pce ) {
				pce->pc_sent = 1;
			}
		}

		ldap_pvt_thread_yield();
	}

	if ( syncUUID_set_cnt > 0 ) {
		rs->sr_err = LDAP_SUCCESS;
		rs->sr_rspoid = LDAP_SYNC_INFO;
		rs->sr_ctrls = NULL;
		slap_send_syncinfo( sop, rs, LDAP_TAG_SYNC_ID_SET,
			NULL, 0, syncUUID_set, 0 );
		ber_bvarray_free_x( syncUUID_set, sop->o_tmpmemctx );
		syncUUID_set_cnt = 0;
	}

nochange:
	if (!IS_PSEARCH && !IS_POST_SEARCH) {
		if ( sop->o_sync_mode & SLAP_SYNC_REFRESH ) {
			if ( sop->o_sync_mode & SLAP_SYNC_PERSIST ) {
				struct berval cookie;
				slap_compose_sync_cookie( sop, &cookie, search_context_csn,
					sop->o_sync_state.sid, sop->o_sync_state.rid );

				if ( sync_send_present_mode ) {
					rs->sr_err = LDAP_SUCCESS;
					rs->sr_rspoid = LDAP_SYNC_INFO;
					rs->sr_ctrls = NULL;
					slap_send_syncinfo( sop, rs,
						LDAP_TAG_SYNC_REFRESH_PRESENT, &cookie, 1, NULL, 0 );

				} else {
					if ( !no_sync_state_change ) {
						int slog_found = 0;
						ldap_pvt_thread_rdwr_rlock( &bdb->bi_pslist_rwlock );
						LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list,
							o_ps_link )
						{
							if ( ps_list->o_sync_slog_size > 0 ) {
								if ( ps_list->o_sync_state.sid ==
									sop->o_sync_state.sid )
								{
									slog_found = 1;
									break;
								}
							}
						}
		
						if ( slog_found ) {
							rs->sr_err = LDAP_SUCCESS;
							rs->sr_rspoid = NULL;
							rs->sr_ctrls = NULL;
							slap_send_session_log( op, ps_list, rs );
						}
						ldap_pvt_thread_rdwr_runlock( &bdb->bi_pslist_rwlock );
					}

					rs->sr_err = LDAP_SUCCESS;
					rs->sr_rspoid = LDAP_SYNC_INFO;
					rs->sr_ctrls = NULL;
					slap_send_syncinfo( sop, rs,
						LDAP_TAG_SYNC_REFRESH_DELETE, &cookie, 1, NULL, 0 );
				}

				if ( cookie.bv_val ) ch_free( cookie.bv_val );

			} else {
				/* refreshOnly mode */
				struct berval cookie;
				slap_compose_sync_cookie( sop, &cookie, search_context_csn,
					sop->o_sync_state.sid, sop->o_sync_state.rid );

				if ( sync_send_present_mode ) {
					slap_build_sync_done_ctrl( sop, rs, ctrls,
						num_ctrls++, 1, &cookie, LDAP_SYNC_REFRESH_PRESENTS );

				} else {
					if ( !no_sync_state_change ) {
						int slog_found = 0;
						ldap_pvt_thread_rdwr_rlock( &bdb->bi_pslist_rwlock );
						LDAP_LIST_FOREACH( ps_list, &bdb->bi_psearch_list,
							o_ps_link )
						{
							if ( ps_list->o_sync_slog_size > 0 ) {
								if ( ps_list->o_sync_state.sid ==
										sop->o_sync_state.sid ) {
									slog_found = 1;
									break;
								}
							}
						}
		
						if ( slog_found ) {
							slap_send_session_log( op, ps_list, rs );
						}
						ldap_pvt_thread_rdwr_runlock( &bdb->bi_pslist_rwlock );
					}

					slap_build_sync_done_ctrl( sop, rs, ctrls,
						num_ctrls++, 1, &cookie, LDAP_SYNC_REFRESH_DELETES );
				}

				rs->sr_ctrls = ctrls;
				rs->sr_ref = rs->sr_v2ref;
				rs->sr_err = (rs->sr_v2ref == NULL)
					? LDAP_SUCCESS : LDAP_REFERRAL;
				rs->sr_rspoid = NULL;
				send_ldap_result( sop, rs );
				if ( ctrls[num_ctrls-1]->ldctl_value.bv_val != NULL ) {
					slap_sl_free( ctrls[num_ctrls-1]->ldctl_value.bv_val,
						sop->o_tmpmemctx );
				}
				slap_sl_free( ctrls[--num_ctrls], sop->o_tmpmemctx );
				ctrls[num_ctrls] = NULL;
				if ( cookie.bv_val ) ch_free( cookie.bv_val );	
			}

		} else {
			rs->sr_ctrls = NULL;
			rs->sr_ref = rs->sr_v2ref;
			rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS : LDAP_REFERRAL;
			rs->sr_rspoid = NULL;
			if ( get_pagedresults(sop) > SLAP_NO_CONTROL ) {
				send_paged_response( sop, rs, NULL, 0 );
			} else {
				send_ldap_result( sop, rs );
			}
		}
	}

	if ( sop->o_refresh_in_progress ) {
		sop->o_refresh_in_progress = 0;
	}

	rs->sr_err = LDAP_SUCCESS;

done:
	if ( sop->o_psearch_finished ) {
		avl_free( sop->o_psearch_finished, ch_free );
	}

	if( !IS_PSEARCH && e != NULL ) {
		/* free reader lock */
		bdb_cache_return_entry_r( bdb->bi_dbenv, &bdb->bi_cache, e, &lock );
	}

	if ( !opinfo )
		LOCK_ID_FREE( bdb->bi_dbenv, locker );

	ber_bvfree( search_context_csn );

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
	Debug(LDAP_DEBUG_ARGS, "base_candidates: base: \"%s\" (0x%08lx)\n",
		e->e_nname.bv_val, (long) e->e_id, 0);

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
	int *max )
{
	int rc = 0;

	assert( f );

	if( cur > *max ) *max = cur;

	switch( f->f_choice ) {
	case LDAP_FILTER_PRESENT:
		if (f->f_desc == slap_schema.si_ad_objectClass) {
			rc = 1;
		}
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
		cur++;
		for ( f=f->f_and; f; f=f->f_next ) {
			(void) oc_filter(f, cur, max);
		}
		break;

	default:
		break;
	}
	return rc;
}

static void search_stack_free( void *key, void *data )
{
	ber_memfree_x(data, NULL);
}

static void *search_stack( Operation *op )
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
		ret = ch_malloc( bdb->bi_search_stack_depth * BDB_IDL_UM_SIZE
			* sizeof( ID ) );
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
	SlapReply *rs,
	Entry *e,
	u_int32_t locker,
	ID	*ids,
	ID	*scopes )
{
	struct bdb_info *bdb = (struct bdb_info *) op->o_bd->be_private;
	int rc, depth = 1;
	Filter		f, rf, xf, nf;
	ID		*stack;
	AttributeAssertion aa_ref;
#ifdef BDB_SUBENTRIES
	Filter	sf;
	AttributeAssertion aa_subentry;
#endif

	/*
	 * This routine takes as input a filter (user-filter)
	 * and rewrites it as follows:
	 *	(&(scope=DN)[(objectClass=subentry)]
	 *		(|[(objectClass=referral)(objectClass=alias)](user-filter))
	 */

	Debug(LDAP_DEBUG_TRACE,
		"search_candidates: base=\"%s\" (0x%08lx) scope=%d\n",
		e->e_nname.bv_val, (long) e->e_id, op->oq_search.rs_scope );

	xf.f_or = op->oq_search.rs_filter;
	xf.f_choice = LDAP_FILTER_OR;
	xf.f_next = NULL;

	/* If the user's filter uses objectClass=*,
	 * these clauses are redundant.
	 */
	if (!oc_filter(op->oq_search.rs_filter, 1, &depth)
		&& !get_subentries_visibility(op)
		&& !is_sync_protocol(op) )
	{
		if( !get_manageDSAit(op) && !get_domainScope(op) ) {
			/* match referral objects */
			struct berval bv_ref = BER_BVC( "referral" );
			rf.f_choice = LDAP_FILTER_EQUALITY;
			rf.f_ava = &aa_ref;
			rf.f_av_desc = slap_schema.si_ad_objectClass;
			rf.f_av_value = bv_ref;
			rf.f_next = xf.f_or;
			xf.f_or = &rf;
			depth++;
		}
	}

	f.f_next = NULL;
	f.f_choice = LDAP_FILTER_AND;
	f.f_and = &nf;
	/* Dummy; we compute scope separately now */
	nf.f_choice = SLAPD_FILTER_COMPUTED;
	nf.f_result = LDAP_SUCCESS;
	nf.f_next = ( xf.f_or == op->oq_search.rs_filter )
		? op->oq_search.rs_filter : &xf ;
	/* Filter depth increased again, adding dummy clause */
	depth++;

#ifdef BDB_SUBENTRIES
	if( get_subentries_visibility( op ) ) {
		struct berval bv_subentry = BER_BVC( "subentry" );
		sf.f_choice = LDAP_FILTER_EQUALITY;
		sf.f_ava = &aa_subentry;
		sf.f_av_desc = slap_schema.si_ad_objectClass;
		sf.f_av_value = bv_subentry;
		sf.f_next = nf.f_next;
		nf.f_next = &sf;
	}
#endif

	/* Allocate IDL stack, plus 1 more for former tmp */
	if ( depth+1 > bdb->bi_search_stack_depth ) {
		stack = ch_malloc( (depth + 1) * BDB_IDL_UM_SIZE * sizeof( ID ) );
	} else {
		stack = search_stack( stackop );
	}

	if( op->ors_deref & LDAP_DEREF_SEARCHING ) {
		rc = search_aliases( op, rs, e, locker, ids, scopes, stack );
	} else {
		rc = bdb_dn2idl( op, e, ids, stack );
	}

	if ( rc == LDAP_SUCCESS ) {
		rc = bdb_filter_candidates( op, &f, ids,
			stack, stack+BDB_IDL_UM_SIZE );
	}

	if ( depth+1 > bdb->bi_search_stack_depth ) {
		ch_free( stack );
	}

	if( rc ) {
		Debug(LDAP_DEBUG_TRACE,
			"bdb_search_candidates: failed (rc=%d)\n",
			rc, NULL, NULL );

	} else {
		Debug(LDAP_DEBUG_TRACE,
			"bdb_search_candidates: id=%ld first=%ld last=%ld\n",
			(long) ids[0],
			(long) BDB_IDL_FIRST(ids),
			(long) BDB_IDL_LAST(ids) );
	}

	return rc;
}

static int
parse_paged_cookie( Operation *op, SlapReply *rs )
{
	LDAPControl	**c;
	int		rc = LDAP_SUCCESS;
	ber_tag_t	tag;
	ber_int_t	size;
	BerElement	*ber;
	struct berval	cookie = BER_BVNULL;

	/* this function must be invoked only if the pagedResults
	 * control has been detected, parsed and partially checked
	 * by the frontend */
	assert( get_pagedresults( op ) > SLAP_NO_CONTROL );

	/* look for the appropriate ctrl structure */
	for ( c = op->o_ctrls; c[0] != NULL; c++ ) {
		if ( strcmp( c[0]->ldctl_oid, LDAP_CONTROL_PAGEDRESULTS ) == 0 )
		{
			break;
		}
	}

	if ( c[0] == NULL ) {
		rs->sr_text = "missing pagedResults control";
		return LDAP_PROTOCOL_ERROR;
	}

	/* Tested by frontend */
	assert( c[0]->ldctl_value.bv_len > 0 );

	/* Parse the control value
	 *	realSearchControlValue ::= SEQUENCE {
	 *		size	INTEGER (0..maxInt),
	 *				-- requested page size from client
	 *				-- result set size estimate from server
	 *		cookie	OCTET STRING
	 * }
	 */
	ber = ber_init( &c[0]->ldctl_value );
	if ( ber == NULL ) {
		rs->sr_text = "internal error";
		return LDAP_OTHER;
	}

	tag = ber_scanf( ber, "{im}", &size, &cookie );

	/* Tested by frontend */
	assert( tag != LBER_ERROR );
	assert( size >= 0 );

	/* cookie decoding/checks deferred to backend... */
	if ( cookie.bv_len ) {
		PagedResultsCookie reqcookie;
		if( cookie.bv_len != sizeof( reqcookie ) ) {
			/* bad cookie */
			rs->sr_text = "paged results cookie is invalid";
			rc = LDAP_PROTOCOL_ERROR;
			goto done;
		}

		AC_MEMCPY( &reqcookie, cookie.bv_val, sizeof( reqcookie ));

		if ( reqcookie > op->o_pagedresults_state.ps_cookie ) {
			/* bad cookie */
			rs->sr_text = "paged results cookie is invalid";
			rc = LDAP_PROTOCOL_ERROR;
			goto done;

		} else if ( reqcookie < op->o_pagedresults_state.ps_cookie ) {
			rs->sr_text = "paged results cookie is invalid or old";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}

	} else {
		/* Initial request.  Initialize state. */
#if 0
		if ( op->o_conn->c_pagedresults_state.ps_cookie != 0 ) {
			/* There's another pagedResults control on the
			 * same connection; reject new pagedResults controls 
			 * (allowed by RFC2696) */
			rs->sr_text = "paged results cookie unavailable; try later";
			rc = LDAP_UNWILLING_TO_PERFORM;
			goto done;
		}
#endif
		op->o_pagedresults_state.ps_cookie = 0;
		op->o_pagedresults_state.ps_count = 0;
	}

done:;
	(void)ber_free( ber, 1 );

	return rc;
}

static void
send_paged_response( 
	Operation	*op,
	SlapReply	*rs,
	ID		*lastid,
	int		tentries )
{
	LDAPControl	ctrl, *ctrls[2];
	BerElementBuffer berbuf;
	BerElement	*ber = (BerElement *)&berbuf;
	PagedResultsCookie respcookie;
	struct berval cookie;

	Debug(LDAP_DEBUG_ARGS,
		"send_paged_response: lastid=0x%08lx nentries=%d\n", 
		lastid ? *lastid : 0, rs->sr_nentries, NULL );

	BER_BVZERO( &ctrl.ldctl_value );
	ctrls[0] = &ctrl;
	ctrls[1] = NULL;

	ber_init2( ber, NULL, LBER_USE_DER );

	if ( lastid ) {
		respcookie = ( PagedResultsCookie )(*lastid);
		cookie.bv_len = sizeof( respcookie );
		cookie.bv_val = (char *)&respcookie;

	} else {
		respcookie = ( PagedResultsCookie )0;
		BER_BVSTR( &cookie, "" );
	}

	op->o_conn->c_pagedresults_state.ps_cookie = respcookie;
	op->o_conn->c_pagedresults_state.ps_count =
		op->o_pagedresults_state.ps_count + rs->sr_nentries;

	/* return size of 0 -- no estimate */
	ber_printf( ber, "{iO}", 0, &cookie ); 

	if ( ber_flatten2( ber, &ctrls[0]->ldctl_value, 0 ) == -1 ) {
		goto done;
	}

	ctrls[0]->ldctl_oid = LDAP_CONTROL_PAGEDRESULTS;
	ctrls[0]->ldctl_iscritical = 0;

	rs->sr_ctrls = ctrls;
	rs->sr_err = LDAP_SUCCESS;
	send_ldap_result( op, rs );
	rs->sr_ctrls = NULL;

done:
	(void) ber_free_buf( ber );
}

static int
bdb_pfid_cmp( const void *v_id1, const void *v_id2 )
{
    const ID *p1 = v_id1, *p2 = v_id2;
	return *p1 - *p2;
}

static ID*
bdb_id_dup( Operation *op, ID *id )
{
	ID *new;
	new = ch_malloc( sizeof(ID) );
	*new = *id;
	return new;
}
