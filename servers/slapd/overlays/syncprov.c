/* syncprov.c - syncrepl provider */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion in
 * OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_SYNCPROV

#include <ac/string.h>
#include "lutil.h"
#include "slap.h"

/* Record of a persistent search */
typedef struct syncops {
	struct syncops *s_next;
	struct berval	s_base;		/* ndn of search base */
	ID		s_eid;		/* entryID of search base */
	Operation	*s_op;		/* search op */
	Filter	*s_filter;
	int		s_flags;	/* search status */
} syncops;

static int	sync_cid;

#define	PS_IS_REFRESHING	0x01

/* Record of which searches matched at premodify step */
typedef struct syncmatches {
	struct syncmatches *sm_next;
	syncops *sm_op;
} syncmatches;

typedef struct syncprov_info_t {
	syncops		*si_ops;
	struct berval	si_ctxcsn;	/* ldapsync context */
	int		si_gotcsn;	/* is our ctxcsn up to date? */
	ldap_pvt_thread_mutex_t	si_csn_mutex;
	ldap_pvt_thread_mutex_t	si_ops_mutex;
} syncprov_info_t;

typedef struct opcookie {
	slap_overinst *son;
	syncmatches *smatches;
	struct berval sdn;	/* DN of entry, for deletes */
	struct berval sndn;
	struct berval suuid;	/* UUID of entry */
	struct berval sctxcsn;
	int sreference;	/* Is the entry a reference? */
} opcookie;

typedef struct fbase_cookie {
	struct berval *fdn;	/* DN of a modified entry, for scope testing */
	syncops *fss;	/* persistent search we're testing against */
	int fbase;	/* if TRUE we found the search base and it's still valid */
	int fscope;	/* if TRUE then fdn is within the psearch scope */
} fbase_cookie;

static AttributeName csn_anlist[2];
static AttributeName uuid_anlist[2];

/* syncprov_findbase:
 *   finds the true DN of the base of a search (with alias dereferencing) and
 * checks to make sure the base entry doesn't get replaced with a different
 * entry (e.g., swapping trees via ModDN, or retargeting an alias). If a
 * change is detected, any persistent search on this base must be terminated /
 * reloaded.
 *   On the first call, we just save the DN and entryID. On subsequent calls
 * we compare the DN and entryID with the saved values.
 */
static int
findbase_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;

	if ( rs->sr_type == REP_SEARCH && rs->sr_err == LDAP_SUCCESS ) {
		fbase_cookie *fc = sc->sc_private;

		/* If no entryID, we're looking for the first time.
		 * Just store whatever we got.
		 */
		if ( fc->fss->s_eid == NOID ) {
			fc->fbase = 1;
			fc->fss->s_eid = rs->sr_entry->e_id;
			ber_dupbv( &fc->fss->s_base, &rs->sr_entry->e_nname );

		} else if ( rs->sr_entry->e_id == fc->fss->s_eid &&
			dn_match( &rs->sr_entry->e_nname, &fc->fss->s_base )) {

		/* OK, the DN is the same and the entryID is the same. Now
		 * see if the fdn resides in the scope.
		 */
			fc->fbase = 1;
			switch ( fc->fss->s_op->ors_scope ) {
			case LDAP_SCOPE_BASE:
				fc->fscope = dn_match( fc->fdn, &rs->sr_entry->e_nname );
				break;
			case LDAP_SCOPE_ONELEVEL: {
				struct berval pdn;
				dnParent( fc->fdn, &pdn );
				fc->fscope = dn_match( &pdn, &rs->sr_entry->e_nname );
				break; }
			case LDAP_SCOPE_SUBTREE:
				fc->fscope = dnIsSuffix( fc->fdn, &rs->sr_entry->e_nname );
				break;
#ifdef LDAP_SCOPE_SUBORDINATE
			case LDAP_SCOPE_SUBORDINATE:
				fc->fscope = dnIsSuffix( fc->fdn, &rs->sr_entry->e_nname ) &&
					!dn_match( fc->fdn, &rs->sr_entry->e_nname );
				break;
#endif
			}
		}
	}
	return LDAP_SUCCESS;
}

static int
syncprov_findbase( Operation *op, fbase_cookie *fc )
{
	opcookie *opc = op->o_callback->sc_private;
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;

	slap_callback cb = {0};
	Operation fop;
	SlapReply frs = { REP_RESULT };
	int rc;

	fop = *op;

	cb.sc_response = findbase_cb;
	cb.sc_private = fc;

	fop.o_sync_mode &= SLAP_CONTROL_MASK;	/* turn off sync mode */
	fop.o_callback = &cb;
	fop.o_tag = LDAP_REQ_SEARCH;
	fop.ors_scope = LDAP_SCOPE_BASE;
	fop.ors_deref = fc->fss->s_op->ors_deref;
	fop.ors_slimit = 1;
	fop.ors_tlimit = SLAP_NO_LIMIT;
	fop.ors_attrs = slap_anlist_no_attrs;
	fop.ors_attrsonly = 1;
	fop.ors_filter = fc->fss->s_op->ors_filter;
	fop.ors_filterstr = fc->fss->s_op->ors_filterstr;

	fop.o_req_ndn = fc->fss->s_op->o_req_ndn;

	fop.o_bd->bd_info = on->on_info->oi_orig;
	rc = fop.o_bd->be_search( &fop, &frs );
	fop.o_bd->bd_info = (BackendInfo *)on;

	if ( fc->fbase ) return LDAP_SUCCESS;

	/* If entryID has changed, then the base of this search has
	 * changed. Invalidate the psearch.
	 */
	return LDAP_NO_SUCH_OBJECT;
}

/* syncprov_findcsn:
 *   This function has three different purposes, but they all use a search
 * that filters on entryCSN so they're combined here.
 * 1: when the current contextCSN is unknown (i.e., at server start time)
 * and a syncrepl search has arrived with a cookie, we search for all entries
 * with CSN >= the cookie CSN, and store the maximum as our contextCSN. Also,
 * we expect to find the cookie CSN in the search results, and note if we did
 * or not. If not, we assume the cookie is stale. (This may be too restrictive,
 * notice case 2.)
 *
 * 2: when the current contextCSN is known and we have a sync cookie, we search
 * for one entry with CSN <= the cookie CSN. (Used to search for =.) If an
 * entry is found, the cookie CSN is valid, otherwise it is stale. Case 1 is
 * considered a special case of case 2, and both are generally called the
 * "find CSN" task.
 *
 * 3: during a refresh phase, we search for all entries with CSN <= the cookie
 * CSN, and generate Present records for them. We always collect this result
 * in SyncID sets, even if there's only one match.
 */
#define	FIND_CSN	1
#define	FIND_PRESENT	2

typedef struct fcsn_cookie {
	struct berval maxcsn;
	int gotmatch;
} fcsn_cookie;

static int
findcsn_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;

	if ( rs->sr_type == REP_SEARCH && rs->sr_err == LDAP_SUCCESS ) {
		/* If the private pointer is set, it points to an fcsn_cookie
		 * and we want to record the maxcsn and match state.
		 */
		if ( sc->sc_private ) {
			int i;
			fcsn_cookie *fc = sc->sc_private;
			syncrepl_state *srs = op->o_controls[sync_cid];
			Attribute *a = attr_find(rs->sr_entry->e_attrs,
				slap_schema.si_ad_entryCSN );
			i = ber_bvcmp( &a->a_vals[0], srs->sr_state.ctxcsn );
			if ( i == 0 ) fc->gotmatch = 1;
			i = ber_bvcmp( &a->a_vals[0], &fc->maxcsn );
			if ( i > 0 ) {
				fc->maxcsn.bv_len = a->a_vals[0].bv_len;
				strcpy(fc->maxcsn.bv_val, a->a_vals[0].bv_val );
			}
		} else {
		/* Otherwise, if the private pointer is not set, we just
		 * want to know if any entry matched the filter.
		 */
			sc->sc_private = (void *)1;
		}
	}
	return LDAP_SUCCESS;
}

/* Build a list of entryUUIDs for sending in a SyncID set */

typedef struct fpres_cookie {
	int num;
	BerVarray uuids;
} fpres_cookie;

static int
findpres_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;
	fpres_cookie *pc = sc->sc_private;
	int ret = SLAP_CB_CONTINUE;

	if ( rs->sr_type == REP_SEARCH ) {
		ret = slap_build_syncUUID_set( op, &pc->uuids, rs->sr_entry );
		if ( ret > 0 ) {
			pc->num++;
			ret = LDAP_SUCCESS;
			if ( pc->num == SLAP_SYNCUUID_SET_SIZE ) {
				rs->sr_rspoid = LDAP_SYNC_INFO;
				ret = slap_send_syncinfo( op, rs, LDAP_TAG_SYNC_ID_SET, NULL,
					0, pc->uuids, 0 );
				ber_bvarray_free_x( pc->uuids, op->o_tmpmemctx );
				pc->uuids = NULL;
				pc->num = 0;
			}
		} else {
			ret = LDAP_OTHER;
		}
	} else if ( rs->sr_type == REP_RESULT ) {
		ret = rs->sr_err;
		if ( pc->num ) {
			rs->sr_rspoid = LDAP_SYNC_INFO;
			ret = slap_send_syncinfo( op, rs, LDAP_TAG_SYNC_ID_SET, NULL,
				0, pc->uuids, 0 );
			ber_bvarray_free_x( pc->uuids, op->o_tmpmemctx );
			pc->uuids = NULL;
			pc->num = 0;
		}
	}
	return ret;
}


static int
syncprov_findcsn( Operation *op, int mode )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	slap_callback cb = {0};
	Operation fop;
	SlapReply frs = { REP_RESULT };
	char buf[LDAP_LUTIL_CSNSTR_BUFSIZE + STRLENOF("(entryCSN<=)")];
	char cbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];
	struct berval fbuf;
	Filter cf;
	AttributeAssertion eq;
	int rc;
	fcsn_cookie fcookie;
	fpres_cookie pcookie;
	int locked = 0;
	syncrepl_state *srs = op->o_controls[sync_cid];

	if ( srs->sr_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE ) {
		return LDAP_OTHER;
	}

	fop = *op;
	fop.o_sync_mode &= SLAP_CONTROL_MASK;	/* turn off sync_mode */

	fbuf.bv_val = buf;
	if ( mode == FIND_CSN ) {
		if ( !si->si_gotcsn ) {
			/* If we don't know the current ctxcsn, find it */
			ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
			locked = 1;
		}
		if ( !si->si_gotcsn ) {
			cf.f_choice = LDAP_FILTER_GE;
			fop.ors_attrsonly = 0;
			fop.ors_attrs = csn_anlist;
			fop.ors_slimit = SLAP_NO_LIMIT;
			cb.sc_private = &fcookie;
			fcookie.maxcsn.bv_val = cbuf;
			fcookie.maxcsn.bv_len = 0;
			fcookie.gotmatch = 0;
			fbuf.bv_len = sprintf( buf, "(entryCSN>=%s)", srs->sr_state.ctxcsn->bv_val );
		} else {
			if ( locked ) {
				ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );
				locked = 0;
			}
			cf.f_choice = LDAP_FILTER_LE;
			fop.ors_attrsonly = 1;
			fop.ors_attrs = slap_anlist_no_attrs;
			fop.ors_slimit = 1;
			cb.sc_private = NULL;
			fbuf.bv_len = sprintf( buf, "(entryCSN<=%s)", srs->sr_state.ctxcsn->bv_val );
		}
		cb.sc_response = findcsn_cb;

	} else if ( mode == FIND_PRESENT ) {
		cf.f_choice = LDAP_FILTER_LE;
		fop.ors_attrsonly = 0;
		fop.ors_attrs = uuid_anlist;
		fop.ors_slimit = SLAP_NO_LIMIT;
		/* We want pure entries, not referrals */
		fop.o_managedsait = SLAP_CONTROL_CRITICAL;
		cb.sc_private = &pcookie;
		cb.sc_response = findpres_cb;
		pcookie.num = 0;
		pcookie.uuids = NULL;
		fbuf.bv_len = sprintf( buf, "(entryCSN<=%s)", srs->sr_state.ctxcsn->bv_val );
	}
	cf.f_ava = &eq;
	cf.f_av_desc = slap_schema.si_ad_entryCSN;
	cf.f_av_value = *srs->sr_state.ctxcsn;
	cf.f_next = NULL;

	fop.o_callback = &cb;
	fop.ors_tlimit = SLAP_NO_LIMIT;
	fop.ors_filter = &cf;
	fop.ors_filterstr = fbuf;

	fop.o_bd->bd_info = on->on_info->oi_orig;
	rc = fop.o_bd->be_search( &fop, &frs );
	fop.o_bd->bd_info = (BackendInfo *)on;

	if ( mode == FIND_CSN ) {
		if ( !si->si_gotcsn ) {
			ber_dupbv( &si->si_ctxcsn, &fcookie.maxcsn );
			si->si_gotcsn = 1;
			ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );
			if ( fcookie.gotmatch ) return LDAP_SUCCESS;
			
		} else {
			if ( cb.sc_private ) return LDAP_SUCCESS;
		}
	} else if ( mode == FIND_PRESENT ) {
		return LDAP_SUCCESS;
	}

	/* If matching CSN was not found, invalidate the context. */
	return LDAP_NO_SUCH_OBJECT;
}

static int
syncprov_sendresp( Operation *op, opcookie *opc, syncops *so, Entry *e, int mode )
{
	slap_overinst *on = opc->son;
	syncprov_info_t *si = on->on_bi.bi_private;

	SlapReply rs = { REP_SEARCH };
	LDAPControl *ctrls[2];
	struct berval cookie;
	Entry e_uuid = {0};
	Attribute a_uuid = {0};
	Operation sop = *so->s_op;
	Opheader ohdr;
	syncrepl_state *srs = sop.o_controls[sync_cid];

	ohdr = *sop.o_hdr;
	sop.o_hdr = &ohdr;
	sop.o_tmpmemctx = op->o_tmpmemctx;

	ctrls[1] = NULL;
	slap_compose_sync_cookie( op, &cookie, &opc->sctxcsn,
		srs->sr_state.sid, srs->sr_state.rid );

	e_uuid.e_attrs = &a_uuid;
	a_uuid.a_desc = slap_schema.si_ad_entryUUID;
	a_uuid.a_nvals = &opc->suuid;
	rs.sr_err = slap_build_sync_state_ctrl( &sop, &rs, &e_uuid,
		mode, ctrls, 0, 1, &cookie );

	rs.sr_entry = e;
	rs.sr_ctrls = ctrls;
	switch( mode ) {
	case LDAP_SYNC_ADD:
		if ( opc->sreference ) {
			rs.sr_ref = get_entry_referrals( &sop, e );
			send_search_reference( &sop, &rs );
			ber_bvarray_free( rs.sr_ref );
			break;
		}
		/* fallthru */
	case LDAP_SYNC_MODIFY:
		rs.sr_attrs = sop.ors_attrs;
		send_search_entry( &sop, &rs );
		break;
	case LDAP_SYNC_DELETE:
		e_uuid.e_attrs = NULL;
		e_uuid.e_name = opc->sdn;
		e_uuid.e_nname = opc->sndn;
		rs.sr_entry = &e_uuid;
		if ( opc->sreference ) {
			struct berval bv;
			bv.bv_val = NULL;
			bv.bv_len = 0;
			rs.sr_ref = &bv;
			send_search_reference( &sop, &rs );
		} else {
			send_search_entry( &sop, &rs );
		}
		break;
	default:
		assert(0);
	}
	free( rs.sr_ctrls[0] );
	return rs.sr_err;
}

static void
syncprov_matchops( Operation *op, opcookie *opc, int saveit )
{
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;

	fbase_cookie fc;
	syncops *ss;
	Entry *e;
	Attribute *a;
	int rc;
	struct berval newdn;

	fc.fdn = &op->o_req_ndn;
	/* compute new DN */
	if ( op->o_tag == LDAP_REQ_MODRDN && !saveit ) {
		struct berval pdn;
		if ( op->orr_nnewSup ) pdn = *op->orr_nnewSup;
		else dnParent( fc.fdn, &pdn );
		build_new_dn( &newdn, &pdn, &op->orr_nnewrdn, op->o_tmpmemctx );
		fc.fdn = &newdn;
	}
	if ( op->o_tag != LDAP_REQ_ADD ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		rc = be_entry_get_rw( op, fc.fdn, NULL, NULL, 0, &e );
		op->o_bd->bd_info = (BackendInfo *)on;
		if ( rc ) return;
	} else {
		e = op->ora_e;
	}

	if ( saveit ) {
		ber_dupbv_x( &opc->sdn, &e->e_name, op->o_tmpmemctx );
		ber_dupbv_x( &opc->sndn, &e->e_nname, op->o_tmpmemctx );
		opc->sreference = is_entry_referral( e );
	}
	if ( saveit || op->o_tag == LDAP_REQ_ADD ) {
		a = attr_find( e->e_attrs, slap_schema.si_ad_entryUUID );
		if ( a )
			ber_dupbv_x( &opc->suuid, &a->a_nvals[0], op->o_tmpmemctx );
	}

	ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
	for (ss = si->si_ops; ss; ss=ss->s_next)
	{
		syncmatches *sm;
		int found = 0;

		/* validate base */
		fc.fss = ss;
		fc.fbase = 0;
		fc.fscope = 0;
		rc = syncprov_findbase( op, &fc );
		if ( rc != LDAP_SUCCESS ) continue;

		/* If we're sending results now, look for this op in old matches */
		if ( !saveit ) {
			syncmatches *old;
			for ( sm=opc->smatches, old=(syncmatches *)&opc->smatches; sm;
				old=sm, sm=sm->sm_next ) {
				if ( sm->sm_op == ss ) {
					found = 1;
					old->sm_next = sm->sm_next;
					op->o_tmpfree( sm, op->o_tmpmemctx );
					break;
				}
			}
		}

		/* check if current o_req_dn is in scope and matches filter */
		if ( fc.fscope && test_filter( op, e, ss->s_filter ) ==
			LDAP_COMPARE_TRUE ) {
			if ( saveit ) {
				sm = op->o_tmpalloc( sizeof(syncmatches), op->o_tmpmemctx );
				sm->sm_next = opc->smatches;
				sm->sm_op = ss;
				opc->smatches = sm;
			} else {
				/* if found send UPDATE else send ADD */
				syncprov_sendresp( op, opc, ss, e,
					found ?  LDAP_SYNC_MODIFY : LDAP_SYNC_ADD );
			}
		} else if ( !saveit && found ) {
			/* send DELETE */
			syncprov_sendresp( op, opc, ss, NULL, LDAP_SYNC_DELETE );
		}
	}
	ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
	if ( op->o_tag != LDAP_REQ_ADD ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		be_entry_release_r( op, e );
		op->o_bd->bd_info = (BackendInfo *)on;
	}
}

static int
syncprov_op_cleanup( Operation *op, SlapReply *rs )
{
	slap_callback *cb = op->o_callback;
	opcookie *opc = cb->sc_private;
	syncmatches *sm, *snext;

	for (sm = opc->smatches; sm; sm=snext) {
		snext = sm->sm_next;
		op->o_tmpfree( sm, op->o_tmpmemctx );
	}
	op->o_callback = cb->sc_next;
	op->o_tmpfree(cb, op->o_tmpmemctx);
}

static int
syncprov_op_response( Operation *op, SlapReply *rs )
{
	opcookie *opc = op->o_callback->sc_private;
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;
	syncmatches *sm;

	if ( rs->sr_err == LDAP_SUCCESS )
	{
		struct berval maxcsn;
		char cbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];
		void *memctx = op->o_tmpmemctx;

		cbuf[0] = '\0';
		ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
		op->o_tmpmemctx = NULL;
		slap_get_commit_csn( op, &maxcsn );
		op->o_tmpmemctx = memctx;
		if ( maxcsn.bv_val ) {
			strcpy( cbuf, maxcsn.bv_val );
			free( si->si_ctxcsn.bv_val );
			si->si_ctxcsn = maxcsn;
			si->si_gotcsn = 1;
		}
		ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );

		opc->sctxcsn.bv_len = maxcsn.bv_len;
		opc->sctxcsn.bv_val = cbuf;

		if ( si->si_ops ) {
			switch(op->o_tag) {
			case LDAP_REQ_ADD:
			case LDAP_REQ_MODIFY:
			case LDAP_REQ_MODRDN:
			case LDAP_REQ_EXTENDED:
				syncprov_matchops( op, opc, 0 );
				break;
			case LDAP_REQ_DELETE:
				/* for each match in opc->smatches:
				 *   send DELETE msg
				 */
				for ( sm = opc->smatches; sm; sm=sm->sm_next ) {
					syncprov_sendresp( op, opc, sm->sm_op, NULL,
						LDAP_SYNC_DELETE );
				}
				break;
			}
		}

	}
	return SLAP_CB_CONTINUE;
}

#if 0
static int
syncprov_op_compare( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;
	int rc = SLAP_CB_CONTINUE;

	if ( dn_match( &op->o_req_ndn, &si->si_e->e_nname ) )
	{
		Attribute *a;

		ldap_pvt_thread_mutex_lock( &si->si_e_mutex );

		if ( get_assert( op ) &&
			( test_filter( op, si->si_e, get_assertion( op ) ) != LDAP_COMPARE_TRUE ) )
		{
			rs->sr_err = LDAP_ASSERTION_FAILED;
			goto return_results;
		}

		rs->sr_err = access_allowed( op, si->si_e, op->oq_compare.rs_ava->aa_desc,
			&op->oq_compare.rs_ava->aa_value, ACL_COMPARE, NULL );
		if ( ! rs->sr_err ) {
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		rs->sr_err = LDAP_NO_SUCH_ATTRIBUTE;

		for ( a = attr_find( si->si_e->e_attrs, op->oq_compare.rs_ava->aa_desc );
			a != NULL;
			a = attr_find( a->a_next, op->oq_compare.rs_ava->aa_desc ) )
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

return_results:;

		ldap_pvt_thread_mutex_unlock( &si->si_e_mutex );

		send_ldap_result( op, rs );

		if( rs->sr_err == LDAP_COMPARE_FALSE || rs->sr_err == LDAP_COMPARE_TRUE ) {
			rs->sr_err = LDAP_SUCCESS;
		}
		rc = rs->sr_err;
	}

	return SLAP_CB_CONTINUE;
}
#endif
	
static int
syncprov_op_mod( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
	opcookie *opc = (opcookie *)(cb+1);
	opc->son = on;
	cb->sc_response = syncprov_op_response;
	cb->sc_cleanup = syncprov_op_cleanup;
	cb->sc_private = opc;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;

	if ( si->si_ops && op->o_tag != LDAP_REQ_ADD )
		syncprov_matchops( op, opc, 1 );

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_extended( Operation *op, SlapReply *rs )
{
	if ( exop_is_write( op ))
		return syncprov_op_mod( op, rs );

	return SLAP_CB_CONTINUE;
}

typedef struct searchstate {
	slap_overinst *ss_on;
	syncops *ss_so;
	int ss_done;
} searchstate;

static int
syncprov_search_cleanup( Operation *op, SlapReply *rs )
{
	searchstate *ss = op->o_callback->sc_private;
	if ( rs->sr_ctrls ) {
		free( rs->sr_ctrls[0] );
		op->o_tmpfree( rs->sr_ctrls, op->o_tmpmemctx );
	}
	if ( ss->ss_done )
		op->o_sync_mode |= SLAP_SYNC_REFRESH_AND_PERSIST;
	return 0;
}

static int
syncprov_search_response( Operation *op, SlapReply *rs )
{
	searchstate *ss = op->o_callback->sc_private;
	slap_overinst *on = ss->ss_on;
	syncprov_info_t		*si = on->on_bi.bi_private;
	syncrepl_state *srs = op->o_controls[sync_cid];

	if ( rs->sr_type == REP_SEARCH || rs->sr_type == REP_SEARCHREF ) {
		int i;
		if ( srs->sr_state.ctxcsn ) {
			Attribute *a = attr_find( rs->sr_entry->e_attrs,
				slap_schema.si_ad_entryCSN );
			/* Don't send the ctx entry twice */
			if ( bvmatch( &a->a_nvals[0], srs->sr_state.ctxcsn ))
				return LDAP_SUCCESS;
		}
		rs->sr_ctrls = op->o_tmpalloc( sizeof(LDAPControl *)*2,
			op->o_tmpmemctx );
		rs->sr_ctrls[1] = NULL;
		rs->sr_err = slap_build_sync_state_ctrl( op, rs, rs->sr_entry,
			LDAP_SYNC_ADD, rs->sr_ctrls, 0, 0, NULL );
	} else if ( rs->sr_type == REP_RESULT && rs->sr_err == LDAP_SUCCESS ) {
		struct berval cookie;

		slap_compose_sync_cookie( op, &cookie,
			&op->ors_filter->f_and->f_ava->aa_value,
			srs->sr_state.sid, srs->sr_state.rid );

		/* Is this a regular refresh? */
		if ( !ss->ss_so ) {
			rs->sr_ctrls = op->o_tmpalloc( sizeof(LDAPControl *)*2,
				op->o_tmpmemctx );
			rs->sr_ctrls[1] = NULL;
			rs->sr_err = slap_build_sync_done_ctrl( op, rs, rs->sr_ctrls,
				0, 1, &cookie, LDAP_SYNC_REFRESH_PRESENTS );
		} else {
		/* It's RefreshAndPersist, transition to Persist phase */
			rs->sr_rspoid = LDAP_SYNC_INFO;
			slap_send_syncinfo( op, rs, rs->sr_nentries ?
	 			LDAP_TAG_SYNC_REFRESH_PRESENT : LDAP_TAG_SYNC_REFRESH_DELETE,
				&cookie, 1, NULL, 0 );
			/* Flush any queued persist messages */
				;

			/* Turn off the refreshing flag */
				ss->ss_so->s_flags ^= PS_IS_REFRESHING;

			/* Detach this Op from frontend control */
				ss->ss_done = 1;
				;

			return LDAP_SUCCESS;
		}
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_search( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;
	slap_callback	*cb;
	int gotstate = 0, nochange = 0;
	Filter *fand, *fava;
	syncops *sop = NULL;
	searchstate *ss;
	syncrepl_state *srs;

	if ( !(op->o_sync_mode & SLAP_SYNC_REFRESH) ) return SLAP_CB_CONTINUE;

	if ( op->ors_deref & LDAP_DEREF_SEARCHING ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "illegal value for derefAliases" );
		return rs->sr_err;
	}

	srs = op->o_controls[sync_cid];

	/* If this is a persistent search, set it up right away */
	if ( op->o_sync_mode & SLAP_SYNC_PERSIST ) {
		syncops so;
		fbase_cookie fc;
		opcookie opc;
		slap_callback sc;

		fc.fss = &so;
		fc.fbase = 0;
		so.s_eid = NOID;
		so.s_op = op;
		so.s_flags = PS_IS_REFRESHING;
		/* syncprov_findbase expects to be called as a callback... */
		sc.sc_private = &opc;
		opc.son = on;
		cb = op->o_callback;
		op->o_callback = &sc;
		rs->sr_err = syncprov_findbase( op, &fc );
		op->o_callback = cb;

		if ( rs->sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, rs );
			return rs->sr_err;
		}
		sop = ch_malloc( sizeof( syncops ));
		*sop = so;
		ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
		sop->s_next = si->si_ops;
		si->si_ops = sop;
		ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
	}

	/* If we have a cookie, handle the PRESENT lookups
	 */
	if ( srs->sr_state.ctxcsn ) {
		/* Is the CSN in a valid format? */
		if ( srs->sr_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE ) {
			send_ldap_error( op, rs, LDAP_OTHER, "invalid sync cookie" );
			return rs->sr_err;
		}
		/* Is the CSN still present in the database? */
		if ( syncprov_findcsn( op, FIND_CSN ) != LDAP_SUCCESS ) {
			/* No, so a reload is required */
#if 0		/* the consumer doesn't seem to send this hint */
			if ( op->o_sync_rhint == 0 ) {
				send_ldap_error( op, rs, LDAP_SYNC_REFRESH_REQUIRED, "sync cookie is stale" );
				return rs->sr_err;
			}
#endif
		} else {
			gotstate = 1;
			/* If just Refreshing and nothing has changed, shortcut it */
			if ( bvmatch( srs->sr_state.ctxcsn, &si->si_ctxcsn )) {
				nochange = 1;
				if ( !(op->o_sync_mode & SLAP_SYNC_PERSIST) ) {
					LDAPControl	*ctrls[2];

					ctrls[0] = NULL;
					ctrls[1] = NULL;
					slap_build_sync_done_ctrl( op, rs, ctrls, 0, 0,
						NULL, LDAP_SYNC_REFRESH_DELETES );
					rs->sr_err = LDAP_SUCCESS;
					send_ldap_result( op, rs );
					return rs->sr_err;
				}
				goto shortcut;
			} else 
			/* If context has changed, check for Present UUIDs */
			if ( syncprov_findcsn( op, FIND_PRESENT ) != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				return rs->sr_err;
			}
		}
	}

	/* If we didn't get a cookie and we don't know our contextcsn, try to
	 * find it anyway.
	 */
	if ( !gotstate && !si->si_gotcsn ) {
		struct berval bv = BER_BVC("1"), *old;
		
		old = srs->sr_state.ctxcsn;
		srs->sr_state.ctxcsn = &bv;
		syncprov_findcsn( op, FIND_CSN );
		srs->sr_state.ctxcsn = old;
	}

	/* Append CSN range to search filter, save original filter
	 * for persistent search evaluation
	 */
	if ( sop ) {
		sop->s_filter = op->ors_filter;
	}

	fand = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
	fand->f_choice = LDAP_FILTER_AND;
	fand->f_next = NULL;
	fava = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
	fava->f_choice = LDAP_FILTER_LE;
	fava->f_ava = op->o_tmpalloc( sizeof(AttributeAssertion), op->o_tmpmemctx );
	fava->f_ava->aa_desc = slap_schema.si_ad_entryCSN;
	ber_dupbv_x( &fava->f_ava->aa_value, &si->si_ctxcsn, op->o_tmpmemctx );
	fand->f_and = fava;
	if ( gotstate ) {
		fava->f_next = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
		fava = fava->f_next;
		fava->f_choice = LDAP_FILTER_GE;
		fava->f_ava = op->o_tmpalloc( sizeof(AttributeAssertion), op->o_tmpmemctx );
		fava->f_ava->aa_desc = slap_schema.si_ad_entryCSN;
		ber_dupbv_x( &fava->f_ava->aa_value, srs->sr_state.ctxcsn, op->o_tmpmemctx );
	}
	fava->f_next = op->ors_filter;
	op->ors_filter = fand;
	filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

shortcut:
	/* Let our callback add needed info to returned entries */
	cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(searchstate), op->o_tmpmemctx);
	ss = (searchstate *)(cb+1);
	ss->ss_on = on;
	ss->ss_so = sop;
	ss->ss_done = 0;
	cb->sc_response = syncprov_search_response;
	cb->sc_cleanup = syncprov_search_cleanup;
	cb->sc_private = ss;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;

	/* FIXME: temporary hack to make sure back-bdb's native Psearch handling
	 * doesn't get invoked. We can skip this after the back-bdb code is
	 * removed, and also delete ss->ss_done.
	 */
	op->o_sync_mode &= SLAP_CONTROL_MASK;

	/* If this is a persistent search and no changes were reported during
	 * the refresh phase, just invoke the response callback to transition
	 * us into persist phase
	 */
	if ( nochange ) {
		rs->sr_err = LDAP_SUCCESS;
		rs->sr_nentries = 0;
		send_ldap_result( op, rs );
		return rs->sr_err;
	}
	return SLAP_CB_CONTINUE;
}

static int
syncprov_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char	**argv
)
{
	slap_overinst		*on = (slap_overinst *)be->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;

#if 0
	if ( strcasecmp( argv[ 0 ], "syncprov-checkpoint" ) == 0 ) {
		if ( argc != 3 ) {
			fprintf( stderr, "%s: line %d: wrong number of arguments in "
				"\"syncprov-checkpoint <ops> <minutes>\"\n", fname, lineno );
			return -1;
		}
		si->si_chkops = atoi( argv[1] );
		si->si_chktime = atoi( argv[2] ) * 60;

	} else {
		return SLAP_CONF_UNKNOWN;
	}
#endif

	return SLAP_CONF_UNKNOWN;
}

static int
syncprov_db_init(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	syncprov_info_t	*si;

	si = ch_calloc(1, sizeof(syncprov_info_t));
	on->on_bi.bi_private = si;
	ldap_pvt_thread_mutex_init( &si->si_csn_mutex );
	ldap_pvt_thread_mutex_init( &si->si_ops_mutex );

	csn_anlist[0].an_desc = slap_schema.si_ad_entryCSN;
	csn_anlist[0].an_name = slap_schema.si_ad_entryCSN->ad_cname;

	uuid_anlist[0].an_desc = slap_schema.si_ad_entryUUID;
	uuid_anlist[0].an_name = slap_schema.si_ad_entryUUID->ad_cname;

	sync_cid = slap_cids.sc_LDAPsync;

	return 0;
}

static int
syncprov_db_destroy(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	syncprov_info_t	*si = (syncprov_info_t *)on->on_bi.bi_private;

	if ( si ) {
		ldap_pvt_thread_mutex_destroy( &si->si_ops_mutex );
		ldap_pvt_thread_mutex_destroy( &si->si_csn_mutex );
		ch_free( si );
	}

	return 0;
}

/* This overlay is set up for dynamic loading via moduleload. For static
 * configuration, you'll need to arrange for the slap_overinst to be
 * initialized and registered by some other function inside slapd.
 */

static slap_overinst 		syncprov;

int
syncprov_init()
{
	syncprov.on_bi.bi_type = "syncprov";
	syncprov.on_bi.bi_db_init = syncprov_db_init;
	syncprov.on_bi.bi_db_config = syncprov_db_config;
	syncprov.on_bi.bi_db_destroy = syncprov_db_destroy;

	syncprov.on_bi.bi_op_add = syncprov_op_mod;
#if 0
	syncprov.on_bi.bi_op_compare = syncprov_op_compare;
#endif
	syncprov.on_bi.bi_op_delete = syncprov_op_mod;
	syncprov.on_bi.bi_op_modify = syncprov_op_mod;
	syncprov.on_bi.bi_op_modrdn = syncprov_op_mod;
	syncprov.on_bi.bi_op_search = syncprov_op_search;
	syncprov.on_bi.bi_extended = syncprov_op_extended;

#if 0
	syncprov.on_response = syncprov_response;
#endif

	return overlay_register( &syncprov );
}

#if SLAPD_OVER_SYNCPROV == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return syncprov_init();
}
#endif /* SLAPD_OVER_SYNCPROV == SLAPD_MOD_DYNAMIC */

#endif /* defined(SLAPD_OVER_SYNCPROV) */
