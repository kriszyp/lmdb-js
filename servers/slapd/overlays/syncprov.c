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

#define	SLAPD_OVER_SYNCPROV	SLAPD_MOD_DYNAMIC

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
	int		s_flags;	/* search status */
} syncops;

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
	struct berval suuid;
} opcookie;

typedef struct findcookie {
	struct berval *fdn;
	syncops *fss;
	int fbase;
	int fsuffix;
} findcookie;

static AttributeName csn_anlist[2];
static AttributeName uuid_anlist[2];

static int
dn_avl_cmp( const void *c1, const void *c2 )
{
	struct berval *bv1 = (struct berval *)c1;
	struct berval *bv2 = (struct berval *)c2;
	int rc = bv1->bv_len - bv2->bv_len;

	if ( rc ) return rc;
	return ber_bvcmp( bv1, bv2 );
}

static int
findbase_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;

	if ( rs->sr_type == REP_SEARCH && rs->sr_err == LDAP_SUCCESS ) {
		findcookie *fc = sc->sc_private;
		if ( rs->sr_entry->e_id == fc->fss->s_eid &&
			dn_match( &rs->sr_entry->e_nname, &fc->fss->s_base )) {
			fc->fbase = 1;
			fc->fsuffix = dnIsSuffix( fc->fdn, &rs->sr_entry->e_nname );
		}
	}
	return LDAP_SUCCESS;
}

static int
syncprov_findbase( Operation *op, syncops *ss, findcookie *fc )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	slap_callback cb = {0};
	Operation fop;
	SlapReply frs = { REP_RESULT };
	int rc;

	fop = *op;

	cb.sc_response = findbase_cb;
	cb.sc_private = fc;

	fop.o_callback = &cb;
	fop.o_tag = LDAP_REQ_SEARCH;
	fop.ors_scope = LDAP_SCOPE_BASE;
	fop.ors_deref = ss->s_op->ors_deref;
	fop.ors_slimit = 1;
	fop.ors_tlimit = SLAP_NO_LIMIT;
	fop.ors_attrs = slap_anlist_no_attrs;
	fop.ors_attrsonly = 1;
	fop.ors_filter = ss->s_op->ors_filter;
	fop.ors_filterstr = ss->s_op->ors_filterstr;

	fop.o_req_ndn = ss->s_op->o_req_ndn;

	rc = fop.o_bd->be_search( &fop, &frs );

	if ( fc->fbase ) return LDAP_SUCCESS;

	/* If entryID has changed, then the base of this search has
	 * changed. Invalidate the psearch.
	 */
	return LDAP_NO_SUCH_OBJECT;
}

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
		if ( sc->sc_private ) {
			int i;
			fcsn_cookie *fc = sc->sc_private;
			Attribute *a = attr_find(rs->sr_entry->e_attrs,
				slap_schema.si_ad_entryCSN );
			i = ber_bvcmp( &a->a_vals[0], op->o_sync_state.ctxcsn );
			if ( i == 0 ) fc->gotmatch = 1;
			i = ber_bvcmp( &a->a_vals[0], &fc->maxcsn );
			if ( i > 0 ) {
				fc->maxcsn.bv_len = a->a_vals[0].bv_len;
				strcpy(fc->maxcsn.bv_val, a->a_vals[0].bv_val );
			}
		} else {
			sc->sc_private = (void *)1;
		}
	}
	return LDAP_SUCCESS;
}

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
		Debug(LDAP_DEBUG_TRACE, "present %s\n", rs->sr_entry->e_name.bv_val, 0, 0);
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

	if ( op->o_sync_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE ) {
		return LDAP_OTHER;
	}

	fop = *op;
	fop.o_sync_mode = 0;

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
			fbuf.bv_len = sprintf( buf, "(entryCSN>=%s)", op->o_sync_state.ctxcsn->bv_val );
		} else {
			if ( locked ) {
				ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );
				locked = 1;
			}
			cf.f_choice = LDAP_FILTER_EQUALITY;
			fop.ors_attrsonly = 1;
			fop.ors_attrs = slap_anlist_no_attrs;
			fop.ors_slimit = 1;
			cb.sc_private = NULL;
			fbuf.bv_len = sprintf( buf, "(entryCSN=%s)", op->o_sync_state.ctxcsn->bv_val );
		}
		cb.sc_response = findcsn_cb;

	} else if ( mode == FIND_PRESENT ) {
		cf.f_choice = LDAP_FILTER_LE;
		fop.ors_attrsonly = 0;
		fop.ors_attrs = uuid_anlist;
		fop.ors_slimit = SLAP_NO_LIMIT;
		cb.sc_private = &pcookie;
		cb.sc_response = findpres_cb;
		pcookie.num = 0;
		pcookie.uuids = NULL;
		fbuf.bv_len = sprintf( buf, "(entryCSN<=%s)", op->o_sync_state.ctxcsn->bv_val );
	}
	cf.f_ava = &eq;
	cf.f_av_desc = slap_schema.si_ad_entryCSN;
	cf.f_av_value = *op->o_sync_state.ctxcsn;
	cf.f_next = NULL;

	fop.o_callback = &cb;
	fop.ors_tlimit = SLAP_NO_LIMIT;
	fop.ors_filter = &cf;
	fop.ors_filterstr = fbuf;

	fop.o_bd->bd_info = on->on_info->oi_orig;
	rc = fop.o_bd->be_search( &fop, &frs );
	fop.o_bd->bd_info = on;

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

static void
syncprov_matchops( Operation *op, opcookie *opc, int saveit )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	findcookie fc;
	syncops *ss;
	Entry *e;
	Attribute *a;
	int rc;

	fc.fdn = &op->o_req_ndn;
	rc = be_entry_get_rw( op, fc.fdn, NULL, NULL, 0, &e );
	if ( rc ) return;

	if ( saveit ) {
		a = attr_find( e->e_attrs, slap_schema.si_ad_entryUUID );
		if ( a )
			ber_dupbv_x( &opc->suuid, &a->a_vals[0], op->o_tmpmemctx );
	}

	ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
	for (ss = si->si_ops; ss; ss=ss->s_next)
	{
		syncmatches *sm;
		int found = 0;

		/* validate base */
		fc.fss = ss;
		fc.fbase = 0;
		fc.fsuffix = 0;
		rc = syncprov_findbase( op, ss, &fc );
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
		if ( fc.fsuffix && test_filter( op, e, ss->s_op->ors_filter ) ==
			LDAP_COMPARE_TRUE ) {
			if ( saveit ) {
				sm = op->o_tmpalloc( sizeof(syncmatches), op->o_tmpmemctx );
				sm->sm_next = opc->smatches;
				sm->sm_op = ss;
				opc->smatches = sm;
			} else {
				/* if found send UPDATE else send ADD */
				if ( found ) {
				} else {
				}
			}
		} else if ( !saveit && found ) {
			/* send DELETE */
		}
	}
	ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
	be_entry_release_r( op, e );
}

static int
syncprov_op_cleanup( Operation *op, SlapReply *rs )
{
	slap_callback *cb = op->o_callback;
	opcookie *opc = (opcookie *)(cb+1);
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
	slap_callback *cb = op->o_callback;
	opcookie *opc = (opcookie *)(cb+1);
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;
	syncmatches *sm;

	if ( rs->sr_err == LDAP_SUCCESS )
	{
		struct berval maxcsn;
		void *memctx = op->o_tmpmemctx;

		ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
		op->o_tmpmemctx = NULL;
		slap_get_commit_csn( op, &maxcsn );
		op->o_tmpmemctx = memctx;
		if ( maxcsn.bv_val ) {
			free( si->si_ctxcsn.bv_val );
			si->si_ctxcsn = maxcsn;
			si->si_gotcsn = 1;
		}
		ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );

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

static int
syncprov_search_cleanup( Operation *op, SlapReply *rs )
{
	if ( rs->sr_ctrls ) {
		free( rs->sr_ctrls[0] );
		op->o_tmpfree( rs->sr_ctrls, op->o_tmpmemctx );
	}
	return 0;
}

static int
syncprov_search_response( Operation *op, SlapReply *rs )
{
	slap_callback *cb = op->o_callback;
	slap_overinst *on = cb->sc_private;
	syncprov_info_t		*si = on->on_bi.bi_private;

	if ( rs->sr_type == REP_SEARCH ) {
		int i;
		if ( op->o_sync_state.ctxcsn ) {
			Attribute *a = attr_find( rs->sr_entry->e_attrs,
				slap_schema.si_ad_entryCSN );
			/* Don't send the ctx entry twice */
			if ( bvmatch( &a->a_nvals[0], op->o_sync_state.ctxcsn ))
				return LDAP_SUCCESS;
		}
		rs->sr_ctrls = op->o_tmpalloc( sizeof(LDAPControl *)*2,
			op->o_tmpmemctx );
		rs->sr_ctrls[1] = NULL;
		rs->sr_err = slap_build_sync_state_ctrl( op, rs, rs->sr_entry,
			LDAP_SYNC_ADD, rs->sr_ctrls, 0, 0, NULL );
	} else if (rs->sr_type == REP_RESULT ) {
		struct berval cookie;
		rs->sr_ctrls = op->o_tmpalloc( sizeof(LDAPControl *)*2,
			op->o_tmpmemctx );
		rs->sr_ctrls[1] = NULL;
		slap_compose_sync_cookie( op, &cookie,
			&op->ors_filter->f_and->f_ava->aa_value,
			op->o_sync_state.sid, op->o_sync_state.rid );
		rs->sr_err = slap_build_sync_done_ctrl( op, rs, rs->sr_ctrls,
			0, 1, &cookie, LDAP_SYNC_REFRESH_PRESENTS );
	}

	return SLAP_CB_CONTINUE;
}

static int
syncprov_op_search( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;
	slap_callback	*cb;
	int gotstate = 0;
	Filter *fand, *fava;

	if ( !op->o_sync_mode ) return SLAP_CB_CONTINUE;

	if ( op->ors_deref & LDAP_DEREF_SEARCHING ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "illegal value for derefAliases" );
		return rs->sr_err;
	}

	/* If we have a cookie, handle the PRESENT lookups
	 */
	if ( op->o_sync_state.ctxcsn ) {
		/* Is the CSN in a valid format? */
		if ( op->o_sync_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE ) {
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
			/* Does it match the current ctxCSN? */
			if ( bvmatch( op->o_sync_state.ctxcsn, &si->si_ctxcsn )) {
				LDAPControl	*ctrls[2];

				ctrls[0] = NULL;
				ctrls[1] = NULL;
				slap_build_sync_done_ctrl( op, rs, ctrls, 0, 0,
					NULL, LDAP_SYNC_REFRESH_DELETES );
				rs->sr_err = LDAP_SUCCESS;
				send_ldap_result( op, rs );
				return rs->sr_err;
			}
			gotstate = 1;
			/* OK, let's send all the Present UUIDs */
			if ( syncprov_findcsn( op, FIND_PRESENT ) != LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				return rs->sr_err;
			}
		}
	}

	if ( !gotstate && !si->si_gotcsn ) {
		struct berval bv = BER_BVC("1"), *old;
		
		old = op->o_sync_state.ctxcsn;
		op->o_sync_state.ctxcsn = &bv;
		syncprov_findcsn( op, FIND_CSN );
		op->o_sync_state.ctxcsn = old;
	}

	/* Append CSN range to search filter */
	op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );

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
		ber_dupbv_x( &fava->f_ava->aa_value, op->o_sync_state.ctxcsn, op->o_tmpmemctx );
	}
	fava->f_next = op->ors_filter;
	op->ors_filter = fand;
	filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

	/* Let our callback add needed info to returned entries */
	cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(opcookie), op->o_tmpmemctx);
	cb->sc_response = syncprov_search_response;
	cb->sc_cleanup = syncprov_search_cleanup;
	cb->sc_private = on;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;

	return SLAP_CB_CONTINUE;
}

#if 0
static int
syncprov_response( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;

	if ( rs->sr_err == LDAP_SUCCESS ) {
		if ( op->o_tag == LDAP_REQ_SEARCH ) {
			/* handle transition from refresh to persist */
			if ( op->o_sync_mode == SLAP_SYNC_REFRESH_AND_PERSIST ) {
			}

		/* If we're checkpointing */
		} else if ( si->si_chkops || si->si_chktime )) {
			int do_check = 0;

			switch ( op->o_tag ) {
			case LDAP_REQ_EXTENDED:
				{ int i, doit = 0;

				/* if not PASSWD_MODIFY, break */
				for ( i=0; write_exop[i]; i++ )
				{
					if ( !ber_bvcmp( write_exop[i], &op->oq_extended.rs_reqoid ))
					{
						doit = 1;
						break;
					}
				}
				if ( !doit ) break;
				}
				/* else fallthru */
			case LDAP_REQ_ADD:
			case LDAP_REQ_MODIFY:
			case LDAP_REQ_MODRDN:
			case LDAP_REQ_DELETE:
				ldap_pvt_thread_mutex_lock( &si->si_chk_mutex );
				if ( si->si_chkops )
				{
					si->si_numops++;
					if ( si->si_numops >= si->si_chkops )
					{
						do_check = 1;
						si->si_numops = 0;
					}
				}
				if ( si->si_chktime )
				{
					if ( op->o_time - si->si_chklast >= si->si_chktime )
					{
						do_check = 1;
						si->si_chklast = op->o_time;
					}
				}
				ldap_pvt_thread_mutex_unlock( &si->si_chk_mutex );
				if ( do_check )
				{
					/* write cn=ldapsync to underlying db */
				}
				break;
			}
		}
	}
	/* Release this DN */
	if ( op->o_tag == LDAP_REQ_MODIFY ) {
		ldap_pvt_thread_mutex_lock( &si->si_mod_mutex );
		avl_delete( &si->si_mods, &op->o_req_ndn, dn_avl_cmp );
		ldap_pvt_thread_mutex_unlock( &si->si_mod_mutex );
	}
	return SLAP_CB_CONTINUE;
}
#endif

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
