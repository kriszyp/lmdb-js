/* $OpenLDAP$ */
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

/* A modify request on a particular entry */
typedef struct modinst {
	struct modinst *mi_next;
	Operation *mi_op;
} modinst;

typedef struct modtarget {
	struct modinst *mt_mods;
	struct modinst *mt_tail;
	Operation *mt_op;
	ldap_pvt_thread_mutex_t mt_mutex;
} modtarget;

/* A queued result of a persistent search */
typedef struct syncres {
	struct syncres *s_next;
	struct berval s_dn;
	struct berval s_ndn;
	struct berval s_uuid;
	struct berval s_csn;
	char s_mode;
	char s_isreference;
} syncres;

/* Record of a persistent search */
typedef struct syncops {
	struct syncops *s_next;
	struct berval	s_base;		/* ndn of search base */
	ID		s_eid;		/* entryID of search base */
	Operation	*s_op;		/* search op */
	int		s_sid;
	int		s_rid;
	struct berval s_filterstr;
	int		s_flags;	/* search status */
	int		s_inuse;	/* reference count */
	struct syncres *s_res;
	struct syncres *s_restail;
	ldap_pvt_thread_mutex_t	s_mutex;
} syncops;

/* A received sync control */
typedef struct sync_control {
	struct sync_cookie sr_state;
	int sr_rhint;
} sync_control;

#if 0 /* moved back to slap.h */
#define	o_sync	o_ctrlflag[slap_cids.sc_LDAPsync]
#endif
/* o_sync_mode uses data bits of o_sync */
#define	o_sync_mode	o_ctrlflag[slap_cids.sc_LDAPsync]

#define SLAP_SYNC_NONE					(LDAP_SYNC_NONE<<SLAP_CONTROL_SHIFT)
#define SLAP_SYNC_REFRESH				(LDAP_SYNC_REFRESH_ONLY<<SLAP_CONTROL_SHIFT)
#define SLAP_SYNC_PERSIST				(LDAP_SYNC_RESERVED<<SLAP_CONTROL_SHIFT)
#define SLAP_SYNC_REFRESH_AND_PERSIST	(LDAP_SYNC_REFRESH_AND_PERSIST<<SLAP_CONTROL_SHIFT)

#define	PS_IS_REFRESHING	0x01

/* Record of which searches matched at premodify step */
typedef struct syncmatches {
	struct syncmatches *sm_next;
	syncops *sm_op;
} syncmatches;

/* Session log data */
typedef struct slog_entry {
	struct slog_entry *se_next;
	struct berval se_uuid;
	struct berval se_csn;
	ber_tag_t	se_tag;
} slog_entry;

typedef struct sessionlog {
	struct sessionlog *sl_next;
	int		sl_sid;
	struct berval	sl_mincsn;
	int		sl_num;
	int		sl_size;
	slog_entry *sl_head;
	slog_entry *sl_tail;
	ldap_pvt_thread_mutex_t sl_mutex;
} sessionlog;

/* The main state for this overlay */
typedef struct syncprov_info_t {
	syncops		*si_ops;
	struct berval	si_ctxcsn;	/* ldapsync context */
	int		si_chkops;	/* checkpointing info */
	int		si_chktime;
	int		si_numops;	/* number of ops since last checkpoint */
	time_t	si_chklast;	/* time of last checkpoint */
	Avlnode	*si_mods;	/* entries being modified */
	sessionlog	*si_logs;
	ldap_pvt_thread_mutex_t	si_csn_mutex;
	ldap_pvt_thread_mutex_t	si_ops_mutex;
	ldap_pvt_thread_mutex_t	si_mods_mutex;
	char		si_ctxcsnbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];
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

/* Build a LDAPsync intermediate state control */
static int
syncprov_state_ctrl(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e,
	int		entry_sync_state,
	LDAPControl	**ctrls,
	int		num_ctrls,
	int		send_cookie,
	struct berval	*cookie )
{
	Attribute* a;
	int ret;
	int res;
	const char *text = NULL;

	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	struct berval	entryuuid_bv = BER_BVNULL;

	ber_init2( ber, 0, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = op->o_tmpalloc( sizeof ( LDAPControl ), op->o_tmpmemctx );

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		AttributeDescription *desc = a->a_desc;
		if ( desc == slap_schema.si_ad_entryUUID ) {
			entryuuid_bv = a->a_nvals[0];
			break;
		}
	}

	if ( send_cookie && cookie ) {
		ber_printf( ber, "{eOON}",
			entry_sync_state, &entryuuid_bv, cookie );
	} else {
		ber_printf( ber, "{eON}",
			entry_sync_state, &entryuuid_bv );
	}

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_STATE;
	ctrls[num_ctrls]->ldctl_iscritical = (op->o_sync == SLAP_CONTROL_CRITICAL);
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

/* Build a LDAPsync final state control */
static int
syncprov_done_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	**ctrls,
	int			num_ctrls,
	int			send_cookie,
	struct berval *cookie,
	int			refreshDeletes )
{
	int ret;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = op->o_tmpalloc( sizeof ( LDAPControl ), op->o_tmpmemctx );

	ber_printf( ber, "{" );
	if ( send_cookie && cookie ) {
		ber_printf( ber, "O", cookie );
	}
	if ( refreshDeletes == LDAP_SYNC_REFRESH_DELETES ) {
		ber_printf( ber, "b", refreshDeletes );
	}
	ber_printf( ber, "N}" );

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_DONE;
	ctrls[num_ctrls]->ldctl_iscritical = (op->o_sync == SLAP_CONTROL_CRITICAL);
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"syncprov_done_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}

#if 0
/* Generate state based on session log - not implemented yet */
static int
syncprov_state_ctrl_from_slog(
	Operation	*op,
	SlapReply	*rs,
	struct slog_entry *slog_e,
	int			entry_sync_state,
	LDAPControl	**ctrls,
	int			num_ctrls,
	int			send_cookie,
	struct berval	*cookie)
{
	Attribute* a;
	int ret;
	int res;
	const char *text = NULL;

	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;

	struct berval entryuuid_bv	= BER_BVNULL;

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	ctrls[num_ctrls] = ch_malloc ( sizeof ( LDAPControl ) );

	entryuuid_bv = slog_e->sl_uuid;

	if ( send_cookie && cookie ) {
		ber_printf( ber, "{eOON}",
			entry_sync_state, &entryuuid_bv, cookie );
	} else {
		ber_printf( ber, "{eON}",
			entry_sync_state, &entryuuid_bv );
	}

	ctrls[num_ctrls]->ldctl_oid = LDAP_CONTROL_SYNC_STATE;
	ctrls[num_ctrls]->ldctl_iscritical = (op->o_sync == SLAP_CONTROL_CRITICAL);
	ret = ber_flatten2( ber, &ctrls[num_ctrls]->ldctl_value, 1 );

	ber_free_buf( ber );

	if ( ret < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"slap_build_sync_ctrl: ber_flatten2 failed\n",
			0, 0, 0 );
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	return LDAP_SUCCESS;
}
#endif

static int
syncprov_sendinfo(
	Operation	*op,
	SlapReply	*rs,
	int			type,
	struct berval *cookie,
	int			refreshDone,
	BerVarray	syncUUIDs,
	int			refreshDeletes )
{
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	struct berval rspdata;

	int ret;

	ber_init2( ber, NULL, LBER_USE_DER );
	ber_set_option( ber, LBER_OPT_BER_MEMCTX, &op->o_tmpmemctx );

	if ( type ) {
		switch ( type ) {
		case LDAP_TAG_SYNC_NEW_COOKIE:
			ber_printf( ber, "tO", type, cookie );
			break;
		case LDAP_TAG_SYNC_REFRESH_DELETE:
		case LDAP_TAG_SYNC_REFRESH_PRESENT:
			ber_printf( ber, "t{", type );
			if ( cookie ) {
				ber_printf( ber, "O", cookie );
			}
			if ( refreshDone == 0 ) {
				ber_printf( ber, "b", refreshDone );
			}
			ber_printf( ber, "N}" );
			break;
		case LDAP_TAG_SYNC_ID_SET:
			ber_printf( ber, "t{", type );
			if ( cookie ) {
				ber_printf( ber, "O", cookie );
			}
			if ( refreshDeletes == 1 ) {
				ber_printf( ber, "b", refreshDeletes );
			}
			ber_printf( ber, "[W]", syncUUIDs );
			ber_printf( ber, "N}" );
			break;
		default:
			Debug( LDAP_DEBUG_TRACE,
				"syncprov_sendinfo: invalid syncinfo type (%d)\n",
				type, 0, 0 );
			return LDAP_OTHER;
		}
	}

	ret = ber_flatten2( ber, &rspdata, 0 );

	if ( ret < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"syncprov_sendinfo: ber_flatten2 failed\n",
			0, 0, 0 );
		send_ldap_error( op, rs, LDAP_OTHER, "internal error" );
		return ret;
	}

	rs->sr_rspoid = LDAP_SYNC_INFO;
	rs->sr_rspdata = &rspdata;
	send_ldap_intermediate( op, rs );
	rs->sr_rspdata = NULL;
	ber_free_buf( ber );

	return LDAP_SUCCESS;
}

/* Find a modtarget in an AVL tree */
static int
sp_avl_cmp( const void *c1, const void *c2 )
{
	const modtarget *m1, *m2;
	int rc;

	m1 = c1; m2 = c2;
	rc = m1->mt_op->o_req_ndn.bv_len - m2->mt_op->o_req_ndn.bv_len;

	if ( rc ) return rc;
	return ber_bvcmp( &m1->mt_op->o_req_ndn, &m2->mt_op->o_req_ndn );
}

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
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "findbase failed! %d\n", rs->sr_err,0,0 );
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
	fop.ors_limit = NULL;
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
 * 1: at startup time, after a contextCSN has been read from the database,
 * we search for all entries with CSN >= contextCSN in case the contextCSN
 * was not checkpointed at the previous shutdown.
 *
 * 2: when the current contextCSN is known and we have a sync cookie, we search
 * for one entry with CSN <= the cookie CSN. (Used to search for =.) If an
 * entry is found, the cookie CSN is valid, otherwise it is stale.
 *
 * 3: during a refresh phase, we search for all entries with CSN <= the cookie
 * CSN, and generate Present records for them. We always collect this result
 * in SyncID sets, even if there's only one match.
 */
#define	FIND_MAXCSN	1
#define	FIND_CSN	2
#define	FIND_PRESENT	3

static int
findmax_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH && rs->sr_err == LDAP_SUCCESS ) {
		struct berval *maxcsn = op->o_callback->sc_private;
		Attribute *a = attr_find( rs->sr_entry->e_attrs,
			slap_schema.si_ad_entryCSN );

		if ( a && ber_bvcmp( &a->a_vals[0], maxcsn )) {
			maxcsn->bv_len = a->a_vals[0].bv_len;
			strcpy( maxcsn->bv_val, a->a_vals[0].bv_val );
		}
	}
	return LDAP_SUCCESS;
}

static int
findcsn_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;

	if ( rs->sr_type == REP_SEARCH && rs->sr_err == LDAP_SUCCESS ) {
		sc->sc_private = (void *)1;
	}
	return LDAP_SUCCESS;
}

/* Build a list of entryUUIDs for sending in a SyncID set */

#define UUID_LEN	16

typedef struct fpres_cookie {
	int num;
	BerVarray uuids;
	char *last;
} fpres_cookie;

static int
findpres_cb( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_callback;
	fpres_cookie *pc = sc->sc_private;
	Attribute *a;
	int ret = SLAP_CB_CONTINUE;

	switch ( rs->sr_type ) {
	case REP_SEARCH:
		a = attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_entryUUID );
		if ( a ) {
			pc->uuids[pc->num].bv_val = pc->last;
			AC_MEMCPY( pc->uuids[pc->num].bv_val, a->a_nvals[0].bv_val,
				pc->uuids[pc->num].bv_len );
			pc->num++;
			pc->last = pc->uuids[pc->num].bv_val;
			pc->uuids[pc->num].bv_val = NULL;
		}
		ret = LDAP_SUCCESS;
		if ( pc->num != SLAP_SYNCUUID_SET_SIZE )
			break;
		/* FALLTHRU */
	case REP_RESULT:
		ret = rs->sr_err;
		if ( pc->num ) {
			ret = syncprov_sendinfo( op, rs, LDAP_TAG_SYNC_ID_SET, NULL,
				0, pc->uuids, 0 );
			pc->uuids[pc->num].bv_val = pc->last;
			pc->num = 0;
			pc->last = pc->uuids[0].bv_val;
		}
		break;
	default:
		break;
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
	struct berval fbuf, maxcsn;
	Filter cf, af;
	AttributeAssertion eq;
	int i, rc = LDAP_SUCCESS;
	fpres_cookie pcookie;
	sync_control *srs;

	if ( mode != FIND_MAXCSN ) {
		srs = op->o_controls[slap_cids.sc_LDAPsync];

		if ( srs->sr_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE ) {
			return LDAP_OTHER;
		}
	}

	fop = *op;
	fop.o_sync_mode &= SLAP_CONTROL_MASK;	/* turn off sync_mode */

	fbuf.bv_val = buf;
	cf.f_ava = &eq;
	cf.f_av_desc = slap_schema.si_ad_entryCSN;
	cf.f_next = NULL;

	fop.o_callback = &cb;
	fop.ors_limit = NULL;
	fop.ors_tlimit = SLAP_NO_LIMIT;
	fop.ors_filter = &cf;
	fop.ors_filterstr = fbuf;

	switch( mode ) {
	case FIND_MAXCSN:
		cf.f_choice = LDAP_FILTER_GE;
		cf.f_av_value = si->si_ctxcsn;
		fbuf.bv_len = sprintf( buf, "(entryCSN>=%s)",
			cf.f_av_value.bv_val );
		fop.ors_attrsonly = 0;
		fop.ors_attrs = csn_anlist;
		fop.ors_slimit = SLAP_NO_LIMIT;
		cb.sc_private = &maxcsn;
		cb.sc_response = findmax_cb;
		maxcsn.bv_val = cbuf;
		maxcsn.bv_len = 0;
		break;
	case FIND_CSN:
		cf.f_choice = LDAP_FILTER_LE;
		cf.f_av_value = *srs->sr_state.ctxcsn;
		fbuf.bv_len = sprintf( buf, "(entryCSN<=%s)",
			cf.f_av_value.bv_val );
		fop.ors_attrsonly = 1;
		fop.ors_attrs = slap_anlist_no_attrs;
		fop.ors_slimit = 1;
		cb.sc_private = NULL;
		cb.sc_response = findcsn_cb;
		break;
	case FIND_PRESENT:
		af.f_choice = LDAP_FILTER_AND;
		af.f_next = NULL;
		af.f_and = &cf;
		cf.f_choice = LDAP_FILTER_LE;
		cf.f_av_value = *srs->sr_state.ctxcsn;
		cf.f_next = op->ors_filter;
		fop.ors_filter = &af;
		filter2bv_x( &fop, fop.ors_filter, &fop.ors_filterstr );
		fop.ors_attrsonly = 0;
		fop.ors_attrs = uuid_anlist;
		fop.ors_slimit = SLAP_NO_LIMIT;
		/* We want pure entries, not referrals */
		fop.o_managedsait = SLAP_CONTROL_CRITICAL;
		cb.sc_private = &pcookie;
		cb.sc_response = findpres_cb;
		pcookie.num = 0;

		/* preallocate storage for a full set */
		pcookie.uuids = op->o_tmpalloc( (SLAP_SYNCUUID_SET_SIZE+1) *
			sizeof(struct berval) + SLAP_SYNCUUID_SET_SIZE * UUID_LEN,
			op->o_tmpmemctx );
		pcookie.last = (char *)(pcookie.uuids + SLAP_SYNCUUID_SET_SIZE+1);
		pcookie.uuids[0].bv_val = pcookie.last;
		pcookie.uuids[0].bv_len = UUID_LEN;
		for (i=1; i<SLAP_SYNCUUID_SET_SIZE; i++) {
			pcookie.uuids[i].bv_val = pcookie.uuids[i-1].bv_val + UUID_LEN;
			pcookie.uuids[i].bv_len = UUID_LEN;
		}
		break;
	}

	fop.o_bd->bd_info = on->on_info->oi_orig;
	fop.o_bd->be_search( &fop, &frs );
	fop.o_bd->bd_info = (BackendInfo *)on;

	switch( mode ) {
	case FIND_MAXCSN:
		if ( maxcsn.bv_len ) {
			strcpy( si->si_ctxcsnbuf, maxcsn.bv_val );
			si->si_ctxcsn.bv_len = maxcsn.bv_len;
		}
		break;
	case FIND_CSN:
		/* If matching CSN was not found, invalidate the context. */
		if ( !cb.sc_private ) rc = LDAP_NO_SUCH_OBJECT;
		break;
	case FIND_PRESENT:
		op->o_tmpfree( pcookie.uuids, op->o_tmpmemctx );
		op->o_tmpfree( fop.ors_filterstr.bv_val, op->o_tmpmemctx );
		break;
	}

	return rc;
}

/* Queue a persistent search response if still in Refresh stage */
static int
syncprov_qresp( opcookie *opc, syncops *so, int mode )
{
	syncres *sr;

	sr = ch_malloc(sizeof(syncres) + opc->suuid.bv_len + 1 +
		opc->sdn.bv_len + 1 + opc->sndn.bv_len + 1 + opc->sctxcsn.bv_len + 1 );
	sr->s_next = NULL;
	sr->s_dn.bv_val = (char *)(sr + 1);
	sr->s_mode = mode;
	sr->s_isreference = opc->sreference;
	sr->s_ndn.bv_val = lutil_strcopy( sr->s_dn.bv_val, opc->sdn.bv_val );
	*(sr->s_ndn.bv_val++) = '\0';
	sr->s_uuid.bv_val = lutil_strcopy( sr->s_ndn.bv_val, opc->sndn.bv_val );
	*(sr->s_uuid.bv_val++) = '\0';
	sr->s_csn.bv_val = lutil_strcopy( sr->s_uuid.bv_val, opc->suuid.bv_val );

	if ( !so->s_res ) {
		so->s_res = sr;
	} else {
		so->s_restail->s_next = sr;
	}
	so->s_restail = sr;
	ldap_pvt_thread_mutex_unlock( &so->s_mutex );
	return LDAP_SUCCESS;
}

/* Send a persistent search response */
static int
syncprov_sendresp( Operation *op, opcookie *opc, syncops *so, Entry *e, int mode, int queue )
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

	ohdr = *sop.o_hdr;
	sop.o_hdr = &ohdr;
	sop.o_tmpmemctx = op->o_tmpmemctx;
	sop.o_bd = op->o_bd;
	sop.o_controls = op->o_controls;

	if ( queue && (so->s_flags & PS_IS_REFRESHING) ) {
		ldap_pvt_thread_mutex_lock( &so->s_mutex );
		if ( so->s_flags & PS_IS_REFRESHING )
			return syncprov_qresp( opc, so, mode );
		ldap_pvt_thread_mutex_unlock( &so->s_mutex );
	}

	ctrls[1] = NULL;
	slap_compose_sync_cookie( op, &cookie, &opc->sctxcsn,
		so->s_sid, so->s_rid );

	e_uuid.e_attrs = &a_uuid;
	a_uuid.a_desc = slap_schema.si_ad_entryUUID;
	a_uuid.a_nvals = &opc->suuid;
	rs.sr_err = syncprov_state_ctrl( &sop, &rs, &e_uuid,
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
			struct berval bv = BER_BVNULL;
			rs.sr_ref = &bv;
			send_search_reference( &sop, &rs );
		} else {
			send_search_entry( &sop, &rs );
		}
		break;
	default:
		assert(0);
	}
	op->o_tmpfree( rs.sr_ctrls[0], op->o_tmpmemctx );
	rs.sr_ctrls = NULL;
	return rs.sr_err;
}

static void
syncprov_free_syncop( syncops *so )
{
	syncres *sr, *srnext;
	GroupAssertion *ga, *gnext;

	ldap_pvt_thread_mutex_lock( &so->s_mutex );
	so->s_inuse--;
	if ( so->s_inuse > 0 ) {
		ldap_pvt_thread_mutex_unlock( &so->s_mutex );
		return;
	}
	ldap_pvt_thread_mutex_unlock( &so->s_mutex );
	filter_free( so->s_op->ors_filter );
	for ( ga = so->s_op->o_groups; ga; ga=gnext ) {
		gnext = ga->ga_next;
		ch_free( ga );
	}
	ch_free( so->s_op );
	ch_free( so->s_base.bv_val );
	for ( sr=so->s_res; sr; sr=srnext ) {
		srnext = sr->s_next;
		ch_free( sr );
	}
	ldap_pvt_thread_mutex_destroy( &so->s_mutex );
	ch_free( so );
}

static int
syncprov_drop_psearch( syncops *so, int lock )
{
	if ( lock )
		ldap_pvt_thread_mutex_lock( &so->s_op->o_conn->c_mutex );
	so->s_op->o_conn->c_n_ops_executing--;
	so->s_op->o_conn->c_n_ops_completed++;
	LDAP_STAILQ_REMOVE( &so->s_op->o_conn->c_ops, so->s_op, slap_op,
		o_next );
	if ( lock )
		ldap_pvt_thread_mutex_unlock( &so->s_op->o_conn->c_mutex );
	syncprov_free_syncop( so );
}

static int
syncprov_op_abandon( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;
	syncops *so, *soprev;

	ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
	for ( so=si->si_ops, soprev = (syncops *)&si->si_ops; so;
		soprev=so, so=so->s_next ) {
		if ( so->s_op->o_connid == op->o_connid &&
			so->s_op->o_msgid == op->orn_msgid ) {
				so->s_op->o_abandon = 1;
				soprev->s_next = so->s_next;
				break;
		}
	}
	ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
	if ( so ) {
		/* Is this really a Cancel exop? */
		if ( op->o_tag != LDAP_REQ_ABANDON ) {
			rs->sr_err = LDAP_CANCELLED;
			send_ldap_result( so->s_op, rs );
		}
		/* Our cloned searches have no ctrls set.
		 * we don't want to muck with real search ops
		 * from the frontend.
		 */
		if ( ! so->s_op->o_sync )
			syncprov_drop_psearch( so, 0 );
	}
	return SLAP_CB_CONTINUE;
}

/* Find which persistent searches are affected by this operation */
static void
syncprov_matchops( Operation *op, opcookie *opc, int saveit )
{
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;

	fbase_cookie fc;
	syncops *ss, *sprev, *snext;
	Entry *e;
	Attribute *a;
	int rc;
	struct berval newdn;
	int freefdn = 0;

	fc.fdn = &op->o_req_ndn;
	/* compute new DN */
	if ( op->o_tag == LDAP_REQ_MODRDN && !saveit ) {
		struct berval pdn;
		if ( op->orr_nnewSup ) pdn = *op->orr_nnewSup;
		else dnParent( fc.fdn, &pdn );
		build_new_dn( &newdn, &pdn, &op->orr_nnewrdn, op->o_tmpmemctx );
		fc.fdn = &newdn;
		freefdn = 1;
	}
	if ( op->o_tag != LDAP_REQ_ADD ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		rc = be_entry_get_rw( op, fc.fdn, NULL, NULL, 0, &e );
		op->o_bd->bd_info = (BackendInfo *)on;
		if ( rc ) return;
	} else {
		e = op->ora_e;
	}

	/* Never replicate these */
	if ( is_entry_syncConsumerSubentry( e )) {
		goto done;
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
	for (ss = si->si_ops, sprev = (syncops *)&si->si_ops; ss;
		sprev = ss, ss=snext)
	{
		syncmatches *sm;
		int found = 0;

		snext = ss->s_next;
		/* validate base */
		fc.fss = ss;
		fc.fbase = 0;
		fc.fscope = 0;

		/* If the base of the search is missing, signal a refresh */
		rc = syncprov_findbase( op, &fc );
		if ( rc != LDAP_SUCCESS ) {
			SlapReply rs = {REP_RESULT};
			send_ldap_error( ss->s_op, &rs, LDAP_SYNC_REFRESH_REQUIRED,
				"search base has changed" );
			sprev->s_next = snext;
			syncprov_drop_psearch( ss, 1 );
			continue;
		}

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
		if ( fc.fscope && test_filter( op, e, ss->s_op->ors_filter ) ==
			LDAP_COMPARE_TRUE ) {
			if ( saveit ) {
				sm = op->o_tmpalloc( sizeof(syncmatches), op->o_tmpmemctx );
				sm->sm_next = opc->smatches;
				sm->sm_op = ss;
				ss->s_inuse++;
				opc->smatches = sm;
			} else {
				/* if found send UPDATE else send ADD */
				syncprov_sendresp( op, opc, ss, e,
					found ? LDAP_SYNC_MODIFY : LDAP_SYNC_ADD, 1 );
			}
		} else if ( !saveit && found ) {
			/* send DELETE */
			syncprov_sendresp( op, opc, ss, NULL, LDAP_SYNC_DELETE, 1 );
		}
	}
	ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
done:
	if ( op->o_tag != LDAP_REQ_ADD ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		be_entry_release_r( op, e );
		op->o_bd->bd_info = (BackendInfo *)on;
	}
	if ( freefdn ) {
		op->o_tmpfree( fc.fdn->bv_val, op->o_tmpmemctx );
	}
}

static int
syncprov_op_cleanup( Operation *op, SlapReply *rs )
{
	slap_callback *cb = op->o_callback;
	opcookie *opc = cb->sc_private;
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;
	syncmatches *sm, *snext;
	modtarget *mt, mtdummy;

	for (sm = opc->smatches; sm; sm=snext) {
		snext = sm->sm_next;
		syncprov_free_syncop( sm->sm_op );
		op->o_tmpfree( sm, op->o_tmpmemctx );
	}

	/* Remove op from lock table */
	mtdummy.mt_op = op;
	ldap_pvt_thread_mutex_lock( &si->si_mods_mutex );
	mt = avl_find( si->si_mods, &mtdummy, sp_avl_cmp );
	ldap_pvt_thread_mutex_unlock( &si->si_mods_mutex );
	if ( mt ) {
		modinst *mi = mt->mt_mods;

		/* If there are more, promote the next one */
		ldap_pvt_thread_mutex_lock( &mt->mt_mutex );
		if ( mi->mi_next ) {
			mt->mt_mods = mi->mi_next;
			mt->mt_op = mt->mt_mods->mi_op;
			ldap_pvt_thread_mutex_unlock( &mt->mt_mutex );
		} else {
			ldap_pvt_thread_mutex_lock( &si->si_mods_mutex );
			avl_delete( &si->si_mods, mt, sp_avl_cmp );
			ldap_pvt_thread_mutex_unlock( &si->si_mods_mutex );
			ldap_pvt_thread_mutex_unlock( &mt->mt_mutex );
			ldap_pvt_thread_mutex_destroy( &mt->mt_mutex );
			ch_free( mt );
		}
	}
	if ( !BER_BVISNULL( &opc->suuid ))
		op->o_tmpfree( opc->suuid.bv_val, op->o_tmpmemctx );
	if ( !BER_BVISNULL( &opc->sndn ))
		op->o_tmpfree( opc->sndn.bv_val, op->o_tmpmemctx );
	if ( !BER_BVISNULL( &opc->sdn ))
		op->o_tmpfree( opc->sdn.bv_val, op->o_tmpmemctx );
	op->o_callback = cb->sc_next;
	op->o_tmpfree(cb, op->o_tmpmemctx);
}

static void
syncprov_checkpoint( Operation *op, SlapReply *rs, slap_overinst *on )
{
	syncprov_info_t		*si = on->on_bi.bi_private;
	Modifications mod;
	Operation opm;
	struct berval bv[2];
	BackendInfo *orig;
	slap_callback cb = {0};

	mod.sml_values = bv;
	bv[1].bv_val = NULL;
	bv[0] = si->si_ctxcsn;
	mod.sml_nvalues = NULL;
	mod.sml_desc = slap_schema.si_ad_contextCSN;
	mod.sml_op = LDAP_MOD_REPLACE;
	mod.sml_next = NULL;

	cb.sc_response = slap_null_cb;
	opm = *op;
	opm.o_tag = LDAP_REQ_MODIFY;
	opm.o_callback = &cb;
	opm.orm_modlist = &mod;
	opm.o_req_dn = op->o_bd->be_suffix[0];
	opm.o_req_ndn = op->o_bd->be_nsuffix[0];
	orig = opm.o_bd->bd_info;
	opm.o_bd->bd_info = on->on_info->oi_orig;
	opm.o_bd->be_modify( &opm, rs );
}

static void
syncprov_add_slog( Operation *op, struct berval *csn )
{
	opcookie *opc = op->o_callback->sc_private;
	slap_overinst *on = opc->son;
	syncprov_info_t		*si = on->on_bi.bi_private;
	sessionlog *sl;
	slog_entry *se;

	for ( sl = si->si_logs; sl; sl=sl->sl_next ) {
		/* Allocate a record. UUIDs are not NUL-terminated. */
		se = ch_malloc( sizeof( slog_entry ) + opc->suuid.bv_len + 
			csn->bv_len + 1 );
		se->se_next = NULL;
		se->se_tag = op->o_tag;

		se->se_uuid.bv_val = (char *)(se+1);
		se->se_csn.bv_val = se->se_uuid.bv_val + opc->suuid.bv_len + 1;
		AC_MEMCPY( se->se_uuid.bv_val, opc->suuid.bv_val, opc->suuid.bv_len );
		se->se_uuid.bv_len = opc->suuid.bv_len;

		AC_MEMCPY( se->se_csn.bv_val, csn->bv_val, csn->bv_len );
		se->se_csn.bv_val[csn->bv_len] = '\0';
		se->se_csn.bv_len = csn->bv_len;

		ldap_pvt_thread_mutex_lock( &sl->sl_mutex );
		if ( sl->sl_head ) {
			sl->sl_tail->se_next = se;
		} else {
			sl->sl_head = se;
		}
		sl->sl_tail = se;
		sl->sl_num++;
		while ( sl->sl_num > sl->sl_size ) {
			se = sl->sl_head;
			sl->sl_head = se->se_next;
			strcpy( sl->sl_mincsn.bv_val, se->se_csn.bv_val );
			sl->sl_mincsn.bv_len = se->se_csn.bv_len;
			ch_free( se );
			sl->sl_num--;
			if ( !sl->sl_head ) {
				sl->sl_tail = NULL;
			}
		}
		ldap_pvt_thread_mutex_unlock( &sl->sl_mutex );
	}
}

/* Just set a flag if we found the matching entry */
static int
playlog_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		op->o_callback->sc_private = (void *)1;
	}
	return rs->sr_err;
}

/* enter with sl->sl_mutex locked, release before returning */
static void
syncprov_playlog( Operation *op, SlapReply *rs, sessionlog *sl,
	struct berval *oldcsn, struct berval *ctxcsn )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;
	slog_entry *se;
	int i, j, ndel, num, nmods, mmods;
	BerVarray uuids;

	if ( !sl->sl_num ) {
		ldap_pvt_thread_mutex_unlock( &sl->sl_mutex );
		return;
	}

	num = sl->sl_num;
	i = 0;
	nmods = 0;

	uuids = op->o_tmpalloc( (num+1) * sizeof( struct berval ) +
		num * UUID_LEN, op->o_tmpmemctx );

	uuids[0].bv_val = (char *)(uuids + num + 1);

	/* Make a copy of the relevant UUIDs. Put the Deletes up front
	 * and everything else at the end. Do this first so we can
	 * unlock the list mutex.
	 */
	for ( se=sl->sl_head; se; se=se->se_next ) {
		if ( ber_bvcmp( &se->se_csn, oldcsn ) < 0 ) continue;
		if ( ber_bvcmp( &se->se_csn, ctxcsn ) > 0 ) break;
		if ( se->se_tag == LDAP_REQ_DELETE ) {
			j = i;
			i++;
		} else {
			nmods++;
			j = num - nmods;
		}
		uuids[j].bv_val = uuids[0].bv_val + (j * UUID_LEN);
		AC_MEMCPY(uuids[j].bv_val, se->se_uuid.bv_val, UUID_LEN);
		uuids[j].bv_len = UUID_LEN;
	}
	ldap_pvt_thread_mutex_unlock( &sl->sl_mutex );

	ndel = i;

	/* Mods must be validated to see if they belong in this delete set.
	 */

	mmods = nmods;
	/* Strip any duplicates */
	for ( i=0; i<nmods; i++ ) {
		for ( j=0; j<ndel; j++ ) {
			if ( bvmatch( &uuids[j], &uuids[num - 1 - i] )) {
				uuids[num - 1 - i].bv_len = 0;
				mmods --;
				break;
			}
		}
		if ( uuids[num - 1 - i].bv_len == 0 ) continue;
		for ( j=0; j<i; j++ ) {
			if ( bvmatch( &uuids[num - 1 - j], &uuids[num - 1 - i] )) {
				uuids[num - 1 - i].bv_len = 0;
				mmods --;
				break;
			}
		}
	}

	if ( mmods ) {
		Operation fop;
		SlapReply frs = { REP_RESULT };
		int rc;
		Filter mf, af;
		AttributeAssertion eq;
		slap_callback cb = {0};

		fop = *op;

		fop.o_sync_mode = 0;
		fop.o_callback = &cb;
		fop.ors_limit = NULL;
		fop.ors_tlimit = SLAP_NO_LIMIT;
		fop.ors_attrs = slap_anlist_all_attributes;
		fop.ors_attrsonly = 0;
		fop.o_managedsait = SLAP_CONTROL_CRITICAL;

		af.f_choice = LDAP_FILTER_AND;
		af.f_next = NULL;
		af.f_and = &mf;
		mf.f_choice = LDAP_FILTER_EQUALITY;
		mf.f_ava = &eq;
		mf.f_av_desc = slap_schema.si_ad_entryUUID;
		mf.f_next = fop.ors_filter;

		fop.ors_filter = &af;

		cb.sc_response = playlog_cb;
		fop.o_bd->bd_info = on->on_info->oi_orig;

		for ( i=ndel; i<num; i++ ) {
			if ( uuids[i].bv_len == 0 ) continue;

			mf.f_av_value = uuids[i];
			cb.sc_private = NULL;
			fop.ors_slimit = 1;
			rc = fop.o_bd->be_search( &fop, &frs );

			/* If entry was not found, add to delete list */
			if ( !cb.sc_private ) {
				uuids[ndel++] = uuids[i];
			}
		}
		fop.o_bd->bd_info = (BackendInfo *)on;
	}
	if ( ndel ) {
		uuids[ndel].bv_val = NULL;
		syncprov_sendinfo( op, rs, LDAP_TAG_SYNC_ID_SET, NULL, 0, uuids, 1 );
	}
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
		struct berval maxcsn = BER_BVNULL, curcsn = BER_BVNULL;
		char cbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];

		/* Update our context CSN */
		cbuf[0] = '\0';
		ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
		slap_get_commit_csn( op, &maxcsn, &curcsn );
		if ( !BER_BVISNULL( &maxcsn ) ) {
			strcpy( cbuf, maxcsn.bv_val );
			if ( ber_bvcmp( &maxcsn, &si->si_ctxcsn ) > 0 ) {
				strcpy( si->si_ctxcsnbuf, cbuf );
				si->si_ctxcsn.bv_len = maxcsn.bv_len;
			}
		}

		si->si_numops++;
		if ( si->si_chkops || si->si_chktime ) {
			int do_check=0;
			if ( si->si_chkops && si->si_numops >= si->si_chkops ) {
				do_check = 1;
				si->si_numops = 0;
			}
			if ( si->si_chktime &&
				(op->o_time - si->si_chklast >= si->si_chktime )) {
				do_check = 1;
				si->si_chklast = op->o_time;
			}
			if ( do_check ) {
				syncprov_checkpoint( op, rs, on );
			}
		}
		ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );

		opc->sctxcsn.bv_len = maxcsn.bv_len;
		opc->sctxcsn.bv_val = cbuf;

		/* Handle any persistent searches */
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
				ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
				for ( sm = opc->smatches; sm; sm=sm->sm_next ) {
					if ( sm->sm_op->s_op->o_abandon )
						continue;
					syncprov_sendresp( op, opc, sm->sm_op, NULL,
						LDAP_SYNC_DELETE, 1 );
				}
				ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
				break;
			}
		}

		/* Add any log records */
		if ( si->si_logs && op->o_tag != LDAP_REQ_ADD ) {
			syncprov_add_slog( op, &curcsn );
		}

	}
	return SLAP_CB_CONTINUE;
}

/* We don't use a subentry to store the context CSN any more.
 * We expose the current context CSN as an operational attribute
 * of the suffix entry.
 */
static int
syncprov_op_compare( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;
	int rc = SLAP_CB_CONTINUE;

	if ( dn_match( &op->o_req_ndn, op->o_bd->be_nsuffix ) &&
		op->oq_compare.rs_ava->aa_desc == slap_schema.si_ad_contextCSN )
	{
		Entry e = {0};
		Attribute a = {0};
		struct berval bv[2];

		e.e_name = op->o_bd->be_suffix[0];
		e.e_nname = op->o_bd->be_nsuffix[0];

		BER_BVZERO( &bv[1] );
		bv[0] = si->si_ctxcsn;

		a.a_desc = slap_schema.si_ad_contextCSN;
		a.a_vals = bv;
		a.a_nvals = a.a_vals;

		ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );

		rs->sr_err = access_allowed( op, &e, op->oq_compare.rs_ava->aa_desc,
			&op->oq_compare.rs_ava->aa_value, ACL_COMPARE, NULL );
		if ( ! rs->sr_err ) {
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			goto return_results;
		}

		if ( get_assert( op ) &&
			( test_filter( op, &e, get_assertion( op ) ) != LDAP_COMPARE_TRUE ) )
		{
			rs->sr_err = LDAP_ASSERTION_FAILED;
			goto return_results;
		}


		rs->sr_err = LDAP_COMPARE_FALSE;

		if ( value_find_ex( op->oq_compare.rs_ava->aa_desc,
			SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
				SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
				a.a_nvals, &op->oq_compare.rs_ava->aa_value, op->o_tmpmemctx ) == 0 )
		{
			rs->sr_err = LDAP_COMPARE_TRUE;
		}

return_results:;

		ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );

		send_ldap_result( op, rs );

		if( rs->sr_err == LDAP_COMPARE_FALSE || rs->sr_err == LDAP_COMPARE_TRUE ) {
			rs->sr_err = LDAP_SUCCESS;
		}
		rc = rs->sr_err;
	}

	return rc;
}

static int
syncprov_op_mod( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = on->on_bi.bi_private;

	slap_callback *cb = op->o_tmpcalloc(1, sizeof(slap_callback)+
		sizeof(opcookie) +
		(si->si_ops ? sizeof(modinst) : 0 ),
		op->o_tmpmemctx);
	opcookie *opc = (opcookie *)(cb+1);
	opc->son = on;
	cb->sc_response = syncprov_op_response;
	cb->sc_cleanup = syncprov_op_cleanup;
	cb->sc_private = opc;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;

	/* If there are active persistent searches, lock this operation.
	 * See seqmod.c for the locking logic on its own.
	 */
	if ( si->si_ops ) {
		modtarget *mt, mtdummy;
		modinst *mi;

		mi = (modinst *)(opc+1);
		mi->mi_op = op;

		/* See if we're already modifying this entry... */
		mtdummy.mt_op = op;
		ldap_pvt_thread_mutex_lock( &si->si_mods_mutex );
		mt = avl_find( si->si_mods, &mtdummy, sp_avl_cmp );
		if ( mt ) {
			ldap_pvt_thread_mutex_lock( &mt->mt_mutex );
			ldap_pvt_thread_mutex_unlock( &si->si_mods_mutex );
			mt->mt_tail->mi_next = mi;
			mt->mt_tail = mi;
			/* wait for this op to get to head of list */
			while ( mt->mt_mods != mi ) {
				ldap_pvt_thread_mutex_unlock( &mt->mt_mutex );
				ldap_pvt_thread_yield();
				ldap_pvt_thread_mutex_lock( &mt->mt_mutex );
			}
			ldap_pvt_thread_mutex_unlock( &mt->mt_mutex );
		} else {
			/* Record that we're modifying this entry now */
			mt = ch_malloc( sizeof(modtarget) );
			mt->mt_mods = mi;
			mt->mt_tail = mi;
			mt->mt_op = mi->mi_op;
			ldap_pvt_thread_mutex_init( &mt->mt_mutex );
			avl_insert( &si->si_mods, mt, sp_avl_cmp, avl_dup_error );
			ldap_pvt_thread_mutex_unlock( &si->si_mods_mutex );
		}
	}

	if (( si->si_ops || si->si_logs ) && op->o_tag != LDAP_REQ_ADD )
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
	int ss_present;
} searchstate;

static int
syncprov_search_cleanup( Operation *op, SlapReply *rs )
{
	if ( rs->sr_ctrls ) {
		op->o_tmpfree( rs->sr_ctrls[0], op->o_tmpmemctx );
		op->o_tmpfree( rs->sr_ctrls, op->o_tmpmemctx );
		rs->sr_ctrls = NULL;
	}
	return 0;
}

static void
syncprov_detach_op( Operation *op, syncops *so )
{
	Operation *op2;
	int i, alen = 0;
	size_t size;
	char *ptr;
	GroupAssertion *g1, *g2;

	/* count the search attrs */
	for (i=0; op->ors_attrs && !BER_BVISNULL( &op->ors_attrs[i].an_name ); i++) {
		alen += op->ors_attrs[i].an_name.bv_len + 1;
	}
	/* Make a new copy of the operation */
	size = sizeof(Operation) + sizeof(Opheader) +
		(i ? ( (i+1) * sizeof(AttributeName) + alen) : 0) +
		op->o_req_dn.bv_len + 1 +
		op->o_req_ndn.bv_len + 1 +
		op->o_ndn.bv_len + 1 +
		so->s_filterstr.bv_len + 1;
	op2 = (Operation *)ch_calloc( 1, size );
	op2->o_hdr = (Opheader *)(op2+1);

	/* Copy the fields we care about explicitly, leave the rest alone */
	*op2->o_hdr = *op->o_hdr;
	op2->o_tag = op->o_tag;
	op2->o_time = op->o_time;
	op2->o_bd = op->o_bd;
	op2->o_request = op->o_request;

	if ( i ) {
		op2->ors_attrs = (AttributeName *)(op2->o_hdr + 1);
		ptr = (char *)(op2->ors_attrs+i+1);
		for (i=0; !BER_BVISNULL( &op->ors_attrs[i].an_name ); i++) {
			op2->ors_attrs[i] = op->ors_attrs[i];
			op2->ors_attrs[i].an_name.bv_val = ptr;
			ptr = lutil_strcopy( ptr, op->ors_attrs[i].an_name.bv_val ) + 1;
		}
		BER_BVZERO( &op2->ors_attrs[i].an_name );
	} else {
		ptr = (char *)(op2->o_hdr + 1);
	}
	op2->o_authz = op->o_authz;
	op2->o_ndn.bv_val = ptr;
	ptr = lutil_strcopy(ptr, op->o_ndn.bv_val) + 1;
	op2->o_dn = op2->o_ndn;
	op2->o_req_dn.bv_len = op->o_req_dn.bv_len;
	op2->o_req_dn.bv_val = ptr;
	ptr = lutil_strcopy(ptr, op->o_req_dn.bv_val) + 1;
	op2->o_req_ndn.bv_len = op->o_req_ndn.bv_len;
	op2->o_req_ndn.bv_val = ptr;
	ptr = lutil_strcopy(ptr, op->o_req_ndn.bv_val) + 1;
	op2->ors_filterstr.bv_val = ptr;
	strcpy( ptr, so->s_filterstr.bv_val );
	op2->ors_filterstr.bv_len = so->s_filterstr.bv_len;
	op2->ors_filter = str2filter( ptr );
	so->s_op = op2;

	/* Copy any cached group ACLs individually */
	op2->o_groups = NULL;
	for ( g1=op->o_groups; g1; g1=g1->ga_next ) {
		g2 = ch_malloc( sizeof(GroupAssertion) + g1->ga_len );
		*g2 = *g1;
		strcpy( g2->ga_ndn, g1->ga_ndn );
		g2->ga_next = op2->o_groups;
		op2->o_groups = g2;
	}

	/* Add op2 to conn so abandon will find us */
	ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
	op->o_conn->c_n_ops_executing++;
	op->o_conn->c_n_ops_completed--;
	LDAP_STAILQ_INSERT_TAIL( &op->o_conn->c_ops, op2, o_next );
	ldap_pvt_thread_mutex_unlock( &op->o_conn->c_mutex );
}

static int
syncprov_search_response( Operation *op, SlapReply *rs )
{
	searchstate *ss = op->o_callback->sc_private;
	slap_overinst *on = ss->ss_on;
	syncprov_info_t		*si = on->on_bi.bi_private;
	sync_control *srs = op->o_controls[slap_cids.sc_LDAPsync];

	if ( rs->sr_type == REP_SEARCH || rs->sr_type == REP_SEARCHREF ) {
		int i;
		/* If we got a referral without a referral object, there's
		 * something missing that we cannot replicate. Just ignore it.
		 * The consumer will abort because we didn't send the expected
		 * control.
		 */
		if ( !rs->sr_entry ) {
			assert( rs->sr_entry );
			Debug( LDAP_DEBUG_ANY, "bogus referral in context\n",0,0,0 );
			return SLAP_CB_CONTINUE;
		}
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
		rs->sr_err = syncprov_state_ctrl( op, rs, rs->sr_entry,
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
			rs->sr_err = syncprov_done_ctrl( op, rs, rs->sr_ctrls,
				0, 1, &cookie, ss->ss_present ?  LDAP_SYNC_REFRESH_PRESENTS :
					LDAP_SYNC_REFRESH_DELETES );
		} else {
			int locked = 0;
		/* It's RefreshAndPersist, transition to Persist phase */
			syncprov_sendinfo( op, rs, ( ss->ss_present && rs->sr_nentries ) ?
	 			LDAP_TAG_SYNC_REFRESH_PRESENT : LDAP_TAG_SYNC_REFRESH_DELETE,
				&cookie, 1, NULL, 0 );
			/* Flush any queued persist messages */
			if ( ss->ss_so->s_res ) {
				syncres *sr, *srnext;
				Entry *e;
				opcookie opc;

				opc.son = on;
				ldap_pvt_thread_mutex_lock( &ss->ss_so->s_mutex );
				locked = 1;
				for (sr = ss->ss_so->s_res; sr; sr=srnext) {
					int rc = LDAP_SUCCESS;
					srnext = sr->s_next;
					opc.sdn = sr->s_dn;
					opc.sndn = sr->s_ndn;
					opc.suuid = sr->s_uuid;
					opc.sctxcsn = sr->s_csn;
					opc.sreference = sr->s_isreference;
					e = NULL;

					if ( sr->s_mode != LDAP_SYNC_DELETE ) {
						op->o_bd->bd_info = (BackendInfo *)on->on_info;
						rc = be_entry_get_rw( op, &opc.sndn, NULL, NULL, 0, &e );
						op->o_bd->bd_info = (BackendInfo *)on;
					}
					if ( rc == LDAP_SUCCESS )
						syncprov_sendresp( op, &opc, ss->ss_so, e,
							sr->s_mode, 0 );

					if ( e ) {
						op->o_bd->bd_info = (BackendInfo *)on->on_info;
						be_entry_release_r( op, e );
						op->o_bd->bd_info = (BackendInfo *)on;
					}
					ch_free( sr );
				}
				ss->ss_so->s_res = NULL;
				ss->ss_so->s_restail = NULL;
			}

			/* Turn off the refreshing flag */
			ss->ss_so->s_flags ^= PS_IS_REFRESHING;
			if ( locked )
				ldap_pvt_thread_mutex_unlock( &ss->ss_so->s_mutex );

			/* Detach this Op from frontend control */
			syncprov_detach_op( op, ss->ss_so );

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
	int gotstate = 0, nochange = 0, do_present = 1;
	Filter *fand, *fava;
	syncops *sop = NULL;
	searchstate *ss;
	sync_control *srs;
	struct berval ctxcsn;
	char csnbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];

	if ( !(op->o_sync_mode & SLAP_SYNC_REFRESH) ) return SLAP_CB_CONTINUE;

	if ( op->ors_deref & LDAP_DEREF_SEARCHING ) {
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR, "illegal value for derefAliases" );
		return rs->sr_err;
	}

	srs = op->o_controls[slap_cids.sc_LDAPsync];

	/* If this is a persistent search, set it up right away */
	if ( op->o_sync_mode & SLAP_SYNC_PERSIST ) {
		syncops so = {0};
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
		ldap_pvt_thread_mutex_init( &sop->s_mutex );
		sop->s_sid = srs->sr_state.sid;
		sop->s_rid = srs->sr_state.rid;
		sop->s_inuse = 1;

		ldap_pvt_thread_mutex_lock( &si->si_ops_mutex );
		sop->s_next = si->si_ops;
		si->si_ops = sop;
		ldap_pvt_thread_mutex_unlock( &si->si_ops_mutex );
	}

	/* snapshot the ctxcsn */
	ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
	strcpy( csnbuf, si->si_ctxcsnbuf );
	ctxcsn.bv_len = si->si_ctxcsn.bv_len;
	ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );
	ctxcsn.bv_val = csnbuf;
	
	/* If we have a cookie, handle the PRESENT lookups */
	if ( srs->sr_state.ctxcsn ) {
		sessionlog *sl;
		int valid = 0;

		/* Is the CSN in a valid format? */
		/* FIXME: should use csnValidate when that is implemented */
		while (!valid) {
			char *ptr;
			struct berval timestamp;
			slap_syntax_validate_func *validate;
			AttributeDescription *ad = slap_schema.si_ad_modifyTimestamp;

			if ( srs->sr_state.ctxcsn->bv_len >= LDAP_LUTIL_CSNSTR_BUFSIZE )
				break;
			ptr = strchr( srs->sr_state.ctxcsn->bv_val, '#' );
			if ( !ptr )
				break;
			timestamp.bv_val = srs->sr_state.ctxcsn->bv_val;
			timestamp.bv_len = ptr - timestamp.bv_val;
			validate = ad->ad_type->sat_syntax->ssyn_validate;
			if ( validate( ad->ad_type->sat_syntax, &timestamp ))
				break;
			valid = 1;
			break;
		}
		/* Skip any present searches, there's nothing to compare */
		if ( !valid ) {
			goto shortcut;
		}
		/* If just Refreshing and nothing has changed, shortcut it */
		if ( bvmatch( srs->sr_state.ctxcsn, &ctxcsn )) {
			nochange = 1;
			if ( !(op->o_sync_mode & SLAP_SYNC_PERSIST) ) {
				LDAPControl	*ctrls[2];

				ctrls[0] = NULL;
				ctrls[1] = NULL;
				syncprov_done_ctrl( op, rs, ctrls, 0, 0,
					NULL, LDAP_SYNC_REFRESH_DELETES );
				rs->sr_ctrls = ctrls;
				rs->sr_err = LDAP_SUCCESS;
				send_ldap_result( op, rs );
				rs->sr_ctrls = NULL;
				return rs->sr_err;
			}
			goto shortcut;
		}
		/* Do we have a sessionlog for this search? */
		for ( sl=si->si_logs; sl; sl=sl->sl_next )
			if ( sl->sl_sid == srs->sr_state.sid ) break;
		if ( sl ) {
			ldap_pvt_thread_mutex_lock( &sl->sl_mutex );
			if ( ber_bvcmp( srs->sr_state.ctxcsn, &sl->sl_mincsn ) >= 0 ) {
				do_present = 0;
				/* mutex is unlocked in playlog */
				syncprov_playlog( op, rs, sl, srs->sr_state.ctxcsn, &ctxcsn );
			} else {
				ldap_pvt_thread_mutex_unlock( &sl->sl_mutex );
			}
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
			/* If changed and doing Present lookup, send Present UUIDs */
			if ( do_present && syncprov_findcsn( op, FIND_PRESENT ) !=
				LDAP_SUCCESS ) {
				send_ldap_result( op, rs );
				return rs->sr_err;
			}
		}
	}

shortcut:
	/* Append CSN range to search filter, save original filter
	 * for persistent search evaluation
	 */
	if ( sop ) {
		sop->s_filterstr= op->ors_filterstr;
	}

	fand = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
	fand->f_choice = LDAP_FILTER_AND;
	fand->f_next = NULL;
	fava = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
	fava->f_choice = LDAP_FILTER_LE;
	fava->f_ava = op->o_tmpalloc( sizeof(AttributeAssertion), op->o_tmpmemctx );
	fava->f_ava->aa_desc = slap_schema.si_ad_entryCSN;
	ber_dupbv_x( &fava->f_ava->aa_value, &ctxcsn, op->o_tmpmemctx );
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

	/* Let our callback add needed info to returned entries */
	cb = op->o_tmpcalloc(1, sizeof(slap_callback)+sizeof(searchstate), op->o_tmpmemctx);
	ss = (searchstate *)(cb+1);
	ss->ss_on = on;
	ss->ss_so = sop;
	ss->ss_present = do_present;
	cb->sc_response = syncprov_search_response;
	cb->sc_cleanup = syncprov_search_cleanup;
	cb->sc_private = ss;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;

#if 0	/* I don't think we need to shortcircuit back-bdb any more */
	op->o_sync_mode &= SLAP_CONTROL_MASK;
#endif

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
syncprov_operational(
	Operation *op,
	SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *)op->o_bd->bd_info;
	syncprov_info_t		*si = (syncprov_info_t *)on->on_bi.bi_private;

	if ( rs->sr_entry &&
		dn_match( &rs->sr_entry->e_nname, op->o_bd->be_nsuffix )) {

		if ( SLAP_OPATTRS( rs->sr_attr_flags ) ||
			ad_inlist( slap_schema.si_ad_contextCSN, rs->sr_attrs )) {
			Attribute *a, **ap = NULL;

			for ( a=rs->sr_entry->e_attrs; a; a=a->a_next ) {
				if ( a->a_desc == slap_schema.si_ad_contextCSN )
					break;
			}

			if ( !a ) {
				for ( ap = &rs->sr_operational_attrs; *ap; ap=&(*ap)->a_next );

				a = ch_malloc( sizeof(Attribute));
				a->a_desc = slap_schema.si_ad_contextCSN;
				a->a_vals = ch_malloc( 2 * sizeof(struct berval));
				a->a_vals[1].bv_val = NULL;
				a->a_nvals = a->a_vals;
				a->a_next = NULL;
				a->a_flags = 0;
				*ap = a;
			}

			ldap_pvt_thread_mutex_lock( &si->si_csn_mutex );
			if ( !ap ) {
				strcpy( a->a_vals[0].bv_val, si->si_ctxcsnbuf );
			} else {
				ber_dupbv( &a->a_vals[0], &si->si_ctxcsn );
			}
			ldap_pvt_thread_mutex_unlock( &si->si_csn_mutex );
		}
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

	if ( strcasecmp( argv[ 0 ], "syncprov-checkpoint" ) == 0 ) {
		if ( argc != 3 ) {
			fprintf( stderr, "%s: line %d: wrong number of arguments in "
				"\"syncprov-checkpoint <ops> <minutes>\"\n", fname, lineno );
			return -1;
		}
		si->si_chkops = atoi( argv[1] );
		si->si_chktime = atoi( argv[2] ) * 60;
		return 0;

	} else if ( strcasecmp( argv[0], "syncprov-sessionlog" ) == 0 ) {
		sessionlog *sl;
		int sid, size;
		if ( argc != 3 ) {
			fprintf( stderr, "%s: line %d: wrong number of arguments in "
				"\"syncprov-sessionlog <sid> <size>\"\n", fname, lineno );
			return -1;
		}
		sid = atoi( argv[1] );
		if ( sid < 0 || sid > 999 ) {
			fprintf( stderr,
				"%s: line %d: session log id %d is out of range [0..999]\n",
				fname, lineno, sid );
			return -1;
		}
		size = atoi( argv[2] );
		if ( size < 0 ) {
			fprintf( stderr,
				"%s: line %d: session log size %d is negative\n",
				fname, lineno, size );
			return -1;
		}
		for ( sl = si->si_logs; sl; sl=sl->sl_next ) {
			if ( sl->sl_sid == sid ) {
				sl->sl_size = size;
				break;
			}
		}
		if ( !sl ) {
			sl = ch_malloc( sizeof( sessionlog ) + LDAP_LUTIL_CSNSTR_BUFSIZE );
			sl->sl_mincsn.bv_val = (char *)(sl+1);
			sl->sl_mincsn.bv_len = 0;
			sl->sl_sid = sid;
			sl->sl_size = size;
			sl->sl_num = 0;
			sl->sl_head = sl->sl_tail = NULL;
			sl->sl_next = si->si_logs;
			ldap_pvt_thread_mutex_init( &sl->sl_mutex );
			si->si_logs = sl;
		}
		return 0;
	}

	return SLAP_CONF_UNKNOWN;
}

/* Cheating - we have no thread pool context for these functions,
 * so make one.
 */
typedef struct thread_keys {
	void *key;
	void *data;
	ldap_pvt_thread_pool_keyfree_t *xfree;
} thread_keys;

#define MAXKEYS	32
/* A fake thread context */
static thread_keys thrctx[MAXKEYS];

/* Read any existing contextCSN from the underlying db.
 * Then search for any entries newer than that. If no value exists,
 * just generate it. Cache whatever result.
 */
static int
syncprov_db_open(
    BackendDB *be
)
{
	slap_overinst   *on = (slap_overinst *) be->bd_info;
	syncprov_info_t *si = (syncprov_info_t *)on->on_bi.bi_private;

	Connection conn;
	char opbuf[OPERATION_BUFFER_SIZE];
	char ctxcsnbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];
	Operation *op = (Operation *)opbuf;
	Entry *e;
	Attribute *a;
	int rc;

	connection_fake_init( &conn, op, thrctx );
	op->o_bd = be;
	op->o_dn = be->be_rootdn;
	op->o_ndn = be->be_rootndn;

	ctxcsnbuf[0] = '\0';

	op->o_bd->bd_info = on->on_info->oi_orig;
	rc = be_entry_get_rw( op, be->be_nsuffix, NULL,
		slap_schema.si_ad_contextCSN, 0, &e );

	if ( e ) {
		a = attr_find( e->e_attrs, slap_schema.si_ad_contextCSN );
		if ( a ) {
			si->si_ctxcsn.bv_len = a->a_nvals[0].bv_len;
			if ( si->si_ctxcsn.bv_len >= sizeof(si->si_ctxcsnbuf ))
				si->si_ctxcsn.bv_len = sizeof(si->si_ctxcsnbuf)-1;
			strncpy( si->si_ctxcsnbuf, a->a_nvals[0].bv_val,
				si->si_ctxcsn.bv_len );
			si->si_ctxcsnbuf[si->si_ctxcsn.bv_len] = '\0';
			strcpy( ctxcsnbuf, si->si_ctxcsnbuf );
		}
		be_entry_release_r( op, e );
		op->o_bd->bd_info = (BackendInfo *)on;
		op->o_req_dn = be->be_suffix[0];
		op->o_req_ndn = be->be_nsuffix[0];
		op->ors_scope = LDAP_SCOPE_SUBTREE;
		syncprov_findcsn( op, FIND_MAXCSN );
	}

	if ( BER_BVISEMPTY( &si->si_ctxcsn ) ) {
		slap_get_csn( op, si->si_ctxcsnbuf, sizeof(si->si_ctxcsnbuf),
				&si->si_ctxcsn, 0 );
	}

	/* If our ctxcsn is different from what was read from the root
	 * entry, write the new value out.
	 */
	if ( strcmp( si->si_ctxcsnbuf, ctxcsnbuf )) {
		SlapReply rs = {REP_RESULT};
		syncprov_checkpoint( op, &rs, on );
	}

	op->o_bd->bd_info = (BackendInfo *)on;
	return 0;
}

/* Write the current contextCSN into the underlying db.
 */
static int
syncprov_db_close(
    BackendDB *be
)
{
    slap_overinst   *on = (slap_overinst *) be->bd_info;
    syncprov_info_t *si = (syncprov_info_t *)on->on_bi.bi_private;
	int i;

	if ( si->si_numops ) {
		Connection conn;
		char opbuf[OPERATION_BUFFER_SIZE];
		Operation *op = (Operation *)opbuf;
		SlapReply rs = {REP_RESULT};

		connection_fake_init( &conn, op, thrctx );
		op->o_bd = be;
		op->o_dn = be->be_rootdn;
		op->o_ndn = be->be_rootndn;
		syncprov_checkpoint( op, &rs, on );
	}
	for ( i=0; thrctx[i].key; i++) {
		if ( thrctx[i].xfree )
			thrctx[i].xfree( thrctx[i].key, thrctx[i].data );
		thrctx[i].key = NULL;
	}

    return 0;
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
	ldap_pvt_thread_mutex_init( &si->si_mods_mutex );
	si->si_ctxcsn.bv_val = si->si_ctxcsnbuf;

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
		ldap_pvt_thread_mutex_destroy( &si->si_mods_mutex );
		ldap_pvt_thread_mutex_destroy( &si->si_ops_mutex );
		ldap_pvt_thread_mutex_destroy( &si->si_csn_mutex );
		ch_free( si );
	}

	return 0;
}

static int syncprov_parseCtrl (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	ber_tag_t tag;
	BerElement *ber;
	ber_int_t mode;
	ber_len_t len;
	struct berval cookie = BER_BVNULL;
	sync_control *sr;
	int rhint = 0;

	if ( op->o_sync != SLAP_CONTROL_NONE ) {
		rs->sr_text = "Sync control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( op->o_pagedresults != SLAP_CONTROL_NONE ) {
		rs->sr_text = "Sync control specified with pagedResults control";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		rs->sr_text = "Sync control value is empty (or absent)";
		return LDAP_PROTOCOL_ERROR;
	}

	/* Parse the control value
	 *      syncRequestValue ::= SEQUENCE {
	 *              mode   ENUMERATED {
	 *                      -- 0 unused
	 *                      refreshOnly		(1),
	 *                      -- 2 reserved
	 *                      refreshAndPersist	(3)
	 *              },
	 *              cookie  syncCookie OPTIONAL
	 *      }
	 */

	ber = ber_init( &ctrl->ldctl_value );
	if( ber == NULL ) {
		rs->sr_text = "internal error";
		return LDAP_OTHER;
	}

	if ( (tag = ber_scanf( ber, "{i" /*}*/, &mode )) == LBER_ERROR ) {
		rs->sr_text = "Sync control : mode decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	switch( mode ) {
	case LDAP_SYNC_REFRESH_ONLY:
		mode = SLAP_SYNC_REFRESH;
		break;
	case LDAP_SYNC_REFRESH_AND_PERSIST:
		mode = SLAP_SYNC_REFRESH_AND_PERSIST;
		break;
	default:
		rs->sr_text = "Sync control : unknown update mode";
		return LDAP_PROTOCOL_ERROR;
	}

	tag = ber_peek_tag( ber, &len );

	if ( tag == LDAP_TAG_SYNC_COOKIE ) {
		if (( ber_scanf( ber, /*{*/ "o", &cookie )) == LBER_ERROR ) {
			rs->sr_text = "Sync control : cookie decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
	}
	if ( tag == LDAP_TAG_RELOAD_HINT ) {
		if (( ber_scanf( ber, /*{*/ "b", &rhint )) == LBER_ERROR ) {
			rs->sr_text = "Sync control : rhint decoding error";
			return LDAP_PROTOCOL_ERROR;
		}
	}
	if (( ber_scanf( ber, /*{*/ "}")) == LBER_ERROR ) {
			rs->sr_text = "Sync control : decoding error";
			return LDAP_PROTOCOL_ERROR;
	}
	sr = op->o_tmpcalloc( 1, sizeof(struct sync_control), op->o_tmpmemctx );
	sr->sr_rhint = rhint;
	if (!BER_BVISNULL(&cookie)) {
		ber_bvarray_add( &sr->sr_state.octet_str, &cookie );
		slap_parse_sync_cookie( &sr->sr_state );
	}

	op->o_controls[slap_cids.sc_LDAPsync] = sr;

	(void) ber_free( ber, 1 );

	op->o_sync = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	op->o_sync_mode |= mode;	/* o_sync_mode shares o_sync */

	return LDAP_SUCCESS;
}

/* This overlay is set up for dynamic loading via moduleload. For static
 * configuration, you'll need to arrange for the slap_overinst to be
 * initialized and registered by some other function inside slapd.
 */

static slap_overinst 		syncprov;

int
syncprov_init()
{
	int rc;

	rc = register_supported_control( LDAP_CONTROL_SYNC,
		SLAP_CTRL_HIDE|SLAP_CTRL_SEARCH, NULL,
		syncprov_parseCtrl, &slap_cids.sc_LDAPsync );
	if ( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "Failed to register control %d\n", rc );
		return rc;
	}

	syncprov.on_bi.bi_type = "syncprov";
	syncprov.on_bi.bi_db_init = syncprov_db_init;
	syncprov.on_bi.bi_db_config = syncprov_db_config;
	syncprov.on_bi.bi_db_destroy = syncprov_db_destroy;
	syncprov.on_bi.bi_db_open = syncprov_db_open;
	syncprov.on_bi.bi_db_close = syncprov_db_close;

	syncprov.on_bi.bi_op_abandon = syncprov_op_abandon;
	syncprov.on_bi.bi_op_cancel = syncprov_op_abandon;

	syncprov.on_bi.bi_op_add = syncprov_op_mod;
	syncprov.on_bi.bi_op_compare = syncprov_op_compare;
	syncprov.on_bi.bi_op_delete = syncprov_op_mod;
	syncprov.on_bi.bi_op_modify = syncprov_op_mod;
	syncprov.on_bi.bi_op_modrdn = syncprov_op_mod;
	syncprov.on_bi.bi_op_search = syncprov_op_search;
	syncprov.on_bi.bi_extended = syncprov_op_extended;
	syncprov.on_bi.bi_operational = syncprov_operational;

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
