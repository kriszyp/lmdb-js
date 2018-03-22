/* message_queue.c - routines to maintain the per-connection lists
 * of pending operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2016-2018 The OpenLDAP Foundation.
 * Portions Copyright 2016 Symas Corporation.
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
 * This work was developed by Symas Corporation
 * based on back-meta module for inclusion in OpenLDAP Software.
 * This work was sponsored by Ericsson. */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "lutil.h"
#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-asyncmeta.h"
#include "../../../libraries/liblber/lber-int.h"
#include "lutil.h"


LDAPControl **asyncmeta_copy_controls(Operation *op)
{
	LDAPControl **new_controls = NULL;
	LDAPControl **c;
	LDAPControl  *tmp_ctl = NULL;
	int i, length = 1;


	if (op->o_ctrls == NULL) {
		return NULL;
	}
	for (c = op->o_ctrls; *c != NULL; c++) {
		length++;
	}

	new_controls = op->o_tmpalloc( sizeof(LDAPControl*)*length, op->o_tmpmemctx );
	for (i = 0; i < length-1; i ++) {
		new_controls[i] = op->o_tmpalloc( sizeof(LDAPControl), op->o_tmpmemctx );
		if (op->o_ctrls[i]->ldctl_value.bv_len > 0) {
			ber_dupbv_x( &new_controls[i]->ldctl_value, &op->o_ctrls[i]->ldctl_value, op->o_tmpmemctx);
		}
		if (op->o_ctrls[i]->ldctl_oid) {
			new_controls[i]->ldctl_oid = ber_strdup_x(op->o_ctrls[i]->ldctl_oid, op->o_tmpmemctx);
		}
		new_controls[i]->ldctl_iscritical = op->o_ctrls[i]->ldctl_iscritical;
	}
	new_controls[length-1] = NULL;
	return new_controls;
}

static
void asyncmeta_free_op_controls(Operation *op)
{
	LDAPControl **c;
	for (c = op->o_ctrls; *c != NULL; c++) {
		if ((*c)->ldctl_value.bv_len > 0) {
			free((*c)->ldctl_value.bv_val);
		}
		if ((*c)->ldctl_oid) {
			free((*c)->ldctl_oid);
		}
		free(*c);
	}
	free(op->o_ctrls);
}


static
Modifications* asyncmeta_copy_modlist(Operation *op, Modifications *modlist)
{
	Modifications *ml;
	Modifications *new_mods = NULL;
	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		Modifications *mod = op->o_tmpalloc( sizeof( Modifications ), op->o_tmpmemctx );
		*mod = *ml;
		if ( ml->sml_values ) {
				ber_bvarray_dup_x( &mod->sml_values, ml->sml_values, op->o_tmpmemctx );
				if ( ml->sml_nvalues ) {
					ber_bvarray_dup_x( &mod->sml_nvalues, ml->sml_nvalues, op->o_tmpmemctx );
				}
			}
		mod->sml_next = NULL;
		if (new_mods == NULL) {
			new_mods = mod;
		} else {
			new_mods->sml_next = mod;
		}
	}
	return new_mods;
}

Operation *asyncmeta_copy_op(Operation *op)
{
	const char	*text;
	int rc;
	char txtbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof txtbuf;
	Entry *e;
	Operation *new_op = op->o_tmpcalloc( 1, sizeof(OperationBuffer), op->o_tmpmemctx );
	*new_op = *op;
	new_op->o_hdr = &((OperationBuffer *) new_op)->ob_hdr;
	*(new_op->o_hdr) = *(op->o_hdr);
	new_op->o_controls = ((OperationBuffer *) new_op)->ob_controls;
	new_op->o_callback = op->o_callback;
	new_op->o_ber = NULL;
	new_op->o_bd = op->o_bd->bd_self;

	ber_dupbv_x( &new_op->o_req_dn, &op->o_req_dn, op->o_tmpmemctx );
	ber_dupbv_x( &new_op->o_req_ndn, &op->o_req_ndn, op->o_tmpmemctx );
	op->o_callback = NULL;

	if (op->o_ndn.bv_len > 0) {
		ber_dupbv_x( &new_op->o_ndn, &op->o_ndn, op->o_tmpmemctx );
	}
	if (op->o_dn.bv_len > 0) {
		ber_dupbv_x( &new_op->o_dn, &op->o_dn, op->o_tmpmemctx );
	}

	new_op->o_ctrls = asyncmeta_copy_controls(op);
	switch (op->o_tag) {
	case LDAP_REQ_SEARCH:
	{
		AttributeName *at_names;
		int i;
		for (i=0; op->ors_attrs && !BER_BVISNULL( &op->ors_attrs[i].an_name ); i++);
		if (i > 0) {
			at_names = op->o_tmpcalloc( i+1, sizeof( AttributeName ), op->o_tmpmemctx );
			at_names[i].an_name.bv_len = 0;
			i--;
			for (i; i >= 0; i--) {
				at_names[i] = op->ors_attrs[i];
				ber_dupbv_x( &at_names[i].an_name, &op->ors_attrs[i].an_name, op->o_tmpmemctx );
			}
		} else {
			at_names = NULL;
		}
		ber_dupbv_x( &new_op->ors_filterstr, &op->ors_filterstr, op->o_tmpmemctx );
		new_op->ors_filter = filter_dup( op->ors_filter, op->o_tmpmemctx );
		new_op->ors_attrs = at_names;
	}
	break;
	case LDAP_REQ_ADD:
	{
		slap_entry2mods(op->ora_e, &new_op->ora_modlist, &text, txtbuf, textlen);
		e = entry_alloc();
		new_op->ora_e = e;
		ber_dupbv_x( &e->e_name, &op->o_req_dn, op->o_tmpmemctx );
		ber_dupbv_x( &e->e_nname, &op->o_req_ndn, op->o_tmpmemctx );
		rc = slap_mods2entry( new_op->ora_modlist, &new_op->ora_e, 1, 0, &text, txtbuf, textlen);
	}
	break;
	case LDAP_REQ_MODIFY:
	{
		new_op->orm_modlist = asyncmeta_copy_modlist(op, op->orm_modlist);
	}
	break;
	case LDAP_REQ_COMPARE:
		new_op->orc_ava = (AttributeAssertion *)ch_calloc( 1, sizeof( AttributeAssertion ));
		*new_op->orc_ava = *op->orc_ava;
		if ( !BER_BVISNULL( &op->orc_ava->aa_value ) ) {
			ber_dupbv_x( &new_op->orc_ava->aa_value,  &op->orc_ava->aa_value, op->o_tmpmemctx);
		}
		break;
	case LDAP_REQ_MODRDN:

		if (op->orr_newrdn.bv_len > 0) {
			ber_dupbv_x( &new_op->orr_newrdn, &op->orr_newrdn, op->o_tmpmemctx );
		}
		if (op->orr_nnewrdn.bv_len > 0) {
			ber_dupbv_x( &new_op->orr_nnewrdn, &op->orr_nnewrdn, op->o_tmpmemctx );
		}
		if (op->orr_newSup != NULL) {
			new_op->orr_newSup = op->o_tmpalloc( sizeof( struct berval ), op->o_tmpmemctx );
			new_op->orr_newSup->bv_len = 0;
			if (op->orr_newSup->bv_len > 0) {
				ber_dupbv_x( new_op->orr_newSup, op->orr_newSup, op->o_tmpmemctx );
			}
		}

		if (op->orr_nnewSup != NULL) {
			new_op->orr_nnewSup = op->o_tmpalloc( sizeof( struct berval ), op->o_tmpmemctx );
			new_op->orr_nnewSup->bv_len = 0;
			if (op->orr_nnewSup->bv_len > 0) {
				ber_dupbv_x( new_op->orr_nnewSup, op->orr_nnewSup, op->o_tmpmemctx );
			}
		}
		new_op->orr_modlist = asyncmeta_copy_modlist(op, op->orr_modlist);
		break;
	case LDAP_REQ_DELETE:
	default:
		break;
	}
	return new_op;
}


typedef struct listptr {
	void *reserved;
	struct listptr *next;
} listptr;

typedef struct listhead {
	struct listptr *list;
	int cnt;
} listhead;

static void *asyncmeta_memctx_destroy(void *key, void *data)
{
	listhead *lh = data;
	listptr *lp;
	while (lp = lh->list) {
		lh->list = lp->next;
		slap_sl_mem_destroy((void *)1, lp);
	}
	ch_free(lh);
}

#ifndef LH_MAX
#define LH_MAX	16
#endif

static void *asyncmeta_memctx_get(void *threadctx)
{
	listhead *lh = NULL;
	listptr *lp = NULL;
	ldap_pvt_thread_pool_getkey(threadctx, asyncmeta_memctx_get, &lh, NULL);
	if (!lh) {
		lh = ch_malloc(sizeof(listhead));
		lh->cnt = 0;
		lh->list = NULL;
		ldap_pvt_thread_pool_setkey(threadctx, asyncmeta_memctx_get, lh, asyncmeta_memctx_destroy, NULL, NULL);
	}
	if (lh->list) {
		lp = lh->list;
		lh->list = lp->next;
		lh->cnt--;
		slap_sl_mem_setctx(threadctx, lp);
	}
	return slap_sl_mem_create(SLAP_SLAB_SIZE, SLAP_SLAB_STACK, threadctx, 1);
}

static void asyncmeta_memctx_put(void *threadctx, void *memctx)
{
	listhead *lh = NULL;
	ldap_pvt_thread_pool_getkey(threadctx, asyncmeta_memctx_get, &lh, NULL);
	if (!lh) {
		lh = ch_malloc(sizeof(listhead));
		lh->cnt = 0;
		lh->list = NULL;
		ldap_pvt_thread_pool_setkey(threadctx, asyncmeta_memctx_get, lh, asyncmeta_memctx_destroy, NULL, NULL);
	}
	if (lh->cnt < LH_MAX) {
		listptr *lp = memctx;
		lp->next = lh->list;
		lh->list = lp;
		lh->cnt++;
	} else {
		slap_sl_mem_destroy((void *)1, memctx);
	}
}

int asyncmeta_new_bm_context(Operation *op, SlapReply *rs, bm_context_t **new_bc, int ntargets)
{
	void *oldctx = op->o_tmpmemctx;
	int i;
	/* prevent old memctx from being destroyed */
	slap_sl_mem_setctx(op->o_threadctx, NULL);
	/* create new memctx */
	op->o_tmpmemctx = asyncmeta_memctx_get( op->o_threadctx );
	*new_bc = op->o_tmpcalloc( 1, sizeof( bm_context_t ), op->o_tmpmemctx );

	(*new_bc)->op = asyncmeta_copy_op(op);
	(*new_bc)->candidates = op->o_tmpcalloc(ntargets, sizeof(SlapReply),op->o_tmpmemctx);
	(*new_bc)->msgids = op->o_tmpcalloc(ntargets, sizeof(int),op->o_tmpmemctx);
	for (i = 0; i < ntargets; i++) {
		(*new_bc)->msgids[i] = META_MSGID_UNDEFINED;
	}
	/* restore original memctx */
	slap_sl_mem_setctx(op->o_threadctx, oldctx);
	op->o_tmpmemctx = oldctx;
	return LDAP_SUCCESS;
}

void asyncmeta_free_op(Operation *op)
{
	assert (op != NULL);
	switch (op->o_tag) {
	case LDAP_REQ_SEARCH:
		if (op->ors_filterstr.bv_len != 0) {
			free(op->ors_filterstr.bv_val);
		}
		if (op->ors_filter) {
			filter_free(op->ors_filter);
		}
		if (op->ors_attrs) {
			free(op->ors_attrs);
		}
		break;
	case LDAP_REQ_ADD:
		if ( op->ora_modlist != NULL ) {
			slap_mods_free(op->ora_modlist, 0 );
		}

		if ( op->ora_e != NULL ) {
			entry_free( op->ora_e );
		}

		break;
	case LDAP_REQ_MODIFY:
		if ( op->orm_modlist != NULL ) {
			slap_mods_free(op->orm_modlist, 1 );
		}
		break;
	case LDAP_REQ_MODRDN:
		if (op->orr_newrdn.bv_len > 0) {
			free(op->orr_newrdn.bv_val);
		}
		if (op->orr_nnewrdn.bv_len > 0) {
			free(op->orr_nnewrdn.bv_val);
		}

		if (op->orr_nnewSup != NULL ) {
			if (op->orr_nnewSup->bv_len > 0) {
				free(op->orr_nnewSup->bv_val);
			}
			free (op->orr_nnewSup);
		}

		if (op->orr_newSup != NULL ) {
			if (op->orr_newSup->bv_len > 0) {
				free(op->orr_newSup->bv_val);
			}
			free (op->orr_newSup);
		}

		if ( op->orr_modlist != NULL ) {
			slap_mods_free(op->orr_modlist, 1 );
		}
		break;
	case LDAP_REQ_COMPARE:
		if ( !BER_BVISNULL( &op->orc_ava->aa_value ) ) {
			free(op->orc_ava->aa_value.bv_val);
		}
		free(op->orc_ava);
		break;
	case LDAP_REQ_DELETE:
		break;
	default:
		Debug( LDAP_DEBUG_TRACE, "==> asyncmeta_free_op : other message type",
	       0, 0, 0 );
	}

	if (op->o_ctrls != NULL) {
		asyncmeta_free_op_controls(op);
	}
	if (op->o_ndn.bv_len > 0) {
		free(op->o_ndn.bv_val);
	}
	if (op->o_dn.bv_len > 0) {
		free( op->o_dn.bv_val );
	}
	if (op->o_req_dn.bv_len > 0) {
		free(op->o_req_dn.bv_val);
	}
	if (op->o_req_dn.bv_len > 0) {
		free(op->o_req_ndn.bv_val);
	}
	free(op);
}




void asyncmeta_clear_bm_context(bm_context_t *bc)
{

	Operation *op = bc->op;
#if 0
	bm_candidates_t  *cl;
	a_metainfo_t	*mi;
	int i = 0;
	if (bmc == NULL) {
		return;
	} else if (bmc->cl == NULL) {
		free(bmc);
		return;
	}
	cl = bmc->cl;
	op = cl->op;
	switch (op->o_tag) {
	case LDAP_REQ_SEARCH:
		break;
	case LDAP_REQ_ADD:
		if ( (bmc->mdn.bv_len != 0) &&
		     (bmc->mdn.bv_val != op->o_req_dn.bv_val) ) {
			free( bmc->mdn.bv_val );
		}

		if (bmc->data.add_d.attrs != NULL )  {
			while (bmc->data.add_d.attrs[i] != NULL) {
				free( bmc->data.add_d.attrs[i]->mod_bvalues );
				free( bmc->data.add_d.attrs[i] );
				i++;
			}
			free( bmc->data.add_d.attrs );
			}
		break;
	case LDAP_REQ_MODIFY:
		if ( bmc->mdn.bv_val != op->o_req_dn.bv_val ) {
			free( bmc->mdn.bv_val );
		}
		if ( bmc->data.mod_d.modv != NULL ) {
			for ( i = 0; bmc->data.mod_d.modv[ i ]; i++ ) {
				free( bmc->data.mod_d.modv[ i ]->mod_bvalues );
			}
		}
		free( bmc->data.mod_d.mods );
		free( bmc->data.mod_d.modv );

		break;
	case LDAP_REQ_MODRDN:
		if ( bmc->mdn.bv_val != op->o_req_dn.bv_val ) {
			free( bmc->mdn.bv_val );
		}

		if ( bmc->data.modrdn_d.newSuperior.bv_len != 0 &&
		     bmc->data.modrdn_d.newSuperior.bv_val != op->orr_newSup->bv_val )
		{
			free( bmc->data.modrdn_d.newSuperior.bv_val );

		}

		if ( bmc->data.modrdn_d.newrdn.bv_len != 0 &&
		     bmc->data.modrdn_d.newrdn.bv_val != op->orr_newrdn.bv_val )
		{
			free( bmc->data.modrdn_d.newrdn.bv_val );

		}
		break;
	case LDAP_REQ_COMPARE:
		if ( bmc->mdn.bv_val != op->o_req_dn.bv_val ) {
			free( bmc->mdn.bv_val );
		}
		if ( op->orc_ava->aa_value.bv_val != bmc->data.comp_d.mapped_value.bv_val ) {
			free( bmc->data.comp_d.mapped_value.bv_val );
			}
		break;
	case LDAP_REQ_DELETE:
		if ( bmc->mdn.bv_val != op->o_req_dn.bv_val ) {
			free( bmc->mdn.bv_val );
		}
		break;
	default:
		Debug( LDAP_DEBUG_TRACE, "==> asyncmeta_clear_bm_context: other message type",
	       0, 0, 0 );
	}
	if (bmc->dc != NULL) {
		free (bmc->dc);
	}
	free(bmc);

	if (clear_cl > 0) {
		asyncmeta_free_candidate_list(cl, lock);
		Debug( LDAP_DEBUG_TRACE, "==> asyncmeta_clear_bm_context: free_cl_list\n",
	       0, 0, 0 );
	}
#else
	asyncmeta_memctx_put(op->o_threadctx, op->o_tmpmemctx);
#endif
}

int asyncmeta_add_message_queue(a_metaconn_t *mc, bm_context_t *bc)
{
	a_metainfo_t *mi = mc->mc_info;
	int max_pending_ops = (mi->mi_max_pending_ops == 0) ? META_BACK_CFG_MAX_PENDING_OPS : mi->mi_max_pending_ops;

	Debug( LDAP_DEBUG_TRACE, "add_message_queue: mc %p, pending_ops %d, max_pending %d\n",
		mc, mc->pending_ops, max_pending_ops );

	if (mc->pending_ops >= max_pending_ops) {
		return LDAP_BUSY;
	}

	LDAP_SLIST_INSERT_HEAD( &mc->mc_om_list, bc, bc_next);
	mc->pending_ops++;
	return LDAP_SUCCESS;
}

void
asyncmeta_drop_bc(a_metaconn_t *mc, bm_context_t *bc)
{
	bm_context_t *om;
	int i;
	LDAP_SLIST_FOREACH( om, &mc->mc_om_list, bc_next ) {
		if (om == bc) {
			for (i = 0; i < mc->mc_info->mi_ntargets; i++)
			{
				if (bc->msgids[i] >= 0) {
					mc->mc_conns[i].msc_pending_ops--;
				}
			}
			LDAP_SLIST_REMOVE(&mc->mc_om_list, om, bm_context_t, bc_next);
			mc->pending_ops--;
			break;
		}
	}
}

bm_context_t *
asyncmeta_find_message(ber_int_t msgid, a_metaconn_t *mc, int candidate)
{
	bm_context_t *om;
	LDAP_SLIST_FOREACH( om, &mc->mc_om_list, bc_next ) {
		if (om->candidates[candidate].sr_msgid == msgid) {
			break;
		}
	}
	return om;
}



bm_context_t *
asyncmeta_find_message_by_opmsguid (ber_int_t msgid, a_metaconn_t *mc, int remove)
{
	bm_context_t *om;
	LDAP_SLIST_FOREACH( om, &mc->mc_om_list, bc_next ) {
		if (om->op->o_msgid == msgid) {
			break;
		}
	}
	if (remove && om) {
		LDAP_SLIST_REMOVE(&mc->mc_om_list, om, bm_context_t, bc_next);
		mc->pending_ops--;
	}
	return om;
}
