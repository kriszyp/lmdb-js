/* backglue.c - backend glue routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
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

/*
 * Functions to glue a bunch of other backends into a single tree.
 * All of the glued backends must share a common suffix. E.g., you
 * can glue o=foo and ou=bar,o=foo but you can't glue o=foo and o=bar.
 *
 * This uses the backend structures and routines extensively, but is
 * not an actual backend of its own. To use it you must add a "subordinate"
 * keyword to the configuration of other backends. Subordinates will
 * automatically be connected to their parent backend.
 *
 * The purpose of these functions is to allow you to split a single database
 * into pieces (for load balancing purposes, whatever) but still be able
 * to treat it as a single database after it's been split. As such, each
 * of the glued backends should have identical rootdn and rootpw.
 *
 * If you need more elaborate configuration, you probably should be using
 * back-meta instead.
 *  -- Howard Chu
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#define SLAPD_TOOLS
#include "slap.h"

typedef struct gluenode {
	BackendDB *be;
	struct berval pdn;
} gluenode;

typedef struct glueinfo {
	BackendInfo bi;
	BackendDB bd;
	int nodes;
	gluenode n[1];
} glueinfo;

static int glueMode;
static BackendDB *glueBack;

static slap_response glue_back_response;

/* Just like select_backend, but only for our backends */
static BackendDB *
glue_back_select (
	BackendDB *be,
	const char *dn
)
{
	glueinfo *gi = (glueinfo *) be->bd_info;
	struct berval bv;
	int i;

	bv.bv_len = strlen(dn);
	bv.bv_val = (char *) dn;

	for (i = 0; i<gi->nodes; i++) {
		if (dnIsSuffix(&bv, &gi->n[i].be->be_nsuffix[0])) {
			return gi->n[i].be;
		}
	}
	return NULL;
}

/* This function will only be called in tool mode */
static int
glue_back_open (
	BackendInfo *bi
)
{
	int rc = 0;
	static int glueOpened = 0;

	if (glueOpened) return 0;

	glueOpened = 1;

	/* If we were invoked in tool mode, open all the underlying backends */
	if (slapMode & SLAP_TOOL_MODE) {
		rc = backend_startup (NULL);
	} /* other case is impossible */
	return rc;
}

/* This function will only be called in tool mode */
static int
glue_back_close (
	BackendInfo *bi
)
{
	static int glueClosed = 0;
	int rc = 0;

	if (glueClosed) return 0;

	glueClosed = 1;

	if (slapMode & SLAP_TOOL_MODE) {
		rc = backend_shutdown (NULL);
	}
	return rc;
}

static int
glue_back_db_open (
	BackendDB *be
)
{
	glueinfo *gi = (glueinfo *) be->bd_info;
	static int glueOpened = 0;
	int rc = 0;

	if (glueOpened) return 0;

	glueOpened = 1;

	gi->bd.be_acl = be->be_acl;

	if (gi->bd.bd_info->bi_db_open)
		rc = gi->bd.bd_info->bi_db_open(&gi->bd);

	return rc;
}

static int
glue_back_db_close (
	BackendDB *be
)
{
	glueinfo *gi = (glueinfo *) be->bd_info;
	static int glueClosed = 0;

	if (glueClosed) return 0;

	glueClosed = 1;

	/* Close the master */
	if (gi->bd.bd_info->bi_db_close)
		gi->bd.bd_info->bi_db_close( &gi->bd );

	return 0;
}

static int
glue_back_db_destroy (
	BackendDB *be
)
{
	glueinfo *gi = (glueinfo *) be->bd_info;

	if (gi->bd.bd_info->bi_db_destroy)
		gi->bd.bd_info->bi_db_destroy( &gi->bd );
	free (gi);
	return 0;
}

typedef struct glue_state {
	int err;
	int is_slimit;
	int slimit;
	int matchlen;
	char *matched;
	int nrefs;
	BerVarray refs;
} glue_state;

static int
glue_back_response ( Operation *op, SlapReply *rs )
{
	glue_state *gs = op->o_callback->sc_private;

	switch(rs->sr_type) {
	case REP_SEARCH:
		if ( gs->is_slimit && rs->sr_nentries >= gs->slimit ) {
			gs->err = LDAP_SIZELIMIT_EXCEEDED;
			return -1;
		}
		/* fallthru */
	case REP_SEARCHREF:
		return SLAP_CB_CONTINUE;

	default:
		if ( gs->is_slimit && rs->sr_err == LDAP_SIZELIMIT_EXCEEDED
				&& rs->sr_nentries >= gs->slimit ) {
			gs->err = LDAP_SIZELIMIT_EXCEEDED;
			return -1;
		}
		if (rs->sr_err == LDAP_SUCCESS || gs->err != LDAP_SUCCESS) {
			gs->err = rs->sr_err;
		}
		if (gs->err == LDAP_SUCCESS && gs->matched) {
			ch_free (gs->matched);
			gs->matched = NULL;
			gs->matchlen = 0;
		}
		if (gs->err != LDAP_SUCCESS && rs->sr_matched) {
			int len;
			len = strlen (rs->sr_matched);
			if (len > gs->matchlen) {
				if (gs->matched)
					ch_free (gs->matched);
				gs->matched = ch_strdup (rs->sr_matched);
				gs->matchlen = len;
			}
		}
		if (rs->sr_ref) {
			int i, j, k;
			BerVarray new;

			for (i=0; rs->sr_ref[i].bv_val; i++);

			j = gs->nrefs;
			if (!j) {
				new = ch_malloc ((i+1)*sizeof(struct berval));
			} else {
				new = ch_realloc(gs->refs,
					(j+i+1)*sizeof(struct berval));
			}
			for (k=0; k<i; j++,k++) {
				ber_dupbv( &new[j], &rs->sr_ref[k] );
			}
			new[j].bv_val = NULL;
			gs->nrefs = j;
			gs->refs = new;
		}
	}
	return 0;
}

static int
glue_back_search ( Operation *op, SlapReply *rs )
{
	BackendDB *b0 = op->o_bd;
	glueinfo *gi = (glueinfo *) b0->bd_info;
	int i;
	long stoptime = 0;
	glue_state gs = {0, 0, 0, 0, NULL, 0, NULL};
	slap_callback cb = { NULL, glue_back_response, NULL, NULL };
	int scope0, slimit0, tlimit0;
	struct berval dn, ndn;

	gs.is_slimit = ( op->ors_slimit > 0 );

	cb.sc_private = &gs;

	cb.sc_next = op->o_callback;

	if (op->ors_tlimit) {
		stoptime = slap_get_time () + op->ors_tlimit;
	}

	switch (op->ors_scope) {
	case LDAP_SCOPE_BASE:
		op->o_bd = glue_back_select (b0, op->o_req_ndn.bv_val);

		if (op->o_bd && op->o_bd->be_search) {
			rs->sr_err = op->o_bd->be_search( op, rs );
		} else {
			send_ldap_error(op, rs, LDAP_UNWILLING_TO_PERFORM,
				      "No search target found");
		}
		return rs->sr_err;

	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
	case LDAP_SCOPE_SUBORDINATE: /* FIXME */
		op->o_callback = &cb;
		rs->sr_err = gs.err = LDAP_UNWILLING_TO_PERFORM;
		scope0 = op->ors_scope;
		if ( gs.is_slimit ) {
			slimit0 = gs.slimit = op->ors_slimit;
		}
		tlimit0 = op->ors_tlimit;
		dn = op->o_req_dn;
		ndn = op->o_req_ndn;

		/*
		 * Execute in reverse order, most general first 
		 */
		for (i = gi->nodes-1; i >= 0; i--) {
			if (!gi->n[i].be || !gi->n[i].be->be_search)
				continue;
			if (tlimit0) {
				op->ors_tlimit = stoptime - slap_get_time ();
				if (op->ors_tlimit <= 0) {
					rs->sr_err = gs.err = LDAP_TIMELIMIT_EXCEEDED;
					break;
				}
			}
			if ( gs.is_slimit ) {
				op->ors_slimit = slimit0 - rs->sr_nentries;
				if (op->ors_slimit < 0) {
					rs->sr_err = gs.err = LDAP_SIZELIMIT_EXCEEDED;
					break;
				}
			}
			rs->sr_err = 0;
			/*
			 * check for abandon 
			 */
			if (op->o_abandon) {
				goto done;
			}
			op->o_bd = gi->n[i].be;
			if (scope0 == LDAP_SCOPE_ONELEVEL && 
				dn_match(&gi->n[i].pdn, &ndn))
			{
				op->ors_scope = LDAP_SCOPE_BASE;
				op->o_req_dn = op->o_bd->be_suffix[0];
				op->o_req_ndn = op->o_bd->be_nsuffix[0];
				rs->sr_err = op->o_bd->be_search(op, rs);

			} else if (scope0 == LDAP_SCOPE_SUBTREE &&
				dnIsSuffix(&op->o_bd->be_nsuffix[0], &ndn))
			{
				op->o_req_dn = op->o_bd->be_suffix[0];
				op->o_req_ndn = op->o_bd->be_nsuffix[0];
				rs->sr_err = op->o_bd->be_search( op, rs );

			} else if (dnIsSuffix(&ndn, &op->o_bd->be_nsuffix[0])) {
				rs->sr_err = op->o_bd->be_search( op, rs );
			}

			switch ( gs.err ) {

			/*
			 * Add errors that should result in dropping
			 * the search
			 */
			case LDAP_SIZELIMIT_EXCEEDED:
			case LDAP_TIMELIMIT_EXCEEDED:
			case LDAP_ADMINLIMIT_EXCEEDED:
				goto end_of_loop;
			
			default:
				break;
			}
		}
end_of_loop:;
		op->ors_scope = scope0;
		if ( gs.is_slimit ) {
			op->ors_slimit = slimit0;
		}
		op->ors_tlimit = tlimit0;
		op->o_req_dn = dn;
		op->o_req_ndn = ndn;

		break;
	}
	op->o_callback = cb.sc_next;
	rs->sr_err = gs.err;
	rs->sr_matched = gs.matched;
	rs->sr_ref = gs.refs;

	send_ldap_result( op, rs );

done:
	op->o_bd = b0;
	if (gs.matched)
		free (gs.matched);
	if (gs.refs)
		ber_bvarray_free(gs.refs);
	return rs->sr_err;
}


static int
glue_tool_entry_open (
	BackendDB *b0,
	int mode
)
{
	/* We don't know which backend to talk to yet, so just
	 * remember the mode and move on...
	 */

	glueMode = mode;
	glueBack = NULL;

	return 0;
}

static int
glue_tool_entry_close (
	BackendDB *b0
)
{
	int rc = 0;

	if (glueBack) {
		if (!glueBack->be_entry_close)
			return 0;
		rc = glueBack->be_entry_close (glueBack);
	}
	return rc;
}

static ID
glue_tool_entry_first (
	BackendDB *b0
)
{
	glueinfo *gi = (glueinfo *) b0->bd_info;
	int i;

	/* If we're starting from scratch, start at the most general */
	if (!glueBack) {
		for (i = gi->nodes-1; i >= 0; i--) {
			if (gi->n[i].be->be_entry_open &&
			    gi->n[i].be->be_entry_first) {
			    	glueBack = gi->n[i].be;
				break;
			}
		}

	}
	if (!glueBack || glueBack->be_entry_open (glueBack, glueMode) != 0)
		return NOID;

	return glueBack->be_entry_first (glueBack);
}

static ID
glue_tool_entry_next (
	BackendDB *b0
)
{
	glueinfo *gi = (glueinfo *) b0->bd_info;
	int i;
	ID rc;

	if (!glueBack || !glueBack->be_entry_next)
		return NOID;

	rc = glueBack->be_entry_next (glueBack);

	/* If we ran out of entries in one database, move on to the next */
	if (rc == NOID) {
		glueBack->be_entry_close (glueBack);
		for (i=0; i<gi->nodes; i++) {
			if (gi->n[i].be == glueBack)
				break;
		}
		if (i == 0) {
			glueBack = NULL;
			rc = NOID;
		} else {
			glueBack = gi->n[i-1].be;
			rc = glue_tool_entry_first (b0);
		}
	}
	return rc;
}

static Entry *
glue_tool_entry_get (
	BackendDB *b0,
	ID id
)
{
	if (!glueBack || !glueBack->be_entry_get)
		return NULL;

	return glueBack->be_entry_get (glueBack, id);
}

static ID
glue_tool_entry_put (
	BackendDB *b0,
	Entry *e,
	struct berval *text
)
{
	BackendDB *be;
	int rc;

	be = glue_back_select (b0, e->e_ndn);
	if (!be->be_entry_put)
		return NOID;

	if (!glueBack) {
		rc = be->be_entry_open (be, glueMode);
		if (rc != 0)
			return NOID;
	} else if (be != glueBack) {
		/* If this entry belongs in a different branch than the
		 * previous one, close the current database and open the
		 * new one.
		 */
		glueBack->be_entry_close (glueBack);
		rc = be->be_entry_open (be, glueMode);
		if (rc != 0)
			return NOID;
	}
	glueBack = be;
	return be->be_entry_put (be, e, text);
}

static int
glue_tool_entry_reindex (
	BackendDB *b0,
	ID id
)
{
	if (!glueBack || !glueBack->be_entry_reindex)
		return -1;

	return glueBack->be_entry_reindex (glueBack, id);
}

static int
glue_tool_sync (
	BackendDB *b0
)
{
	glueinfo *gi = (glueinfo *) b0->bd_info;
	int i;

	/* just sync everyone */
	for (i = 0; i<gi->nodes; i++)
		if (gi->n[i].be->be_sync)
			gi->n[i].be->be_sync (gi->n[i].be);
	return 0;
}

int
glue_sub_init( )
{
	int i, j;
	int cont = num_subordinates;
	BackendDB *b1, *be;
	BackendInfo *bi = NULL;
	glueinfo *gi;

	/* While there are subordinate backends, search backwards through the
	 * backends and connect them to their superior.
	 */
	for (i = nBackendDB - 1, b1=&backendDB[i]; cont && i>=0; b1--,i--) {
		if (SLAP_GLUE_SUBORDINATE ( b1 ) ) {
			/* The last database cannot be a subordinate of noone */
			if (i == nBackendDB - 1) {
				b1->be_flags ^= SLAP_BFLAG_GLUE_SUBORDINATE;
			}
			continue;
		}
		gi = NULL;
		for (j = i-1, be=&backendDB[j]; j>=0; be--,j--) {
			if ( ! SLAP_GLUE_SUBORDINATE( be ) ) {
				continue;
			}
			/* We will only link it once */
			if ( SLAP_GLUE_LINKED( be ) ) {
				continue;
			}
			if (!dnIsSuffix(&be->be_nsuffix[0], &b1->be_nsuffix[0])) {
				continue;
			}
			cont--;
			be->be_flags |= SLAP_BFLAG_GLUE_LINKED;
			if (gi == NULL) {
				/* We create a copy of the superior's be
				 * structure, pointing to all of its original
				 * information. Then we replace elements of
				 * the superior's info with our own. The copy
				 * is used whenever we have operations to pass
				 * down to the real database.
				 */
				b1->be_flags |= SLAP_BFLAG_GLUE_INSTANCE;
				gi = (glueinfo *)ch_malloc(sizeof(glueinfo));
				gi->nodes = 0;
				gi->bd = *b1;
				gi->bi = *b1->bd_info;
				bi = (BackendInfo *)gi;
				bi->bi_open = glue_back_open;
				bi->bi_close = glue_back_close;
				bi->bi_db_open = glue_back_db_open;
				bi->bi_db_close = glue_back_db_close;
				bi->bi_db_destroy = glue_back_db_destroy;

				bi->bi_op_search = glue_back_search;

				/*
				 * hooks for slap tools
				 */
				bi->bi_tool_entry_open = glue_tool_entry_open;
				bi->bi_tool_entry_close = glue_tool_entry_close;
				bi->bi_tool_entry_first = glue_tool_entry_first;
				bi->bi_tool_entry_next = glue_tool_entry_next;
				bi->bi_tool_entry_get = glue_tool_entry_get;
				bi->bi_tool_entry_put = glue_tool_entry_put;
				bi->bi_tool_entry_reindex = glue_tool_entry_reindex;
				bi->bi_tool_sync = glue_tool_sync;
				/* FIXME : will support later */
				bi->bi_tool_dn2id_get = 0;
				bi->bi_tool_id2entry_get = 0;
				bi->bi_tool_entry_modify = 0;
			} else {
				gi = (glueinfo *)ch_realloc(gi,
					sizeof(glueinfo) +
					gi->nodes * sizeof(gluenode));
			}
			gi->n[gi->nodes].be = be;
			dnParent( &be->be_nsuffix[0], &gi->n[gi->nodes].pdn ); 
			gi->nodes++;
		}
		if (gi) {
			/* One more node for the master */
			gi = (glueinfo *)ch_realloc(gi,
				sizeof(glueinfo) + gi->nodes * sizeof(gluenode));
			gi->n[gi->nodes].be = &gi->bd;
			dnParent( &b1->be_nsuffix[0], &gi->n[gi->nodes].pdn );
			gi->nodes++;
			b1->bd_info = (BackendInfo *)gi;
		}
	}
	/* If there are any unresolved subordinates left, something is wrong */
	return cont;
}
