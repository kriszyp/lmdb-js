/* backglue.c - backend glue routines */
/* $OpenLDAP$ */
/*
 * Copyright 2001-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
	int nentries;
	int matchlen;
	char *matched;
	int nrefs;
	BerVarray refs;
	slap_callback *prevcb;
} glue_state;

static void
glue_back_response (
	Connection *conn,
	Operation *op,
	ber_tag_t tag,
	ber_int_t msgid,
	ber_int_t err,
	const char *matched,
	const char *text,
	BerVarray ref,
	const char *resoid,
	struct berval *resdata,
	struct berval *sasldata,
	LDAPControl **ctrls
)
{
	glue_state *gs = op->o_callback->sc_private;

	if (err == LDAP_SUCCESS || gs->err != LDAP_SUCCESS)
		gs->err = err;
	if (gs->err == LDAP_SUCCESS && gs->matched) {
		free (gs->matched);
		gs->matched = NULL;
		gs->matchlen = 0;
	}
	if (gs->err != LDAP_SUCCESS && matched) {
		int len;
		len = strlen (matched);
		if (len > gs->matchlen) {
			if (gs->matched)
				free (gs->matched);
			gs->matched = ch_strdup (matched);
			gs->matchlen = len;
		}
	}
	if (ref) {
		int i, j, k;
		BerVarray new;

		for (i=0; ref[i].bv_val; i++);

		j = gs->nrefs;
		if (!j) {
			new = ch_malloc ((i+1)*sizeof(struct berval));
		} else {
			new = ch_realloc(gs->refs,
				(j+i+1)*sizeof(struct berval));
		}
		for (k=0; k<i; j++,k++) {
			ber_dupbv( &new[j], &ref[k] );
		}
		new[j].bv_val = NULL;
		gs->nrefs = j;
		gs->refs = new;
	}
}

static void
glue_back_sresult (
	Connection *c,
	Operation *op,
	ber_int_t err,
	const char *matched,
	const char *text,
	BerVarray refs,
	LDAPControl **ctrls,
	int nentries
)
{
	glue_state *gs = op->o_callback->sc_private;

	gs->nentries += nentries;
	glue_back_response (c, op, 0, 0, err, matched, text, refs,
			    NULL, NULL, NULL, ctrls);
}

static int
glue_back_sendentry (
	BackendDB *be,
	Connection *c,
	Operation *op,
	Entry *e,
	AttributeName *an,
	int ao,
	LDAPControl **ctrls
)
{
	slap_callback *tmp = op->o_callback;
	glue_state *gs = tmp->sc_private;
	int rc;

	op->o_callback = gs->prevcb;
	if (op->o_callback && op->o_callback->sc_sendentry) {
		rc = op->o_callback->sc_sendentry(be, c, op, e, an, ao, ctrls);
	} else {
		rc = send_search_entry(be, c, op, e, an, ao, ctrls);
	}
	op->o_callback = tmp;
	return rc;
}

static int
glue_back_search (
	BackendDB *b0,
	Connection *conn,
	Operation *op,
	struct berval *dn,
	struct berval *ndn,
	int scope,
	int deref,
	int slimit,
	int tlimit,
	Filter *filter,
	struct berval *filterstr,
	AttributeName *attrs,
	int attrsonly
)
{
	glueinfo *gi = (glueinfo *) b0->bd_info;
	BackendDB *be;
	int i, rc = 0, t2limit = 0, s2limit = 0;
	long stoptime = 0;
	glue_state gs = {0};
	slap_callback cb;

	cb.sc_response = glue_back_response;
	cb.sc_sresult = glue_back_sresult;
	cb.sc_sendentry = glue_back_sendentry;
	cb.sc_private = &gs;

	gs.prevcb = op->o_callback;

	if (tlimit) {
		stoptime = slap_get_time () + tlimit;
	}

	switch (scope) {
	case LDAP_SCOPE_BASE:
		be = glue_back_select (b0, ndn->bv_val);

		if (be && be->be_search) {
			rc = be->be_search (be, conn, op, dn, ndn, scope,
				   deref, slimit, tlimit, filter, filterstr,
					    attrs, attrsonly);
		} else {
			rc = LDAP_UNWILLING_TO_PERFORM;
			send_ldap_result (conn, op, rc, NULL,
				      "No search target found", NULL, NULL);
		}
		return rc;

	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
		op->o_callback = &cb;
		rc = gs.err = LDAP_UNWILLING_TO_PERFORM;

		/*
		 * Execute in reverse order, most general first 
		 */
		for (i = gi->nodes-1; i >= 0; i--) {
			if (!gi->n[i].be || !gi->n[i].be->be_search)
				continue;
			if (tlimit) {
				t2limit = stoptime - slap_get_time ();
				if (t2limit <= 0) {
					rc = gs.err = LDAP_TIMELIMIT_EXCEEDED;
					break;
				}
			}
			if (slimit) {
				s2limit = slimit - gs.nentries;
				if (s2limit <= 0) {
					rc = gs.err = LDAP_SIZELIMIT_EXCEEDED;
					break;
				}
			}
			rc = 0;
			/*
			 * check for abandon 
			 */
			if (op->o_abandon) {
				goto done;
			}
			be = gi->n[i].be;
			if (scope == LDAP_SCOPE_ONELEVEL && 
				dn_match(&gi->n[i].pdn, ndn)) {
				rc = be->be_search (be, conn, op,
					&be->be_suffix[0], &be->be_nsuffix[0],
					LDAP_SCOPE_BASE, deref,
					s2limit, t2limit, filter, filterstr,
					attrs, attrsonly);

			} else if (scope == LDAP_SCOPE_SUBTREE &&
				dnIsSuffix(&be->be_nsuffix[0], ndn)) {
				rc = be->be_search (be, conn, op,
					&be->be_suffix[0], &be->be_nsuffix[0],
					scope, deref,
					s2limit, t2limit, filter, filterstr,
					attrs, attrsonly);

			} else if (dnIsSuffix(ndn, &be->be_nsuffix[0])) {
				rc = be->be_search (be, conn, op, dn, ndn,
					scope, deref,
					s2limit, t2limit, filter, filterstr,
					attrs, attrsonly);
			}
		}
		break;
	}
	op->o_callback = gs.prevcb;

	send_search_result (conn, op, gs.err, gs.matched, NULL,
		gs.refs, NULL, gs.nentries);

done:
	if (gs.matched)
		free (gs.matched);
	if (gs.refs)
		ber_bvarray_free(gs.refs);
	return rc;
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
		if (b1->be_flags & SLAP_BFLAG_GLUE_SUBORDINATE) {
			/* The last database cannot be a subordinate of noone */
			if (i == nBackendDB - 1) {
				b1->be_flags ^= SLAP_BFLAG_GLUE_SUBORDINATE;
			}
			continue;
		}
		gi = NULL;
		for (j = i-1, be=&backendDB[j]; j>=0; be--,j--) {
			if (!(be->be_flags & SLAP_BFLAG_GLUE_SUBORDINATE)) {
				continue;
			}
			/* We will only link it once */
			if (be->be_flags & SLAP_BFLAG_GLUE_LINKED) {
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
			b1->bd_info = bi;
		}
	}
	/* If there are any unresolved subordinates left, something is wrong */
	return cont;
}
