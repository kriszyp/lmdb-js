/* glue.c - backend glue overlay */
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
 * The purpose of these functions is to allow you to split a single database
 * into pieces (for load balancing purposes, whatever) but still be able
 * to treat it as a single database after it's been split. As such, each
 * of the glued backends should have identical rootdn.
 *  -- Howard Chu
 */

#include "portable.h"

#ifdef SLAPD_OVER_GLUE

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#define SLAPD_TOOLS
#include "slap.h"

typedef struct gluenode {
	BackendDB *gn_be;
	int	gn_bx;
	struct berval gn_pdn;
	int gn_async;
} gluenode;

typedef struct glueinfo {
	int gi_nodes;
	struct berval gi_pdn;
	gluenode gi_n[1];
} glueinfo;

static slap_overinst	glue;

static int glueMode;
static BackendDB *glueBack;

static slap_response glue_op_response;

/* Just like select_backend, but only for our backends */
static BackendDB *
glue_back_select (
	BackendDB *be,
	struct berval *dn
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;
	int i;

	for (i = 0; i<gi->gi_nodes; i++) {
		assert( gi->gi_n[i].gn_be->be_nsuffix );

		if (dnIsSuffix(dn, &gi->gi_n[i].gn_be->be_nsuffix[0])) {
			return gi->gi_n[i].gn_be;
		}
	}
	be->bd_info = on->on_info->oi_orig;
	return be;
}


typedef struct glue_state {
	int err;
	int slimit;
	int matchlen;
	char *matched;
	int nrefs;
	BerVarray refs;
} glue_state;

static int
glue_op_response ( Operation *op, SlapReply *rs )
{
	glue_state *gs = op->o_callback->sc_private;

	switch(rs->sr_type) {
	case REP_SEARCH:
		if ( gs->slimit != SLAP_NO_LIMIT
				&& rs->sr_nentries >= gs->slimit )
		{
			rs->sr_err = gs->err = LDAP_SIZELIMIT_EXCEEDED;
			return -1;
		}
		/* fallthru */
	case REP_SEARCHREF:
		return SLAP_CB_CONTINUE;

	default:
		if (rs->sr_err == LDAP_SUCCESS ||
			rs->sr_err == LDAP_SIZELIMIT_EXCEEDED ||
			rs->sr_err == LDAP_TIMELIMIT_EXCEEDED ||
			rs->sr_err == LDAP_ADMINLIMIT_EXCEEDED ||
			rs->sr_err == LDAP_NO_SUCH_OBJECT ||
			gs->err != LDAP_SUCCESS)
			gs->err = rs->sr_err;
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

enum glue_which {
	op_modify = 0,
	op_modrdn,
	op_add,
	op_delete
};

static int
glue_op_func ( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;
	BackendDB *b0 = op->o_bd;
	BackendInfo *bi0 = op->o_bd->bd_info;
	BI_op_modify **func;
	enum glue_which which;
	int rc;

	op->o_bd = glue_back_select (b0, &op->o_req_ndn);
	b0->bd_info = on->on_info->oi_orig;

	switch(op->o_tag) {
	case LDAP_REQ_ADD: which = op_add; break;
	case LDAP_REQ_DELETE: which = op_delete; break;
	case LDAP_REQ_MODIFY: which = op_modify; break;
	case LDAP_REQ_MODRDN: which = op_modrdn; break;
	}

	func = &op->o_bd->bd_info->bi_op_modify;
	if ( func[which] )
		rc = func[which]( op, rs );
	else
		rc = SLAP_CB_CONTINUE;

	op->o_bd = b0;
	op->o_bd->bd_info = bi0;
	return rc;
}

static int
glue_op_search ( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;
	BackendDB *b0 = op->o_bd;
	BackendDB *b1 = NULL, *btmp;
	BackendInfo *bi0 = op->o_bd->bd_info;
	int i;
	long stoptime = 0;
	glue_state gs = {0, 0, 0, NULL, 0, NULL};
	slap_callback cb = { NULL, glue_op_response, NULL, NULL };
	int scope0, slimit0, tlimit0;
	struct berval dn, ndn, *pdn;

	cb.sc_private = &gs;

	cb.sc_next = op->o_callback;

	stoptime = slap_get_time () + op->ors_tlimit;

	op->o_bd = glue_back_select (b0, &op->o_req_ndn);
	b0->bd_info = on->on_info->oi_orig;

	switch (op->ors_scope) {
	case LDAP_SCOPE_BASE:
		return SLAP_CB_CONTINUE;

	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_SCOPE_SUBORDINATE
	case LDAP_SCOPE_SUBORDINATE: /* FIXME */
#endif

#if 0
		if ( op->o_sync ) {
			if (op->o_bd && op->o_bd->be_search) {
				rs->sr_err = op->o_bd->be_search( op, rs );
			} else {
				send_ldap_error(op, rs, LDAP_UNWILLING_TO_PERFORM,
						"No search target found");
			}
			return rs->sr_err;
		}
#endif

		op->o_callback = &cb;
		rs->sr_err = gs.err = LDAP_UNWILLING_TO_PERFORM;
		scope0 = op->ors_scope;
		slimit0 = gs.slimit = op->ors_slimit;
		tlimit0 = op->ors_tlimit;
		dn = op->o_req_dn;
		ndn = op->o_req_ndn;
		b1 = op->o_bd;

		/*
		 * Execute in reverse order, most general first 
		 */
		for (i = gi->gi_nodes; i >= 0; i--) {
			if ( i == gi->gi_nodes ) {
				btmp = b0;
				pdn = &gi->gi_pdn;
			} else {
				btmp = gi->gi_n[i].gn_be;
				pdn = &gi->gi_n[i].gn_pdn;
			}
			if (!btmp || !btmp->be_search)
				continue;
			if (!dnIsSuffix(&btmp->be_nsuffix[0], &b1->be_nsuffix[0]))
				continue;
			if (tlimit0 != SLAP_NO_LIMIT) {
				op->ors_tlimit = stoptime - slap_get_time ();
				if (op->ors_tlimit <= 0) {
					rs->sr_err = gs.err = LDAP_TIMELIMIT_EXCEEDED;
					break;
				}
			}
			if (slimit0 != SLAP_NO_LIMIT) {
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
				goto end_of_loop;
			}
			op->o_bd = btmp;

			assert( op->o_bd->be_suffix );
			assert( op->o_bd->be_nsuffix );
			
			if (scope0 == LDAP_SCOPE_ONELEVEL && 
				dn_match(pdn, &ndn))
			{
				op->ors_scope = LDAP_SCOPE_BASE;
				op->o_req_dn = op->o_bd->be_suffix[0];
				op->o_req_ndn = op->o_bd->be_nsuffix[0];
				rs->sr_err = op->o_bd->be_search(op, rs);

			} else if (scope0 == LDAP_SCOPE_SUBTREE &&
				dn_match(&op->o_bd->be_nsuffix[0], &ndn))
			{
				rs->sr_err = op->o_bd->be_search( op, rs );

			} else if (scope0 == LDAP_SCOPE_SUBTREE &&
				dnIsSuffix(&op->o_bd->be_nsuffix[0], &ndn))
			{
				op->o_req_dn = op->o_bd->be_suffix[0];
				op->o_req_ndn = op->o_bd->be_nsuffix[0];
				rs->sr_err = op->o_bd->be_search( op, rs );
				if ( rs->sr_err == LDAP_NO_SUCH_OBJECT ) {
					gs.err = LDAP_SUCCESS;
				}

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
			case LDAP_NO_SUCH_OBJECT:
				goto end_of_loop;
			
			default:
				break;
			}
		}
end_of_loop:;
		op->ors_scope = scope0;
		op->ors_slimit = slimit0;
		op->ors_tlimit = tlimit0;
		op->o_req_dn = dn;
		op->o_req_ndn = ndn;

		break;
	}
	if ( !op->o_abandon ) {
		op->o_callback = cb.sc_next;
		rs->sr_err = gs.err;
		rs->sr_matched = gs.matched;
		rs->sr_ref = gs.refs;

		send_ldap_result( op, rs );
	}

	op->o_bd = b0;
	op->o_bd->bd_info = bi0;
	if (gs.matched)
		free (gs.matched);
	if (gs.refs)
		ber_bvarray_free(gs.refs);
	return rs->sr_err;
}

static BackendDB toolDB;

static int
glue_tool_entry_open (
	BackendDB *b0,
	int mode
)
{
	slap_overinfo	*oi = (slap_overinfo *)b0->bd_info;

	/* We don't know which backend to talk to yet, so just
	 * remember the mode and move on...
	 */

	glueMode = mode;
	glueBack = NULL;
	toolDB = *b0;
	toolDB.bd_info = oi->oi_orig;

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

static slap_overinst *
glue_tool_inst(
	BackendInfo *bi
)
{
	slap_overinfo	*oi = (slap_overinfo *)bi;
	slap_overinst	*on;

	for ( on = oi->oi_list; on; on=on->on_next ) {
		if ( !strcmp( on->on_bi.bi_type, glue.on_bi.bi_type ))
			return on;
	}
	return NULL;
}

/* This function will only be called in tool mode */
static int
glue_open (
	BackendInfo *bi
)
{
	slap_overinst *on = glue_tool_inst( bi );
	glueinfo		*gi = on->on_bi.bi_private;
	static int glueOpened = 0;
	int i, rc = 0;

	if (glueOpened) return 0;

	glueOpened = 1;

	/* If we were invoked in tool mode, open all the underlying backends */
	if (slapMode & SLAP_TOOL_MODE) {
		rc = backend_startup( NULL );
	} /* other case is impossible */
	return rc;
}

/* This function will only be called in tool mode */
static int
glue_close (
	BackendInfo *bi
)
{
	slap_overinst *on = glue_tool_inst( bi );
	glueinfo		*gi = on->on_bi.bi_private;
	static int glueClosed = 0;
	int i, rc = 0;

	if (glueClosed) return 0;

	glueClosed = 1;

	if (slapMode & SLAP_TOOL_MODE) {
		rc = backend_shutdown( NULL );
	}
	return rc;
}

static int
glue_entry_release_rw (
	Operation *op,
	Entry *e,
	int rw
)
{
	BackendDB *b0, b2;
	int rc;

	b0 = op->o_bd;
	b2.bd_info = (BackendInfo *)glue_tool_inst( op->o_bd->bd_info );
	op->o_bd = glue_back_select (&b2, &e->e_nname);

	rc = op->o_bd->be_release( op, e, rw );
	op->o_bd = b0;
	return rc;
}

static ID
glue_tool_entry_first (
	BackendDB *b0
)
{
	slap_overinst	*on = glue_tool_inst( b0->bd_info );
	glueinfo		*gi = on->on_bi.bi_private;
	int i;

	/* If we're starting from scratch, start at the most general */
	if (!glueBack) {
		if ( toolDB.be_entry_open && toolDB.be_entry_first ) {
			glueBack = &toolDB;
		} else {
			for (i = gi->gi_nodes-1; i >= 0; i--) {
				if (gi->gi_n[i].gn_be->be_entry_open &&
					gi->gi_n[i].gn_be->be_entry_first) {
						glueBack = gi->gi_n[i].gn_be;
					break;
				}
			}
		}
	}
	if (!glueBack || !glueBack->be_entry_open || !glueBack->be_entry_first ||
		glueBack->be_entry_open (glueBack, glueMode) != 0)
		return NOID;

	return glueBack->be_entry_first (glueBack);
}

static ID
glue_tool_entry_next (
	BackendDB *b0
)
{
	slap_overinst	*on = glue_tool_inst( b0->bd_info );
	glueinfo		*gi = on->on_bi.bi_private;
	int i;
	ID rc;

	if (!glueBack || !glueBack->be_entry_next)
		return NOID;

	rc = glueBack->be_entry_next (glueBack);

	/* If we ran out of entries in one database, move on to the next */
	while (rc == NOID) {
		if ( glueBack && glueBack->be_entry_close )
			glueBack->be_entry_close (glueBack);
		for (i=0; i<gi->gi_nodes; i++) {
			if (gi->gi_n[i].gn_be == glueBack)
				break;
		}
		if (i == 0) {
			glueBack = NULL;
			break;
		} else {
			glueBack = gi->gi_n[i-1].gn_be;
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
	BackendDB *be, b2;
	int rc;

	b2 = *b0;
	b2.bd_info = (BackendInfo *)glue_tool_inst( b0->bd_info );
	be = glue_back_select (&b2, &e->e_nname);
	if ( be == &b2 ) be = &toolDB;

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
	slap_overinst	*on = glue_tool_inst( b0->bd_info );
	glueinfo		*gi = on->on_bi.bi_private;
	int i;

	/* just sync everyone */
	for (i = 0; i<gi->gi_nodes; i++)
		if (gi->gi_n[i].gn_be->be_sync)
			gi->gi_n[i].gn_be->be_sync (gi->gi_n[i].gn_be);
	return 0;
}

static int
glue_db_init(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	slap_overinfo	*oi = on->on_info;
	glueinfo *gi;

	gi = ch_calloc( 1, sizeof(glueinfo));
	on->on_bi.bi_private = gi;
	dnParent( be->be_nsuffix, &gi->gi_pdn );

	/* Currently the overlay framework doesn't handle these entry points
	 * but we need them....
	 */
	oi->oi_bi.bi_open = glue_open;
	oi->oi_bi.bi_close = glue_close;

	oi->oi_bi.bi_entry_release_rw = glue_entry_release_rw;

	oi->oi_bi.bi_tool_entry_open = glue_tool_entry_open;
	oi->oi_bi.bi_tool_entry_close = glue_tool_entry_close;
	oi->oi_bi.bi_tool_entry_first = glue_tool_entry_first;
	oi->oi_bi.bi_tool_entry_next = glue_tool_entry_next;
	oi->oi_bi.bi_tool_entry_get = glue_tool_entry_get;
	oi->oi_bi.bi_tool_entry_put = glue_tool_entry_put;
	oi->oi_bi.bi_tool_entry_reindex = glue_tool_entry_reindex;
	oi->oi_bi.bi_tool_sync = glue_tool_sync;

	/*FIXME : need to add support */
	oi->oi_bi.bi_tool_dn2id_get = 0;
	oi->oi_bi.bi_tool_id2entry_get = 0;
	oi->oi_bi.bi_tool_entry_modify = 0;

	return 0;
}

static int
glue_db_destroy (
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;

	free (gi);
	return SLAP_CB_CONTINUE;
}

static int
glue_db_open (
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;
	int i;

	for ( i=0; i<gi->gi_nodes; i++ ) {
		gi->gi_n[i].gn_be = backendDB + gi->gi_n[i].gn_bx;
	}
	return 0;
}

static int
glue_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char	**argv
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	glueinfo		*gi = (glueinfo *)on->on_bi.bi_private;

	if ( strcasecmp( argv[0], "glue-sub" ) == 0 ) {
		int async = 0;
		BackendDB *b2;
		struct berval bv, dn;
		gluenode *gn;

		if ( argc < 2 ) {
			fprintf( stderr, "%s: line %d: too few arguments in "
				"\"glue-sub <suffixDN> [async]\"\n", fname, lineno );
			return -1;
		}
		if ( argc == 3 ) {
			if ( strcasecmp( argv[2], "async" )) {
				fprintf( stderr, "%s: line %d: unrecognized option "
					"\"%s\" ignored.\n", fname, lineno, argv[2] );
			} else {
				async = 1;
			}
		}
		ber_str2bv( argv[1], 0, 0, &bv );
		if ( dnNormalize( 0, NULL, NULL, &bv, &dn, NULL )) {
			fprintf( stderr, "invalid suffixDN \"%s\"\n", argv[1] );
			return -1;
		}
		b2 = select_backend( &dn, 0, 1 );
		if ( !b2 ) {
			fprintf( stderr, "%s: line %d: unknown suffix \"%s\"\n",
				fname, lineno, argv[1] );
			return -1;
		}
		SLAP_DBFLAGS(b2) |= SLAP_DBFLAG_GLUE_SUBORDINATE;
		gi = (glueinfo *)ch_realloc( gi, sizeof(glueinfo) +
			gi->gi_nodes * sizeof(gluenode));
		gi->gi_n[gi->gi_nodes].gn_bx = b2 - backendDB;
		dnParent( &b2->be_nsuffix[0], &gi->gi_n[gi->gi_nodes].gn_pdn );
		gi->gi_n[gi->gi_nodes].gn_async = async;
		gi->gi_nodes++;
		on->on_bi.bi_private = gi;
		return 0;
	}
	return SLAP_CONF_UNKNOWN;
}

int
glue_init()
{
	glue.on_bi.bi_type = "glue";

	glue.on_bi.bi_db_init = glue_db_init;
	glue.on_bi.bi_db_config = glue_db_config;
	glue.on_bi.bi_db_open = glue_db_open;
	glue.on_bi.bi_db_destroy = glue_db_destroy;

	glue.on_bi.bi_op_search = glue_op_search;
	glue.on_bi.bi_op_modify = glue_op_func;
	glue.on_bi.bi_op_modrdn = glue_op_func;
	glue.on_bi.bi_op_add = glue_op_func;
	glue.on_bi.bi_op_delete = glue_op_func;

	return overlay_register( &glue );
}

#if SLAPD_OVER_GLUE == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return glue_init();
}
#endif	/* SLAPD_OVER_GLUE == SLAPD_MOD_DYNAMIC */

#endif	/* defined(SLAPD_OVER_GLUE */
