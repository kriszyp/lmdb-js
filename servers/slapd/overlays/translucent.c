/* translucent.c - translucent proxy module */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2008 The OpenLDAP Foundation.
 * Portions Copyright 2005 Symas Corporation.
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
 * This work was initially developed by Symas Corp. for inclusion in
 * OpenLDAP Software.  This work was sponsored by Hewlett-Packard.
 */

#include "portable.h"

#ifdef SLAPD_OVER_TRANSLUCENT

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "lutil.h"

/* config block */

typedef struct translucent_configuration {
	int debug;
	int strict;
	int no_add;
	int glue;
} translucent_configuration;

/* stack of captive backends */

typedef struct overlay_stack {
	BackendInfo *info;			/* captive backend */
	void *private;				/* local backend_private */
	translucent_configuration *config;	/* our_private: configuration */
} overlay_stack;

/* for translucent_init() */

static slap_overinst translucent;

/*
** glue_parent()
**	call syncrepl_add_glue() with the parent suffix;
**
*/

static struct berval glue[] = { BER_BVC("top"), BER_BVC("glue"), BER_BVNULL };

void glue_parent(Operation *op) {
	Operation nop = *op;
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	struct berval ndn = BER_BVNULL;
	Attribute *a;
	Entry *e;
	struct berval	pdn;

	dnParent( &op->o_req_ndn, &pdn );
	ber_dupbv_x( &ndn, &pdn, op->o_tmpmemctx );

	Debug(LDAP_DEBUG_TRACE, "=> glue_parent: fabricating glue for <%s>\n", ndn.bv_val, 0, 0);

	e = ch_calloc(1, sizeof(Entry));
	e->e_id = NOID;
	ber_dupbv(&e->e_name, &ndn);
	ber_dupbv(&e->e_nname, &ndn);

	a = ch_calloc(1, sizeof(Attribute));
	a->a_desc = slap_schema.si_ad_objectClass;
	a->a_vals = ch_malloc(sizeof(struct berval) * 3);
	ber_dupbv(&a->a_vals[0], &glue[0]);
	ber_dupbv(&a->a_vals[1], &glue[1]);
	ber_dupbv(&a->a_vals[2], &glue[2]);
	a->a_nvals = a->a_vals;
	a->a_next = e->e_attrs;
	e->e_attrs = a;

	a = ch_calloc(1, sizeof(Attribute));
	a->a_desc = slap_schema.si_ad_structuralObjectClass;
	a->a_vals = ch_malloc(sizeof(struct berval) * 2);
	ber_dupbv(&a->a_vals[0], &glue[1]);
	ber_dupbv(&a->a_vals[1], &glue[2]);
	a->a_nvals = a->a_vals;
	a->a_next = e->e_attrs;
	e->e_attrs = a;

	nop.o_req_dn = ndn;
	nop.o_req_ndn = ndn;
	nop.ora_e = e;
	nop.o_bd->bd_info = (BackendInfo *) on->on_info->oi_orig;

	syncrepl_add_glue(&nop, e);

	op->o_tmpfree( ndn.bv_val, op->o_tmpmemctx );

	return;
}

/*
** dup_bervarray()
**	copy a BerVarray;
*/

BerVarray dup_bervarray(BerVarray b) {
	int i, len;
	BerVarray nb;
	for(len = 0; b[len].bv_val; len++);
	nb = ch_malloc((len+1) * sizeof(BerValue));
	for(i = 0; i < len; i++) ber_dupbv(&nb[i], &b[i]);
	nb[len].bv_val = NULL;
	nb[len].bv_len = 0;
	return(nb);
}

/*
** free_attr_chain()
**	free only the Attribute*, not the contents;
**
*/
void free_attr_chain(Attribute *a) {
	Attribute *ax;
	for(; a; a = ax) {
		ax = a->a_next;
		ch_free(a);
	}
	return;
}

/*
** translucent_add()
**	if not bound as root, send ACCESS error;
**	if config.glue, glue_parent();
**	return CONTINUE;
**
*/

static int translucent_add(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	Debug(LDAP_DEBUG_TRACE, "==> translucent_add: %s\n",
		op->o_req_dn.bv_val, 0, 0);
	if(!be_isroot(op)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INSUFFICIENT_ACCESS,
			"user modification of overlay database not permitted");
		return(rs->sr_err);
	}
	if(!ov->config->glue) glue_parent(op);
	return(SLAP_CB_CONTINUE);
}

/*
** translucent_modrdn()
**	if not bound as root, send ACCESS error;
**	if !config.glue, glue_parent();
**	else return CONTINUE;
**
*/

static int translucent_modrdn(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	Debug(LDAP_DEBUG_TRACE, "==> translucent_modrdn: %s -> %s\n",
		op->o_req_dn.bv_val, op->orr_newrdn.bv_val, 0);
	if(!be_isroot(op)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INSUFFICIENT_ACCESS,
			"user modification of overlay database not permitted");
		return(rs->sr_err);
	}
	if(!ov->config->glue) glue_parent(op);
	return(SLAP_CB_CONTINUE);
}

/*
** translucent_delete()
**	if not bound as root, send ACCESS error;
**	else return CONTINUE;
**
*/

static int translucent_delete(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	Debug(LDAP_DEBUG_TRACE, "==> translucent_delete: %s\n",
		op->o_req_dn.bv_val, 0, 0);
	if(!be_isroot(op)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INSUFFICIENT_ACCESS,
			"user modification of overlay database not permitted");
		return(rs->sr_err);
	}
	return(SLAP_CB_CONTINUE);
}

static int
translucent_tag_cb( Operation *op, SlapReply *rs )
{
	op->o_tag = LDAP_REQ_MODIFY;
	op->orm_modlist = op->o_callback->sc_private;
	rs->sr_tag = slap_req2res( op->o_tag );

	return SLAP_CB_CONTINUE;
}

/*
** translucent_modify()
**	modify in local backend if exists in both;
**	otherwise, add to local backend;
**	fail if not defined in captive backend;
**
*/

static int translucent_modify(Operation *op, SlapReply *rs) {
	SlapReply nrs = { REP_RESULT };
	Operation nop = *op;

	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = op->o_bd->be_private;
	Entry ne, *e = NULL, *re = NULL;
	Attribute *a, *ax;
	Modifications *m, **mm;
	int del, rc, erc = 0;
	slap_callback cb = { 0 };

	Debug(LDAP_DEBUG_TRACE, "==> translucent_modify: %s\n",
		op->o_req_dn.bv_val, 0, 0);

/*
** fetch entry from the captive backend;
** if it did not exist, fail;
** release it, if captive backend supports this;
**
*/

	op->o_bd->bd_info = (BackendInfo *) on->on_info;
	op->o_bd->be_private = ov->private;
	rc = ov->info->bi_entry_get_rw(op, &op->o_req_ndn, NULL, NULL, 0, &re);
	op->o_bd->be_private = private;

	/* if(ov->config->no_add && (!re || rc != LDAP_SUCCESS)) */
	if(rc != LDAP_SUCCESS || re == NULL ) {
		send_ldap_error(op, rs, LDAP_NO_SUCH_OBJECT,
			"attempt to modify nonexistent local record");
		return(rs->sr_err);
	}

/*
** fetch entry from local backend;
** if it exists:
**	foreach Modification:
**	    if attr not present in local:
**		if Mod == LDAP_MOD_DELETE:
**		    if remote attr not present, return NO_SUCH;
**		    if remote attr present, drop this Mod;
**		else force this Mod to LDAP_MOD_ADD;
**	return CONTINUE;
**
*/

	rc = be_entry_get_rw(op, &op->o_req_ndn, NULL, NULL, 0, &e);

	if(e && rc == LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_TRACE, "=> translucent_modify: found local entry\n", 0, 0, 0);
		for(mm = &op->orm_modlist; *mm; ) {
			m = *mm;
			for(a = e->e_attrs; a; a = a->a_next)
				if(a->a_desc == m->sml_desc) break;
			if(a) {
				mm = &m->sml_next;
				continue;		/* found local attr */
			}
			if(m->sml_op == LDAP_MOD_DELETE) {
				for(a = re->e_attrs; a; a = a->a_next)
					if(a->a_desc == m->sml_desc) break;
				/* not found remote attr */
				if(!a) {
					erc = LDAP_NO_SUCH_ATTRIBUTE;
					goto release;
				}
				if(ov->config->strict) {
					erc = LDAP_CONSTRAINT_VIOLATION;
					goto release;
				}
				Debug(LDAP_DEBUG_TRACE,
					"=> translucent_modify: silently dropping delete: %s\n",
					m->sml_desc->ad_cname.bv_val, 0, 0);
				*mm = m->sml_next;
				m->sml_next = NULL;
				slap_mods_free(m, 1);
				continue;
			}
			m->sml_op = LDAP_MOD_ADD;
			mm = &m->sml_next;
		}
		erc = SLAP_CB_CONTINUE;
release:
		if(re) {
			op->o_bd->be_private = ov->private;
			if(ov->info->bi_entry_release_rw)
				ov->info->bi_entry_release_rw(op, re, 0);
			else
				entry_free(re);
			op->o_bd->be_private = private;
		}
		be_entry_release_r(op, e);
		if(erc == SLAP_CB_CONTINUE) {
			op->o_bd->bd_info = (BackendInfo *) on;
			return(erc);
		} else if(erc) {
			send_ldap_error(op, rs, erc,
				"attempt to delete nonexistent attribute");
			return(erc);
		}
	}

	/* don't leak remote entry copy */
	if(re) {
		op->o_bd->be_private = ov->private;
		if(ov->info->bi_entry_release_rw)
			ov->info->bi_entry_release_rw(op, re, 0);
		else
			entry_free(re);
		op->o_bd->be_private = private;
	}
/*
** foreach Modification:
**	if MOD_ADD or MOD_REPLACE, add Attribute;
** if no Modifications were suitable:
**	if config.strict, throw CONSTRAINT_VIOLATION;
**	else, return early SUCCESS;
** fabricate Entry with new Attribute chain;
** glue_parent() for this Entry;
** call bi_op_add() in local backend;
**
*/

	Debug(LDAP_DEBUG_TRACE, "=> translucent_modify: fabricating local add\n", 0, 0, 0);
	a = NULL;
	for(del = 0, ax = NULL, m = op->orm_modlist; m; m = m->sml_next) {
		if(((m->sml_op & LDAP_MOD_OP) != LDAP_MOD_ADD) &&
		   ((m->sml_op & LDAP_MOD_OP) != LDAP_MOD_REPLACE)) {
			Debug(LDAP_DEBUG_ANY,
				"=> translucent_modify: silently dropped modification(%d): %s\n",
				m->sml_op, m->sml_desc->ad_cname.bv_val, 0);
			if((m->sml_op & LDAP_MOD_OP) == LDAP_MOD_DELETE) del++;
			continue;
		}
		a = ch_calloc(1, sizeof(Attribute));
		a->a_desc  = m->sml_desc;
		a->a_vals  = m->sml_values;
		a->a_nvals = m->sml_nvalues ? m->sml_nvalues : a->a_vals;
		a->a_next  = ax;
		ax = a;
	}

	if(del && ov->config->strict) {
		free_attr_chain(a);
		send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION,
			"attempt to delete attributes from local database");
		return(rs->sr_err);
	}

	if(!ax) {
		if(ov->config->strict) {
			send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION,
				"modification contained other than ADD or REPLACE");
			return(rs->sr_err);
		}
		op->o_bd->bd_info = (BackendInfo *) on;
		/* rs->sr_text = "no valid modification found"; */
		rs->sr_err = LDAP_SUCCESS;
		send_ldap_result(op, rs);
		return(rs->sr_err);
	}

	ne.e_id		= NOID;
	ne.e_name	= op->o_req_dn;
	ne.e_nname	= op->o_req_ndn;
	ne.e_attrs	= a;
	ne.e_ocflags	= 0;
	ne.e_bv.bv_len	= 0;
	ne.e_bv.bv_val	= NULL;
	ne.e_private	= NULL;

	nop.o_tag	= LDAP_REQ_ADD;
	nop.oq_add.rs_e	= &ne;

	op->o_bd->bd_info = (BackendInfo *) on;
	glue_parent(&nop);

	cb.sc_response = translucent_tag_cb;
	cb.sc_private = op->orm_modlist;
	cb.sc_next = nop.o_callback;
	nop.o_callback = &cb;
	rc = on->on_info->oi_orig->bi_op_add(&nop, &nrs);
	free_attr_chain(a);

	return(rc);
}

static int translucent_compare(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = op->o_bd->be_private;

	AttributeAssertion *ava = op->orc_ava;
	Entry *e;
	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_compare: <%s> %s:%s\n",
		op->o_req_dn.bv_val, ava->aa_desc->ad_cname.bv_val, ava->aa_value.bv_val);

/*
** if the local backend has an entry for this attribute:
**	CONTINUE and let it do the compare;
**
*/

	op->o_bd->bd_info = (BackendInfo *) on->on_info;
	rc = be_entry_get_rw(op, &op->o_req_ndn, NULL, ava->aa_desc, 0, &e);
	if(e && rc == LDAP_SUCCESS) {
		be_entry_release_r(op, e);
		op->o_bd->bd_info = (BackendInfo *) on;
		return(SLAP_CB_CONTINUE);
	}

/*
** call compare() in the captive backend;
** return the result;
**
*/

	op->o_bd->be_private = ov->private;
	rc = ov->info->bi_op_compare(op, rs);
	op->o_bd->be_private = private;
	op->o_bd->bd_info = (BackendInfo *) on;
	return(rc);
}

/*
** translucent_search_cb()
**	merge local data with the search result
**
*/

static int translucent_search_cb(Operation *op, SlapReply *rs) {
	slap_overinst *on;
	Entry *e, *re = NULL;
	Attribute *a, *ax, *an, *as = NULL;
	void *private;
	int rc;

	if(!op || !rs || rs->sr_type != REP_SEARCH || !rs->sr_entry)
		return(SLAP_CB_CONTINUE);

	Debug(LDAP_DEBUG_TRACE, "==> tranclucent_search_cb: %s\n",
		rs->sr_entry->e_name.bv_val, 0, 0);

	on = (slap_overinst *) op->o_bd->bd_info;
	op->o_bd->bd_info = (BackendInfo *) on->on_info;

	private = op->o_bd->be_private;
	op->o_bd->be_private = op->o_callback->sc_private;

	rc = be_entry_get_rw(op, &rs->sr_entry->e_nname, NULL, NULL, 0, &e);

/*
** if we got an entry from local backend:
**	make a copy of this search result;
**	foreach local attr:
**		foreach search result attr:
**			if match, result attr with local attr;
**			if new local, add to list;
**	append new local attrs to search result;
**
*/

	if(e && rc == LDAP_SUCCESS) {
		re = entry_dup(rs->sr_entry);
		for(ax = e->e_attrs; ax; ax = ax->a_next) {
#if 0
			if(is_at_operational(ax->a_desc->ad_type)) continue;
#endif
			for(a = re->e_attrs; a; a = a->a_next) {
				if(a->a_desc == ax->a_desc) {
					if(a->a_vals != a->a_nvals)
						ber_bvarray_free(a->a_nvals);
					ber_bvarray_free(a->a_vals);
					a->a_vals = dup_bervarray(ax->a_vals);
					a->a_nvals = (ax->a_vals == ax->a_nvals) ?
						a->a_vals : dup_bervarray(ax->a_nvals);
					break;
				}
			}
			if(a) continue;
			an = attr_dup(ax);
			an->a_next = as;
			as = an;
		}
		be_entry_release_r(op, e);

		/* literally append, so locals are always last */
		if(as) {
			if(re->e_attrs) {
				for(ax = re->e_attrs; ax->a_next; ax = ax->a_next);
				ax->a_next = as;
			} else {
				re->e_attrs = as;
			}
		}
		rs->sr_entry = re;
		rs->sr_flags |= REP_ENTRY_MUSTBEFREED;
	}

	op->o_bd->be_private = private;
	op->o_bd->bd_info = (BackendInfo *) on;

	return(SLAP_CB_CONTINUE);
}

/*
** translucent_search()
**	search via captive backend;
**	override results with any local data;
**
*/

static int translucent_search(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	slap_callback cb = { NULL, NULL, NULL, NULL };
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = op->o_bd->be_private;
	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_search: <%s> %s\n",
		op->o_req_dn.bv_val, op->ors_filterstr.bv_val, 0);
	cb.sc_response = (slap_response *) translucent_search_cb;
	cb.sc_private = private;

	cb.sc_next = op->o_callback;
	op->o_callback = &cb;

	op->o_bd->be_private = ov->private;
	rc = ov->info->bi_op_search(op, rs);
	op->o_bd->be_private = private;

	return(rs->sr_err);
}


/*
** translucent_bind()
**	pass bind request to captive backend;
**
*/

static int translucent_bind(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = op->o_bd->be_private;
	int rc = 0;

	Debug(LDAP_DEBUG_TRACE, "translucent_bind: <%s> method %d\n",
		op->o_req_dn.bv_val, op->orb_method, 0);

	op->o_bd->be_private = ov->private;
	rc = ov->info->bi_op_bind(op, rs);
	op->o_bd->be_private = private;

	return(rc);
}

/*
** translucent_connection_destroy()
**	pass disconnect notification to captive backend;
**
*/

static int translucent_connection_destroy(BackendDB *be, Connection *conn) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = be->be_private;
	int rc = 0;

	Debug(LDAP_DEBUG_TRACE, "translucent_connection_destroy\n", 0, 0, 0);

	be->be_private = ov->private;
	rc = ov->info->bi_connection_destroy(be, conn);
	be->be_private = private;

	return(rc);
}

/*
** translucent_db_config()
**	pass config directives to captive backend;
**	parse unrecognized directives ourselves;
**
*/

static int translucent_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = be->be_private;
	void *be_cf_ocs = be->be_cf_ocs;
	int rc;

	/* "this should never happen" */
	if(!ov->info) {
		fprintf(stderr, "fatal: captive backend not initialized");
		return(1);
	}

	be->be_private = ov->private;
	be->be_cf_ocs = ov->info->bi_cf_ocs;
	rc = ov->info->bi_db_config ? ov->info->bi_db_config(be, fname, lineno, argc, argv) : 0;
	be->be_private = private;
	be->be_cf_ocs = be_cf_ocs;

	/* pass okay or error up, SLAP_CONF_UNKNOWN might be ours */
	if(rc == 0 || rc == 1) return(rc);

	rc = 0;
	if(!strcasecmp(*argv, "translucent_strict")) {
		ov->config->strict++;
	} else if(!strcasecmp(*argv, "translucent_no_add")) {
		ov->config->no_add++;
	} else if(!strcasecmp(*argv, "translucent_no_glue")) {
		ov->config->glue++;
	} else if(!strcasecmp(*argv, "translucent_debug")) {
		if(argc == 1) {
			ov->config->debug = 0xFFFF;
			rc = 0;
		} else if(argc == 2) {
			if ( lutil_atoi( &ov->config->debug, argv[1]) != 0 ) {
				fprintf(stderr, "%s: line %d: unable to parse debug \"%s\"\n",
					fname, lineno, argv[1]);
				return 1;
			}
			rc = 0;
		} else {
			fprintf(stderr, "%s: line %d: too many arguments (%d) to debug\n",
				fname, lineno, argc);
			rc = 1;
		}
	} else {
		fprintf(stderr, "%s: line %d: unknown keyword %s\n",
			fname, lineno, *argv);
		rc = SLAP_CONF_UNKNOWN;
	}
	return(rc);
}

/*
** translucent_db_init()
**	initialize the captive backend;
**
*/

static int translucent_db_init(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	void *private = be->be_private;
	overlay_stack *ov;
	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_init\n", 0, 0, 0);

	ov = ch_calloc(1, sizeof(overlay_stack));
	ov->config = ch_calloc(1, sizeof(translucent_configuration));
	ov->info = backend_info("ldap");

	if(!ov->info) {
		Debug(LDAP_DEBUG_ANY, "translucent: backend_info failed!\n", 0, 0, 0);
		return(1);
	}

	/* forcibly disable schema checking on the local backend */
	SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NO_SCHEMA_CHECK;

	be->be_private = NULL;
	rc = ov->info->bi_db_init ? ov->info->bi_db_init(be) : 0;

	if(rc) Debug(LDAP_DEBUG_TRACE,
		"translucent: bi_db_init() returned error %d\n", rc, 0, 0);

	ov->private = be->be_private;
	be->be_private = private;
	on->on_bi.bi_private = ov;
	return(rc);
}

/*
** translucent_db_open()
**	if the captive backend has an open() method, call it;
**
*/

static int translucent_db_open(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	void *private = be->be_private;
	int rc;

	/* "should never happen" */
	if(!ov->info) {
		Debug(LDAP_DEBUG_ANY, "translucent_db_open() called with bad ov->info\n", 0, 0, 0);
		return(LDAP_OTHER);
	}

	Debug(LDAP_DEBUG_TRACE, "translucent_db_open\n", 0, 0, 0);

	be->be_private = ov->private;
	rc = ov->info->bi_db_open ? ov->info->bi_db_open(be) : 0;
	be->be_private = private;

	if(rc) Debug(LDAP_DEBUG_TRACE,
		"translucent: bi_db_open() returned error %d\n", rc, 0, 0);

	return(rc);
}

/*
** translucent_db_close()
**	if the captive backend has a close() method, call it;
**	free any config data;
**
*/

static int translucent_db_close(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	int rc = 0;

	if ( ov ) {
		void *private = be->be_private;

		be->be_private = ov->private;
		rc = (ov->info && ov->info->bi_db_close) ? ov->info->bi_db_close(be) : 0;
		be->be_private = private;
		if(ov->config) ch_free(ov->config);
		ov->config = NULL;
	}

	return(rc);
}

/*
** translucent_db_destroy()
**	if the captive backend has a db_destroy() method, call it
**
*/

static int translucent_db_destroy(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	overlay_stack *ov = on->on_bi.bi_private;
	int rc = 0;

	if ( ov ) {
		void *private = be->be_private;

		be->be_private = ov->private;
		rc = (ov->info && ov->info->bi_db_destroy) ? ov->info->bi_db_destroy(be) : 0;
		be->be_private = private;
		ch_free(ov);
		on->on_bi.bi_private = NULL;
	}

	return(rc);
}

/*
** translucent_initialize()
**	initialize the slap_overinst with our entry points;
**
*/

int translucent_initialize() {

	translucent.on_bi.bi_type	= "translucent";
	translucent.on_bi.bi_db_init	= translucent_db_init;
	translucent.on_bi.bi_db_config	= translucent_db_config;
	translucent.on_bi.bi_db_open	= translucent_db_open;
	translucent.on_bi.bi_db_close	= translucent_db_close;
	translucent.on_bi.bi_db_destroy	= translucent_db_destroy;
	translucent.on_bi.bi_op_bind	= translucent_bind;
	translucent.on_bi.bi_op_add	= translucent_add;
	translucent.on_bi.bi_op_modify	= translucent_modify;
	translucent.on_bi.bi_op_modrdn	= translucent_modrdn;
	translucent.on_bi.bi_op_delete	= translucent_delete;
	translucent.on_bi.bi_op_search	= translucent_search;
	translucent.on_bi.bi_op_compare	= translucent_compare;
	translucent.on_bi.bi_connection_destroy = translucent_connection_destroy;

	return(overlay_register(&translucent));
}

#if SLAPD_OVER_TRANSLUCENT == SLAPD_MOD_DYNAMIC && defined(PIC)
int init_module(int argc, char *argv[]) {
	return translucent_initialize();
}
#endif

#endif /* SLAPD_OVER_TRANSLUCENT */

