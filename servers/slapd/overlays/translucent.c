/* translucent.c - translucent proxy module */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2006 The OpenLDAP Foundation.
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

#include "config.h"

/* config block */
typedef struct translucent_info {
	BackendDB db;			/* captive backend */
	int strict;
	int no_glue;
} translucent_info;

static ConfigLDAPadd translucent_ldadd;
static ConfigCfAdd translucent_cfadd;

static ConfigTable translucentcfg[] = {
	{ "translucent_strict", "on|off", 1, 2, 0,
	  ARG_ON_OFF|ARG_OFFSET,
	  (void *)offsetof(translucent_info, strict),
	  "( OLcfgOvAt:14.1 NAME 'olcTranslucentStrict' "
	  "DESC 'Reveal attribute deletion constraint violations' "
	  "SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "translucent_no_glue", "on|off", 1, 2, 0,
	  ARG_ON_OFF|ARG_OFFSET,
	  (void *)offsetof(translucent_info, no_glue),
	  "( OLcfgOvAt:14.2 NAME 'olcTranslucentNoGlue' "
	  "DESC 'Disable automatic glue records for ADD and MODRDN' "
	  "SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs translucentocs[] = {
	{ "( OLcfgOvOc:14.1 "
	  "NAME 'olcTranslucentConfig' "
	  "DESC 'Translucent configuration' "
	  "SUP olcOverlayConfig "
	  "MAY ( olcTranslucentStrict $ olcTranslucentNoGlue ) )",
	  Cft_Overlay, translucentcfg, NULL, translucent_cfadd },
	{ "( OLcfgOvOc:14.2 "
	  "NAME 'olcTranslucentDatabase' "
	  "DESC 'Translucent target database configuration' "
	  "AUXILIARY )", Cft_Misc, translucentcfg, translucent_ldadd },
	{ NULL, 0, NULL }
};
/* for translucent_init() */

static int
translucent_ldadd( CfEntryInfo *cei, Entry *e, ConfigArgs *ca )
{
	slap_overinst *on;
	translucent_info *ov;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_ldadd\n", 0, 0, 0);

	if ( cei->ce_type != Cft_Overlay || !cei->ce_bi ||
	     cei->ce_bi->bi_cf_ocs != translucentocs )
		return LDAP_CONSTRAINT_VIOLATION;

	on = (slap_overinst *)cei->ce_bi;
	ov = on->on_bi.bi_private;
	ca->be = &ov->db;
	return LDAP_SUCCESS;
}

static int
translucent_cfadd( Operation *op, SlapReply *rs, Entry *e, ConfigArgs *ca )
{
	CfEntryInfo *cei = e->e_private;
	slap_overinst *on = (slap_overinst *)cei->ce_bi;
	translucent_info *ov = on->on_bi.bi_private;
	struct berval bv;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_cfadd\n", 0, 0, 0);

	/* FIXME: should not hardcode "olcDatabase" here */
	bv.bv_len = sprintf( ca->msg, "olcDatabase=%s",
			     ov->db.bd_info->bi_type );
	bv.bv_val = ca->msg;
	ca->be = &ov->db;

	/* We can only create this entry if the database is table-driven
	 */
	if ( ov->db.bd_info->bi_cf_ocs )
		config_build_entry( op, rs, cei, ca, &bv,
				    ov->db.bd_info->bi_cf_ocs,
				    &translucentocs[1] );

	return 0;
}

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

	e = entry_alloc();
	e->e_id = NOID;
	ber_dupbv(&e->e_name, &ndn);
	ber_dupbv(&e->e_nname, &ndn);

	a = attr_alloc( slap_schema.si_ad_objectClass );
	a->a_vals = ch_malloc(sizeof(struct berval) * 3);
	ber_dupbv(&a->a_vals[0], &glue[0]);
	ber_dupbv(&a->a_vals[1], &glue[1]);
	ber_dupbv(&a->a_vals[2], &glue[2]);
	a->a_nvals = a->a_vals;
	a->a_next = e->e_attrs;
	e->e_attrs = a;

	a = attr_alloc( slap_schema.si_ad_structuralObjectClass );
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
	nop.o_bd->bd_info = (BackendInfo *) on;

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
void free_attr_chain(Attribute *b) {
	Attribute *a;
	for(a=b; a; a=a->a_next) {
		a->a_vals = NULL;
		a->a_nvals = NULL;
	}
	attrs_free( b );
	return;
}

/*
** translucent_add()
**	if not bound as root, send ACCESS error;
**	if glue, glue_parent();
**	return CONTINUE;
**
*/

static int translucent_add(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	Debug(LDAP_DEBUG_TRACE, "==> translucent_add: %s\n",
		op->o_req_dn.bv_val, 0, 0);
	if(!be_isroot(op)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INSUFFICIENT_ACCESS,
			"user modification of overlay database not permitted");
		op->o_bd->bd_info = (BackendInfo *) on;
		return(rs->sr_err);
	}
	if(!ov->no_glue) glue_parent(op);
	return(SLAP_CB_CONTINUE);
}

/*
** translucent_modrdn()
**	if not bound as root, send ACCESS error;
**	if !glue, glue_parent();
**	else return CONTINUE;
**
*/

static int translucent_modrdn(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	Debug(LDAP_DEBUG_TRACE, "==> translucent_modrdn: %s -> %s\n",
		op->o_req_dn.bv_val, op->orr_newrdn.bv_val, 0);
	if(!be_isroot(op)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INSUFFICIENT_ACCESS,
			"user modification of overlay database not permitted");
		op->o_bd->bd_info = (BackendInfo *) on;
		return(rs->sr_err);
	}
	if(!ov->no_glue) glue_parent(op);
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
		op->o_bd->bd_info = (BackendInfo *) on;
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
	translucent_info *ov = on->on_bi.bi_private;
	Entry *e = NULL, *re = NULL;
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

	nop.o_bd = &ov->db;
	rc = ov->db.bd_info->bi_entry_get_rw(&nop, &nop.o_req_ndn, NULL, NULL, 0, &re);
	if(rc != LDAP_SUCCESS || re == NULL ) {
		send_ldap_error((&nop), rs, LDAP_NO_SUCH_OBJECT,
			"attempt to modify nonexistent local record");
		return(rs->sr_err);
	}
	nop = *op;
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

	op->o_bd->bd_info = (BackendInfo *) on->on_info;
	rc = be_entry_get_rw(op, &op->o_req_ndn, NULL, NULL, 0, &e);
	op->o_bd->bd_info = (BackendInfo *) on;

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
				if(ov->strict) {
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
			if(ov->db.bd_info->bi_entry_release_rw)
				ov->db.bd_info->bi_entry_release_rw(&nop, re, 0);
			else
				entry_free(re);
		}
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		be_entry_release_r(op, e);
		op->o_bd->bd_info = (BackendInfo *) on;
		if(erc == SLAP_CB_CONTINUE) {
			return(erc);
		} else if(erc) {
			send_ldap_error(op, rs, erc,
				"attempt to delete nonexistent attribute");
			return(erc);
		}
	}

	/* don't leak remote entry copy */
	if(re) {
		if(ov->db.bd_info->bi_entry_release_rw)
			ov->db.bd_info->bi_entry_release_rw(&nop, re, 0);
		else
			entry_free(re);
	}
/*
** foreach Modification:
**	if MOD_ADD or MOD_REPLACE, add Attribute;
** if no Modifications were suitable:
**	if strict, throw CONSTRAINT_VIOLATION;
**	else, return early SUCCESS;
** fabricate Entry with new Attribute chain;
** glue_parent() for this Entry;
** call bi_op_add() in local backend;
**
*/

	Debug(LDAP_DEBUG_TRACE, "=> translucent_modify: fabricating local add\n", 0, 0, 0);
	a = NULL;
	for(del = 0, ax = NULL, m = op->orm_modlist; m; m = m->sml_next) {
		Attribute atmp;
		if(((m->sml_op & LDAP_MOD_OP) != LDAP_MOD_ADD) &&
		   ((m->sml_op & LDAP_MOD_OP) != LDAP_MOD_REPLACE)) {
			Debug(LDAP_DEBUG_ANY,
				"=> translucent_modify: silently dropped modification(%d): %s\n",
				m->sml_op, m->sml_desc->ad_cname.bv_val, 0);
			if((m->sml_op & LDAP_MOD_OP) == LDAP_MOD_DELETE) del++;
			continue;
		}
		atmp.a_desc = m->sml_desc;
		atmp.a_vals = m->sml_values;
		atmp.a_nvals = m->sml_nvalues ? m->sml_nvalues : atmp.a_vals;
		a = attr_dup( &atmp );
		a->a_next  = ax;
		ax = a;
	}

	if(del && ov->strict) {
		attrs_free( a );
		send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION,
			"attempt to delete attributes from local database");
		return(rs->sr_err);
	}

	if(!ax) {
		if(ov->strict) {
			send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION,
				"modification contained other than ADD or REPLACE");
			return(rs->sr_err);
		}
		/* rs->sr_text = "no valid modification found"; */
		rs->sr_err = LDAP_SUCCESS;
		send_ldap_result(op, rs);
		return(rs->sr_err);
	}

	e = entry_alloc();
	ber_dupbv( &e->e_name, &op->o_req_dn );
	ber_dupbv( &e->e_nname, &op->o_req_ndn );
	e->e_attrs = a;

	nop.o_tag	= LDAP_REQ_ADD;
	nop.oq_add.rs_e	= e;

	glue_parent(&nop);

	cb.sc_response = translucent_tag_cb;
	cb.sc_private = op->orm_modlist;
	cb.sc_next = nop.o_callback;
	nop.o_callback = &cb;
	rc = on->on_info->oi_orig->bi_op_add(&nop, &nrs);
	if ( nop.ora_e == e )
		entry_free( e );

	return(rc);
}

static int translucent_compare(Operation *op, SlapReply *rs) {
	Operation nop = *op;
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
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
	op->o_bd->bd_info = (BackendInfo *) on;

/*
** call compare() in the captive backend;
** return the result;
**
*/
	nop.o_bd = &ov->db;
	nop.o_callback = NULL;
	rc = ov->db.bd_info->bi_op_compare(&nop, rs);

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
	Operation * original_op, local_op;
	int rc;

	if(!op || !rs || rs->sr_type != REP_SEARCH || !rs->sr_entry)
		return(SLAP_CB_CONTINUE);

	Debug(LDAP_DEBUG_TRACE, "==> translucent_search_cb: %s\n",
		rs->sr_entry->e_name.bv_val, 0, 0);

	original_op = op->o_callback->sc_private;
	on = (slap_overinst *) original_op->o_bd->bd_info;
	local_op = *original_op;

	local_op.o_bd->bd_info = (BackendInfo *) on->on_info->oi_orig;
	rc = be_entry_get_rw(&local_op, &rs->sr_entry->e_nname, NULL, NULL, 0, &e);
	local_op.o_bd->bd_info = (BackendInfo *) on;

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
		local_op.o_bd->bd_info = (BackendInfo *) on->on_info->oi_orig;
		be_entry_release_r(&local_op, e);
		local_op.o_bd->bd_info = (BackendInfo *) on;

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
	Operation nop = *op;
	translucent_info *ov = on->on_bi.bi_private;
	slap_callback cb = { NULL, NULL, NULL, NULL };

	Debug(LDAP_DEBUG_TRACE, "==> translucent_search: <%s> %s\n",
		op->o_req_dn.bv_val, op->ors_filterstr.bv_val, 0);

	cb.sc_response = (slap_response *) translucent_search_cb;
	cb.sc_private = op;
	cb.sc_next = nop.o_callback;

	nop.o_callback = &cb;
	nop.o_bd = &ov->db;
	return (ov->db.bd_info->bi_op_search(&nop, rs));
}


/*
** translucent_bind()
**	pass bind request to captive backend;
**
*/

static int translucent_bind(Operation *op, SlapReply *rs) {
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	Operation nop = *op;
	translucent_info *ov = on->on_bi.bi_private;

	Debug(LDAP_DEBUG_TRACE, "translucent_bind: <%s> method %d\n",
		op->o_req_dn.bv_val, op->orb_method, 0);

	nop.o_bd = &ov->db;
	return (ov->db.bd_info->bi_op_bind(&nop, rs));
}

/*
** translucent_connection_destroy()
**	pass disconnect notification to captive backend;
**
*/

static int translucent_connection_destroy(BackendDB *be, Connection *conn) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	int rc = 0;

	Debug(LDAP_DEBUG_TRACE, "translucent_connection_destroy\n", 0, 0, 0);

	rc = ov->db.bd_info->bi_connection_destroy(&ov->db, conn);

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
	translucent_info *ov = on->on_bi.bi_private;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_config: %s\n",
	      argc ? argv[0] : "", 0, 0);

	/* Something for the captive database? */
	if ( ov->db.bd_info && ov->db.bd_info->bi_db_config )
		return ov->db.bd_info->bi_db_config( &ov->db, fname, lineno,
			argc, argv );
	return SLAP_CONF_UNKNOWN;
}

/*
** translucent_db_init()
**	initialize the captive backend;
**
*/

static int translucent_db_init(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	translucent_info *ov;
	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_init\n", 0, 0, 0);

	ov = ch_calloc(1, sizeof(translucent_info));
	on->on_bi.bi_private = ov;
	ov->db = *be;
	ov->db.be_private = NULL;
	ov->db.be_pcl_mutexp = &ov->db.be_pcl_mutex;

	if ( !backend_db_init( "ldap", &ov->db, -1 )) {
		Debug( LDAP_DEBUG_CONFIG, "translucent: unable to open captive back-ldap\n", 0, 0, 0);
		return 1;
	}
	SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NO_SCHEMA_CHECK;
	SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NOLASTMOD;

	return 0;
}

/*
** translucent_db_open()
**	if the captive backend has an open() method, call it;
**
*/

static int translucent_db_open(BackendDB *be) {
	slap_overinst *on = (slap_overinst *) be->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_open\n", 0, 0, 0);

	/* need to inherit something from the original database... */
	ov->db.be_def_limit = be->be_def_limit;
	ov->db.be_limits = be->be_limits;
	ov->db.be_acl = be->be_acl;
	ov->db.be_dfltaccess = be->be_dfltaccess;

	rc = backend_startup_one( &ov->db );

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

static int
translucent_db_close( BackendDB *be )
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	int rc = 0;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_close\n", 0, 0, 0);

	if ( ov && ov->db.bd_info && ov->db.bd_info->bi_db_close ) {
		rc = ov->db.bd_info->bi_db_close(&ov->db);
	}

	return(rc);
}

/*
** translucent_db_destroy()
**	if the captive backend has a db_destroy() method, call it
**
*/

static int
translucent_db_destroy( BackendDB *be )
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	translucent_info *ov = on->on_bi.bi_private;
	int rc = 0;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_db_close\n", 0, 0, 0);

	if ( ov ) {
		if ( ov->db.be_private != NULL ) {
			backend_stopdown_one( &ov->db );
		}

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

	int rc;

	Debug(LDAP_DEBUG_TRACE, "==> translucent_initialize\n", 0, 0, 0);

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

	translucent.on_bi.bi_cf_ocs = translucentocs;
	rc = config_register_schema ( translucentcfg, translucentocs );
	if ( rc ) return rc;

	return(overlay_register(&translucent));
}

#if SLAPD_OVER_TRANSLUCENT == SLAPD_MOD_DYNAMIC && defined(PIC)
int init_module(int argc, char *argv[]) {
	return translucent_initialize();
}
#endif

#endif /* SLAPD_OVER_TRANSLUCENT */
