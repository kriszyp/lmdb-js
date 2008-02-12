/* unique.c - attribute uniqueness module */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2008 The OpenLDAP Foundation.
 * Portions Copyright 2004 Symas Corporation.
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

#ifdef SLAPD_OVER_UNIQUE

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

static slap_overinst unique;

typedef struct unique_attrs_s {
	struct unique_attrs_s *next;		/* list of attrs */
	AttributeDescription *attr;
} unique_attrs;

typedef struct unique_data_s {
	const char *message;			/* breadcrumbs */
	struct unique_attrs_s *attrs;		/* list of known attrs */
	struct unique_attrs_s *ignore;		/* list of ignored attrs */
	BerValue dn;				/* base of "unique tree" */
	char strict;				/* null considered unique too */
} unique_data;

typedef struct unique_counter_s {
	struct berval *ndn;
	int count;
} unique_counter;

/*
** allocate new unique_data;
** initialize, copy basedn;
** store in on_bi.bi_private;
**
*/

static int unique_db_init(
	BackendDB	*be
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	unique_data *ud   = ch_malloc(sizeof(unique_data));

	/* Debug(LDAP_DEBUG_TRACE, "==> unique_init\n", 0, 0, 0); */

	ud->message	= "_init";
	ud->attrs	= NULL;
	ud->ignore	= NULL;
	ud->strict	= 0;

	/* default to the base of our configured database */
	ber_dupbv(&ud->dn, &be->be_nsuffix[0]);
	on->on_bi.bi_private = ud;

	return 0;
}


/*
** if command = attributes:
**	foreach argument:
**		convert to attribute;
**		add to configured attribute list;
** elseif command = base:
**	set our basedn to argument;
** else complain about invalid directive;
**
*/

static int unique_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	unique_data *ud	  = on->on_bi.bi_private;
	unique_attrs *up;
	const char *text;
	AttributeDescription *ad;
	int i;

	ud->message = "_config";
	Debug(LDAP_DEBUG_TRACE, "==> unique_config\n", 0, 0, 0);

	if(!strcasecmp(*argv, "unique_attributes") ||
	   !strcasecmp(*argv, "unique_ignore")) {
		for(i = 1; i < argc; i++) {
			for(up = ud->attrs; up; up = up->next)
			    if(!strcmp(argv[i], up->attr->ad_cname.bv_val)) {
				Debug(LDAP_DEBUG_ANY,
					"%s: line %d: duplicate attribute <%s>, ignored\n",
					fname, lineno, argv[i]);
				continue;
			}
			ad = NULL;
			if(slap_str2ad(argv[i], &ad, &text) != LDAP_SUCCESS) {
				Debug(LDAP_DEBUG_ANY,
					"%s: line %d: bad attribute <%s>, ignored\n",
					fname, lineno, text);
				continue;		/* XXX */
			} else if(ad->ad_next) {
				Debug(LDAP_DEBUG_ANY,
					"%s: line %d: multiple attributes match <%s>, ignored\n",
					fname, lineno, argv[i]);
				continue;
			}
			up = ch_malloc(sizeof(unique_attrs));
			up->attr = ad;
			if(!strcasecmp(*argv, "unique_ignore")) {
				up->next = ud->ignore;
				ud->ignore = up;
			} else {
				up->next = ud->attrs;
				ud->attrs = up;
			}
			Debug(LDAP_DEBUG_CONFIG, "%s: line %d: new attribute <%s>\n",
				fname, lineno, argv[i]);
		}
	} else if(!strcasecmp(*argv, "unique_strict")) {
		ud->strict = 1;
	} else if(!strcasecmp(*argv, "unique_base")) {
		struct berval bv;
		ber_str2bv( argv[1], 0, 0, &bv );
		ch_free(ud->dn.bv_val);
		dnNormalize(0, NULL, NULL, &bv, &ud->dn, NULL);
		Debug(LDAP_DEBUG_CONFIG, "%s: line %d: new base dn <%s>\n",
			fname, lineno, argv[1]);
	} else {
		return(SLAP_CONF_UNKNOWN);
	}

	return(0);
}


/*
** mostly, just print the init message;
**
*/

static int
unique_open(
	BackendDB *be
)
{
	slap_overinst *on	= (slap_overinst *)be->bd_info;
	unique_data *ud		= on->on_bi.bi_private;
	ud->message		= "_open";

	Debug(LDAP_DEBUG_TRACE, "unique_open: overlay initialized\n", 0, 0, 0);

	return(0);
}


/*
** foreach configured attribute:
**	free it;
** free our basedn;
** (do not) free ud->message;
** reset on_bi.bi_private;
** free our config data;
**
*/

static int
unique_close(
	BackendDB *be
)
{
	slap_overinst *on	= (slap_overinst *) be->bd_info;
	unique_data *ud		= on->on_bi.bi_private;
	unique_attrs *ii, *ij;
	ud->message		= "_close";

	Debug(LDAP_DEBUG_TRACE, "==> unique_close\n", 0, 0, 0);

	for(ii = ud->attrs; ii; ii = ij) {
		ij = ii->next;
		ch_free(ii);
	}

	for(ii = ud->ignore; ii; ii = ij) {
		ij = ii->next;
		ch_free(ii);
	}

	ch_free(ud->dn.bv_val);

	on->on_bi.bi_private = NULL;	/* XXX */

	ch_free(ud);

	return(0);
}


/*
** search callback
**	if this is a REP_SEARCH, count++;
**
*/

static int count_attr_cb(
	Operation *op,
	SlapReply *rs
)
{
	unique_counter *uc;

	/* because you never know */
	if(!op || !rs) return(0);

	/* Only search entries are interesting */
	if(rs->sr_type != REP_SEARCH) return(0);

	uc = op->o_callback->sc_private;

	/* Ignore the current entry */
	if ( dn_match( uc->ndn, &rs->sr_entry->e_nname )) return(0);

	Debug(LDAP_DEBUG_TRACE, "==> count_attr_cb <%s>\n",
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "UNKNOWN_DN", 0, 0);

	uc->count++;

	return(0);
}

static int count_filter_len(
	unique_data *ud,
	AttributeDescription *ad,
	BerVarray b,
	int ks
)
{
	unique_attrs *up;
	int i;

	while ( !is_at_operational( ad->ad_type ) ) {
		if ( ud->ignore ) {
			for ( up = ud->ignore; up; up = up->next ) {
				if (ad == up->attr ) {
					break;
				}
			}
			if ( up ) {
				break;
			}
		}
		if ( ud->attrs ) {
			for ( up = ud->attrs; up; up = up->next ) {
				if ( ad == up->attr ) {
					break;
				}
			}
			if ( !up ) {
				break;
			}
		}
		if ( b && b[0].bv_val ) {
			for (i = 0; b[i].bv_val; i++ ) {
				/* note: make room for filter escaping... */
				ks += ( 3 * b[i].bv_len ) + ad->ad_cname.bv_len + STRLENOF( "(=)" );
			}
		} else if ( ud->strict ) {
			ks += ad->ad_cname.bv_len + STRLENOF( "(=*)" );	/* (attr=*) */
		}
		break;
	}
	return ks;
}

static char *build_filter(
	unique_data *ud,
	AttributeDescription *ad,
	BerVarray b,
	char *kp,
	void *ctx
)
{
	unique_attrs *up;
	int i;

	while ( !is_at_operational( ad->ad_type ) ) {
		if ( ud->ignore ) {
			for ( up = ud->ignore; up; up = up->next ) {
				if ( ad == up->attr ) {
					break;
				}
			}
			if ( up ) {
				break;
			}
		}
		if ( ud->attrs ) {
			for ( up = ud->attrs; up; up = up->next ) {
				if ( ad == up->attr ) {
					break;
				}
			}
			if ( !up ) {
				break;
			}
		}
		if ( b && b[0].bv_val ) {
			for ( i = 0; b[i].bv_val; i++ ) {
				struct berval	bv;

				ldap_bv2escaped_filter_value_x( &b[i], &bv, 1, ctx );
				kp += sprintf( kp, "(%s=%s)", ad->ad_cname.bv_val, bv.bv_val );
				if ( bv.bv_val != b[i].bv_val ) {
					ber_memfree_x( bv.bv_val, ctx );
				}
			}
		} else if ( ud->strict ) {
			kp += sprintf( kp, "(%s=*)", ad->ad_cname.bv_val );
		}
		break;
	}
	return kp;
}

static int unique_search(
	Operation *op,
	Operation *nop,
	SlapReply *rs,
	char *key
)
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	unique_data *ud = on->on_bi.bi_private;
	SlapReply nrs = { REP_RESULT };
	slap_callback cb = { NULL, NULL, NULL, NULL }; /* XXX */
	unique_counter uq = { NULL, 0 };
	int rc;

	nop->ors_filter = str2filter_x(nop, key);
	ber_str2bv(key, 0, 0, &nop->ors_filterstr);

	cb.sc_response	= (slap_response*)count_attr_cb;
	cb.sc_private	= &uq;
	nop->o_callback	= &cb;
	nop->o_tag	= LDAP_REQ_SEARCH;
	nop->ors_scope	= LDAP_SCOPE_SUBTREE;
	nop->ors_deref	= LDAP_DEREF_NEVER;
	nop->ors_limit	= NULL;
	nop->ors_slimit	= SLAP_NO_LIMIT;
	nop->ors_tlimit	= SLAP_NO_LIMIT;
	nop->ors_attrs	= slap_anlist_no_attrs;
	nop->ors_attrsonly = 1;

	uq.ndn = &op->o_req_ndn;

	nop->o_req_ndn	= ud->dn;
	nop->o_ndn = op->o_bd->be_rootndn;

	nop->o_bd = on->on_info->oi_origdb;
	rc = nop->o_bd->be_search(nop, &nrs);
	filter_free_x(nop, nop->ors_filter);
	op->o_tmpfree( key, op->o_tmpmemctx );

	if(rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_OBJECT) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, rc, "unique_search failed");
		return(rs->sr_err);
	}

	Debug(LDAP_DEBUG_TRACE, "=> unique_search found %d records\n", uq.count, 0, 0);

	if(uq.count) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_CONSTRAINT_VIOLATION,
			"some attributes not unique");
		return(rs->sr_err);
	}

	return(SLAP_CB_CONTINUE);
}

#define ALLOC_EXTRA	16	/* extra slop */

static int unique_add(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	unique_data *ud = on->on_bi.bi_private;
	Operation nop = *op;

	Attribute *a;
	char *key, *kp;
	int ks = 0;

	Debug(LDAP_DEBUG_TRACE, "==> unique_add <%s>\n", op->o_req_dn.bv_val, 0, 0);

	if ( !dnIsSuffix( &op->o_req_ndn, &ud->dn ))
		return SLAP_CB_CONTINUE;

/*
** count everything first;
** allocate some memory;
** write the search key;
**
*/

	if(!(a = op->ora_e->e_attrs)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INVALID_SYNTAX,
			"unique_add() got null op.ora_e.e_attrs");
		return(rs->sr_err);
	} else for(; a; a = a->a_next) {
		ks = count_filter_len(ud, a->a_desc, a->a_vals, ks);
	}

	if ( !ks )
		return SLAP_CB_CONTINUE;

	ks += ALLOC_EXTRA;
	key = op->o_tmpalloc(ks, op->o_tmpmemctx);

	kp = key + sprintf(key, "(|");

	for(a = op->ora_e->e_attrs; a; a = a->a_next) {
		kp = build_filter(ud, a->a_desc, a->a_vals, kp, op->o_tmpmemctx);
	}

	sprintf(kp, ")");

	Debug(LDAP_DEBUG_TRACE, "=> unique_add %s\n", key, 0, 0);

	return unique_search(op, &nop, rs, key);
}


static int unique_modify(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	unique_data *ud = on->on_bi.bi_private;
	Operation nop = *op;

	Modifications *m;
	char *key, *kp;
	int ks = 0;

	Debug(LDAP_DEBUG_TRACE, "==> unique_modify <%s>\n", op->o_req_dn.bv_val, 0, 0);

	if ( !dnIsSuffix( &op->o_req_ndn, &ud->dn ))
		return SLAP_CB_CONTINUE;

/*
** count everything first;
** allocate some memory;
** write the search key;
**
*/

	if(!(m = op->orm_modlist)) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INVALID_SYNTAX,
			"unique_modify() got null op.orm_modlist");
		return(rs->sr_err);
	} else for(; m; m = m->sml_next) {
		if ((m->sml_op & LDAP_MOD_OP) == LDAP_MOD_DELETE) continue;
		ks = count_filter_len(ud, m->sml_desc, m->sml_values, ks);
	}

	if ( !ks )
		return SLAP_CB_CONTINUE;

	ks += ALLOC_EXTRA;
	key = op->o_tmpalloc(ks, op->o_tmpmemctx);

	kp = key + sprintf(key, "(|");

	for(m = op->orm_modlist; m; m = m->sml_next) {
 		if ((m->sml_op & LDAP_MOD_OP) == LDAP_MOD_DELETE) continue;
 		kp = build_filter(ud, m->sml_desc, m->sml_values, kp, op->o_tmpmemctx);
	}

	sprintf(kp, ")");

	Debug(LDAP_DEBUG_TRACE, "=> unique_modify %s\n", key, 0, 0);

	return unique_search(op, &nop, rs, key);
}


static int unique_modrdn(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	unique_data *ud = on->on_bi.bi_private;
	Operation nop = *op;

	char *key, *kp;
	int i, ks = 0;
	LDAPRDN	newrdn;
	struct berval bv[2];

	Debug(LDAP_DEBUG_TRACE, "==> unique_modrdn <%s> <%s>\n",
		op->o_req_dn.bv_val, op->orr_newrdn.bv_val, 0);

	if ( !dnIsSuffix( &op->o_req_ndn, &ud->dn ) && 
		(!op->orr_nnewSup || !dnIsSuffix( op->orr_nnewSup, &ud->dn )))
		return SLAP_CB_CONTINUE;

	if(ldap_bv2rdn_x(&op->oq_modrdn.rs_newrdn, &newrdn,
		(char **)&rs->sr_text, LDAP_DN_FORMAT_LDAP, op->o_tmpmemctx )) {
		op->o_bd->bd_info = (BackendInfo *) on->on_info;
		send_ldap_error(op, rs, LDAP_INVALID_SYNTAX,
			"unknown type(s) used in RDN");
		return(rs->sr_err);
	}
	for(i = 0; newrdn[i]; i++) {
		AttributeDescription *ad = NULL;
		if ( slap_bv2ad( &newrdn[i]->la_attr, &ad, &rs->sr_text )) {
			ldap_rdnfree_x( newrdn, op->o_tmpmemctx );
			rs->sr_err = LDAP_INVALID_SYNTAX;
			send_ldap_result( op, rs );
			return(rs->sr_err);
		}
		newrdn[i]->la_private = ad;
	}

	bv[1].bv_val = NULL;
	bv[1].bv_len = 0;

	for(i = 0; newrdn[i]; i++) {
		bv[0] = newrdn[i]->la_value;
		ks = count_filter_len(ud, newrdn[i]->la_private, bv, ks);
	}

	if ( !ks )
		return SLAP_CB_CONTINUE;

	ks += ALLOC_EXTRA;
	key = op->o_tmpalloc(ks, op->o_tmpmemctx);
	kp = key + sprintf(key, "(|");

	for(i = 0; newrdn[i]; i++) {
		bv[0] = newrdn[i]->la_value;
		kp = build_filter(ud, newrdn[i]->la_private, bv, kp, op->o_tmpmemctx);
	}

	sprintf(kp, ")");

	Debug(LDAP_DEBUG_TRACE, "=> unique_modrdn %s\n", key, 0, 0);

	return unique_search(op, &nop, rs, key);
}

/*
** init_module is last so the symbols resolve "for free" --
** it expects to be called automagically during dynamic module initialization
*/

int unique_initialize() {

	/* statically declared just after the #includes at top */
	unique.on_bi.bi_type = "unique";
	unique.on_bi.bi_db_init = unique_db_init;
	unique.on_bi.bi_db_config = unique_config;
	unique.on_bi.bi_db_open = unique_open;
	unique.on_bi.bi_db_close = unique_close;
	unique.on_bi.bi_op_add = unique_add;
	unique.on_bi.bi_op_modify = unique_modify;
	unique.on_bi.bi_op_modrdn = unique_modrdn;
	unique.on_bi.bi_op_delete = NULL;

	return(overlay_register(&unique));
}

#if SLAPD_OVER_UNIQUE == SLAPD_MOD_DYNAMIC && defined(PIC)
int init_module(int argc, char *argv[]) {
	return unique_initialize();
}
#endif

#endif /* SLAPD_OVER_UNIQUE */
