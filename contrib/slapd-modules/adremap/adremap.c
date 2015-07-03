/* adremap.c - Case-folding and DN-value remapping for AD proxies */
/* $OpenLDAP$ */
/*
 * Copyright 2015 Howard Chu <hyc@symas.com>.
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

#include "portable.h"

/*
 * This file implements an overlay that performs two remapping functions
 * to allow older POSIX clients to use Microsoft AD:
 * 1: downcase the values of a configurable list of attributes
 * 2: dereference some DN-valued attributes and convert to their simple names
 *	   e.g. generate memberUid based on member
 */

#ifdef SLAPD_OVER_ADREMAP

#include <ldap.h>
#include "lutil.h"
#include "slap.h"
#include <ac/errno.h>
#include <ac/time.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include "config.h"

typedef struct adremap_dnv {
	struct adremap_dnv *ad_next;
	AttributeDescription *ad_dnattr;	/* DN-valued attr to deref */
	AttributeDescription *ad_deref;		/* target attr's value to retrieve */
	AttributeDescription *ad_newattr;	/* New attr to collect new values */
} adremap_dnv;
/* example: member uid memberUid */

typedef struct adremap_case {
	struct adremap_case *ac_next;
	AttributeDescription *ac_attr;
} adremap_case;

/* Per-instance configuration information */
typedef struct adremap_info {
	adremap_case *ai_case;	/* attrs to downcase */
	adremap_dnv *ai_dnv;	/* DN attrs to remap */
} adremap_info;

enum {
	ADREMAP_CASE = 1,
	ADREMAP_DNV
};

static ConfigDriver adremap_cf_case;
static ConfigDriver adremap_cf_dnv;

/* configuration attribute and objectclass */
static ConfigTable adremapcfg[] = {
	{ "adremap-downcase", "attrs", 2, 0, 0,
	  ARG_MAGIC|ADREMAP_CASE, adremap_cf_case,
	  "( OLcfgCtAt:6.1 "
	  "NAME 'olcADremapDowncase' "
	  "DESC 'List of attributes to casefold to lower case' "
	  "SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "adremap-dnmap", "dnattr simpleattr newattr", 4, 4, 0,
	  ARG_MAGIC|ADREMAP_DNV, adremap_cf_dnv,
	  "( OLcfgCtAt:6.2 "
	  "NAME 'olcADremapDNmap' "
	  "DESC 'DN attr to map, attr from target to use, attr to generate' "
	  "SYNTAX OMsDirectoryString )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs adremapocs[] = {
	{ "( OLcfgCtOc:6.1 "
	  "NAME 'olcADremapConfig' "
	  "DESC 'AD remap configuration' "
	  "SUP olcOverlayConfig "
	  "MAY ( olcADremapDowncase $ olcADremapDNmap ) )",
	  Cft_Overlay, adremapcfg, NULL, NULL },
	{ NULL, 0, NULL }
};

static int
adremap_cf_case(ConfigArgs *c)
{
	BackendDB *be = (BackendDB *)c->be;
	slap_overinst *on = (slap_overinst *)c->bi;
	adremap_info *ai = on->on_bi.bi_private;
	adremap_case *ac, **a2;
	int rc = ARG_BAD_CONF;

	switch(c->op) {
	case SLAP_CONFIG_EMIT:
		for (ac = ai->ai_case; ac; ac=ac->ac_next) {
			rc = value_add_one(&c->rvalue_vals, &ac->ac_attr->ad_cname);
			if (rc) break;
		}
		break;
	case LDAP_MOD_DELETE:
		if (c->valx < 0) {
			for (ac = ai->ai_case; ac; ac=ai->ai_case) {
				ai->ai_case = ac->ac_next;
				ch_free(ac);
			}
		} else {
			int i;
			for (i=0, a2 = &ai->ai_case; i<c->valx; i++, a2 = &(*a2)->ac_next);
			ac = *a2;
			*a2 = ac->ac_next;
			ch_free(ac);
		}
		rc = 0;
		break;
	default: {
		const char *text;
		adremap_case ad;
		ad.ac_attr = NULL;
		rc = slap_str2ad(c->argv[1], &ad.ac_attr, &text);
		if (rc) break;
		for (a2 = &ai->ai_case; *a2; a2 = &(*a2)->ac_next);
		ac = ch_malloc(sizeof(adremap_case));
		ac->ac_next = NULL;
		ac->ac_attr = ad.ac_attr;
		*a2 = ac;
		break;
		}
	}
	return rc;
}

static int
adremap_cf_dnv(ConfigArgs *c)
{
	BackendDB *be = (BackendDB *)c->be;
	slap_overinst *on = (slap_overinst *)c->bi;
	adremap_info *ai = on->on_bi.bi_private;
	adremap_dnv *ad, **a2;
	int rc = ARG_BAD_CONF;

	switch(c->op) {
	case SLAP_CONFIG_EMIT:
		for (ad = ai->ai_dnv; ad; ad=ad->ad_next) {
			char *ptr;
			struct berval bv;
			bv.bv_len = ad->ad_dnattr->ad_cname.bv_len + ad->ad_deref->ad_cname.bv_len + ad->ad_newattr->ad_cname.bv_len + 2;
			bv.bv_val = ch_malloc(bv.bv_len + 1);
			ptr = lutil_strcopy(bv.bv_val, ad->ad_dnattr->ad_cname.bv_val);
			*ptr++ = ' ';
			ptr = lutil_strcopy(ptr, ad->ad_deref->ad_cname.bv_val);
			*ptr++ = ' ';
			strcpy(ptr, ad->ad_newattr->ad_cname.bv_val);
			ber_bvarray_add(&c->rvalue_vals, &bv);
		}
		if (ai->ai_dnv) rc = 0;
		break;
	case LDAP_MOD_DELETE:
		if (c->valx < 0) {
			for (ad = ai->ai_dnv; ad; ad=ai->ai_dnv) {
				ai->ai_dnv = ad->ad_next;
				ch_free(ad);
			}
		} else {
			int i;
			for (i=0, a2 = &ai->ai_dnv; i<c->valx; i++, a2 = &(*a2)->ad_next);
			ad = *a2;
			*a2 = ad->ad_next;
			ch_free(ad);
		}
		rc = 0;
		break;
	default: {
		const char *text;
		adremap_dnv av = {0};
		rc = slap_str2ad(c->argv[1], &av.ad_dnattr, &text);
		if (rc) break;
		if (av.ad_dnattr->ad_type->sat_syntax != slap_schema.si_syn_distinguishedName) {
			rc = 1;
			snprintf(c->cr_msg, sizeof(c->cr_msg), "<%s> not a DN-valued attribute",
				c->argv[0]);
			Debug(LDAP_DEBUG_ANY, "%s: %s(%s)\n", c->log, c->cr_msg, c->argv[1]);
			break;
		}
		rc = slap_str2ad(c->argv[2], &av.ad_deref, &text);
		if (rc) break;
		rc = slap_str2ad(c->argv[3], &av.ad_newattr, &text);
		if (rc) break;

		for (a2 = &ai->ai_dnv; *a2; a2 = &(*a2)->ad_next);
		ad = ch_malloc(sizeof(adremap_dnv));
		ad->ad_next = NULL;
		ad->ad_dnattr = av.ad_dnattr;
		ad->ad_deref = av.ad_deref;
		ad->ad_newattr = av.ad_newattr;
		*a2 = ad;
		break;
		}
	}
	return rc;
}

static int
adremap_search_resp(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = op->o_callback->sc_private;
	adremap_info *ai = on->on_bi.bi_private;
	adremap_case *ac;
	adremap_dnv *ad;
	Attribute *a;
	Entry *e;

	if (rs->sr_type != REP_SEARCH)
		return SLAP_CB_CONTINUE;

	e = rs->sr_entry;
	for (ac = ai->ai_case; ac; ac = ac->ac_next) {
		a = attr_find(e->e_attrs, ac->ac_attr);
		if (a) {
			int i, j;
			if (!(rs->sr_flags & REP_ENTRY_MODIFIABLE)) {
				e = entry_dup(e);
				rs_replace_entry(op, rs, on, e);
				rs->sr_flags |= REP_ENTRY_MODIFIABLE|REP_ENTRY_MUSTBEFREED;
				a = attr_find(e->e_attrs, ac->ac_attr);
			}
			for (i=0; i<a->a_numvals; i++) {
				unsigned char *c = a->a_vals[i].bv_val;
				for (j=0; j<a->a_vals[i].bv_len; j++)
					if (isupper(c[j]))
						c[j] = tolower(c[j]);
			}
		}
	}
	for (ad = ai->ai_dnv; ad; ad = ad->ad_next) {
		a = attr_find(e->e_attrs, ad->ad_dnattr);
		if (a) {
			Entry *n;
			Attribute *dr;
			int i, rc;
			if (!(rs->sr_flags & REP_ENTRY_MODIFIABLE)) {
				e = entry_dup(e);
				rs_replace_entry(op, rs, on, e);
				rs->sr_flags |= REP_ENTRY_MODIFIABLE|REP_ENTRY_MUSTBEFREED;
				a = attr_find(e->e_attrs, ad->ad_dnattr);
			}
			for (i=0; i<a->a_numvals; i++) {
				n = NULL;
				rc = be_entry_get_rw(op, &a->a_nvals[i], NULL, ad->ad_deref, 0, &n);
				if (!rc && n) {
					dr = attr_find(n->e_attrs, ad->ad_deref);
					if (dr)
						attr_merge_one(e, ad->ad_newattr, dr->a_vals, dr->a_nvals);
					be_entry_release_r(op, n);
				}
			}
		}
	}
	return SLAP_CB_CONTINUE;
}

static int
adremap_search(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	slap_callback *cb;

	cb = op->o_tmpcalloc(1, sizeof(slap_callback), op->o_tmpmemctx);
	cb->sc_response = adremap_search_resp;
	cb->sc_private = on;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;
	return SLAP_CB_CONTINUE;
}

static int
adremap_db_init(
	BackendDB *be,
	ConfigReply *cr
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;

	/* initialize private structure to store configuration */
	on->on_bi.bi_private = ch_calloc( 1, sizeof(adremap_info) );

	return 0;
}

static int
adremap_db_destroy(
	BackendDB *be,
	ConfigReply *cr
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	adremap_info *ai = (adremap_info *) on->on_bi.bi_private;
	adremap_case *ac;
	adremap_dnv *ad;

	/* free config */
	for (ac = ai->ai_case; ac; ac = ai->ai_case) {
		ai->ai_case = ac->ac_next;
		ch_free(ac);
	}
	for (ad = ai->ai_dnv; ad; ad = ai->ai_dnv) {
		ai->ai_dnv = ad->ad_next;
		ch_free(ad);
	}
	free( ai );

	return 0;
}

static slap_overinst adremap;

int adremap_initialize()
{
	int i, code;

	adremap.on_bi.bi_type = "adremap";
	adremap.on_bi.bi_db_init = adremap_db_init;
	adremap.on_bi.bi_db_destroy = adremap_db_destroy;
	adremap.on_bi.bi_op_search = adremap_search;

	/* register configuration directives */
	adremap.on_bi.bi_cf_ocs = adremapocs;
	code = config_register_schema( adremapcfg, adremapocs );
	if ( code ) return code;

	return overlay_register( &adremap );
}

#if SLAPD_OVER_ADREMAP == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return adremap_initialize();
}
#endif

#endif	/* defined(SLAPD_OVER_ADREMAP) */
