/* refint.c - referential integrity module */
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

/* This module maintains referential integrity for a set of
 * DN-valued attributes by searching for all references to a given
 * DN whenever the DN is changed or its entry is deleted, and making
 * the appropriate update.
 *
 * Updates are performed using the database rootdn, but the ModifiersName
 * is always set to refint_dn.
 */

#ifdef SLAPD_OVER_REFINT

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

static slap_overinst refint;

/* The DN to use in the ModifiersName for all refint updates */
static BerValue refint_dn = BER_BVC("cn=Referential Integrity Overlay");

typedef struct refint_attrs_s {
	struct refint_attrs_s *next;
	AttributeDescription *attr;
} refint_attrs;

typedef struct dependents_s {
	struct dependents_s *next;
	BerValue dn;				/* target dn */
	Modifications *mm;
} dependent_data;

typedef struct refint_data_s {
	const char *message;			/* breadcrumbs */
	struct refint_attrs_s *attrs;	/* list of known attrs */
	struct dependents_s *mods;		/* modifications returned from callback */
	BerValue dn;				/* basedn in parent, searchdn in call */
	BerValue newdn;				/* replacement value for modrdn callback */
	BerValue nnewdn;			/* normalized replacement value */
	BerValue nothing;			/* the nothing value, if needed */
	BerValue nnothing;			/* normalized nothingness */
} refint_data;

/*
** allocate new refint_data;
** initialize, copy basedn;
** store in on_bi.bi_private;
**
*/

static int
refint_db_init(
	BackendDB	*be
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	refint_data *id = ch_malloc(sizeof(refint_data));

	id->message = "_init";
	id->attrs = NULL;
	id->newdn.bv_val = NULL;
	id->nothing.bv_val = NULL;
	id->nnothing.bv_val = NULL;
	ber_dupbv( &id->dn, &be->be_nsuffix[0] );
	on->on_bi.bi_private = id;
	return(0);
}


/*
** if command = attributes:
**	foreach argument:
**		convert to attribute;
**		add to configured attribute list;
** elseif command = basedn:
**	set our basedn to argument;
**
*/

static int
refint_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	slap_overinst *on	= (slap_overinst *) be->bd_info;
	refint_data *id	= on->on_bi.bi_private;
	refint_attrs *ip;
	const char *text;
	AttributeDescription *ad;
	BerValue dn;
	int i;

	if(!strcasecmp(*argv, "refint_attributes")) {
		for(i = 1; i < argc; i++) {
			for(ip = id->attrs; ip; ip = ip->next)
			    if(!strcmp(argv[i], ip->attr->ad_cname.bv_val)) {
				Debug(LDAP_DEBUG_ANY,
					"%s: line %d: duplicate attribute <s>, ignored\n",
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
			ip = ch_malloc(sizeof(refint_attrs));
			ip->attr = ad;
			ip->next = id->attrs;
			id->attrs = ip;
			Debug(LDAP_DEBUG_CONFIG, "%s: line %d: new attribute <%s>\n",
				fname, lineno, argv[i]);
		}
	} else if(!strcasecmp(*argv, "refint_base")) {
		/* XXX only one basedn (yet) - need validate argument! */
		if(id->dn.bv_val) ch_free(id->dn.bv_val);
		ber_str2bv( argv[1], 0, 0, &dn );
		if(dnNormalize(0, NULL, NULL, &dn, &id->dn, NULL)) {
			Debug(LDAP_DEBUG_ANY, "%s: line %d: bad baseDN!\n", fname, lineno, 0);
			return(1);
		}
		Debug(LDAP_DEBUG_CONFIG, "%s: line %d: new baseDN <%s>\n",
			fname, lineno, argv[1]);
	} else if(!strcasecmp(*argv, "refint_nothing")) {
		if(id->nothing.bv_val) ch_free(id->nothing.bv_val);
		if(id->nnothing.bv_val) ch_free(id->nnothing.bv_val);
		ber_str2bv( argv[1], 0, 1, &id->nothing );
		if(dnNormalize(0, NULL, NULL, &id->nothing, &id->nnothing, NULL)) {
			Debug(LDAP_DEBUG_ANY, "%s: line %d: bad nothingDN!\n", fname, lineno, 0);
			return(1);
		}
		Debug(LDAP_DEBUG_CONFIG, "%s: line %d: new nothingDN<%s>\n",
			fname, lineno, argv[1]);
	} else {
		return(SLAP_CONF_UNKNOWN);
	}

	id->message = "_config";
	return(0);
}


/*
** nothing really happens here;
**
*/

static int
refint_open(
	BackendDB *be
)
{
	slap_overinst *on	= (slap_overinst *)be->bd_info;
	refint_data *id	= on->on_bi.bi_private;
	id->message		= "_open";
	return(0);
}


/*
** foreach configured attribute:
**	free it;
** free our basedn;
** (do not) free id->message;
** reset on_bi.bi_private;
** free our config data;
**
*/

static int
refint_close(
	BackendDB *be
)
{
	slap_overinst *on	= (slap_overinst *) be->bd_info;
	refint_data *id	= on->on_bi.bi_private;
	refint_attrs *ii, *ij;
	id->message		= "_close";

	for(ii = id->attrs; ii; ii = ij) {
		ij = ii->next;
		ch_free(ii);
	}

	ch_free(id->dn.bv_val);
	ch_free(id->nothing.bv_val);
	ch_free(id->nnothing.bv_val);

	on->on_bi.bi_private = NULL;	/* XXX */

	ch_free(id);

	return(0);
}

/*
** delete callback
** generates a list of Modification* from search results
*/

static int
refint_delete_cb(
	Operation *op,
	SlapReply *rs
)
{
	Attribute *a;
	BerVarray b = NULL;
	refint_data *dd = op->o_callback->sc_private;
	refint_attrs *ia, *da = dd->attrs;
	dependent_data *ip;
	Modifications *mp, *ma;
	int i;

	Debug(LDAP_DEBUG_TRACE, "refint_delete_cb <%s>\n",
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "NOTHING", 0, 0);

	if (rs->sr_type != REP_SEARCH || !rs->sr_entry) return(0);
	dd->message = "_delete_cb";

	/*
	** foreach configured attribute type:
	**	if this attr exists in the search result,
	**	and it has a value matching the target:
	**		allocate a Modification;
	**		allocate its array of 2 BerValues;
	**		if only one value, and we have a configured Nothing:
	**			allocate additional Modification
	**			type = MOD_ADD
	**			BerValues[] = { Nothing, NULL };
	**			add to list
	**		type = MOD_DELETE
	**		BerValues[] = { our target dn, NULL };
	**	add this mod to the list of mods;
	**
	*/

	ip = ch_malloc(sizeof(dependent_data));
	ip->dn.bv_val = NULL;
	ip->next = NULL;
	ip->mm = NULL;
	ma = NULL;
	for(ia = da; ia; ia = ia->next) {
	    if ( (a = attr_find(rs->sr_entry->e_attrs, ia->attr) ) )
		for(i = 0, b = a->a_nvals; b[i].bv_val; i++)
		    if(bvmatch(&dd->dn, &b[i])) {
			if(!ip->dn.bv_val) ber_dupbv(&ip->dn, &rs->sr_entry->e_nname);
			if(!b[1].bv_val && dd->nothing.bv_val) {
				mp = ch_malloc(sizeof(Modifications));
				mp->sml_desc = ia->attr;		/* XXX */
				mp->sml_type = a->a_desc->ad_cname;
				mp->sml_values  = ch_malloc(2 * sizeof(BerValue));
				mp->sml_nvalues = ch_malloc(2 * sizeof(BerValue));
				mp->sml_values[1].bv_len = mp->sml_nvalues[1].bv_len = 0;
				mp->sml_values[1].bv_val = mp->sml_nvalues[1].bv_val = NULL;

				mp->sml_op = LDAP_MOD_ADD;
				mp->sml_flags = 0;
				ber_dupbv(&mp->sml_values[0],  &dd->nothing);
				ber_dupbv(&mp->sml_nvalues[0], &dd->nnothing);
				mp->sml_next = ma;
				ma = mp;
			}
		 	/* this might violate the object class */
			mp = ch_malloc(sizeof(Modifications));
			mp->sml_desc = ia->attr;		/* XXX */
			mp->sml_type = a->a_desc->ad_cname;
			mp->sml_values  = ch_malloc(2 * sizeof(BerValue));
			mp->sml_nvalues = ch_malloc(2 * sizeof(BerValue));
			mp->sml_values[1].bv_len = mp->sml_nvalues[1].bv_len = 0;
			mp->sml_values[1].bv_val = mp->sml_nvalues[1].bv_val = NULL;
			mp->sml_op = LDAP_MOD_DELETE;
			mp->sml_flags = 0;
			ber_dupbv(&mp->sml_values[0], &dd->dn);
			ber_dupbv(&mp->sml_nvalues[0], &mp->sml_values[0]);
			mp->sml_next = ma;
			ma = mp;
			Debug(LDAP_DEBUG_TRACE, "refint_delete_cb: %s: %s\n",
				a->a_desc->ad_cname.bv_val, dd->dn.bv_val, 0);
			break;
	    }
	}
	ip->mm = ma;
	ip->next = dd->mods;
	dd->mods = ip;

	return(0);
}

/*
** null callback
** does nothing
*/

static int
refint_null_cb(
	Operation *op,
	SlapReply *rs
)
{
	((refint_data *)op->o_callback->sc_private)->message = "_null_cb";
	return(LDAP_SUCCESS);
}

/*
** modrdn callback
** generates a list of Modification* from search results
*/

static int
refint_modrdn_cb(
	Operation *op,
	SlapReply *rs
)
{
	Attribute *a;
	BerVarray b = NULL;
	refint_data *dd = op->o_callback->sc_private;
	refint_attrs *ia, *da = dd->attrs;
	dependent_data *ip = NULL;
	Modifications *mp;
	int i, fix;

	Debug(LDAP_DEBUG_TRACE, "refint_modrdn_cb <%s>\n",
		rs->sr_entry ? rs->sr_entry->e_name.bv_val : "NOTHING", 0, 0);

	if (rs->sr_type != REP_SEARCH || !rs->sr_entry) return(0);
	dd->message = "_modrdn_cb";

	/*
	** foreach configured attribute type:
	**   if this attr exists in the search result,
	**   and it has a value matching the target:
	**	allocate a pair of Modifications;
	**	make it MOD_ADD the new value and MOD_DELETE the old;
	**	allocate its array of BerValues;
	**	foreach value in the search result:
	**	   if it matches our target value, replace it;
	**	   otherwise, copy from the search result;
	**	terminate the array of BerValues;
	**   add these mods to the list of mods;
	**
	*/

	for(ia = da; ia; ia = ia->next) {
	    if((a = attr_find(rs->sr_entry->e_attrs, ia->attr))) {
		    for(fix = 0, i = 0, b = a->a_nvals; b[i].bv_val; i++)
			if(bvmatch(&dd->dn, &b[i])) { fix++; break; }
		    if(fix) {
			if (!ip) {
	    		    ip = ch_malloc(sizeof(dependent_data));
	    		    ip->next = NULL;
	    		    ip->mm = NULL;
	    		    ber_dupbv(&ip->dn, &rs->sr_entry->e_nname);
			}
			mp = ch_malloc(sizeof(Modifications));
			mp->sml_op = LDAP_MOD_ADD;
			mp->sml_flags = 0;
			mp->sml_desc = ia->attr;		/* XXX */
			mp->sml_type = ia->attr->ad_cname;
			mp->sml_values  = ch_malloc(2 * sizeof(BerValue));
			mp->sml_nvalues = ch_malloc(2 * sizeof(BerValue));
			ber_dupbv(&mp->sml_values[0], &dd->newdn);
			ber_dupbv(&mp->sml_nvalues[0], &dd->nnewdn);
			mp->sml_values[1].bv_len = mp->sml_nvalues[1].bv_len = 0;
			mp->sml_values[1].bv_val = mp->sml_nvalues[1].bv_val = NULL;
			mp->sml_next = ip->mm;
			ip->mm = mp;
			mp = ch_malloc(sizeof(Modifications));
			mp->sml_op = LDAP_MOD_DELETE;
			mp->sml_flags = 0;
			mp->sml_desc = ia->attr;		/* XXX */
			mp->sml_type = ia->attr->ad_cname;
			mp->sml_values  = ch_malloc(2 * sizeof(BerValue));
			mp->sml_nvalues = ch_malloc(2 * sizeof(BerValue));
			ber_dupbv(&mp->sml_values[0], &dd->dn);
			ber_dupbv(&mp->sml_nvalues[0], &dd->dn);
			mp->sml_values[1].bv_len = mp->sml_nvalues[1].bv_len = 0;
			mp->sml_values[1].bv_val = mp->sml_nvalues[1].bv_val = NULL;
			mp->sml_next = ip->mm;
			ip->mm = mp;
			Debug(LDAP_DEBUG_TRACE, "refint_modrdn_cb: %s: %s\n",
				a->a_desc->ad_cname.bv_val, dd->dn.bv_val, 0);
		}
	    }
	}
	if (ip) {
		ip->next = dd->mods;
		dd->mods = ip;
	}

	return(0);
}


/*
** refint_response
** search for matching records and modify them
*/

static int
refint_response(
	Operation *op,
	SlapReply *rs
)
{
	Operation nop = *op;
	SlapReply nrs = { REP_RESULT };
	slap_callback cb = { NULL, NULL, NULL, NULL };
	slap_callback cb2 = { NULL, slap_replog_cb, NULL, NULL };
	slap_callback *cbo, *cbp;
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	refint_data *id = on->on_bi.bi_private;
	refint_data dd = *id;
	refint_attrs *ip;
	dependent_data *dp;
	BerValue pdn;
	int rc, ac;
	Filter ftop, *fptr;

	id->message = "_refint_response";

	/* If the main op failed or is not a Delete or ModRdn, ignore it */
	if (( op->o_tag != LDAP_REQ_DELETE && op->o_tag != LDAP_REQ_MODRDN ) ||
		rs->sr_err != LDAP_SUCCESS )
		return SLAP_CB_CONTINUE;

	/*
	** validate (and count) the list of attrs;
	**
	*/

	for(ip = id->attrs, ac = 0; ip; ip = ip->next, ac++);
	if(!ac) {
		Debug( LDAP_DEBUG_TRACE,
			"refint_response called without any attributes\n", 0, 0, 0 );
		return SLAP_CB_CONTINUE;
	}

	/*
	** find the backend that matches our configured basedn;
	** make sure it exists and has search and modify methods;
	**
	*/

	nop.o_bd = select_backend(&id->dn, 0, 1);

	if(nop.o_bd) {
		if (!nop.o_bd->be_search || !nop.o_bd->be_modify) {
			Debug( LDAP_DEBUG_TRACE,
				"refint_response: backend missing search and/or modify\n",
				0, 0, 0 );
			return SLAP_CB_CONTINUE;
		}
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"refint_response: no backend for our baseDN %s??\n",
			id->dn.bv_val, 0, 0 );
		return SLAP_CB_CONTINUE;
	}

	cb2.sc_next = &cb;

	/*
	** if delete: set delete callback;
	** else modrdn: create a newdn, set modify callback;
	**
	*/

	if(op->o_tag == LDAP_REQ_DELETE) {
		cb.sc_response = &refint_delete_cb;
		dd.newdn.bv_val = NULL;
		dd.nnewdn.bv_val = NULL;
	} else {
		cb.sc_response = &refint_modrdn_cb;
		if ( op->oq_modrdn.rs_newSup ) {
			pdn = *op->oq_modrdn.rs_newSup;
		} else {
			dnParent( &op->o_req_dn, &pdn );
		}
		build_new_dn( &dd.newdn, &pdn, &op->orr_newrdn, NULL );
		if ( op->oq_modrdn.rs_nnewSup ) {
			pdn = *op->oq_modrdn.rs_nnewSup;
		} else {
			dnParent( &op->o_req_ndn, &pdn );
		}
		build_new_dn( &dd.nnewdn, &pdn, &op->orr_nnewrdn, NULL );
	}

	/*
	** build a search filter for all configured attributes;
	** populate our Operation;
	** pass our data (attr list, dn) to backend via sc_private;
	** call the backend search function;
	** nb: (|(one=thing)) is valid, but do smart formatting anyway;
	** nb: 16 is arbitrarily a dozen or so extra bytes;
	**
	*/

	ftop.f_choice = LDAP_FILTER_OR;
	ftop.f_next = NULL;
	ftop.f_or = NULL;
	nop.ors_filter = &ftop;
	for(ip = id->attrs; ip; ip = ip->next) {
		fptr = ch_malloc( sizeof(Filter) + sizeof(AttributeAssertion) );
		fptr->f_choice = LDAP_FILTER_EQUALITY;
		fptr->f_ava = (AttributeAssertion *)(fptr+1);
		fptr->f_ava->aa_desc = ip->attr;
		fptr->f_ava->aa_value = op->o_req_ndn;
		fptr->f_next = ftop.f_or;
		ftop.f_or = fptr;
	}
	filter2bv( nop.ors_filter, &nop.ors_filterstr );

	/* callback gets the searched dn instead */
	dd.dn = op->o_req_ndn;
	dd.message	= "_dependent_search";
	dd.mods		= NULL;
	cb.sc_private	= &dd;
	nop.o_callback	= &cb;
	nop.o_tag	= LDAP_REQ_SEARCH;
	nop.ors_scope	= LDAP_SCOPE_SUBTREE;
	nop.ors_deref	= LDAP_DEREF_NEVER;
	nop.ors_limit   = NULL;
	nop.ors_slimit	= SLAP_NO_LIMIT;
	nop.ors_tlimit	= SLAP_NO_LIMIT;

	/* no attrs! */
	nop.ors_attrs = slap_anlist_no_attrs;
	nop.ors_attrsonly = 1;

	nop.o_req_ndn = id->dn;
	nop.o_req_dn = id->dn;

	/* search */
	rc = nop.o_bd->be_search(&nop, &nrs);

	ch_free( nop.ors_filterstr.bv_val );
	while ( (fptr = ftop.f_or) != NULL ) {
		ftop.f_or = fptr->f_next;
		ch_free( fptr );
	}
	ch_free(dd.nnewdn.bv_val);
	ch_free(dd.newdn.bv_val);
	dd.newdn.bv_val	= NULL;
	dd.nnewdn.bv_val = NULL;

	if(rc != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_TRACE,
			"refint_response: search failed: %d\n",
			rc, 0, 0 );
		goto done;
	}

	/* safety? paranoid just in case */
	if(!cb.sc_private) {
		Debug( LDAP_DEBUG_TRACE,
			"refint_response: callback wiped out sc_private?!\n",
			0, 0, 0 );
		goto done;
	}

	/* presto! now it's a modify request with null callback */
	cb.sc_response	= &refint_null_cb;
	nop.o_tag	= LDAP_REQ_MODIFY;
	dd.message	= "_dependent_modify";

	/* See if the parent operation is going into the replog */
	for (cbo=op->o_callback, cbp = cbo->sc_next; cbp; cbo=cbp,cbp=cbp->sc_next) {
		if (cbp->sc_response == slap_replog_cb) {
			/* Invoke replog now, arrange for our
			 * dependent mods to also be logged
			 */
			cbo->sc_next = cbp->sc_next;
			replog( op );
			nop.o_callback = &cb2;
			break;
		}
	}

	/*
	** [our search callback builds a list of mods]
	** foreach mod:
	**	make sure its dn has a backend;
	**	connect Modification* chain to our op;
	**	call the backend modify function;
	**	pass any errors upstream;
	**
	*/

	for(dp = dd.mods; dp; dp = dp->next) {
		nop.o_req_dn	= dp->dn;
		nop.o_req_ndn	= dp->dn;
		nop.o_bd = select_backend(&dp->dn, 0, 1);
		if(!nop.o_bd) {
			Debug( LDAP_DEBUG_TRACE,
				"refint_response: no backend for DN %s!\n",
				dp->dn.bv_val, 0, 0 );
			goto done;
		}
		nrs.sr_type	= REP_RESULT;
		nop.orm_modlist = dp->mm;	/* callback did all the work */
		nop.o_dn = refint_dn;
		nop.o_ndn = refint_dn;
		nop.o_dn = nop.o_bd->be_rootdn;
		nop.o_ndn = nop.o_bd->be_rootndn;
		if(rs->sr_err != LDAP_SUCCESS) goto done;
		if((rc = nop.o_bd->be_modify(&nop, &nrs)) != LDAP_SUCCESS) {
			Debug( LDAP_DEBUG_TRACE,
				"refint_response: dependent modify failed: %d\n",
				nrs.sr_err, 0, 0 );
			goto done;
		}
	}

done:
	for(dp = dd.mods; dp; dp = dd.mods) {
		dd.mods = dp->next;
		ch_free(dp->dn.bv_val);
		slap_mods_free(dp->mm, 1);
	}
	dd.mods = NULL;

	return(SLAP_CB_CONTINUE);
}

/*
** init_module is last so the symbols resolve "for free" --
** it expects to be called automagically during dynamic module initialization
*/

int refint_initialize() {

	/* statically declared just after the #includes at top */
	refint.on_bi.bi_type = "refint";
	refint.on_bi.bi_db_init = refint_db_init;
	refint.on_bi.bi_db_config = refint_config;
	refint.on_bi.bi_db_open = refint_open;
	refint.on_bi.bi_db_close = refint_close;
	refint.on_response = refint_response;

	return(overlay_register(&refint));
}

#if SLAPD_OVER_REFINT == SLAPD_MOD_DYNAMIC && defined(PIC)
int init_module(int argc, char *argv[]) {
	return refint_initialize();
}
#endif

#endif /* SLAPD_OVER_REFINT */
