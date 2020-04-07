/* dynlist.c - dynamic list overlay */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2020 The OpenLDAP Foundation.
 * Portions Copyright 2004-2005 Pierangelo Masarati.
 * Portions Copyright 2008 Emmanuel Dreyfus.
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
 * This work was initially developed by Pierangelo Masarati
 * for SysNet s.n.c., for inclusion in OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_OVER_DYNLIST

#if SLAPD_OVER_DYNGROUP != SLAPD_MOD_STATIC
#define TAKEOVER_DYNGROUP
#endif

#include <stdio.h>

#include <ac/string.h>

#include "slap.h"
#include "config.h"
#include "lutil.h"

static AttributeDescription *ad_dgIdentity, *ad_dgAuthz;

typedef struct dynlist_map_t {
	AttributeDescription	*dlm_member_ad;
	AttributeDescription	*dlm_mapped_ad;
	AttributeDescription	*dlm_memberOf_ad;
	struct dynlist_map_t	*dlm_next;
} dynlist_map_t;

typedef struct dynlist_info_t {
	ObjectClass		*dli_oc;
	AttributeDescription	*dli_ad;
	struct dynlist_map_t	*dli_dlm;
	struct berval		dli_uri;
	LDAPURLDesc		*dli_lud;
	struct berval		dli_uri_nbase;
	Filter			*dli_uri_filter;
	struct berval		dli_default_filter;
	struct dynlist_info_t	*dli_next;
} dynlist_info_t;

typedef struct dynlist_gen_t {
	dynlist_info_t	*dlg_dli;
	int				*dlg_memberOf;
} dynlist_gen_t;
#define DYNLIST_HAS_MEMBEROF	1

#define DYNLIST_USAGE \
	"\"dynlist-attrset <oc> [uri] <URL-ad> [[<mapped-ad>:]<member-ad>[@<memberOf-ad>] ...]\": "

static int
ad_infilter( AttributeDescription *ad, Filter *f )
{
	if ( !f )
		return 0;

	switch( f->f_choice & SLAPD_FILTER_MASK ) {
	case SLAPD_FILTER_COMPUTED:
		return 0;
	case LDAP_FILTER_PRESENT:
		return f->f_desc == ad;
	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_APPROX:
	case LDAP_FILTER_SUBSTRINGS:
	case LDAP_FILTER_EXT:
		return f->f_av_desc == ad;
	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT: {
		for ( f = f->f_list; f; f = f->f_next )
			if ( ad_infilter( ad, f ))
				return 1;
		}
	}
	return 0;
}

static int
dynlist_make_filter( Operation *op, Entry *e, dynlist_info_t *dli, const char *url, struct berval *oldf, struct berval *newf )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;

	char		*ptr;
	int		needBrackets = 0;

	assert( oldf != NULL );
	assert( newf != NULL );
	assert( !BER_BVISNULL( oldf ) );
	assert( !BER_BVISEMPTY( oldf ) );

	if ( oldf->bv_val[0] != '(' ) {
		Debug( LDAP_DEBUG_ANY, "%s: dynlist, DN=\"%s\": missing parentheses in URI=\"%s\" filter\n",
			op->o_log_prefix, e->e_name.bv_val, url );
		needBrackets = 2;
	}

	newf->bv_len = STRLENOF( "(&(!(objectClass=" "))" ")" )
		+ dli->dli_oc->soc_cname.bv_len + oldf->bv_len + needBrackets;
	newf->bv_val = op->o_tmpalloc( newf->bv_len + 1, op->o_tmpmemctx );
	if ( newf->bv_val == NULL ) {
		return -1;
	}
	ptr = lutil_strcopy( newf->bv_val, "(&(!(objectClass=" );
	ptr = lutil_strcopy( ptr, dli->dli_oc->soc_cname.bv_val );
	ptr = lutil_strcopy( ptr, "))" );
	if ( needBrackets ) *ptr++ = '(';
	ptr = lutil_strcopy( ptr, oldf->bv_val );
	if ( needBrackets ) *ptr++ = ')';
	ptr = lutil_strcopy( ptr, ")" );
	newf->bv_len = ptr - newf->bv_val;

	return 0;
}

/* dynlist_sc_update() callback info set by dynlist_prepare_entry() */
typedef struct dynlist_sc_t {
	dynlist_info_t    *dlc_dli;
	Entry		*dlc_e;
} dynlist_sc_t;

static int
dynlist_sc_update( Operation *op, SlapReply *rs )
{
	Entry			*e;
	Attribute		*a;
	int			opattrs,
				userattrs;
	AccessControlState	acl_state = ACL_STATE_INIT;

	dynlist_sc_t		*dlc;
	dynlist_map_t		*dlm;

	if ( rs->sr_type != REP_SEARCH ) {
		return 0;
	}

	dlc = (dynlist_sc_t *)op->o_callback->sc_private;
	e = dlc->dlc_e;

	assert( e != NULL );
	assert( rs->sr_entry != NULL );

	/* test access to entry */
	if ( !access_allowed( op, rs->sr_entry, slap_schema.si_ad_entry,
				NULL, ACL_READ, NULL ) )
	{
		goto done;
	}

	/* if there is only one member_ad, and it's not mapped,
	 * consider it as old-style member listing */
	dlm = dlc->dlc_dli->dli_dlm;
	if ( dlm && dlm->dlm_mapped_ad == NULL && dlm->dlm_next == NULL ) {
		/* if access allowed, try to add values, emulating permissive
		 * control to silently ignore duplicates */
		if ( access_allowed( op, rs->sr_entry, slap_schema.si_ad_entry,
					NULL, ACL_READ, NULL ) )
		{
			Modification	mod;
			const char	*text = NULL;
			char		textbuf[1024];
			struct berval	vals[ 2 ], nvals[ 2 ];

			vals[ 0 ] = rs->sr_entry->e_name;
			BER_BVZERO( &vals[ 1 ] );
			nvals[ 0 ] = rs->sr_entry->e_nname;
			BER_BVZERO( &nvals[ 1 ] );

			mod.sm_op = LDAP_MOD_ADD;
			mod.sm_desc = dlm->dlm_member_ad;
			mod.sm_type = dlm->dlm_member_ad->ad_cname;
			mod.sm_values = vals;
			mod.sm_nvalues = nvals;
			mod.sm_numvals = 1;

			(void)modify_add_values( e, &mod, /* permissive */ 1,
					&text, textbuf, sizeof( textbuf ) );
		}

		goto done;
	}

	opattrs = SLAP_OPATTRS( rs->sr_attr_flags );
	userattrs = SLAP_USERATTRS( rs->sr_attr_flags );

	for ( a = rs->sr_entry->e_attrs; a != NULL; a = a->a_next ) {
		BerVarray	vals, nvals = NULL;
		int		i, j,
				is_oc = a->a_desc == slap_schema.si_ad_objectClass;

		/* if attribute is not requested, skip it */
		if ( rs->sr_attrs == NULL ) {
			if ( is_at_operational( a->a_desc->ad_type ) ) {
				continue;
			}

		} else {
			if ( is_at_operational( a->a_desc->ad_type ) ) {
				if ( !opattrs && !ad_inlist( a->a_desc, rs->sr_attrs ) )
				{
					continue;
				}

			} else {
				if ( !userattrs && !ad_inlist( a->a_desc, rs->sr_attrs ) )
				{
					continue;
				}
			}
		}

		/* test access to attribute */
		if ( op->ors_attrsonly ) {
			if ( !access_allowed( op, rs->sr_entry, a->a_desc, NULL,
						ACL_READ, &acl_state ) )
			{
				continue;
			}
		}

		/* single-value check: keep first only */
		if ( is_at_single_value( a->a_desc->ad_type ) ) {
			if ( attr_find( e->e_attrs, a->a_desc ) != NULL ) {
				continue;
			}
		}

		/* test access to attribute */
		i = a->a_numvals;

		vals = op->o_tmpalloc( ( i + 1 ) * sizeof( struct berval ), op->o_tmpmemctx );
		if ( a->a_nvals != a->a_vals ) {
			nvals = op->o_tmpalloc( ( i + 1 ) * sizeof( struct berval ), op->o_tmpmemctx );
		}

		for ( i = 0, j = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
			if ( is_oc ) {
				ObjectClass	*soc = oc_bvfind( &a->a_vals[i] );

				if ( soc->soc_kind == LDAP_SCHEMA_STRUCTURAL ) {
					continue;
				}
			}

			if ( access_allowed( op, rs->sr_entry, a->a_desc,
						&a->a_nvals[i], ACL_READ, &acl_state ) )
			{
				vals[j] = a->a_vals[i];
				if ( nvals ) {
					nvals[j] = a->a_nvals[i];
				}
				j++;
			}
		}

		/* if access allowed, try to add values, emulating permissive
		 * control to silently ignore duplicates */
		if ( j != 0 ) {
			Modification	mod;
			const char	*text = NULL;
			char		textbuf[1024];
			dynlist_map_t	*dlm;
			AttributeDescription *ad;

			BER_BVZERO( &vals[j] );
			if ( nvals ) {
				BER_BVZERO( &nvals[j] );
			}

			ad = a->a_desc;
			for ( dlm = dlc->dlc_dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
				if ( dlm->dlm_member_ad == a->a_desc ) {
					if ( dlm->dlm_mapped_ad ) {
						ad = dlm->dlm_mapped_ad;
					}
					break;
				}
			}

			mod.sm_op = LDAP_MOD_ADD;
			mod.sm_desc = ad;
			mod.sm_type = ad->ad_cname;
			mod.sm_values = vals;
			mod.sm_nvalues = nvals;
			mod.sm_numvals = j;

			(void)modify_add_values( e, &mod, /* permissive */ 1,
					&text, textbuf, sizeof( textbuf ) );
		}

		op->o_tmpfree( vals, op->o_tmpmemctx );
		if ( nvals ) {
			op->o_tmpfree( nvals, op->o_tmpmemctx );
		}
	}

done:;
	if ( rs->sr_flags & REP_ENTRY_MUSTBEFREED ) {
		entry_free( rs->sr_entry );
		rs->sr_entry = NULL;
		rs->sr_flags &= ~REP_ENTRY_MASK;
	}

	return 0;
}
	
static int
dynlist_prepare_entry( Operation *op, SlapReply *rs, dynlist_info_t *dli )
{
	Attribute	*a, *id = NULL;
	slap_callback	cb = { 0 };
	Operation	o = *op;
	struct berval	*url;
	Entry		*e;
	int		opattrs,
			userattrs;
	dynlist_sc_t	dlc = { 0 };
	dynlist_map_t	*dlm;

	a = attrs_find( rs->sr_entry->e_attrs, dli->dli_ad );
	if ( a == NULL ) {
		/* FIXME: error? */
		return SLAP_CB_CONTINUE;
	}

	opattrs = SLAP_OPATTRS( rs->sr_attr_flags );
	userattrs = SLAP_USERATTRS( rs->sr_attr_flags );

	/* Don't generate member list if it wasn't requested */
	for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
		AttributeDescription *ad = dlm->dlm_mapped_ad ? dlm->dlm_mapped_ad : dlm->dlm_member_ad;
		if ( userattrs || ad_inlist( ad, rs->sr_attrs )
			|| ad_infilter( ad, op->ors_filter ))
			break;
	}
	if ( dli->dli_dlm && !dlm )
		return SLAP_CB_CONTINUE;

	if ( ad_dgIdentity && ( id = attrs_find( rs->sr_entry->e_attrs, ad_dgIdentity ))) {
		Attribute *authz = NULL;

		/* if not rootdn and dgAuthz is present,
		 * check if user can be authorized as dgIdentity */
		if ( ad_dgAuthz && !BER_BVISEMPTY( &id->a_nvals[0] ) && !be_isroot( op )
			&& ( authz = attrs_find( rs->sr_entry->e_attrs, ad_dgAuthz ) ) )
		{
			if ( slap_sasl_matches( op, authz->a_nvals,
				&o.o_ndn, &o.o_ndn ) != LDAP_SUCCESS )
			{
				return SLAP_CB_CONTINUE;
			}
		}

		o.o_dn = id->a_vals[0];
		o.o_ndn = id->a_nvals[0];
		o.o_groups = NULL;
	}

	e = rs->sr_entry;
	/* ensure e is modifiable, but do not replace
	 * sr_entry yet since we have pointers into it */
	if ( !( rs->sr_flags & REP_ENTRY_MODIFIABLE ) ) {
		e = entry_dup( rs->sr_entry );
	}

	dlc.dlc_e = e;
	dlc.dlc_dli = dli;
	cb.sc_private = &dlc;
	cb.sc_response = dynlist_sc_update;

	o.o_callback = &cb;
	o.ors_deref = LDAP_DEREF_NEVER;
	o.ors_limit = NULL;
	o.ors_tlimit = SLAP_NO_LIMIT;
	o.ors_slimit = SLAP_NO_LIMIT;

	for ( url = a->a_nvals; !BER_BVISNULL( url ); url++ ) {
		LDAPURLDesc	*lud = NULL;
		int		i, j;
		struct berval	dn;
		int		rc;

		BER_BVZERO( &o.o_req_dn );
		BER_BVZERO( &o.o_req_ndn );
		o.ors_filter = NULL;
		o.ors_attrs = NULL;
		BER_BVZERO( &o.ors_filterstr );

		if ( ldap_url_parse( url->bv_val, &lud ) != LDAP_URL_SUCCESS ) {
			/* FIXME: error? */
			continue;
		}

		if ( lud->lud_host != NULL ) {
			/* FIXME: host not allowed; reject as illegal? */
			Debug( LDAP_DEBUG_ANY, "dynlist_prepare_entry(\"%s\"): "
				"illegal URI \"%s\"\n",
				e->e_name.bv_val, url->bv_val );
			goto cleanup;
		}

		if ( lud->lud_dn == NULL ) {
			/* note that an empty base is not honored in terms
			 * of defaultSearchBase, because select_backend()
			 * is not aware of the defaultSearchBase option;
			 * this can be useful in case of a database serving
			 * the empty suffix */
			BER_BVSTR( &dn, "" );

		} else {
			ber_str2bv( lud->lud_dn, 0, 0, &dn );
		}
		rc = dnPrettyNormal( NULL, &dn, &o.o_req_dn, &o.o_req_ndn, op->o_tmpmemctx );
		if ( rc != LDAP_SUCCESS ) {
			/* FIXME: error? */
			goto cleanup;
		}
		o.ors_scope = lud->lud_scope;

		for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
			if ( dlm->dlm_mapped_ad != NULL ) {
				break;
			}
		}

		if ( dli->dli_dlm && !dlm ) {
			/* if ( lud->lud_attrs != NULL ),
			 * the URL should be ignored */
			o.ors_attrs = slap_anlist_no_attrs;

		} else if ( lud->lud_attrs == NULL ) {
			o.ors_attrs = rs->sr_attrs;

		} else {
			for ( i = 0; lud->lud_attrs[i]; i++)
				/* just count */ ;

			o.ors_attrs = op->o_tmpcalloc( i + 1, sizeof( AttributeName ), op->o_tmpmemctx );
			for ( i = 0, j = 0; lud->lud_attrs[i]; i++) {
				const char	*text = NULL;
	
				ber_str2bv( lud->lud_attrs[i], 0, 0, &o.ors_attrs[j].an_name );
				o.ors_attrs[j].an_desc = NULL;
				(void)slap_bv2ad( &o.ors_attrs[j].an_name, &o.ors_attrs[j].an_desc, &text );
				/* FIXME: ignore errors... */

				if ( ad_infilter( o.ors_attrs[j].an_desc, op->ors_filter )) {
					/* if referenced in filter, must retrieve */
				} else if ( rs->sr_attrs == NULL ) {
					if ( o.ors_attrs[j].an_desc != NULL &&
							is_at_operational( o.ors_attrs[j].an_desc->ad_type ) )
					{
						continue;
					}

				} else {
					if ( o.ors_attrs[j].an_desc != NULL &&
							is_at_operational( o.ors_attrs[j].an_desc->ad_type ) )
					{
						if ( !opattrs ) {
							continue;
						}

						if ( !ad_inlist( o.ors_attrs[j].an_desc, rs->sr_attrs ) ) {
							/* lookup if mapped -- linear search,
							 * not very efficient unless list
							 * is very short */
							for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
								if ( dlm->dlm_member_ad == o.ors_attrs[j].an_desc ) {
									break;
								}
							}

							if ( dlm == NULL ) {
								continue;
							}
						}

					} else {
						if ( !userattrs && 
								o.ors_attrs[j].an_desc != NULL &&
								!ad_inlist( o.ors_attrs[j].an_desc, rs->sr_attrs ) )
						{
							/* lookup if mapped -- linear search,
							 * not very efficient unless list
							 * is very short */
							for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
								if ( dlm->dlm_member_ad == o.ors_attrs[j].an_desc ) {
									break;
								}
							}

							if ( dlm == NULL ) {
								continue;
							}
						}
					}
				}

				j++;
			}

			if ( j == 0 ) {
				goto cleanup;
			}
		
			BER_BVZERO( &o.ors_attrs[j].an_name );
		}

		if ( lud->lud_filter == NULL ) {
			ber_dupbv_x( &o.ors_filterstr,
					&dli->dli_default_filter, op->o_tmpmemctx );

		} else {
			struct berval	flt;
			ber_str2bv( lud->lud_filter, 0, 0, &flt );
			if ( dynlist_make_filter( op, rs->sr_entry, dli, url->bv_val, &flt, &o.ors_filterstr ) ) {
				/* error */
				goto cleanup;
			}
		}
		o.ors_filter = str2filter_x( op, o.ors_filterstr.bv_val );
		if ( o.ors_filter == NULL ) {
			goto cleanup;
		}
		
		o.o_bd = select_backend( &o.o_req_ndn, 1 );
		if ( o.o_bd && o.o_bd->be_search ) {
			SlapReply	r = { REP_SEARCH };
			r.sr_attr_flags = slap_attr_flags( o.ors_attrs );
			o.o_managedsait = SLAP_CONTROL_CRITICAL;
			(void)o.o_bd->be_search( &o, &r );
		}

cleanup:;
		if ( id ) {
			slap_op_groups_free( &o );
		}
		if ( o.ors_filter ) {
			filter_free_x( &o, o.ors_filter, 1 );
		}
		if ( o.ors_attrs && o.ors_attrs != rs->sr_attrs
				&& o.ors_attrs != slap_anlist_no_attrs )
		{
			op->o_tmpfree( o.ors_attrs, op->o_tmpmemctx );
		}
		if ( !BER_BVISNULL( &o.o_req_dn ) ) {
			op->o_tmpfree( o.o_req_dn.bv_val, op->o_tmpmemctx );
		}
		if ( !BER_BVISNULL( &o.o_req_ndn ) ) {
			op->o_tmpfree( o.o_req_ndn.bv_val, op->o_tmpmemctx );
		}
		assert( BER_BVISNULL( &o.ors_filterstr )
			|| o.ors_filterstr.bv_val != lud->lud_filter );
		op->o_tmpfree( o.ors_filterstr.bv_val, op->o_tmpmemctx );
		ldap_free_urldesc( lud );
	}

	if ( e != rs->sr_entry ) {
		rs_replace_entry( op, rs, (slap_overinst *)op->o_bd->bd_info, e );
		rs->sr_flags |= REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED;
	}

	return SLAP_CB_CONTINUE;
}

/* dynlist_sc_compare_entry() callback set by dynlist_compare() */
typedef struct dynlist_cc_t {
	slap_callback dc_cb;
#	define dc_ava	dc_cb.sc_private /* attr:val to compare with */
	int *dc_res;
} dynlist_cc_t;

static int
dynlist_sc_compare_entry( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH && rs->sr_entry != NULL ) {
		dynlist_cc_t *dc = (dynlist_cc_t *)op->o_callback;
		AttributeAssertion *ava = dc->dc_ava;
		Attribute *a = attrs_find( rs->sr_entry->e_attrs, ava->aa_desc );

		if ( a != NULL ) {
			while ( LDAP_SUCCESS != attr_valfind( a,
					SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
						SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
					&ava->aa_value, NULL, op->o_tmpmemctx )
				&& (a = attrs_find( a->a_next, ava->aa_desc )) != NULL )
				;
			*dc->dc_res = a ? LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE;
		}
	}

	return 0;
}

static int
dynlist_compare( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_gen_t	*dlg = (dynlist_gen_t *)on->on_bi.bi_private;
	dynlist_info_t	*dli = dlg->dlg_dli;
	Operation o = *op;
	Entry *e = NULL;
	dynlist_map_t *dlm;
	BackendDB *be;
	int ret = SLAP_CB_CONTINUE;

	if ( get_manageDSAit( op ) )
		return SLAP_CB_CONTINUE;

	for ( ; dli != NULL; dli = dli->dli_next ) {
		for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
			AttributeDescription *ad = dlm->dlm_mapped_ad ? dlm->dlm_mapped_ad : dlm->dlm_member_ad;
			/* builtin dyngroup evaluator only works for DNs */
			if ( ad->ad_type->sat_syntax != slap_schema.si_syn_distinguishedName )
				continue;
			if ( op->oq_compare.rs_ava->aa_desc == ad )
				break;
		}

		if ( dlm ) {
			/* This compare is for one of the attributes we're
			 * interested in. We'll use slapd's existing dyngroup
			 * evaluator to get the answer we want.
			 */
			BerVarray id = NULL, authz = NULL;

			o.o_do_not_cache = 1;

			if ( ad_dgIdentity && backend_attribute( &o, NULL, &o.o_req_ndn,
				ad_dgIdentity, &id, ACL_READ ) == LDAP_SUCCESS )
			{
				/* if not rootdn and dgAuthz is present,
				 * check if user can be authorized as dgIdentity */
				if ( ad_dgAuthz && !BER_BVISEMPTY( id ) && !be_isroot( op )
					&& backend_attribute( &o, NULL, &o.o_req_ndn,
						ad_dgAuthz, &authz, ACL_READ ) == LDAP_SUCCESS )
				{
					
					rs->sr_err = slap_sasl_matches( op, authz,
						&o.o_ndn, &o.o_ndn );
					ber_bvarray_free_x( authz, op->o_tmpmemctx );
					if ( rs->sr_err != LDAP_SUCCESS ) {
						goto done;
					}
				}

				o.o_dn = *id;
				o.o_ndn = *id;
				o.o_groups = NULL; /* authz changed, invalidate cached groups */
			}

			rs->sr_err = backend_group( &o, NULL, &o.o_req_ndn,
				&o.oq_compare.rs_ava->aa_value, dli->dli_oc, dli->dli_ad );
			switch ( rs->sr_err ) {
			case LDAP_SUCCESS:
				rs->sr_err = LDAP_COMPARE_TRUE;
				break;

			case LDAP_NO_SUCH_OBJECT:
				/* NOTE: backend_group() returns noSuchObject
				 * if op_ndn does not exist; however, since
				 * dynamic list expansion means that the
				 * member attribute is virtually present, the
				 * non-existence of the asserted value implies
				 * the assertion is FALSE rather than
				 * UNDEFINED */
				rs->sr_err = LDAP_COMPARE_FALSE;
				break;
			}

done:;
			if ( id ) ber_bvarray_free_x( id, o.o_tmpmemctx );

			send_ldap_result( op, rs );
			return rs->sr_err;
		}
	}

	be = select_backend( &o.o_req_ndn, 1 );
	if ( !be || !be->be_search ) {
		return SLAP_CB_CONTINUE;
	}

	if ( overlay_entry_get_ov( &o, &o.o_req_ndn, NULL, NULL, 0, &e, on ) !=
		LDAP_SUCCESS || e == NULL )
	{
		return SLAP_CB_CONTINUE;
	}

	/* check for dynlist objectClass; done if not found */
	dli = (dynlist_info_t *)dlg->dlg_dli;
	while ( dli != NULL && !is_entry_objectclass_or_sub( e, dli->dli_oc ) ) {
		dli = dli->dli_next;
	}
	if ( dli == NULL ) {
		goto release;
	}

	if ( ad_dgIdentity ) {
		Attribute *id = attrs_find( e->e_attrs, ad_dgIdentity );
		if ( id ) {
			Attribute *authz;

			/* if not rootdn and dgAuthz is present,
			 * check if user can be authorized as dgIdentity */
			if ( ad_dgAuthz && !BER_BVISEMPTY( &id->a_nvals[0] ) && !be_isroot( op )
				&& ( authz = attrs_find( e->e_attrs, ad_dgAuthz ) ) )
			{
				if ( slap_sasl_matches( op, authz->a_nvals,
					&o.o_ndn, &o.o_ndn ) != LDAP_SUCCESS )
				{
					goto release;
				}
			}

			o.o_dn = id->a_vals[0];
			o.o_ndn = id->a_nvals[0];
			o.o_groups = NULL;
		}
	}

	/* generate dynamic list with dynlist_response() and compare */
	{
		SlapReply	r = { REP_SEARCH };
		Attribute *a;
		AttributeName an[2];

		o.o_tag = LDAP_REQ_SEARCH;
		o.ors_limit = NULL;
		o.ors_tlimit = SLAP_NO_LIMIT;
		o.ors_slimit = SLAP_NO_LIMIT;

		o.ors_filterstr = *slap_filterstr_objectClass_pres;
		o.ors_filter = (Filter *) slap_filter_objectClass_pres;

		o.ors_scope = LDAP_SCOPE_BASE;
		o.ors_deref = LDAP_DEREF_NEVER;
		an[0].an_name = op->orc_ava->aa_desc->ad_cname;
		an[0].an_desc = op->orc_ava->aa_desc;
		BER_BVZERO( &an[1].an_name );
		o.ors_attrs = an;
		o.ors_attrsonly = 0;
		r.sr_entry = e;
		r.sr_attrs = an;

		o.o_acl_priv = ACL_COMPARE;
		dynlist_prepare_entry( &o, &r, dli );
		a = attrs_find( r.sr_entry->e_attrs, op->orc_ava->aa_desc );

		ret = LDAP_NO_SUCH_ATTRIBUTE;
		for ( ; a ; a = attrs_find( a->a_next, op->orc_ava->aa_desc )) {
			ret = LDAP_COMPARE_FALSE;
			if ( attr_valfind( a,
					SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
						SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
					&op->orc_ava->aa_value, NULL, op->o_tmpmemctx ) == LDAP_SUCCESS ) {
				ret = LDAP_COMPARE_TRUE;
				break;
			}
		}
		rs->sr_err = ret;

		if ( r.sr_entry != e )
			entry_free( r.sr_entry );
		send_ldap_result( op, rs );
	}

release:;
	if ( e != NULL ) {
		overlay_entry_release_ov( &o, e, 0, on );
	}

	return ret;
}

typedef struct dynlist_name_t {
	struct berval dy_name;
	dynlist_info_t *dy_dli;
	int dy_seen;
	int dy_numuris;
	LDAPURLDesc *dy_uris[];
} dynlist_name_t;

typedef struct dynlist_search_t {
	TAvlnode *ds_names;
	dynlist_info_t *ds_dli;
	Filter *ds_origfilter;
	struct berval ds_origfilterbv;
	int ds_memberOf;
} dynlist_search_t;

static int
dynlist_avl_cmp( const void *c1, const void *c2 )
{
	const dynlist_name_t *n1, *n2;
	int rc;
	n1 = c1; n2 = c2;

	rc = n1->dy_name.bv_len - n2->dy_name.bv_len;
	if ( rc ) return rc;
	return ber_bvcmp( &n1->dy_name, &n2->dy_name );
}

/* build a list of dynamic entries */
static int
dynlist_search1resp( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH && rs->sr_entry != NULL ) {
		dynlist_search_t *ds = op->o_callback->sc_private;
		Attribute *a = attr_find( rs->sr_entry->e_attrs, ds->ds_dli->dli_ad );
		if ( a ) {
			dynlist_name_t *dyn = ch_calloc(1, sizeof(dynlist_name_t)+rs->sr_entry->e_nname.bv_len + 1+
				(a->a_numvals * sizeof(LDAPURLDesc *)));
			struct berval bv, nbase;
			LDAPURLDesc *ludp;
			int i, j;
			dyn->dy_name.bv_val = ((char *)(dyn+1)) + (a->a_numvals * sizeof(LDAPURLDesc *));
			dyn->dy_dli = ds->ds_dli;
			dyn->dy_name.bv_len = rs->sr_entry->e_nname.bv_len;
			/* parse and validate the URIs */
			for (i=0, j=0; i<a->a_numvals; i++) {
				if (ldap_url_parse( a->a_vals[i].bv_val, &ludp ) != LDAP_URL_SUCCESS )
					continue;
				if (( ludp->lud_host && *ludp->lud_host)
					|| ludp->lud_exts ) {
skipit:
					ldap_free_urldesc( ludp );
					continue;
				}
				ber_str2bv( ludp->lud_dn, 0, 0, &bv );
				if ( dnNormalize( 0, NULL, NULL, &bv, &nbase, op->o_tmpmemctx ) != LDAP_SUCCESS )
					goto skipit;
				ldap_memfree( ludp->lud_dn );
				ludp->lud_dn = ldap_strdup( nbase.bv_val );
				op->o_tmpfree( nbase.bv_val, op->o_tmpmemctx );
				/* cheat here, reuse fields */
				ludp->lud_port = nbase.bv_len;
				if ( ludp->lud_filter && *ludp->lud_filter ) {
					Filter *f = str2filter( ludp->lud_filter );
					if ( f == NULL )
						goto skipit;
					ldap_memfree( ludp->lud_filter );
					ludp->lud_filter = (char *)f;
				}
				dyn->dy_uris[j] = ludp;
				j++;
			}
			dyn->dy_numuris = j;
			memcpy(dyn->dy_name.bv_val, rs->sr_entry->e_nname.bv_val, rs->sr_entry->e_nname.bv_len );

			if ( tavl_insert( &ds->ds_names, dyn, dynlist_avl_cmp, avl_dup_error )) {
				for (i=dyn->dy_numuris-1; i>=0; i--) {
					ludp = dyn->dy_uris[i];
					if ( ludp->lud_filter ) {
						filter_free( (Filter *)ludp->lud_filter );
						ludp->lud_filter = NULL;
					}
					ldap_free_urldesc( ludp );
				}
				ch_free( dyn );
			}
		}
	}
	return 0;
}

/* replace a filter clause (memberOf=<groupDN>) with an expansion of
 * (&(entryDN=<groupURIbase>)<groupURIfilter>)
 */
static int
dynlist_filter_group( Operation *op, Filter *f, Filter *n, AttributeDescription *uri )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	Entry *e;
	Attribute *a;
	Filter *andf = NULL, *dnf, *urif, *orf = NULL;
	LDAPURLDesc *ludp;
	struct berval bv, nbase;
	int i;

	if ( overlay_entry_get_ov( op, &f->f_av_value, NULL, NULL, 0, &e, on ) !=
		LDAP_SUCCESS || e == NULL ) {
		return -1;
	}
	a = attr_find( e->e_attrs, uri );
	if ( !a ) {
		overlay_entry_release_ov( op, e, 0, on );
		return -1;
	}
	for (i=0; i<a->a_numvals; i++) {
		if ( ldap_url_parse( a->a_vals[i].bv_val, &ludp ) != LDAP_URL_SUCCESS )
			continue;
		if (( ludp->lud_host && *ludp->lud_host )
			|| ludp->lud_attrs
			|| ludp->lud_exts ) {
	skip:
			ldap_free_urldesc( ludp );
			continue;
		}
		ber_str2bv( ludp->lud_dn, 0, 0, &bv );
		if ( dnNormalize( 0, NULL, NULL, &bv, &nbase, op->o_tmpmemctx ) != LDAP_SUCCESS )
			goto skip;
		if ( ludp->lud_filter && *ludp->lud_filter ) {
			urif = str2filter_x( op, ludp->lud_filter );
			if ( urif == NULL ) {
				op->o_tmpfree( nbase.bv_val, op->o_tmpmemctx );
				goto skip;
			}
		} else {
			urif = NULL;
		}
		if ( !andf ) {
			andf = n;
		} else {
			if ( !orf ) {
				andf = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
				andf->f_choice = n->f_choice;
				andf->f_list = n->f_list;
				orf = n;
				orf->f_choice = LDAP_FILTER_OR;
				orf->f_list = andf;
			}
			andf->f_next = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
			andf = andf->f_next;
		}
		dnf = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
		andf->f_choice = LDAP_FILTER_AND;
		andf->f_next = NULL;
		andf->f_list = dnf;
		dnf->f_next = urif;
		if ( ludp->lud_scope == LDAP_SCOPE_BASE ) {
			dnf->f_choice = LDAP_FILTER_EQUALITY;
			dnf->f_ava = op->o_tmpalloc( sizeof(AttributeAssertion), op->o_tmpmemctx );
			dnf->f_av_desc = slap_schema.si_ad_entryDN;
			dnf->f_av_value = nbase;
		} else {
			dnf->f_choice = LDAP_FILTER_EXT;
			dnf->f_mra = op->o_tmpcalloc( 1, sizeof(MatchingRuleAssertion), op->o_tmpmemctx );
			dnf->f_mr_desc = slap_schema.si_ad_entryDN;
			dnf->f_mr_value = nbase;
			switch ( ludp->lud_scope ) {
			case LDAP_SCOPE_ONELEVEL:
				dnf->f_mr_rule = slap_schema.si_mr_dnOneLevelMatch;
				break;
			case LDAP_SCOPE_SUBTREE:
				dnf->f_mr_rule = slap_schema.si_mr_dnSubtreeMatch;
				break;
			case LDAP_SCOPE_SUBORDINATE:
				dnf->f_mr_rule = slap_schema.si_mr_dnSubordinateMatch;
				break;
			}
			ber_str2bv( dnf->f_mr_rule->smr_names[0], 0, 0, &dnf->f_mr_rule_text );
		}
		ldap_free_urldesc( ludp );
	}
	overlay_entry_release_ov( op, e, 0, on );
	if ( !andf )
		return -1;
	return 0;
}

/* Dup the filter, replacing any references to given ad with dyngroup evaluation */
static Filter *
dynlist_filter_dup( Operation *op, Filter *f, AttributeDescription *ad, AttributeDescription *uri )
{
	Filter *n = NULL;

	if ( !f )
		return NULL;

	n = op->o_tmpalloc( sizeof(Filter), op->o_tmpmemctx );
	n->f_next = NULL;
	switch( f->f_choice & SLAPD_FILTER_MASK ) {
	case SLAPD_FILTER_COMPUTED:
		n->f_choice = f->f_choice;
		n->f_result = f->f_result;
		break;

	case LDAP_FILTER_PRESENT:
		n->f_choice = f->f_choice;
		n->f_desc = f->f_desc;
		break;

	case LDAP_FILTER_EQUALITY:
		if ( f->f_av_desc == ad && !dynlist_filter_group( op, f, n, uri ))
			break;
		/* FALLTHRU */
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_APPROX:
		n->f_choice = f->f_choice;
		n->f_ava = f->f_ava;
		break;

	case LDAP_FILTER_SUBSTRINGS:
		n->f_choice = f->f_choice;
		n->f_sub_initial = f->f_sub_initial;
		n->f_sub_final = f->f_sub_final;
		n->f_sub = f->f_sub;
		break;

	case LDAP_FILTER_EXT:
		n->f_choice = f->f_choice;
		n->f_mra = f->f_mra;
		break;

	case LDAP_FILTER_NOT:
	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR: {
		Filter **p;

		n->f_choice = f->f_choice;

		for ( p = &n->f_list, f = f->f_list; f; f = f->f_next ) {
			*p = dynlist_filter_dup( op, f, ad, uri );
			if ( !*p )
				continue;
			p = &(*p)->f_next;
		}
		}
		break;
	}
	return n;
}

static void
dynlist_filter_free( Operation *op, Filter *f )
{
	Filter *p, *next;

	if ( f == NULL )
		return;

	f->f_choice &= SLAPD_FILTER_MASK;
	switch( f->f_choice ) {
	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		for ( p = f->f_list; p; p = next ) {
			next = p->f_next;
			op->o_tmpfree( p, op->o_tmpmemctx );
		}
		break;
	default:
		op->o_tmpfree( f, op->o_tmpmemctx );
	}
}

static void
dynlist_search_free( void *ptr )
{
	dynlist_name_t *dyn = (dynlist_name_t *)ptr;
	LDAPURLDesc *ludp;
	int i;

	for (i=dyn->dy_numuris-1; i>=0; i--) {
		ludp = dyn->dy_uris[i];
		if ( ludp->lud_filter ) {
			filter_free( (Filter *)ludp->lud_filter );
			ludp->lud_filter = NULL;
		}
		ldap_free_urldesc( ludp );
	}
	ch_free( ptr );
}

static int
dynlist_search_cleanup( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_RESULT || op->o_abandon ||
		rs->sr_err == SLAPD_ABANDON ) {
		slap_callback *sc = op->o_callback;
		dynlist_search_t *ds = op->o_callback->sc_private;
		tavl_free( ds->ds_names, dynlist_search_free );
		if ( ds->ds_origfilter ) {
			op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
			dynlist_filter_free( op, op->ors_filter );
			op->ors_filter = ds->ds_origfilter;
			op->ors_filterstr = ds->ds_origfilterbv;
		}
		op->o_callback = sc->sc_next;
		op->o_tmpfree( sc, op->o_tmpmemctx );

	}
	return 0;
}

static int
dynlist_testurl(Operation *op, dynlist_name_t *dyn, Entry *e)
{
	LDAPURLDesc *ludp;
	struct berval nbase, bv;
	int i, rc = LDAP_COMPARE_FALSE;
	for (i=0; i<dyn->dy_numuris; i++) {
		ludp = dyn->dy_uris[i];
		nbase.bv_val = ludp->lud_dn;
		nbase.bv_len = ludp->lud_port;
		if ( ludp->lud_attrs )
			continue;
		switch( ludp->lud_scope ) {
		case LDAP_SCOPE_BASE:
			if ( !dn_match( &nbase, &e->e_nname ))
				continue;
			break;
		case LDAP_SCOPE_ONELEVEL:
			dnParent( &e->e_nname, &bv );
			if ( !dn_match( &nbase, &bv ))
				continue;
			break;
		case LDAP_SCOPE_SUBTREE:
			if ( !dnIsSuffix( &e->e_nname, &nbase ))
				continue;
			break;
		case LDAP_SCOPE_SUBORDINATE:
			if ( dn_match( &nbase, &e->e_nname ) ||
				!dnIsSuffix( &e->e_nname, &nbase ))
				continue;
			break;
		}
		if ( !ludp->lud_filter )	/* there really should always be a filter */
			rc = LDAP_COMPARE_TRUE;
		else
			rc = test_filter( op, e, (Filter *)ludp->lud_filter );
		if ( rc == LDAP_COMPARE_TRUE )
			break;
	}
	return rc;
}

/* process the search responses */
static int
dynlist_search2resp( Operation *op, SlapReply *rs )
{
	dynlist_search_t *ds = op->o_callback->sc_private;
	dynlist_name_t *dyn;
	int rc;

	if ( rs->sr_type == REP_SEARCH && rs->sr_entry != NULL ) {
		/* See if this is one of our dynamic entries */
		dyn = tavl_find( ds->ds_names, &rs->sr_entry->e_nname, dynlist_avl_cmp );
		if ( dyn ) {
			Entry *e = rs->sr_entry;
			dyn->dy_seen = 1;
			rc = dynlist_prepare_entry( op, rs, dyn->dy_dli );
			if ( ds->ds_origfilter && test_filter( op, rs->sr_entry, ds->ds_origfilter ) != LDAP_COMPARE_TRUE ) {
				if ( e != rs->sr_entry )
					rs_flush_entry( op, rs, NULL );
				rc = LDAP_SUCCESS;
			}
			return rc;
		} else if ( ds->ds_memberOf ) {
			TAvlnode *ptr;
			Entry *e = rs->sr_entry;
			/* See if there are any memberOf values to attach to this entry */
			for ( ptr = tavl_end( ds->ds_names, TAVL_DIR_LEFT ); ptr;
				ptr = tavl_next( ptr, TAVL_DIR_RIGHT )) {
				dynlist_map_t *dlm;
				dyn = ptr->avl_data;
				for ( dlm = dyn->dy_dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
					if ( dlm->dlm_memberOf_ad ) {
						if ( dynlist_testurl( op, dyn, e ) == LDAP_COMPARE_TRUE ) {
							/* ensure e is modifiable, but do not replace
							 * sr_entry yet since we have pointers into it */
							if ( !( rs->sr_flags & REP_ENTRY_MODIFIABLE ) && e == rs->sr_entry ) {
								e = entry_dup( rs->sr_entry );
							}
							attr_merge_one( e, dlm->dlm_memberOf_ad, &dyn->dy_name, &dyn->dy_name );
							break;
						}
					}
				}
			}
			if ( e != rs->sr_entry ) {
				rs_replace_entry( op, rs, (slap_overinst *)op->o_bd->bd_info, e );
				rs->sr_flags |= REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED;
			}
			if ( ds->ds_origfilter && test_filter( op, rs->sr_entry, ds->ds_origfilter ) != LDAP_COMPARE_TRUE ) {
				rs_flush_entry( op, rs, NULL );
				return LDAP_SUCCESS;
			}
		}
	} else if ( rs->sr_type == REP_RESULT && rs->sr_err == LDAP_SUCCESS ) {
		TAvlnode *ptr;
		SlapReply r = *rs;
		/* Check for any unexpanded dynamic group entries that weren't picked up
		 * by the original search filter.
		 */
		for ( ptr = tavl_end( ds->ds_names, TAVL_DIR_LEFT ); ptr;
			ptr = tavl_next( ptr, TAVL_DIR_RIGHT )) {
			dyn = ptr->avl_data;
			if ( dyn->dy_seen )
				continue;
			if ( !dnIsSuffixScope( &dyn->dy_name, &op->o_req_ndn, op->ors_scope ))
				continue;
			if ( overlay_entry_get_ov( op, &dyn->dy_name, NULL, NULL, 0, &r.sr_entry, (slap_overinst *)op->o_bd->bd_info ) != LDAP_SUCCESS ||
				r.sr_entry == NULL )
				continue;
			r.sr_flags = REP_ENTRY_MUSTRELEASE;
			dynlist_prepare_entry( op, &r, dyn->dy_dli );
			if ( test_filter( op, r.sr_entry, op->ors_filter ) == LDAP_COMPARE_TRUE ) {
				r.sr_attrs = op->ors_attrs;
				rs->sr_err = send_search_entry( op, &r );
				if ( rs->sr_err != LDAP_SUCCESS )
					break;
			} else {
				rs_flush_entry( op, &r, NULL );
			}
		}
		rs->sr_nentries = r.sr_nentries;
	}
	return SLAP_CB_CONTINUE;
}

static void
dynlist_fix_filter( Operation *op, AttributeDescription *ad, dynlist_search_t *ds )
{
	Filter *f;
	f = dynlist_filter_dup( op, op->ors_filter, ad, ds->ds_dli->dli_ad );
	if ( ds->ds_origfilter ) {
		dynlist_filter_free( op, op->ors_filter );
		op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	} else {
		ds->ds_origfilter = op->ors_filter;
		ds->ds_origfilterbv = op->ors_filterstr;
	}
	op->ors_filter = f;
	filter2bv_x( op, f, &op->ors_filterstr );
}

static int
dynlist_search( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_gen_t	*dlg = (dynlist_gen_t *)on->on_bi.bi_private;
	dynlist_info_t	*dli;
	Operation o = *op;
	dynlist_map_t *dlm;
	Filter f;
	AttributeAssertion ava;
	AttributeName an[2] = {0};

	slap_callback *sc;
	dynlist_search_t *ds;

	if ( get_manageDSAit( op ) )
		return SLAP_CB_CONTINUE;

	sc = op->o_tmpcalloc( 1, sizeof(slap_callback)+sizeof(dynlist_search_t), op->o_tmpmemctx );
	sc->sc_private = (void *)(sc+1);
	ds = sc->sc_private;
	ds->ds_memberOf = 0;

	f.f_choice = LDAP_FILTER_EQUALITY;
	f.f_ava = &ava;
	f.f_av_desc = slap_schema.si_ad_objectClass;
	f.f_next = NULL;
	o.o_managedsait = SLAP_CONTROL_CRITICAL;

	/* Are we using memberOf, and does it affect this request? */
	if ( dlg->dlg_memberOf ) {
		int attrflags = slap_attr_flags( op->ors_attrs );
		int opattrs = SLAP_OPATTRS( attrflags );
		int userattrs = SLAP_USERATTRS( attrflags );

		for ( dli = dlg->dlg_dli; dli; dli = dli->dli_next ) {
			for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
				if ( dlm->dlm_memberOf_ad ) {
					/* if attribute is in filter, fix it */
					if ( ad_infilter( dlm->dlm_memberOf_ad, op->ors_filter )) {
						ds->ds_dli = dli;
						dynlist_fix_filter( op, dlm->dlm_memberOf_ad, ds );
					}

					/* if attribute is not requested, skip it */
					if ( op->ors_attrs == NULL ) {
						if ( is_at_operational( dlm->dlm_memberOf_ad->ad_type ) ) {
							continue;
						}
					} else {
						if ( is_at_operational( dlm->dlm_memberOf_ad->ad_type ) ) {
							if ( !opattrs && !ad_inlist( dlm->dlm_memberOf_ad, op->ors_attrs ) )
							{
								continue;
							}
						} else {
							if ( !userattrs && !ad_inlist( dlm->dlm_memberOf_ad, op->ors_attrs ) )
							{
								continue;
							}
						}
					}
					ds->ds_memberOf = 1;
				}
			}
		}
	}

	/* Find all dyngroups in scope. For group expansion
	 * we only need the groups within the search scope, but
	 * for memberOf populating, we need all dyngroups.
	 */
	for ( dli = dlg->dlg_dli; dli != NULL; dli = dli->dli_next ) {
		if ( o.o_callback != sc ) {
			o.o_callback = sc;
			o.ors_filter = &f;
			if ( ds->ds_memberOf ) {
				o.o_req_dn = op->o_bd->be_suffix[0];
				o.o_req_ndn = op->o_bd->be_nsuffix[0];
				o.ors_scope = LDAP_SCOPE_SUBTREE;
			} else {
				o.o_req_dn = op->o_req_dn;
				o.o_req_ndn = op->o_req_ndn;
				o.ors_scope = op->ors_scope;
			}
			o.ors_attrsonly = 0;
			o.ors_attrs = an;
			o.o_bd = select_backend( op->o_bd->be_nsuffix, 1 );
			BER_BVZERO( &o.ors_filterstr );
			sc->sc_response = dynlist_search1resp;
		}
		ds->ds_dli = dli;
		f.f_av_value = dli->dli_oc->soc_cname;
		if ( o.ors_filterstr.bv_val )
			o.o_tmpfree( o.ors_filterstr.bv_val, o.o_tmpmemctx );
		filter2bv_x( &o, &f, &o.ors_filterstr );
		an[0].an_desc = dli->dli_ad;
		an[0].an_name = dli->dli_ad->ad_cname;
		{
			SlapReply	r = { REP_SEARCH };
			(void)o.o_bd->be_search( &o, &r );
		}
	}

	if ( ds->ds_names != NULL ) {
		sc->sc_response = dynlist_search2resp;
		sc->sc_cleanup = dynlist_search_cleanup;
		sc->sc_next = op->o_callback;
		op->o_callback = sc;
	} else {
		op->o_tmpfree( sc, op->o_tmpmemctx );
	}
	return SLAP_CB_CONTINUE;
}

static int
dynlist_build_def_filter( dynlist_info_t *dli )
{
	char	*ptr;

	dli->dli_default_filter.bv_len = STRLENOF( "(!(objectClass=" "))" )
		+ dli->dli_oc->soc_cname.bv_len;
	dli->dli_default_filter.bv_val = ch_malloc( dli->dli_default_filter.bv_len + 1 );
	if ( dli->dli_default_filter.bv_val == NULL ) {
		Debug( LDAP_DEBUG_ANY, "dynlist_db_open: malloc failed.\n" );
		return -1;
	}

	ptr = lutil_strcopy( dli->dli_default_filter.bv_val, "(!(objectClass=" );
	ptr = lutil_strcopy( ptr, dli->dli_oc->soc_cname.bv_val );
	ptr = lutil_strcopy( ptr, "))" );

	assert( ptr == &dli->dli_default_filter.bv_val[dli->dli_default_filter.bv_len] );

	return 0;
}

enum {
	DL_ATTRSET = 1,
	DL_ATTRPAIR,
	DL_ATTRPAIR_COMPAT,
	DL_LAST
};

static ConfigDriver	dl_cfgen;

/* XXXmanu 255 is the maximum arguments we allow. Can we go beyond? */
static ConfigTable dlcfg[] = {
	{ "dynlist-attrset", "group-oc> [uri] <URL-ad> <[mapped:]member-ad> [...]",
		3, 0, 0, ARG_MAGIC|DL_ATTRSET, dl_cfgen,
		"( OLcfgOvAt:8.1 NAME 'olcDlAttrSet' "
			"DESC 'Dynamic list: <group objectClass>, <URL attributeDescription>, <member attributeDescription>' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )",
			NULL, NULL },
	{ "dynlist-attrpair", "member-ad> <URL-ad",
		3, 3, 0, ARG_MAGIC|DL_ATTRPAIR, dl_cfgen,
			NULL, NULL, NULL },
#ifdef TAKEOVER_DYNGROUP
	{ "attrpair", "member-ad> <URL-ad",
		3, 3, 0, ARG_MAGIC|DL_ATTRPAIR_COMPAT, dl_cfgen,
			NULL, NULL, NULL },
#endif
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs dlocs[] = {
	{ "( OLcfgOvOc:8.1 "
		"NAME 'olcDynamicList' "
		"DESC 'Dynamic list configuration' "
		"SUP olcOverlayConfig "
		"MAY olcDLattrSet )",
		Cft_Overlay, dlcfg, NULL, NULL },
	{ NULL, 0, NULL }
};

static int
dl_cfgen( ConfigArgs *c )
{
	slap_overinst	*on = (slap_overinst *)c->bi;
	dynlist_gen_t	*dlg = (dynlist_gen_t *)on->on_bi.bi_private;
	dynlist_info_t	*dli = dlg->dlg_dli;

	int		rc = 0, i;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
		case DL_ATTRSET:
			for ( i = 0; dli; i++, dli = dli->dli_next ) {
				struct berval	bv;
				char		*ptr = c->cr_msg;
				dynlist_map_t	*dlm;

				assert( dli->dli_oc != NULL );
				assert( dli->dli_ad != NULL );

				/* FIXME: check buffer overflow! */
				ptr += snprintf( c->cr_msg, sizeof( c->cr_msg ),
					SLAP_X_ORDERED_FMT "%s", i,
					dli->dli_oc->soc_cname.bv_val );

				if ( !BER_BVISNULL( &dli->dli_uri ) ) {
					*ptr++ = ' ';
					*ptr++ = '"';
					ptr = lutil_strncopy( ptr, dli->dli_uri.bv_val,
						dli->dli_uri.bv_len );
					*ptr++ = '"';
				}

				*ptr++ = ' ';
				ptr = lutil_strncopy( ptr, dli->dli_ad->ad_cname.bv_val,
					dli->dli_ad->ad_cname.bv_len );

				for ( dlm = dli->dli_dlm; dlm; dlm = dlm->dlm_next ) {
					ptr[ 0 ] = ' ';
					ptr++;
					if ( dlm->dlm_mapped_ad ) {
						ptr = lutil_strcopy( ptr, dlm->dlm_mapped_ad->ad_cname.bv_val );
						ptr[ 0 ] = ':';
						ptr++;
					}
						
					ptr = lutil_strcopy( ptr, dlm->dlm_member_ad->ad_cname.bv_val );

					if ( dlm->dlm_memberOf_ad ) {
						*ptr++ = '@';
						ptr = lutil_strcopy( ptr, dlm->dlm_memberOf_ad->ad_cname.bv_val );
					}
				}

				bv.bv_val = c->cr_msg;
				bv.bv_len = ptr - bv.bv_val;
				value_add_one( &c->rvalue_vals, &bv );
			}
			break;

		case DL_ATTRPAIR_COMPAT:
		case DL_ATTRPAIR:
			rc = 1;
			break;

		default:
			rc = 1;
			break;
		}

		return rc;

	} else if ( c->op == LDAP_MOD_DELETE ) {
		switch( c->type ) {
		case DL_ATTRSET:
			if ( c->valx < 0 ) {
				dynlist_info_t	*dli_next;

				for ( dli_next = dli; dli_next; dli = dli_next ) {
					dynlist_map_t *dlm = dli->dli_dlm;
					dynlist_map_t *dlm_next;

					dli_next = dli->dli_next;

					if ( !BER_BVISNULL( &dli->dli_uri ) ) {
						ch_free( dli->dli_uri.bv_val );
					}

					if ( dli->dli_lud != NULL ) {
						ldap_free_urldesc( dli->dli_lud );
					}

					if ( !BER_BVISNULL( &dli->dli_uri_nbase ) ) {
						ber_memfree( dli->dli_uri_nbase.bv_val );
					}

					if ( dli->dli_uri_filter != NULL ) {
						filter_free( dli->dli_uri_filter );
					}

					ch_free( dli->dli_default_filter.bv_val );

					while ( dlm != NULL ) {
						dlm_next = dlm->dlm_next;
						ch_free( dlm );
						dlm = dlm_next;
					}
					ch_free( dli );
				}

				dlg->dlg_dli = NULL;
				dlg->dlg_memberOf = 0;

			} else {
				dynlist_info_t	**dlip;
				dynlist_map_t *dlm;
				dynlist_map_t *dlm_next;

				for ( i = 0, dlip = (dynlist_info_t **)&dlg->dlg_dli;
					i < c->valx; i++ )
				{
					if ( *dlip == NULL ) {
						return 1;
					}
					dlip = &(*dlip)->dli_next;
				}

				dli = *dlip;
				*dlip = dli->dli_next;

				if ( !BER_BVISNULL( &dli->dli_uri ) ) {
					ch_free( dli->dli_uri.bv_val );
				}

				if ( dli->dli_lud != NULL ) {
					ldap_free_urldesc( dli->dli_lud );
				}

				if ( !BER_BVISNULL( &dli->dli_uri_nbase ) ) {
					ber_memfree( dli->dli_uri_nbase.bv_val );
				}

				if ( dli->dli_uri_filter != NULL ) {
					filter_free( dli->dli_uri_filter );
				}

				ch_free( dli->dli_default_filter.bv_val );

				dlm = dli->dli_dlm;
				while ( dlm != NULL ) {
					dlm_next = dlm->dlm_next;
					if ( dlm->dlm_memberOf_ad )
						dlg->dlg_memberOf--;
					ch_free( dlm );
					dlm = dlm_next;
				}
				ch_free( dli );

				dli = (dynlist_info_t *)dlg->dlg_dli;
			}
			break;

		case DL_ATTRPAIR_COMPAT:
		case DL_ATTRPAIR:
			rc = 1;
			break;

		default:
			rc = 1;
			break;
		}

		return rc;
	}

	switch( c->type ) {
	case DL_ATTRSET: {
		dynlist_info_t		**dlip,
					*dli_next = NULL;
		ObjectClass		*oc = NULL;
		AttributeDescription	*ad = NULL;
		int			attridx = 2;
		LDAPURLDesc		*lud = NULL;
		struct berval		nbase = BER_BVNULL;
		Filter			*filter = NULL;
		struct berval		uri = BER_BVNULL;
		dynlist_map_t           *dlm = NULL, *dlml = NULL;
		const char		*text;

		oc = oc_find( c->argv[ 1 ] );
		if ( oc == NULL ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
				"unable to find ObjectClass \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			return 1;
		}

		if ( strncasecmp( c->argv[ attridx ], "ldap://", STRLENOF("ldap://") ) == 0 ) {
			if ( ldap_url_parse( c->argv[ attridx ], &lud ) != LDAP_URL_SUCCESS ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
					"unable to parse URI \"%s\"",
					c->argv[ attridx ] );
				rc = 1;
				goto done_uri;
			}

			if ( lud->lud_host != NULL ) {
				if ( lud->lud_host[0] == '\0' ) {
					ch_free( lud->lud_host );
					lud->lud_host = NULL;

				} else {
					snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
						"host not allowed in URI \"%s\"",
						c->argv[ attridx ] );
					rc = 1;
					goto done_uri;
				}
			}

			if ( lud->lud_attrs != NULL ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
					"attrs not allowed in URI \"%s\"",
					c->argv[ attridx ] );
				rc = 1;
				goto done_uri;
			}

			if ( lud->lud_exts != NULL ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
					"extensions not allowed in URI \"%s\"",
					c->argv[ attridx ] );
				rc = 1;
				goto done_uri;
			}

			if ( lud->lud_dn != NULL && lud->lud_dn[ 0 ] != '\0' ) {
				struct berval dn;
				ber_str2bv( lud->lud_dn, 0, 0, &dn );
				rc = dnNormalize( 0, NULL, NULL, &dn, &nbase, NULL );
				if ( rc != LDAP_SUCCESS ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
						"DN normalization failed in URI \"%s\"",
						c->argv[ attridx ] );
					goto done_uri;
				}
			}

			if ( lud->lud_filter != NULL && lud->lud_filter[ 0 ] != '\0' ) {
				filter = str2filter( lud->lud_filter );
				if ( filter == NULL ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
						"filter parsing failed in URI \"%s\"",
						c->argv[ attridx ] );
					rc = 1;
					goto done_uri;
				}
			}

			ber_str2bv( c->argv[ attridx ], 0, 1, &uri );

done_uri:;
			if ( rc ) {
				if ( lud ) {
					ldap_free_urldesc( lud );
				}

				if ( !BER_BVISNULL( &nbase ) ) {
					ber_memfree( nbase.bv_val );
				}

				if ( filter != NULL ) {
					filter_free( filter );
				}

				while ( dlm != NULL ) {
					dlml = dlm;
					dlm = dlm->dlm_next;
					ch_free( dlml );
				}

				Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
					c->log, c->cr_msg );

				return rc;
			}

			attridx++;
		}

		rc = slap_str2ad( c->argv[ attridx ], &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
				"unable to find AttributeDescription \"%s\"",
				c->argv[ attridx ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			rc = 1;
			goto done_uri;
		}

		if ( !is_at_subtype( ad->ad_type, slap_schema.si_ad_labeledURI->ad_type ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ), DYNLIST_USAGE
				"AttributeDescription \"%s\" "
				"must be a subtype of \"labeledURI\"",
				c->argv[ attridx ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			rc = 1;
			goto done_uri;
		}

		attridx++;

		for ( i = attridx; i < c->argc; i++ ) {
			char *arg; 
			char *cp;
			AttributeDescription *member_ad = NULL;
			AttributeDescription *mapped_ad = NULL;
			AttributeDescription *memberOf_ad = NULL;
			dynlist_map_t *dlmp;


			/*
			 * If no mapped attribute is given, dn is used 
			 * for backward compatibility.
			 */
			arg = c->argv[i];
			if ( ( cp = strchr( arg, ':' ) ) != NULL ) {
				struct berval bv;
				ber_str2bv( arg, cp - arg, 0, &bv );
				rc = slap_bv2ad( &bv, &mapped_ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						DYNLIST_USAGE
						"unable to find mapped AttributeDescription #%d \"%s\"\n",
						i - 3, c->argv[ i ] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
						c->log, c->cr_msg );
					rc = 1;
					goto done_uri;
				}
				arg = cp + 1;
			}
			if ( ( cp = strchr( arg, '@' ) ) != NULL ) {
				struct berval bv;
				ber_str2bv( cp+1, 0, 0, &bv );
				rc = slap_bv2ad( &bv, &memberOf_ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						DYNLIST_USAGE
						"unable to find memberOf AttributeDescription #%d \"%s\"\n",
						i - 3, c->argv[ i ] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
						c->log, c->cr_msg );
					rc = 1;
					goto done_uri;
				}
				dlg->dlg_memberOf++;
				*cp = '\0';
			}

			rc = slap_str2ad( arg, &member_ad, &text );
			if ( rc != LDAP_SUCCESS ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					DYNLIST_USAGE
					"unable to find AttributeDescription #%d \"%s\"\n",
					i - 3, c->argv[ i ] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
					c->log, c->cr_msg );
				rc = 1;
				goto done_uri;
			}

			dlmp = (dynlist_map_t *)ch_calloc( 1, sizeof( dynlist_map_t ) );
			if ( dlm == NULL ) {
				dlm = dlmp;
			}
			dlmp->dlm_member_ad = member_ad;
			dlmp->dlm_mapped_ad = mapped_ad;
			dlmp->dlm_memberOf_ad = memberOf_ad;
			dlmp->dlm_next = NULL;
		
			if ( dlml != NULL ) 
				dlml->dlm_next = dlmp;
			dlml = dlmp;
		}

		if ( c->valx > 0 ) {
			int	i;

			for ( i = 0, dlip = (dynlist_info_t **)&dlg->dlg_dli;
				i < c->valx; i++ )
			{
				if ( *dlip == NULL ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						DYNLIST_USAGE
						"invalid index {%d}\n",
						c->valx );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
						c->log, c->cr_msg );
					rc = 1;
					goto done_uri;
				}
				dlip = &(*dlip)->dli_next;
			}
			dli_next = *dlip;

		} else {
			for ( dlip = (dynlist_info_t **)&dlg->dlg_dli;
				*dlip; dlip = &(*dlip)->dli_next )
				/* goto last */;
		}

		*dlip = (dynlist_info_t *)ch_calloc( 1, sizeof( dynlist_info_t ) );

		(*dlip)->dli_oc = oc;
		(*dlip)->dli_ad = ad;
		(*dlip)->dli_dlm = dlm;
		(*dlip)->dli_next = dli_next;

		(*dlip)->dli_lud = lud;
		(*dlip)->dli_uri_nbase = nbase;
		(*dlip)->dli_uri_filter = filter;
		(*dlip)->dli_uri = uri;

		rc = dynlist_build_def_filter( *dlip );

		} break;

	case DL_ATTRPAIR_COMPAT:
		snprintf( c->cr_msg, sizeof( c->cr_msg ),
			"warning: \"attrpair\" only supported for limited "
			"backward compatibility with overlay \"dyngroup\"" );
		Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg );
		/* fallthru */

	case DL_ATTRPAIR: {
		dynlist_info_t		**dlip;
		ObjectClass		*oc = NULL;
		AttributeDescription	*ad = NULL,
					*member_ad = NULL;
		const char		*text;

		oc = oc_find( "groupOfURLs" );
		if ( oc == NULL ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"dynlist-attrpair <member-ad> <URL-ad>\": "
				"unable to find default ObjectClass \"groupOfURLs\"" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			return 1;
		}

		rc = slap_str2ad( c->argv[ 1 ], &member_ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"dynlist-attrpair <member-ad> <URL-ad>\": "
				"unable to find AttributeDescription \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			return 1;
		}

		rc = slap_str2ad( c->argv[ 2 ], &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"dynlist-attrpair <member-ad> <URL-ad>\": "
				"unable to find AttributeDescription \"%s\"\n",
				c->argv[ 2 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			return 1;
		}

		if ( !is_at_subtype( ad->ad_type, slap_schema.si_ad_labeledURI->ad_type ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				DYNLIST_USAGE
				"AttributeDescription \"%s\" "
				"must be a subtype of \"labeledURI\"",
				c->argv[ 2 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
				c->log, c->cr_msg );
			return 1;
		}

		for ( dlip = (dynlist_info_t **)&dlg->dlg_dli;
			*dlip; dlip = &(*dlip)->dli_next )
		{
			/* 
			 * The same URL attribute / member attribute pair
			 * cannot be repeated, but we enforce this only 
			 * when the member attribute is unique. Performing
			 * the check for multiple values would require
			 * sorting and comparing the lists, which is left
			 * as a future improvement
			 */
			if ( (*dlip)->dli_ad == ad &&
			     (*dlip)->dli_dlm->dlm_next == NULL &&
			     member_ad == (*dlip)->dli_dlm->dlm_member_ad ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"\"dynlist-attrpair <member-ad> <URL-ad>\": "
					"URL attributeDescription \"%s\" already mapped.\n",
					ad->ad_cname.bv_val );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n",
					c->log, c->cr_msg );
#if 0
				/* make it a warning... */
				return 1;
#endif
			}
		}

		*dlip = (dynlist_info_t *)ch_calloc( 1, sizeof( dynlist_info_t ) );

		(*dlip)->dli_oc = oc;
		(*dlip)->dli_ad = ad;
		(*dlip)->dli_dlm = (dynlist_map_t *)ch_calloc( 1, sizeof( dynlist_map_t ) );
		(*dlip)->dli_dlm->dlm_member_ad = member_ad;
		(*dlip)->dli_dlm->dlm_mapped_ad = NULL;

		rc = dynlist_build_def_filter( *dlip );

		} break;

	default:
		rc = 1;
		break;
	}

	return rc;
}

static int
dynlist_db_init(
	BackendDB *be,
	ConfigReply *cr)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	dynlist_gen_t *dlg;

	dlg = (dynlist_gen_t *)ch_malloc( sizeof( *dlg ));
	on->on_bi.bi_private = dlg;
	dlg->dlg_dli = NULL;
	dlg->dlg_memberOf = 0;

	return 0;
}

static int
dynlist_db_open(
	BackendDB	*be,
	ConfigReply	*cr )
{
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	dynlist_gen_t		*dlg = (dynlist_gen_t *)on->on_bi.bi_private;
	dynlist_info_t		*dli = dlg->dlg_dli;
	ObjectClass		*oc = NULL;
	AttributeDescription	*ad = NULL;
	const char	*text;
	int rc;

	if ( dli == NULL ) {
		dli = ch_calloc( 1, sizeof( dynlist_info_t ) );
		dlg->dlg_dli = dli;
	}

	for ( ; dli; dli = dli->dli_next ) {
		if ( dli->dli_oc == NULL ) {
			if ( oc == NULL ) {
				oc = oc_find( "groupOfURLs" );
				if ( oc == NULL ) {
					snprintf( cr->msg, sizeof( cr->msg),
						"unable to fetch objectClass \"groupOfURLs\"" );
					Debug( LDAP_DEBUG_ANY, "dynlist_db_open: %s.\n", cr->msg );
					return 1;
				}
			}

			dli->dli_oc = oc;
		}

		if ( dli->dli_ad == NULL ) {
			if ( ad == NULL ) {
				rc = slap_str2ad( "memberURL", &ad, &text );
				if ( rc != LDAP_SUCCESS ) {
					snprintf( cr->msg, sizeof( cr->msg),
						"unable to fetch attributeDescription \"memberURL\": %d (%s)",
						rc, text );
					Debug( LDAP_DEBUG_ANY, "dynlist_db_open: %s.\n", cr->msg );
					return 1;
				}
			}
		
			dli->dli_ad = ad;			
		}

		if ( BER_BVISNULL( &dli->dli_default_filter ) ) {
			rc = dynlist_build_def_filter( dli );
			if ( rc != 0 ) {
				return rc;
			}
		}
	}

	if ( ad_dgIdentity == NULL ) {
		rc = slap_str2ad( "dgIdentity", &ad_dgIdentity, &text );
		if ( rc != LDAP_SUCCESS ) {
			snprintf( cr->msg, sizeof( cr->msg),
				"unable to fetch attributeDescription \"dgIdentity\": %d (%s)",
				rc, text );
			Debug( LDAP_DEBUG_ANY, "dynlist_db_open: %s\n", cr->msg );
			/* Just a warning */
		}
	}

	if ( ad_dgAuthz == NULL ) {
		rc = slap_str2ad( "dgAuthz", &ad_dgAuthz, &text );
		if ( rc != LDAP_SUCCESS ) {
			snprintf( cr->msg, sizeof( cr->msg),
				"unable to fetch attributeDescription \"dgAuthz\": %d (%s)",
				rc, text );
			Debug( LDAP_DEBUG_ANY, "dynlist_db_open: %s\n", cr->msg );
			/* Just a warning */
		}
	}

	return 0;
}

static int
dynlist_db_destroy(
	BackendDB	*be,
	ConfigReply	*cr )
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;

	if ( on->on_bi.bi_private ) {
		dynlist_gen_t	*dlg = (dynlist_gen_t *)on->on_bi.bi_private;
		dynlist_info_t	*dli = dlg->dlg_dli,
				*dli_next;

		for ( dli_next = dli; dli_next; dli = dli_next ) {
			dynlist_map_t *dlm;
			dynlist_map_t *dlm_next;

			dli_next = dli->dli_next;

			if ( !BER_BVISNULL( &dli->dli_uri ) ) {
				ch_free( dli->dli_uri.bv_val );
			}

			if ( dli->dli_lud != NULL ) {
				ldap_free_urldesc( dli->dli_lud );
			}

			if ( !BER_BVISNULL( &dli->dli_uri_nbase ) ) {
				ber_memfree( dli->dli_uri_nbase.bv_val );
			}

			if ( dli->dli_uri_filter != NULL ) {
				filter_free( dli->dli_uri_filter );
			}

			ch_free( dli->dli_default_filter.bv_val );

			dlm = dli->dli_dlm;
			while ( dlm != NULL ) {
				dlm_next = dlm->dlm_next;
				ch_free( dlm );
				dlm = dlm_next;
			}
			ch_free( dli );
		}
		ch_free( dlg );
	}

	return 0;
}

static slap_overinst	dynlist = { { NULL } };
#ifdef TAKEOVER_DYNGROUP
static char		*obsolete_names[] = {
	"dyngroup",
	NULL
};
#endif

#if SLAPD_OVER_DYNLIST == SLAPD_MOD_DYNAMIC
static
#endif /* SLAPD_OVER_DYNLIST == SLAPD_MOD_DYNAMIC */
int
dynlist_initialize(void)
{
	int	rc = 0;

	dynlist.on_bi.bi_type = "dynlist";

#ifdef TAKEOVER_DYNGROUP
	/* makes dynlist incompatible with dyngroup */
	dynlist.on_bi.bi_obsolete_names = obsolete_names;
#endif

	dynlist.on_bi.bi_db_init = dynlist_db_init;
	dynlist.on_bi.bi_db_config = config_generic_wrapper;
	dynlist.on_bi.bi_db_open = dynlist_db_open;
	dynlist.on_bi.bi_db_destroy = dynlist_db_destroy;

	dynlist.on_bi.bi_op_search = dynlist_search;
	dynlist.on_bi.bi_op_compare = dynlist_compare;

	dynlist.on_bi.bi_cf_ocs = dlocs;

	rc = config_register_schema( dlcfg, dlocs );
	if ( rc ) {
		return rc;
	}

	return overlay_register( &dynlist );
}

#if SLAPD_OVER_DYNLIST == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return dynlist_initialize();
}
#endif

#endif /* SLAPD_OVER_DYNLIST */
