/* dynlist.c - dynamic list overlay */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2005 The OpenLDAP Foundation.
 * Portions Copyright 2004-2005 Pierangelo Masarati.
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

#include <stdio.h>

#include <ac/string.h>

#include "slap.h"
#include "lutil.h"

/* FIXME: the code differs if SLAP_OPATTRS is defined or not;
 * SLAP_OPATTRS is not defined in 2.2 yet, while this overlay
 * expects HEAD code at least later than August 6, 2004. */
/* FIXME: slap_anlist_no_attrs was introduced in 2.3; here it
 * is anticipated to allow using this overlay with 2.2. */

#if LDAP_VENDOR_VERSION_MINOR != X && LDAP_VENDOR_VERSION_MINOR < 3
static AttributeName anlist_no_attrs[] = {
	{ BER_BVC( LDAP_NO_ATTRS ), NULL, 0, NULL },
	{ BER_BVNULL, NULL, 0, NULL }
};

static AttributeName *slap_anlist_no_attrs = anlist_no_attrs;
#endif

typedef struct dynlist_info {
	ObjectClass		*dli_oc;
	AttributeDescription	*dli_ad;
	AttributeDescription	*dli_member_ad;
	struct berval		dli_default_filter;
} dynlist_info;

static int
dynlist_is_dynlist( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

	Attribute	*a;

	a = attrs_find( rs->sr_entry->e_attrs, slap_schema.si_ad_objectClass );
	if ( a == NULL ) {
		/* FIXME: objectClass must be present; for non-storage
		 * backends, like back-ldap, it needs to be added
		 * to the requested attributes */
		return 0;
	}

	if ( value_find_ex( slap_schema.si_ad_objectClass, 
			SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
			SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
			a->a_nvals, &dli->dli_oc->soc_cname,
			op->o_tmpmemctx ) == 0 )
	{
		return 1;
	}

	return 0;
}

static int
dynlist_make_filter( Operation *op, struct berval *oldf, struct berval *newf )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

	char		*ptr;

	assert( oldf != NULL );
	assert( newf != NULL );
	assert( !BER_BVISNULL( oldf ) );
	assert( !BER_BVISEMPTY( oldf ) );

	newf->bv_len = STRLENOF( "(&(!(objectClass=" "))" ")" )
		+ dli->dli_oc->soc_cname.bv_len + oldf->bv_len;
	newf->bv_val = op->o_tmpalloc( newf->bv_len + 1, op->o_tmpmemctx );
	if ( newf->bv_val == NULL ) {
		return -1;
	}
	ptr = lutil_strcopy( newf->bv_val, "(&(!(objectClass=" );
	ptr = lutil_strcopy( ptr, dli->dli_oc->soc_cname.bv_val );
	ptr = lutil_strcopy( ptr, "))" );
	ptr = lutil_strcopy( ptr, oldf->bv_val );
	ptr = lutil_strcopy( ptr, ")" );
	newf->bv_len = ptr - newf->bv_val;

	return 0;
}

typedef struct dynlist_sc_t {
	dynlist_info    *dlc_dli;
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

	if ( dlc->dlc_dli->dli_member_ad ) {

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
			mod.sm_desc = dlc->dlc_dli->dli_member_ad;
			mod.sm_type = dlc->dlc_dli->dli_member_ad->ad_cname;
			mod.sm_values = vals;
			mod.sm_nvalues = nvals;

			(void)modify_add_values( e, &mod, /* permissive */ 1,
					&text, textbuf, sizeof( textbuf ) );
		}

		goto done;
	}

#ifndef SLAP_OPATTRS
	opattrs = ( rs->sr_attrs == NULL ) ? 0 : an_find( rs->sr_attrs, &AllOper );
	userattrs = ( rs->sr_attrs == NULL ) ? 1 : an_find( rs->sr_attrs, &AllUser );
#else /* SLAP_OPATTRS */
	opattrs = SLAP_OPATTRS( rs->sr_attr_flags );
	userattrs = SLAP_USERATTRS( rs->sr_attr_flags );
#endif /* SLAP_OPATTRS */

	for ( a = rs->sr_entry->e_attrs; a != NULL; a = a->a_next ) {
		BerVarray	vals, nvals = NULL;
		int		i, j;

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
		for ( i = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ )
			/* just count */ ;

		vals = op->o_tmpalloc( ( i + 1 ) * sizeof( struct berval ), op->o_tmpmemctx );
		if ( a->a_nvals != a->a_vals ) {
			nvals = op->o_tmpalloc( ( i + 1 ) * sizeof( struct berval ), op->o_tmpmemctx );
		}

		for ( i = 0, j = 0; !BER_BVISNULL( &a->a_vals[i] ); i++ ) {
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

			BER_BVZERO( &vals[j] );
			if ( nvals ) {
				BER_BVZERO( &nvals[j] );
			}

			mod.sm_op = LDAP_MOD_ADD;
			mod.sm_desc = a->a_desc;
			mod.sm_type = a->a_desc->ad_cname;
			mod.sm_values = vals;
			mod.sm_nvalues = nvals;

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
	}

	return 0;
}
	
static int
dynlist_send_entry( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

	Attribute	*a;
	slap_callback	cb;
	Operation	o = *op;
	SlapReply	r = { REP_SEARCH };
	struct berval	*url;
	Entry		*e;
	slap_mask_t	e_flags;
	int		opattrs,
			userattrs;
	dynlist_sc_t	dlc = { 0 };

	a = attrs_find( rs->sr_entry->e_attrs, dli->dli_ad );
	if ( a == NULL ) {
		/* FIXME: error? */
		return SLAP_CB_CONTINUE;
	}

	e = entry_dup( rs->sr_entry );
	e_flags = rs->sr_flags | ( REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED );

	dlc.dlc_e = e;
	dlc.dlc_dli = dli;
	cb.sc_private = &dlc;
	cb.sc_response = dynlist_sc_update;
	cb.sc_cleanup = NULL;
	cb.sc_next = NULL;

	o.o_callback = &cb;
	o.ors_deref = LDAP_DEREF_NEVER;
	o.ors_limit = NULL;
	o.ors_tlimit = SLAP_NO_LIMIT;
	o.ors_slimit = SLAP_NO_LIMIT;

#ifndef SLAP_OPATTRS
	opattrs = ( rs->sr_attrs == NULL ) ? 0 : an_find( rs->sr_attrs, &AllOper );
	userattrs = ( rs->sr_attrs == NULL ) ? 1 : an_find( rs->sr_attrs, &AllUser );
#else /* SLAP_OPATTRS */
	opattrs = SLAP_OPATTRS( rs->sr_attr_flags );
	userattrs = SLAP_USERATTRS( rs->sr_attr_flags );
#endif /* SLAP_OPATTRS */

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

		if ( lud->lud_host ) {
			/* FIXME: host not allowed; reject as illegal? */
			Debug( LDAP_DEBUG_ANY, "dynlist_send_entry(\"%s\"): "
				"illegal URI \"%s\"\n",
				e->e_name.bv_val, url->bv_val, 0 );
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

		if ( dli->dli_member_ad != NULL ) {
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

				if ( rs->sr_attrs == NULL ) {
					if ( o.ors_attrs[j].an_desc != NULL &&
							is_at_operational( o.ors_attrs[j].an_desc->ad_type ) )
					{
						continue;
					}

				} else {
					if ( o.ors_attrs[j].an_desc != NULL &&
							is_at_operational( o.ors_attrs[j].an_desc->ad_type ) )
					{
						if ( !opattrs && !ad_inlist( o.ors_attrs[j].an_desc, rs->sr_attrs ) )
						{
							continue;
						}

					} else {
						if ( !userattrs && 
								o.ors_attrs[j].an_desc != NULL &&
								!ad_inlist( o.ors_attrs[j].an_desc, rs->sr_attrs ) )
						{
							continue;
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
			if ( dynlist_make_filter( op, &flt, &o.ors_filterstr ) ) {
				/* error */
				goto cleanup;
			}
		}
		o.ors_filter = str2filter_x( op, o.ors_filterstr.bv_val );
		if ( o.ors_filter == NULL ) {
			goto cleanup;
		}
		
		o.o_bd = select_backend( &o.o_req_ndn, 0, 1 );
		if ( o.o_bd && o.o_bd->be_search ) {
#ifdef SLAP_OPATTRS
			r.sr_attr_flags = slap_attr_flags( o.ors_attrs );
#endif /* SLAP_OPATTRS */
			(void)o.o_bd->be_search( &o, &r );
		}

cleanup:;
		if ( o.ors_filter ) {
			filter_free_x( &o, o.ors_filter );
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
		if ( o.ors_filterstr.bv_val != lud->lud_filter ) {
			op->o_tmpfree( o.ors_filterstr.bv_val, op->o_tmpmemctx );
			lud->lud_filter = NULL;
		}
		if ( lud ) {
			ldap_free_urldesc( lud );
		}
	}

	rs->sr_entry = e;
	rs->sr_flags = e_flags;

	return SLAP_CB_CONTINUE;
}

static int
dynlist_sc_save_entry( Operation *op, SlapReply *rs )
{
	/* save the entry in the private field of the callback,
	 * so it doesn't get freed (it's temporary!) */
	if ( rs->sr_entry != NULL ) {
		dynlist_sc_t	*dlc = (dynlist_sc_t *)op->o_callback->sc_private;
		dlc->dlc_e = rs->sr_entry;
		rs->sr_entry = NULL;
	}

	return 0;
}

static int
dynlist_compare( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *)op->o_bd->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

	Attribute	*a;
	slap_callback	cb;
	Operation	o = *op;
	SlapReply	r = { REP_SEARCH };
	AttributeName	an[2];
	int		rc;
	dynlist_sc_t	dlc = { 0 };

	dlc.dlc_dli = dli;
	cb.sc_private = &dlc;
	cb.sc_response = dynlist_sc_save_entry;
	cb.sc_cleanup = NULL;
	cb.sc_next = NULL;
	o.o_callback = &cb;

	o.o_tag = LDAP_REQ_SEARCH;
	o.ors_limit = NULL;
	o.ors_tlimit = SLAP_NO_LIMIT;
	o.ors_slimit = SLAP_NO_LIMIT;

	o.o_bd = select_backend( &o.o_req_ndn, 0, 1 );
	if ( !o.o_bd || !o.o_bd->be_search ) {
		return SLAP_CB_CONTINUE;
	}

	BER_BVSTR( &o.ors_filterstr, "(objectClass=*)" );
	o.ors_filter = str2filter_x( op, o.ors_filterstr.bv_val );
	if ( o.ors_filter == NULL ) {
		/* FIXME: error? */
		return SLAP_CB_CONTINUE;
	}

	o.ors_scope = LDAP_SCOPE_BASE;
	o.ors_deref = LDAP_DEREF_NEVER;
	an[0].an_name = op->orc_ava->aa_desc->ad_cname;
	an[0].an_desc = op->orc_ava->aa_desc;
	BER_BVZERO( &an[1].an_name );
	o.ors_attrs = an;
	o.ors_attrsonly = 0;

	rc = o.o_bd->be_search( &o, &r );
	filter_free_x( &o, o.ors_filter );

	if ( rc != 0 ) {
		return rc;
	}

	if ( dlc.dlc_e != NULL ) {
		r.sr_entry = dlc.dlc_e;
	}

	if ( r.sr_err != LDAP_SUCCESS || r.sr_entry == NULL ) {
		/* error? */
		return SLAP_CB_CONTINUE;
	}

	/* if we're here, we got a match... */
	rs->sr_err = LDAP_COMPARE_FALSE;
	for ( a = attrs_find( r.sr_entry->e_attrs, op->orc_ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, op->orc_ava->aa_desc ) )
	{
		if ( value_find_ex( op->orc_ava->aa_desc,
			SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
				SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
			a->a_nvals, &op->orc_ava->aa_value, op->o_tmpmemctx ) == 0 )
		{
			rs->sr_err = LDAP_COMPARE_TRUE;
			break;
		}
	}

	if ( r.sr_flags & REP_ENTRY_MUSTBEFREED ) {
		entry_free( r.sr_entry );
	}

	return SLAP_CB_CONTINUE;
}

static int
dynlist_response( Operation *op, SlapReply *rs )
{
	switch ( op->o_tag ) {
	case LDAP_REQ_SEARCH:
		if ( rs->sr_type == REP_SEARCH && !get_manageDSAit( op ) )
		{
			if ( dynlist_is_dynlist( op, rs ) ) {
				return dynlist_send_entry( op, rs );
			}
		}
		break;

	case LDAP_REQ_COMPARE:
		if ( rs->sr_err == LDAP_NO_SUCH_ATTRIBUTE ) {
			return dynlist_compare( op, rs );
		}
		break;

	default:
		break;
	}

	return SLAP_CB_CONTINUE;
}

static int
dynlist_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

	int		rc = 0;

	if ( strcasecmp( argv[0], "dynlist-oc" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr, "dynlist-oc <oc>\n" );
			return 1;
		}
		dli->dli_oc = oc_find( argv[1] );
		if ( dli->dli_oc == NULL ) {
			fprintf( stderr, "dynlist-oc <oc>: "
					"unable to find ObjectClass "
					"\"%s\"\n", argv[1] );
			return 1;
		}

	} else if ( strcasecmp( argv[0], "dynlist-ad" ) == 0 ) {
		const char	*text;

		if ( argc != 2 ) {
			fprintf( stderr, "dynlist-ad <ad>\n" );
			return 1;
		}
		dli->dli_ad = NULL;
		rc = slap_str2ad( argv[1], &dli->dli_ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "dynlist-ad <ad>: "
					"unable to find AttributeDescription "
					"\"%s\"\n", argv[1] );
			return 1;
		}

	} else if ( strcasecmp( argv[0], "dynlist-member-ad" ) == 0 ) {
		const char	*text;

		if ( argc != 2 ) {
			fprintf( stderr, "dynlist-member-ad <ad>\n" );
			return 1;
		}
		dli->dli_member_ad = NULL;
		rc = slap_str2ad( argv[1], &dli->dli_member_ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "dynlist-member-ad <ad>: "
					"unable to find AttributeDescription "
					"\"%s\"\n", argv[1] );
			return 1;
		}

	} else {
		rc = SLAP_CONF_UNKNOWN;
	}

	return rc;
}

static int
dynlist_db_init(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	dynlist_info	*dli;

	dli = (dynlist_info *)ch_malloc( sizeof( dynlist_info ) );
	memset( dli, 0, sizeof( dynlist_info ) );

	on->on_bi.bi_private = (void *)dli;

	return 0;
}

static int
dynlist_db_open(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;
	ber_len_t	len;
	char		*ptr;

	if ( dli->dli_oc == NULL ) {
		fprintf( stderr, "dynlist_db_open(): missing \"dynlist-oc <ObjectClass>\"\n" );
		return -1;
	}

	if ( dli->dli_ad == NULL ) {
		fprintf( stderr, "dynlist_db_open(): missing \"dynlist-ad <AttributeDescription>\"\n" );
		return -1;
	}

	len = STRLENOF( "(!(objectClass=" "))" )
		+ dli->dli_oc->soc_cname.bv_len;
	dli->dli_default_filter.bv_val = SLAP_MALLOC( len + 1 );
	if ( dli->dli_default_filter.bv_val == NULL ) {
		fprintf( stderr, "dynlist_db_open(): malloc failed\n" );
		return -1;
	}
	ptr = lutil_strcopy( dli->dli_default_filter.bv_val, "(!(objectClass=" );
	ptr = lutil_strcopy( ptr, dli->dli_oc->soc_cname.bv_val );
	ptr = lutil_strcopy( ptr, "))" );
	dli->dli_default_filter.bv_len = ptr - dli->dli_default_filter.bv_val;

	return 0;
}

static int
dynlist_db_destroy(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	int		rc = 0;

	if ( on->on_bi.bi_private ) {
		dynlist_info	*dli = (dynlist_info *)on->on_bi.bi_private;

		dli->dli_oc = NULL;
		dli->dli_ad = NULL;

		ch_free( dli );
	}

	return rc;
}

static slap_overinst dynlist = { { NULL } };

int
dynlist_init(void)
{
	dynlist.on_bi.bi_type = "dynlist";
	dynlist.on_bi.bi_db_init = dynlist_db_init;
	dynlist.on_bi.bi_db_config = dynlist_db_config;
	dynlist.on_bi.bi_db_open = dynlist_db_open;
	dynlist.on_bi.bi_db_destroy = dynlist_db_destroy;

	dynlist.on_response = dynlist_response;

	return overlay_register( &dynlist );
}

#if SLAPD_OVER_DYNLIST == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return dynlist_init();
}
#endif

#endif /* SLAPD_OVER_DYNLIST */
