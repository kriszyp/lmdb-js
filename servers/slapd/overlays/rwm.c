/* rwm.c - rewrite/remap operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Portions Copyright 2003 Pierangelo Masarati.
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

#ifdef SLAPD_OVER_RWM

#include <stdio.h>

#include "slap.h"
#include "rwm.h"

static int
rwm_op_dn_massage( Operation *op, SlapReply *rs, void *cookie )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	struct berval		dn, ndn, mdn = BER_BVNULL;
	int			rc = 0;
	dncookie		dc;

	/*
	 * Rewrite the bind dn if needed
	 */
	dc.rwmap = rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = (char *)cookie;
#else
	dc.tofrom = ((int *)cookie)[0];
	dc.normalized = 0;
#endif

	rc = rwm_dn_massage( &dc, &op->o_req_dn, &mdn );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( mdn.bv_val == op->o_req_dn.bv_val ) {
		return LDAP_SUCCESS;
	}

	rc = dnPrettyNormal( NULL, &mdn, &dn, &ndn, op->o_tmpmemctx );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	if ( mdn.bv_val != dn.bv_val ) {
		ch_free( mdn.bv_val );
	}

	op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
	op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );

	op->o_req_dn = dn;
	op->o_req_ndn = ndn;

	return LDAP_SUCCESS;
}

static int
rwm_add( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	int			rc,
				i,
				isupdate;
	Attribute		**ap = NULL;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "addDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "addDn massage error" );
		return -1;
	}

	/* Count number of attributes in entry */ 
	isupdate = be_isupdate( op );
	for ( i = 0, ap = &op->oq_add.rs_e->e_attrs; *ap; ) {
		struct berval	mapped;
		Attribute	*a;

		if ( !isupdate && (*ap)->a_desc->ad_type->sat_no_user_mod ) {
			goto cleanup_attr;
		}

		rwm_map( &rwmap->rwm_at, &(*ap)->a_desc->ad_cname,
				&mapped, RWM_MAP );
		if ( mapped.bv_val == NULL || mapped.bv_val[0] == '\0' ) {
			goto cleanup_attr;
		}

		if ( (*ap)->a_desc->ad_type->sat_syntax
				== slap_schema.si_syn_distinguishedName )
		{
			/*
			 * FIXME: rewrite could fail; in this case
			 * the operation should give up, right?
			 */
#ifdef ENABLE_REWRITE
			rc = rwm_dnattr_rewrite( op, rs, "addDn",
					(*ap)->a_vals );
#else
			rc = 1;
			rc = rwm_dnattr_rewrite( op, rs, &rc,
					(*ap)->a_vals );
#endif
			if ( rc ) {
				goto cleanup_attr;
			}
		}

		ap = &(*ap)->a_next;
		continue;

cleanup_attr:;
		/* FIXME: leaking attribute/values? */
		a = *ap;

		*ap = (*ap)->a_next;
		ber_bvarray_free( a->a_vals );
		ber_bvarray_free( a->a_nvals );
		ch_free( a );
	}


	/* TODO: map attribute types, values of DN-valued attributes ... */
	return SLAP_CB_CONTINUE;
}

static int
rwm_bind( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;
	int			rc;

#ifdef ENABLE_REWRITE
	( void )rewrite_session_init( rwmap->rwm_rw, op->o_conn );

	rc = rwm_op_dn_massage( op, rs, "bindDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "bindDn massage error" );
		return -1;
	}

	return SLAP_CB_CONTINUE;
}

static int
rwm_unbind( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

#ifdef ENABLE_REWRITE
	rewrite_session_delete( rwmap->rwm_rw, op->o_conn );
#endif

	return SLAP_CB_CONTINUE;
}

static int
rwm_compare( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	int			rc;
	struct berval		mapped_at = BER_BVNULL,
				mapped_vals[2] = { BER_BVNULL, BER_BVNULL };

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "compareDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "compareDn massage error" );
		return -1;
	}

	/* if the attribute is an objectClass, try to remap its value */
	if ( op->orc_ava->aa_desc == slap_schema.si_ad_objectClass
			|| op->orc_ava->aa_desc == slap_schema.si_ad_structuralObjectClass )
	{
		rwm_map( &rwmap->rwm_oc, &op->orc_ava->aa_value,
				&mapped_vals[0], RWM_MAP );
		if ( mapped_vals[0].bv_val == NULL
				|| mapped_vals[0].bv_val[0] == '\0')
		{
			op->o_bd->bd_info = (BackendInfo *)on->on_info;
			send_ldap_error( op, rs, LDAP_OTHER, "compare objectClass map error" );
			return -1;

		} else if ( mapped_vals[0].bv_val != op->orc_ava->aa_value.bv_val ) {
			free( op->orc_ava->aa_value.bv_val );
			op->orc_ava->aa_value = mapped_vals[0];
		}
		mapped_at = op->orc_ava->aa_desc->ad_cname;

	} else {
		rwm_map( &rwmap->rwm_at,
				&op->orc_ava->aa_desc->ad_cname,
				&mapped_at,
				RWM_MAP );
		if ( mapped_at.bv_val == NULL 
				|| mapped_at.bv_val[0] == '\0')
		{
			op->o_bd->bd_info = (BackendInfo *)on->on_info;
			send_ldap_error( op, rs, LDAP_OTHER, "compare attributeType map error" );
			return -1;
		}
		if ( op->orc_ava->aa_desc->ad_type->sat_syntax == slap_schema.si_syn_distinguishedName )
		{
			mapped_vals[0] = op->orc_ava->aa_value;
			rc = rwm_dnattr_rewrite( op, rs, "compareAttrDN", mapped_vals );
			if ( rc != LDAP_SUCCESS ) {
				op->o_bd->bd_info = (BackendInfo *)on->on_info;
				send_ldap_error( op, rs, rc, "compareAttrDN massage error" );
				return -1;
			}

			if ( mapped_vals[0].bv_val != op->orc_ava->aa_value.bv_val ) {
				free( op->orc_ava->aa_value.bv_val );
				op->orc_ava->aa_value = mapped_vals[0];
			}
		}
	}

	/* TODO: rewrite attribute types, values of DN-valued attributes ... */
	return SLAP_CB_CONTINUE;
}

static int
rwm_delete( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	int			rc;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "deleteDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "deleteDn massage error" );
		return rc;
	}

	return SLAP_CB_CONTINUE;
}

static int
rwm_modify( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	int			rc;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "modifyDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "modifyDn massage error" );
		return rc;
	}

	/* TODO: rewrite attribute types, values of DN-valued attributes ... */
	return SLAP_CB_CONTINUE;
}

static int
rwm_modrdn( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	int			rc;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "renameDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "renameDn massage error" );
		return rc;
	}

	/* TODO: rewrite attribute types, values of DN-valued attributes ... */
	return SLAP_CB_CONTINUE;
}

static int
rwm_search( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	int			rc;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "searchDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "searchDn massage error" );
		return rc;
	}

	/* TODO: rewrite/map filter & attrs */
	return SLAP_CB_CONTINUE;
}

static int
rwm_extended( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	int			rc;

#ifdef ENABLE_REWRITE
	rc = rwm_op_dn_massage( op, rs, "extendedDn" );
#else
	rc = 1;
	rc = rwm_op_dn_massage( op, rs, &rc );
#endif
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = (BackendInfo *)on->on_info;
		send_ldap_error( op, rs, rc, "extendedDn massage error" );
		return rc;
	}

	/* TODO: rewrite/map extended data ? ... */
	return 0;
}

static int
rwm_matched( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	struct berval		dn, mdn;
	dncookie		dc;

	if ( rs->sr_matched == NULL ) {
		return SLAP_CB_CONTINUE;
	}

	dc.rwmap = rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "matchedDN";
#else
	dc.tofrom = 0;
	dc.normalized = 0;
#endif
	ber_str2bv( rs->sr_matched, 0, 0, &dn );
	rwm_dn_massage( &dc, &dn, &mdn );

	if ( mdn.bv_val != dn.bv_val ) {
		if ( rs->sr_flags & REP_MATCHED_MUSTBEFREED ) {
			ch_free( (void *)rs->sr_matched );
		} else {
			rs->sr_flags |= REP_MATCHED_MUSTBEFREED;
		}
		rs->sr_matched = mdn.bv_val;
	}
	
	return SLAP_CB_CONTINUE;
}

static int
rwm_send_entry( Operation *op, SlapReply *rs )
{
	slap_overinst		*on = (slap_overinst *) op->o_bd->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	Entry		*e = NULL;
	struct berval	dn = BER_BVNULL, ndn = BER_BVNULL;
	dncookie	dc;
	int		rc = SLAP_CB_CONTINUE;

	assert( rs->sr_entry );

	e = rs->sr_entry;

	/*
	 * Rewrite the dn of the result, if needed
	 */
	dc.rwmap = rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = NULL; 
	dc.ctx = "searchResult";
#else
	dc.tofrom = 0;
	dc.normalized = 0;
#endif
	if ( rwm_dn_massage( &dc, &e->e_name, &dn ) ) {
		return LDAP_OTHER;
	}

	if ( e->e_name.bv_val == dn.bv_val ) {
		return SLAP_CB_CONTINUE;
	}

	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 */
	if ( dnNormalize( 0, NULL, NULL, &dn, &ndn, NULL ) != LDAP_SUCCESS ) {
		if ( dn.bv_val != e->e_name.bv_val ) {
			ch_free( dn.bv_val );
		}
		rc = LDAP_INVALID_DN_SYNTAX;
		goto fail;
	}

	if ( !( rs->sr_flags & REP_ENTRY_MODIFIABLE ) ) {
		e = entry_dup( e );
		if ( e == NULL ) {
			goto fail;
		}
		rs->sr_flags |= ( REP_ENTRY_MODIFIABLE | REP_ENTRY_MUSTBEFREED );
	}

	free( e->e_name.bv_val );
	free( e->e_nname.bv_val );

	e->e_name = dn;
	e->e_nname = ndn;

	rs->sr_entry = e;

	/* TODO: map entry attribute types, objectclasses 
	 * and dn-valued attribute values */
	
	return SLAP_CB_CONTINUE;

fail:;
	if ( dn.bv_val && ( dn.bv_val != e->e_name.bv_val ) ) {
		ch_free( dn.bv_val );
	}

	if ( ndn.bv_val ) {
		ch_free( ndn.bv_val );
	}

	return rc;
}

static int
rwm_rw_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
#ifdef ENABLE_REWRITE
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	return rewrite_parse( rwmap->rwm_rw,
				fname, lineno, argc, argv );

#else /* !ENABLE_REWRITE */
	fprintf( stderr, "%s: line %d: rewrite capabilities "
			"are not enabled\n", fname, lineno );
#endif /* !ENABLE_REWRITE */
		
	return 0;
}

static int
rwm_suffixmassage_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	struct berval	bvnc, nvnc, pvnc, brnc, nrnc, prnc;
#ifdef ENABLE_REWRITE
	int		rc;
#endif /* ENABLE_REWRITE */
		
	/*
	 * syntax:
	 * 
	 * 	suffixmassage <suffix> <massaged suffix>
	 *
	 * the <suffix> field must be defined as a valid suffix
	 * (or suffixAlias?) for the current database;
	 * the <massaged suffix> shouldn't have already been
	 * defined as a valid suffix or suffixAlias for the 
	 * current server
	 */
	if ( argc != 3 ) {
 		fprintf( stderr, "%s: line %d: syntax is"
			       " \"suffixMassage <suffix>"
			       " <massaged suffix>\"\n",
			fname, lineno );
		return 1;
	}
		
	ber_str2bv( argv[1], 0, 0, &bvnc );
	if ( dnPrettyNormal( NULL, &bvnc, &pvnc, &nvnc, NULL ) != LDAP_SUCCESS ) {
		fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
			fname, lineno, bvnc.bv_val );
		return 1;
	}

	ber_str2bv( argv[2], 0, 0, &brnc );
	if ( dnPrettyNormal( NULL, &brnc, &prnc, &nrnc, NULL ) != LDAP_SUCCESS ) {
		fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, brnc.bv_val );
		free( nvnc.bv_val );
		free( pvnc.bv_val );
		return 1;
	}

#ifdef ENABLE_REWRITE
	/*
	 * The suffix massaging is emulated 
	 * by means of the rewrite capabilities
	 */
 	rc = rwm_suffix_massage_config( rwmap->rwm_rw,
			&pvnc, &nvnc, &prnc, &nrnc );
	free( nvnc.bv_val );
	free( pvnc.bv_val );
	free( nrnc.bv_val );
	free( prnc.bv_val );

	return( rc );

#else /* !ENABLE_REWRITE */
	ber_bvarray_add( &rwmap->rwm_suffix_massage, &pvnc );
	ber_bvarray_add( &rwmap->rwm_suffix_massage, &nvnc );
		
	ber_bvarray_add( &rwmap->rwm_suffix_massage, &prnc );
	ber_bvarray_add( &rwmap->rwm_suffix_massage, &nrnc );
#endif /* !ENABLE_REWRITE */

	return 0;
}

static int
rwm_m_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

	/* objectclass/attribute mapping */
	return rwm_map_config( &rwmap->rwm_oc,
			&rwmap->rwm_at,
			fname, lineno, argc, argv );
}

static int
rwm_response( Operation *op, SlapReply *rs )
{
	int	rc;

	if ( op->o_tag == LDAP_REQ_SEARCH && rs->sr_type == REP_SEARCH ) {
		return rwm_send_entry( op, rs );
	}

	switch( op->o_tag ) {
	case LDAP_REQ_BIND:
	case LDAP_REQ_ADD:
	case LDAP_REQ_DELETE:
	case LDAP_REQ_MODRDN:
	case LDAP_REQ_MODIFY:
	case LDAP_REQ_COMPARE:
	case LDAP_REQ_SEARCH:
	case LDAP_REQ_EXTENDED:
		rc = rwm_matched( op, rs );
		break;
	default:
		rc = SLAP_CB_CONTINUE;
		break;
	}

	return rc;
}

static int
rwm_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		rc = 0;
	char		*argv0 = NULL;

	if ( strncasecmp( argv[ 0 ], "rwm-", sizeof( "rwm-" ) - 1 ) == 0 ) {
		argv0 = argv[ 0 ];
		argv[ 0 ] = &argv0[ sizeof( "rwm-" ) - 1 ];
	}

	if ( strncasecmp( argv[0], "rewrite", sizeof("rewrite") - 1 ) == 0 ) {
		rc = rwm_rw_config( be, fname, lineno, argc, argv );

	} else if (strcasecmp( argv[0], "map" ) == 0 ) {
		rc = rwm_m_config( be, fname, lineno, argc, argv );

	} else if (strcasecmp( argv[0], "suffixmassage" ) == 0 ) {
		rc = rwm_suffixmassage_config( be, fname, lineno, argc, argv );

	} else {
		rc = SLAP_CONF_UNKNOWN;
	}

	if ( argv0 ) {
		argv[ 0 ] = argv0;
	}

	return rc;
}

static int
rwm_over_init(
	BackendDB *be
)
{
	slap_overinst		*on = (slap_overinst *) be->bd_info;
	struct ldapmapping	*mapping = NULL;
	struct ldaprwmap	*rwmap;

	rwmap = (struct ldaprwmap *)ch_malloc(sizeof(struct ldaprwmap));
	memset(rwmap, 0, sizeof(struct ldaprwmap));

#ifdef ENABLE_REWRITE
 	rwmap->rwm_rw = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
	if ( rwmap->rwm_rw == NULL ) {
 		ch_free( rwmap );
 		return -1;
 	}

	{
		char	*rargv[3];

		/* this rewriteContext by default must be null;
		 * rules can be added if required */
		rargv[ 0 ] = "rewriteContext";
		rargv[ 1 ] = "searchFilter";
		rargv[ 2 ] = NULL;
		rewrite_parse( rwmap->rwm_rw, "<suffix massage>", 1, 2, rargv );

		rargv[ 0 ] = "rewriteContext";
		rargv[ 1 ] = "default";
		rargv[ 2 ] = NULL;
		rewrite_parse( rwmap->rwm_rw, "<suffix massage>", 2, 2, rargv );
	}
	
#endif /* ENABLE_REWRITE */

	rwm_map_init( &rwmap->rwm_oc, &mapping );
	rwm_map_init( &rwmap->rwm_at, &mapping );

	on->on_bi.bi_private = (void *)rwmap;

	return 0;
}

static int
rwm_destroy(
	BackendDB *be
)
{
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	int		rc = 0;

	if ( on->on_bi.bi_private ) {
		struct ldaprwmap	*rwmap = 
			(struct ldaprwmap *)on->on_bi.bi_private;

#ifdef ENABLE_REWRITE
		if (rwmap->rwm_rw) {
			rewrite_info_delete( &rwmap->rwm_rw );
		}
#else /* !ENABLE_REWRITE */
		if ( rwmap->rwm_suffix_massage ) {
  			ber_bvarray_free( rwmap->rwm_suffix_massage );
 		}
#endif /* !ENABLE_REWRITE */

		avl_free( rwmap->rwm_oc.remap, NULL );
		avl_free( rwmap->rwm_oc.map, rwm_mapping_free );
		avl_free( rwmap->rwm_at.remap, NULL );
		avl_free( rwmap->rwm_at.map, rwm_mapping_free );
	}

	return rc;
}

static slap_overinst rwm = { { NULL } };

int
rwm_init(void)
{
	memset( &rwm, 0, sizeof(slap_overinst) );

	rwm.on_bi.bi_type = "rwm";
	rwm.on_bi.bi_db_init = rwm_over_init;
	rwm.on_bi.bi_db_config = rwm_config;
	rwm.on_bi.bi_db_destroy = rwm_destroy;

	rwm.on_bi.bi_op_bind = rwm_bind;
	rwm.on_bi.bi_op_search = rwm_search;
	rwm.on_bi.bi_op_compare = rwm_compare;
	rwm.on_bi.bi_op_modify = rwm_modify;
	rwm.on_bi.bi_op_modrdn = rwm_modrdn;
	rwm.on_bi.bi_op_add = rwm_add;
	rwm.on_bi.bi_op_delete = rwm_delete;
	rwm.on_bi.bi_op_unbind = rwm_unbind;
	rwm.on_bi.bi_extended = rwm_extended;

	rwm.on_response = rwm_response;

	return overlay_register( &rwm );
}

#if SLAPD_OVER_RWM == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return rwm_init();
}
#endif

#endif /* SLAPD_OVER_RWM */
