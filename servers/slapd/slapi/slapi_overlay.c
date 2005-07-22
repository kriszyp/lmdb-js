/* slapi_overlay.c - SLAPI overlay */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2005 The OpenLDAP Foundation.
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
 * This work was initially developed by Luke Howard for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "slapi.h"

#ifdef LDAP_SLAPI

static slap_overinst slapi;

static int
slapi_over_compute_output(
	computed_attr_context *c,
	Slapi_Attr *attribute,
	Slapi_Entry *entry
)
{
	int			rc;
	Attribute		**a;
	AttributeDescription	*desc;
	Operation		*op = c->cac_op;
	SlapReply		*rs = (SlapReply *)c->cac_private;

	if ( c == NULL || attribute == NULL || entry == NULL ) {
		return 0;
	}

	assert( rs->sr_entry == entry );

	desc = attribute->a_desc;

	if ( rs->sr_attrs == NULL ) {
		/* All attrs request, skip operational attributes */
		if ( is_at_operational( desc->ad_type ) ) {
			return 0;
		}
	} else {
		/* Specific attributes requested */
		if ( is_at_operational( desc->ad_type ) ) {
			if ( !SLAP_OPATTRS( rs->sr_attr_flags ) &&
			     !ad_inlist( desc, rs->sr_attrs ) ) {
				return 0;
			}
		} else {
			if ( !SLAP_USERATTRS( rs->sr_attr_flags ) &&
			     !ad_inlist( desc, rs->sr_attrs ) ) {
				return 0;
			}
		}
	}

	if ( !access_allowed( op, entry, desc, NULL, ACL_READ, c->cac_acl_state) ) {
		slapi_log_error( SLAPI_LOG_ACL, "slapi_over_compute_output",
			"acl: access to attribute %s not allowed\n",
			desc->ad_cname.bv_val );
		return 0;
	}

	for ( a = &rs->sr_operational_attrs; *a != NULL; a = &(*a)->a_next )
		;

	*a = attr_dup( attribute );

	return 0;
}

static int
slapi_over_aux_operational( Operation *op, SlapReply *rs )
{
	/* Support for computed attribute plugins */
	computed_attr_context    ctx;
	AttributeName		*anp;
	AccessControlState	acl_state = ACL_STATE_INIT;

	ctx.cac_pb = op->o_pb;
	ctx.cac_op = op;
	ctx.cac_private = rs;
	ctx.cac_acl_state = &acl_state;

	if ( rs->sr_entry != NULL ) {
		/*
		 * For each client requested attribute, call the plugins.
		 */
		if ( rs->sr_attrs != NULL ) {
			for ( anp = rs->sr_attrs; anp->an_name.bv_val != NULL; anp++ ) {
				if ( compute_evaluator( &ctx, anp->an_name.bv_val,
					rs->sr_entry, slapi_over_compute_output ) == 1 ) {
					break;
				}
			}
		} else {
			/*
			 * Technically we shouldn't be returning operational attributes
			 * when the user requested only user attributes. We'll let the
			 * plugin decide whether to be naughty or not.
			 */
			compute_evaluator( &ctx, "*", rs->sr_entry, slapi_over_compute_output );
		}
	}

	return SLAP_CB_CONTINUE;
}

static int
slapi_over_search( Operation *op, SlapReply *rs, int type )
{
	int			rc;
	Slapi_PBlock		*pb;

	assert( rs->sr_type == REP_SEARCH || rs->sr_type == REP_SEARCHREF );

	pb = slapi_pblock_new();

	slapi_int_pblock_set_operation( pb, op );
	slapi_pblock_set( pb, SLAPI_RESCONTROLS, (void *)rs->sr_ctrls );
	slapi_pblock_set( pb, SLAPI_SEARCH_RESULT_ENTRY, (void *)rs->sr_entry );

	rc = slapi_int_call_plugins( op->o_bd, type, pb );
	if ( rc >= 0 ) /* 1 means no plugins called */
		rc = SLAP_CB_CONTINUE;
	else
		rc = LDAP_SUCCESS; /* confusing: don't abort, but don't send */

	if ( rc == SLAP_CB_CONTINUE && rs->sr_type == REP_SEARCH ) {
		/* XXX we shouldn't need this here */
		slapi_over_aux_operational( op, rs );
	}

	slapi_pblock_set( pb, SLAPI_RESCONTROLS, NULL ); /* don't free */
	slapi_pblock_destroy(pb);

	return rc;
}

static int
slapi_over_merge_controls( Operation *op, SlapReply *rs, Slapi_PBlock *pb)
{
	LDAPControl **slapiControls = NULL, **resControls;
	int nSlapiControls = 0;
	int nResControls = 0;
	int i;

	/* merge in controls */
	if ( rs->sr_ctrls != NULL ) {
		for ( nResControls = 0; rs->sr_ctrls[nResControls] != NULL; nResControls++ )
			;
	}
	slapi_pblock_get( op->o_pb, SLAPI_RESCONTROLS, (void **)&slapiControls );
	if ( slapiControls != NULL ) {
		for ( nSlapiControls = 0; slapiControls[nSlapiControls] != NULL; nSlapiControls++ )
			;
	}

	/* XXX this is a bit tricky, rs->sr_ctrls may have been allocated on stack */
	resControls = (LDAPControl **)op->o_tmpalloc( ( nResControls + nSlapiControls + 1 ) *
							sizeof( LDAPControl *), op->o_tmpmemctx );
	if ( resControls == NULL ) {
		return LDAP_OTHER;
	}

	if ( rs->sr_ctrls != NULL ) {
		for ( i = 0; i < nResControls; i++ )
			resControls[i] = rs->sr_ctrls[i];
	}
	if ( slapiControls != NULL ) {
		for ( i = 0; i < nSlapiControls; i++ )
			resControls[nResControls + i] = slapiControls[i];
	}
	resControls[nResControls + nSlapiControls] = NULL;

	if ( slapiControls != NULL ) {
		slapi_ch_free( (void **)&slapiControls );
		slapi_pblock_set( op->o_pb, SLAPI_RESCONTROLS, NULL ); /* don't free */
	}

	rs->sr_ctrls = resControls;

	return LDAP_SUCCESS;
}

static int
slapi_over_result( Operation *op, SlapReply *rs, int type )
{
	int rc;

	assert( rs->sr_type == REP_RESULT );

	slapi_pblock_set( op->o_pb, SLAPI_RESULT_CODE,    (void *)rs->sr_err );
	slapi_pblock_set( op->o_pb, SLAPI_RESULT_TEXT,    (void *)rs->sr_text );
	slapi_pblock_set( op->o_pb, SLAPI_RESULT_MATCHED, (void *)rs->sr_matched );

	rc = slapi_int_call_plugins( op->o_bd, type, op->o_pb );
	
	slapi_pblock_get( op->o_pb, SLAPI_RESULT_CODE,    (void **)&rs->sr_err );
	slapi_pblock_get( op->o_pb, SLAPI_RESULT_TEXT,    (void **)&rs->sr_text );
	slapi_pblock_get( op->o_pb, SLAPI_RESULT_MATCHED, (void **)&rs->sr_matched );

	if ( type == SLAPI_PLUGIN_PRE_RESULT_FN ) {
		rc = slapi_over_merge_controls( op, rs, op->o_pb );
	}

	return SLAP_CB_CONTINUE;
}

static int
slapi_op_add_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	slapi_pblock_set( pb, SLAPI_ADD_ENTRY, (void *)op->ora_e );

	return LDAP_SUCCESS;
}

static int
slapi_op_bind_preop_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	slapi_pblock_set( pb, SLAPI_BIND_TARGET,      (void *)op->o_req_dn.bv_val );
	slapi_pblock_set( pb, SLAPI_BIND_METHOD,      (void *)op->orb_method );
	slapi_pblock_set( pb, SLAPI_BIND_CREDENTIALS, (void *)&op->orb_cred );
	slapi_pblock_set( pb, SLAPI_CONN_DN,          NULL );

	return LDAP_SUCCESS;
}

static int
slapi_op_bind_postop_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	char *dn = NULL;

	if ( rs->sr_err == LDAP_SUCCESS ) {
		/* fix for ITS#2971 */
		slapi_pblock_set( pb, SLAPI_CONN_DN, op->o_conn->c_authz.sai_dn.bv_val );
	}

	return LDAP_SUCCESS;
}

static int
slapi_op_bind_callback( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	int rc = rs->sr_err;

	switch ( rc ) {
	case SLAPI_BIND_SUCCESS:
		/* Continue with backend processing */
		break;
	case SLAPI_BIND_FAIL:
		/* Failure, frontend (that's us) sends result */
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );
		return rs->sr_err;
		break;
	case SLAPI_BIND_ANONYMOUS: /* undocumented */
	default:
		/*
		 * Plugin sent authoritative result or no plugins were called
		 */
		if ( slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void **)&rs->sr_err ) != 0 ) {
			rs->sr_err = LDAP_OTHER;
		}

		BER_BVZERO( &op->orb_edn );

		if ( rs->sr_err == LDAP_SUCCESS ) {
			slapi_pblock_get( pb, SLAPI_CONN_DN, (void *)&op->orb_edn.bv_val );
			if ( BER_BVISNULL( &op->orb_edn ) ) {
				if ( rc == 1 ) {
					/* No plugins were called; continue processing */
					return LDAP_SUCCESS;
				}
			} else {
				op->orb_edn.bv_len = strlen( op->orb_edn.bv_val );
			}
			rs->sr_err = dnPrettyNormal( NULL, &op->orb_edn,
			&op->o_req_dn, &op->o_req_ndn, op->o_tmpmemctx );
			ldap_pvt_thread_mutex_lock( &op->o_conn->c_mutex );
			ber_dupbv(&op->o_conn->c_dn, &op->o_req_dn);
			ber_dupbv(&op->o_conn->c_ndn, &op->o_req_ndn);
			op->o_tmpfree( op->o_req_dn.bv_val, op->o_tmpmemctx );
			BER_BVZERO( &op->o_req_dn );
			op->o_tmpfree( op->o_req_ndn.bv_val, op->o_tmpmemctx );
			BER_BVZERO( &op->o_req_ndn );
			if ( !BER_BVISEMPTY( &op->o_conn->c_dn ) ) {
				ber_len_t max = sockbuf_max_incoming_auth;
				ber_sockbuf_ctrl( op->o_conn->c_sb,
					LBER_SB_OPT_SET_MAX_INCOMING, &max );
			}
			/* log authorization identity */
			Statslog( LDAP_DEBUG_STATS,
				"%s BIND dn=\"%s\" mech=%s (SLAPI) ssf=0\n",
				op->o_log_prefix,
				BER_BVISNULL( &op->o_conn->c_dn )
					? "<empty>" : op->o_conn->c_dn.bv_val,
				op->orb_tmp_mech.bv_val, 0, 0 );
		
			return -1;
		}
		break;
	}

	return rc;
}

static int
slapi_op_compare_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	slapi_pblock_set( pb, SLAPI_COMPARE_TYPE,  (void *)op->orc_ava->aa_desc->ad_cname.bv_val );
	slapi_pblock_set( pb, SLAPI_COMPARE_VALUE, (void *)&op->orc_ava->aa_value );

	return LDAP_SUCCESS;
}

static int
slapi_op_modify_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	LDAPMod		**modv = NULL;

	modv = slapi_int_modifications2ldapmods( &op->orm_modlist );
	slapi_pblock_set( pb, SLAPI_MODIFY_MODS, (void *)modv );

	return LDAP_SUCCESS;
}

static int
slapi_op_modify_callback( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	LDAPMod		**modv = NULL;

	/* check preoperation result code */
	if ( rs->sr_err < 0 ) {
		slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void **)&rs->sr_err );
		return rs->sr_err;
	}

	/*
	 * NB: it is valid for the plugin to return no modifications
	 * (for example, a plugin might store some attributes elsewhere
	 * and remove them from the modification list; if only those
	 * attribute types were included in the modification request,
	 * then slapi_int_ldapmods2modifications() above will return
	 * NULL).
	 *
	 * However, the post-operation plugin should still be
	 * called.
	 */

	slapi_pblock_get( pb, SLAPI_MODIFY_MODS, (void **)&modv );
	op->orm_modlist = slapi_int_ldapmods2modifications( modv );

	return LDAP_SUCCESS;
}

static int
slapi_op_modify_cleanup( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	LDAPMod		**modv = NULL;

	slapi_pblock_get( pb, SLAPI_MODIFY_MODS, (void **)&modv );

	if ( modv != NULL )
		slapi_int_free_ldapmods( modv );

	return LDAP_SUCCESS;
}

static int
slapi_op_modrdn_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWRDN,      (void *)op->orr_newrdn.bv_val );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWSUPERIOR, (void *)op->orr_newSup->bv_val );
	slapi_pblock_set( pb, SLAPI_MODRDN_DELOLDRDN,   (void *)op->orr_deleteoldrdn );

	return LDAP_SUCCESS;
}

static int
slapi_op_search_init( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	char		**attrs;

	attrs = anlist2charray_x( op->ors_attrs, 0, op->o_tmpmemctx );

	slapi_pblock_set( pb, SLAPI_SEARCH_SCOPE,     (void *)op->ors_scope );
	slapi_pblock_set( pb, SLAPI_SEARCH_DEREF,     (void *)op->ors_deref );
	slapi_pblock_set( pb, SLAPI_SEARCH_SIZELIMIT, (void *)op->ors_slimit );
	slapi_pblock_set( pb, SLAPI_SEARCH_TIMELIMIT, (void *)op->ors_tlimit );
	slapi_pblock_set( pb, SLAPI_SEARCH_FILTER,    (void *)op->ors_filter );
	slapi_pblock_set( pb, SLAPI_SEARCH_STRFILTER, (void *)op->ors_filterstr.bv_val );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRS,     (void *)attrs );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRSONLY, (void *)op->ors_attrsonly );

	return LDAP_SUCCESS;
}

static int
slapi_op_search_callback( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	/* check preoperation result code */
	if ( rs->sr_err < 0 ) {
		slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void **)&rs->sr_err );
		return rs->sr_err;
	}

	if ( slapi_int_call_plugins( op->o_bd, SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN, pb ) != 0 ) {
		return LDAP_SUCCESS;
	}

	/*
	 * The plugin can set the SLAPI_SEARCH_FILTER.
	 * SLAPI_SEARCH_STRFILER is not normative.
	 */
	slapi_pblock_get( pb, SLAPI_SEARCH_FILTER, (void *)&op->ors_filter );
	op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	filter2bv_x( op, op->ors_filter, &op->ors_filterstr );

	slapi_pblock_get( pb, SLAPI_SEARCH_TARGET, (void **)&op->o_req_dn.bv_val );
	op->o_req_dn.bv_len = strlen( op->o_req_dn.bv_val );

	if( !BER_BVISNULL( &op->o_req_ndn ) ) {
		slap_sl_free( op->o_req_ndn.bv_val, op->o_tmpmemctx );
	}
	rs->sr_err = dnNormalize( 0, NULL, NULL, &op->o_req_dn, &op->o_req_ndn,
				  op->o_tmpmemctx );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	slapi_pblock_get( pb, SLAPI_SEARCH_SCOPE, (void **)&op->ors_scope );
	slapi_pblock_get( pb, SLAPI_SEARCH_DEREF, (void **)&op->ors_deref );

	return LDAP_SUCCESS;
}

static int
slapi_op_search_cleanup( Operation *op, SlapReply *rs, Slapi_PBlock *pb )
{
	char		**attrs = NULL;

	slapi_pblock_get( pb, SLAPI_SEARCH_ATTRS,     (void *)&attrs );

	if ( attrs != NULL )
		op->o_tmpfree( attrs, op->o_tmpmemctx );

	return LDAP_SUCCESS;
}

typedef int (slapi_over_callback)( Operation *, SlapReply *rs, Slapi_PBlock * );

struct slapi_op_info {
	int soi_preop;
	int soi_postop;
	slapi_over_callback *soi_preop_init;
	slapi_over_callback *soi_callback; 
	slapi_over_callback *soi_postop_init;
	slapi_over_callback *soi_cleanup;
} slapi_op_dispatch_table[] = {
	{
		SLAPI_PLUGIN_PRE_BIND_FN,
		SLAPI_PLUGIN_POST_BIND_FN,
		slapi_op_bind_preop_init,
		slapi_op_bind_callback,
		slapi_op_bind_postop_init,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_UNBIND_FN, /* UNBIND */
		SLAPI_PLUGIN_POST_UNBIND_FN,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_SEARCH_FN,
		SLAPI_PLUGIN_POST_SEARCH_FN,
		slapi_op_search_init,
		slapi_op_search_callback,
		NULL,
		slapi_op_search_cleanup
	},
	{
		SLAPI_PLUGIN_PRE_COMPARE_FN,
		SLAPI_PLUGIN_POST_COMPARE_FN,
		slapi_op_compare_init,
		NULL,
		NULL,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_MODIFY_FN,
		SLAPI_PLUGIN_POST_MODIFY_FN,
		slapi_op_modify_init,
		slapi_op_modify_callback,
		NULL,
		slapi_op_modify_cleanup
	},
	{
		SLAPI_PLUGIN_PRE_MODRDN_FN,
		SLAPI_PLUGIN_POST_MODRDN_FN,
		slapi_op_modrdn_init,
		NULL,
		NULL,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_ADD_FN,
		SLAPI_PLUGIN_POST_ADD_FN,
		slapi_op_add_init,
		NULL,
		NULL,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_DELETE_FN,
		SLAPI_PLUGIN_POST_DELETE_FN,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		SLAPI_PLUGIN_PRE_ABANDON_FN,
		SLAPI_PLUGIN_POST_ABANDON_FN,
		NULL,
		NULL,
		NULL,
		NULL
	},
	{
		0,
		0,
		NULL,
		NULL,
		NULL,
		NULL
	}
};

slap_operation_t
slapi_tag2op( ber_tag_t tag )
{
	slap_operation_t op;

	switch ( tag ) {
	case LDAP_REQ_BIND:
		op = op_bind;
		break;
	case LDAP_REQ_ADD:
		op = op_add;
		break;
	case LDAP_REQ_DELETE:
		op = op_compare;
		break;
	case LDAP_REQ_MODRDN:
		op = op_modrdn;
		break;
	case LDAP_REQ_MODIFY:
		op = op_modify;
		break;
	case LDAP_REQ_COMPARE:
		op = op_compare;
		break;
	case LDAP_REQ_SEARCH:
		op = op_search;
		break;
	case LDAP_REQ_UNBIND:
		op = op_unbind;
		break;
	default:
		op = op_last;
		break;
	}

	return op;
}

static int
slapi_over_response( Operation *op, SlapReply *rs )
{
	int			rc;

	switch ( rs->sr_type ) {
	case REP_RESULT:
		rc = slapi_over_result( op, rs, SLAPI_PLUGIN_PRE_RESULT_FN );
		break;
	case REP_SEARCH:
		rc = slapi_over_search( op, rs, SLAPI_PLUGIN_PRE_ENTRY_FN );
		break;
	case REP_SEARCHREF:
		rc = slapi_over_search( op, rs, SLAPI_PLUGIN_PRE_REFERRAL_FN );
		break;
	default:
		rc = SLAP_CB_CONTINUE;
		break;
	}

	return rc;
}

static int
slapi_over_cleanup( Operation *op, SlapReply *rs )
{
	int			rc;

	switch ( rs->sr_type ) {
	case REP_RESULT:
		rc = slapi_over_result( op, rs, SLAPI_PLUGIN_POST_RESULT_FN );
		break;
	case REP_SEARCH:
		rc = slapi_over_search( op, rs, SLAPI_PLUGIN_POST_ENTRY_FN );
		break;
	case REP_SEARCHREF:
		rc = slapi_over_search( op, rs, SLAPI_PLUGIN_POST_REFERRAL_FN );
		break;
	default:
		rc = SLAP_CB_CONTINUE;
		break;
	}

	return rc;
}

static int
slapi_op_func( Operation *op, SlapReply *rs )
{
	Slapi_PBlock		*pb = op->o_pb;
	slap_operation_t	which;
	struct slapi_op_info	*opinfo;
	int			rc, flags = 0;
	slap_overinfo		*oi;
	slap_overinst		*on;
	slap_callback		cb;

	/*
	 * We check for op->o_extensions to verify that we are not
	 * processing a SLAPI internal operation. XXX
	 */
	if ( op->o_pb == NULL || op->o_extensions == NULL ) {
		return SLAP_CB_CONTINUE;
	}

	/*
	 * Find the SLAPI operation information for this LDAP
	 * operation; this will contain the preop and postop
	 * plugin types, as well as optional callbacks for
	 * setting up the SLAPI environment.
	 */
	which = slapi_tag2op( op->o_tag );
	if ( which >= op_last ) {
		/* invalid operation, but let someone else deal with it */
		return SLAP_CB_CONTINUE;
	}

	opinfo = &slapi_op_dispatch_table[which];
	if ( opinfo == NULL || opinfo->soi_preop == 0 ) {
		/* no SLAPI plugin types for this operation */
		return SLAP_CB_CONTINUE;
	}

	slapi_int_pblock_set_operation( pb, op );

	cb.sc_response = slapi_over_response; /* call pre-entry/result plugins */
	cb.sc_cleanup = slapi_over_cleanup;  /* call post-entry/result plugins */
	cb.sc_private = opinfo;
	cb.sc_next = op->o_callback;
	op->o_callback = &cb;

	/*
	 * Call preoperation plugins 
	 */
	if ( opinfo->soi_preop_init != NULL ) {
		rs->sr_err = (opinfo->soi_preop_init)( op, rs, pb );
		if ( rs->sr_err != LDAP_SUCCESS )
			return rs->sr_err;
	}

	rs->sr_err = slapi_int_call_plugins( op->o_bd, opinfo->soi_preop, pb );

	/*
	 * soi_callback is responsible for examining the result code
	 * of the preoperation plugin and determining whether to
	 * abort. This is needed because of special SLAPI behaviour
	 * with bind preoperation plugins.
	 *
	 * The soi_callback function is also used to reset any values
	 * returned from the preoperation plugin before calling the
	 * backend (for the success case).
	 */
	if ( opinfo->soi_callback == NULL ) {
		/* default behaviour is preop plugin can abort operation */
		if ( rs->sr_err < 0 ) {
			slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void **)&rs->sr_err );
			goto cleanup;
		}
	} else {
		rc = (opinfo->soi_callback)( op, rs, pb );
		if ( rc )
			goto cleanup;
	}

	/*
	 * Call actual backend (or next overlay in stack)
	 */
	on = (slap_overinst *)op->o_bd->bd_info;
	oi = on->on_info;

	rs->sr_err = overlay_op_walk( op, rs, which, oi, on->on_next );

	/*
	 * Call postoperation plugins
	 */
	slapi_pblock_set( pb, SLAPI_RESULT_CODE, (void *)rs->sr_err );

	if ( opinfo->soi_postop_init != NULL ) {
		(opinfo->soi_postop_init)( op, rs, pb );
	}

	slapi_int_call_plugins( op->o_bd, opinfo->soi_postop, pb );

cleanup:
	if ( opinfo->soi_cleanup != NULL ) {
		(opinfo->soi_cleanup)( op, rs, pb );
	}

	op->o_callback = cb.sc_next;

	return rs->sr_err;
}

static int
slapi_over_extended( Operation *op, SlapReply *rs )
{
	Slapi_PBlock	*pb = op->o_pb;
	SLAPI_FUNC	callback;
	int		sentResult = 0;
	int		rc;
	struct berval	reqdata = BER_BVNULL;

	slapi_int_get_extop_plugin( &op->ore_reqoid, &callback );
	if ( callback == NULL ) {
		return SLAP_CB_CONTINUE;
	}

	slapi_int_pblock_set_operation( pb, op );

	if ( op->ore_reqdata != NULL ) {
		reqdata = *op->ore_reqdata;
	}

	slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_OID,   (void *)op->ore_reqoid.bv_val);
	slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_VALUE, (void *)&reqdata);

	rc = (*callback)( pb );
	if ( rc == SLAPI_PLUGIN_EXTENDED_SENT_RESULT ) {
		return rc;
	} else if ( rc == SLAPI_PLUGIN_EXTENDED_NOT_HANDLED ) {
		return SLAP_CB_CONTINUE;
	}

	slapi_pblock_get( pb, SLAPI_EXT_OP_RET_OID,   (void **)&rs->sr_rspoid );
	slapi_pblock_get( pb, SLAPI_EXT_OP_RET_VALUE, (void **)&rs->sr_rspdata );

	rs->sr_err = rc;
	send_ldap_extended( op, rs );

	if ( rs->sr_rspoid != NULL )
		slapi_ch_free_string( (char **)&rs->sr_rspoid );

	if ( rs->sr_rspdata != NULL )
		ber_bvfree( rs->sr_rspdata );

	return rs->sr_err;
}

static int
slapi_over_access_allowed(
	Operation		*op,
	Entry			*e,
	AttributeDescription	*desc,
	struct berval		*val,
	slap_access_t		access,
	AccessControlState	*state,
	slap_mask_t		*maskp )
{
	int rc;

	rc = slapi_int_access_allowed( op, e, desc, val, access, state );
	if ( rc != 0 )
		rc = SLAP_CB_CONTINUE;

	return rc;
}

static int
slapi_over_acl_group(
	Operation		*op,
	Entry			*target,
	struct berval		*gr_ndn,
	struct berval		*op_ndn,
	ObjectClass		*group_oc,
	AttributeDescription	*group_at )
{
	Slapi_Entry		*e;
	int			rc;
	Slapi_PBlock		*pb = op->o_pb;

	if ( pb == NULL ) {
		return SLAP_CB_CONTINUE;
	}

	rc = be_entry_get_rw( op, gr_ndn, group_oc, group_at, 0, &e );
	if ( e == NULL ) {
		return SLAP_CB_CONTINUE;
	}

	slapi_pblock_set( pb, SLAPI_X_GROUP_ENTRY,        (void *)e );
	slapi_pblock_set( pb, SLAPI_X_GROUP_OPERATION_DN, (void *)op_ndn->bv_val );
	slapi_pblock_set( pb, SLAPI_X_GROUP_ATTRIBUTE,    (void *)group_at->ad_cname.bv_val );
	slapi_pblock_set( pb, SLAPI_X_GROUP_TARGET_ENTRY, (void *)target );

	rc = slapi_int_call_plugins( op->o_bd, SLAPI_X_PLUGIN_PRE_GROUP_FN, pb );
	if ( rc == 0 )
		rc = SLAP_CB_CONTINUE;
	else
		slapi_pblock_get( pb, SLAPI_RESULT_CODE, (void **)&rc );

	slapi_pblock_set( pb, SLAPI_X_GROUP_ENTRY,         NULL );
	slapi_pblock_set( pb, SLAPI_X_GROUP_OPERATION_DN,  NULL );
	slapi_pblock_set( pb, SLAPI_X_GROUP_ATTRIBUTE,     NULL );
	slapi_pblock_set( pb, SLAPI_X_GROUP_TARGET_ENTRY,  NULL );

	if ( e != target )
		be_entry_release_r( op, e );

	/*
	 * XXX don't call POST_GROUP_FN, I have no idea what the point of
	 * that plugin function was anyway
	 */
	return rc;
}

#if 0
static int
slapi_over_compute_output_attr_access(computed_attr_context *c, Slapi_Attr *a, Slapi_Entry *e)
{
	struct berval	*nval = (struct berval *)c->cac_private;

	return access_allowed( c->cac_op, e, a->a_desc, nval, ACL_AUTH, NULL ) == 0;
}

static int
slapi_over_acl_attribute(
	Operation		*op,
	Entry			*target,
	struct berval		*entry_ndn,
	AttributeDescription	*entry_at,
	BerVarray		*vals,
	slap_access_t		access )
{
	computed_attr_context	ctx;

	ctx.cac_pb = op->o_pb;
	ctx.cac_op = op;
	ctx.cac_acl_state = NULL;
	ctx.cac_private = nval;
}
#endif

int
slapi_int_overlay_init()
{
	memset( &slapi, 0, sizeof(slapi) );

	slapi.on_bi.bi_type = SLAPI_OVERLAY_NAME;

	slapi.on_bi.bi_op_bind = slapi_op_func;
	slapi.on_bi.bi_op_unbind = slapi_op_func;
	slapi.on_bi.bi_op_search = slapi_op_func;
	slapi.on_bi.bi_op_compare = slapi_op_func;
	slapi.on_bi.bi_op_modify = slapi_op_func;
	slapi.on_bi.bi_op_modrdn = slapi_op_func;
	slapi.on_bi.bi_op_add = slapi_op_func;
	slapi.on_bi.bi_op_delete = slapi_op_func;
	slapi.on_bi.bi_op_abandon = slapi_op_func;
	slapi.on_bi.bi_op_cancel = slapi_op_func;

	slapi.on_bi.bi_extended = slapi_over_extended;
	slapi.on_bi.bi_access_allowed = slapi_over_access_allowed;
	slapi.on_bi.bi_operational = slapi_over_aux_operational;

	return overlay_register( &slapi );
}

#endif /* LDAP_SLAPI */
