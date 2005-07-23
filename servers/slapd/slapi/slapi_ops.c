/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2005 The OpenLDAP Foundation.
 * Portions Copyright 1997,2002-2003 IBM Corporation.
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
 * This work was initially developed by IBM Corporation for use in
 * IBM products and subsequently ported to OpenLDAP Software by
 * Steve Omrani.  Additional significant contributors include:
 *   Luke Howard
 */

#include "portable.h"

#include <ac/string.h>
#include <ac/stdarg.h>
#include <ac/ctype.h>
#include <ac/unistd.h>

#include <slap.h>
#include <lber_pvt.h>
#include <slapi.h>

/*
 * use a fake listener when faking a connection,
 * so it can be used in ACLs
 */
static struct slap_listener slap_unknown_listener = {
	BER_BVC("unknown"),	/* FIXME: use a URI form? (e.g. slapi://) */
	BER_BVC("UNKNOWN")
};

static void
slapi_int_mods_free( Modifications *ml )
{
	Modifications		*next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		/* Don't free unnormalized values */
		if ( ml->sml_nvalues != NULL ) {
			ber_bvarray_free( ml->sml_nvalues );
		        ml->sml_nvalues = NULL;
		}
		slapi_ch_free((void **)&ml->sml_values);
		slapi_ch_free((void **)&ml);
	}
}

static int
slapi_int_result(
	Operation	*op, 
	SlapReply	*rs )
{
	LDAPControl		**controls = NULL;
	size_t			i;
	plugin_result_callback	prc = NULL;
	void			*callback_data = NULL;
	Slapi_PBlock		*pb = SLAPI_OPERATION_PBLOCK( op );

	assert( pb != NULL );	

	slapi_pblock_get( pb, SLAPI_RESCONTROLS,             (void **)&controls );
	slapi_pblock_get( pb, SLAPI_X_INTOP_RESULT_CALLBACK, (void **)&prc );
	slapi_pblock_get( pb, SLAPI_X_INTOP_CALLBACK_DATA,   &callback_data );

	assert( controls == NULL );

	/* Copy these before they go out of scope */
	if ( rs->sr_ctrls != NULL ) {
		for ( i = 0; rs->sr_ctrls[i] != NULL; i++ )
			;

		controls = (LDAPControl **)slapi_ch_calloc( i + 1,
			sizeof(LDAPControl ));

		for ( i = 0; rs->sr_ctrls[i] != NULL; i++ )
			controls[i] = slapi_dup_control( rs->sr_ctrls[i] );

		controls[i] = NULL;
	}

	slapi_pblock_set( pb, SLAPI_RESCONTROLS,         (void *)controls );
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs->sr_err );

	if ( prc != NULL ) {
		(*prc)( rs->sr_err, callback_data );
	}

	return LDAP_SUCCESS;
}

static int
slapi_int_search_entry(
	Operation	*op,
	SlapReply	*rs )
{
	plugin_search_entry_callback	psec = NULL;
	void				*callback_data = NULL;
	Slapi_PBlock			*pb = SLAPI_OPERATION_PBLOCK( op );
	int				rc = SLAP_CB_CONTINUE;

	assert( pb != NULL );

	slapi_pblock_get( pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK, (void **)&psec );
	slapi_pblock_get( pb, SLAPI_X_INTOP_CALLBACK_DATA,         &callback_data );

	if ( psec != NULL ) {
		rc = (*psec)( rs->sr_entry, callback_data );
	}

	return LDAP_SUCCESS;
}

static int
slapi_int_search_reference(
	Operation	*op,	
	SlapReply	*rs )
{
	int				i, rc = LDAP_SUCCESS;
	plugin_referral_entry_callback	prec = NULL;
	void				*callback_data = NULL;
	Slapi_PBlock			*pb = SLAPI_OPERATION_PBLOCK( op );

	assert( pb != NULL );

	slapi_pblock_get( pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, (void **)&prec );
	slapi_pblock_get( pb, SLAPI_X_INTOP_CALLBACK_DATA,           &callback_data );

	if ( prec != NULL ) {
		for ( i = 0; rs->sr_ref[i].bv_val != NULL; i++ ) {
			rc = (*prec)( rs->sr_ref[i].bv_val, callback_data );
			if ( rc != LDAP_SUCCESS ) {
				break;
			}
		}
	}

	return rc;
}

int
slapi_int_response( Slapi_Operation *op, SlapReply *rs )
{
	int				rc;

	switch ( rs->sr_type ) {
	case REP_RESULT:
		rc = slapi_int_result( op, rs );
		break;
	case REP_SEARCH:
		rc = slapi_int_search_entry( op, rs );
		break;
	case REP_SEARCHREF:
		rc = slapi_int_search_reference( op, rs );
		break;
	default:
		rc = LDAP_OTHER;
		break;
	}

	assert( rc != SLAP_CB_CONTINUE );

	return rc;
}

static int
slapi_int_get_ctrls( Operation *op, SlapReply *rs, LDAPControl **controls )
{
	LDAPControl		**c;
	int			rc;

	op->o_ctrls = controls;
	if ( op->o_ctrls == NULL ) {
		return LDAP_SUCCESS;
	}

	for ( c = op->o_ctrls; *c != NULL; c++ ) {
		rc = slap_parse_ctrl( op, rs, *c, &rs->sr_text );
		if ( rc != LDAP_SUCCESS )
			break;
	}

	return rc;
}

/*
 * To allow plugins to forward frontend requests to internal operations,
 * the internal operation and connection structures should import as
 * much state as practicable from the supplied parameter block.
 */

/*
 * Select the backend to be used for an internal operation, either
 * from the operation target DN or from the parameter block.
 */
static int
slapi_int_pblock_get_backend( Slapi_PBlock *pb, Operation *op )
{
	int			manageDsaIt = 0, isCritical;
	LDAPControl		**controls = NULL;
	BackendDB		*be_op;

	slapi_pblock_get( pb, SLAPI_REQCONTROLS, (void **)&controls );

	slapi_pblock_get( pb, SLAPI_MANAGEDSAIT, (void **)&manageDsaIt );
	if ( manageDsaIt != 0 )
		manageDsaIt = SLAP_CONTROL_CRITICAL;
	else if ( slapi_control_present( controls, SLAPI_CONTROL_MANAGEDSAIT_OID,
		    NULL, &isCritical ))
		manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL;

	/* let caller force a specific backend */
	slapi_pblock_get( pb, SLAPI_BACKEND, (void **)&be_op );
	if ( be_op == NULL ) {
		be_op = select_backend( &op->o_req_ndn, 0, 0 );
		slapi_pblock_set( pb, SLAPI_BACKEND, (void *)be_op );
	}

	op->o_bd = frontendDB; /* but we actually use frontend DB */

	return LDAP_SUCCESS;
}

static int
slapi_int_pblock_get_connection( Slapi_PBlock *pb, Operation *op )
{
	char			*connDn = NULL;
	Connection		*conn = op->o_conn;

	slapi_pblock_get( pb, SLAPI_X_CONN_SSF, (void **)&conn->c_ssf );
	slapi_pblock_get( pb, SLAPI_X_CONN_SASL_CONTEXT, (void **)&conn->c_sasl_authctx );

	if ( slapi_pblock_get( pb, SLAPI_CONN_DN, (void **)&connDn ) != 0
			|| connDn == NULL )
	{
		/* default to operation DN */
		conn->c_ndn = op->o_ndn;
		conn->c_dn = op->o_ndn;

	} else {
		/* NB: conn DN must be normalized */
		ber_str2bv( connDn, 0, 0, &conn->c_ndn );
		conn->c_dn = conn->c_ndn;
	}

	return LDAP_SUCCESS;
}

static int
slapi_int_pblock_get_operation( Slapi_PBlock *pb, Operation *op, SlapReply *rs )
{
	int			isRoot = 0;
	int			isUpdateDn = 0;
	char			*requestorDn = NULL;
	struct berval		targetDn = BER_BVNULL;
	LDAPControl		**controls;
	int			rc;
	BackendDB		*be_op;

	/* All internal operations must specify a target DN */
	slapi_pblock_get( pb, SLAPI_TARGET_DN, (void **)&targetDn.bv_val );
	if ( targetDn.bv_val == NULL) {
		return LDAP_PARAM_ERROR; 
	}
	targetDn.bv_len = strlen( targetDn.bv_val );

	rc = dnPrettyNormal( NULL, &targetDn, &op->o_req_dn, &op->o_req_ndn, NULL );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rc = slapi_int_pblock_get_backend( pb, op );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	slapi_pblock_get( pb, SLAPI_REQUESTOR_ISROOT, (void **)&isRoot );
	slapi_pblock_get( pb, SLAPI_REQUESTOR_ISUPDATEDN, (void **)&isUpdateDn );
	/* NB: requestor DN must be normalized */
	slapi_pblock_get( pb, SLAPI_REQUESTOR_DN, (void **)&requestorDn );
	slapi_pblock_get( pb, SLAPI_BACKEND, (void **)&be_op );

	/* Default authorization identity for internal operations is root DN */
	if ( isRoot || requestorDn == NULL ) {
		assert( be_op != NULL );
		op->o_dn = be_op->be_rootdn;
		op->o_ndn = be_op->be_rootndn;
		isRoot = 1;
	} else {
		ber_str2bv( requestorDn, 0, 0, &op->o_ndn );
		op->o_dn = op->o_ndn;
	}

	slapi_pblock_set( pb, SLAPI_REQUESTOR_ISROOT, (void *)isRoot );

	rc = slapi_int_pblock_get_connection( pb, op );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	slapi_pblock_get( pb, SLAPI_REQCONTROLS, (void **)&controls );
	rc = slapi_int_get_ctrls( op, rs, controls );
	if ( rc != LDAP_SUCCESS ) {
		return rs->sr_err;
	}

	return LDAP_SUCCESS;
}

int
slapi_int_connection_init( Slapi_PBlock *pb,
	SlapReply *rs,
	int OpType,
	Connection **pConn )
{
	Connection		*conn;
	Operation		*op;
	ber_len_t		max = sockbuf_max_incoming;
	int			rc;

	conn = (Connection *) slapi_ch_calloc( 1, sizeof(Connection) );

	LDAP_STAILQ_INIT( &conn->c_pending_ops );

	op = (Operation *) slapi_ch_calloc( 1, OPERATION_BUFFER_SIZE );
	op->o_hdr = (Opheader *)(op + 1);
	op->o_hdr->oh_extensions = NULL;
	op->o_controls = (void **)(op->o_hdr + 1);

	op->o_callback = (slap_callback *) slapi_ch_calloc( 1, sizeof(slap_callback) );
	op->o_callback->sc_response = slapi_int_response;
	op->o_callback->sc_cleanup = NULL;
	op->o_callback->sc_private = pb;
	op->o_callback->sc_next = NULL;

	conn->c_pending_ops.stqh_first = op;

	/* connection object authorization information */
	conn->c_authtype = LDAP_AUTH_NONE;
	BER_BVZERO( &conn->c_authmech );
	BER_BVZERO( &conn->c_dn );
	BER_BVZERO( &conn->c_ndn );

	conn->c_listener = &slap_unknown_listener;
	ber_dupbv( &conn->c_peer_domain, (struct berval *)&slap_unknown_bv );
	ber_dupbv( &conn->c_peer_name, (struct berval *)&slap_unknown_bv );

	LDAP_STAILQ_INIT( &conn->c_ops );

	BER_BVZERO( &conn->c_sasl_bind_mech );
	conn->c_sasl_authctx = NULL;
	conn->c_sasl_sockctx = NULL;
	conn->c_sasl_extra = NULL;

	conn->c_sb = ber_sockbuf_alloc( );

	ber_sockbuf_ctrl( conn->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );

	conn->c_currentber = NULL;

	/* should check status of thread calls */
	ldap_pvt_thread_mutex_init( &conn->c_mutex );
	ldap_pvt_thread_mutex_init( &conn->c_write_mutex );
	ldap_pvt_thread_cond_init( &conn->c_write_cv );

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );

	conn->c_n_ops_received = 0;
	conn->c_n_ops_executing = 0;
	conn->c_n_ops_pending = 0;
	conn->c_n_ops_completed = 0;

	conn->c_n_get = 0;
	conn->c_n_read = 0;
	conn->c_n_write = 0;

	conn->c_protocol = LDAP_VERSION3; 

	conn->c_activitytime = conn->c_starttime = slap_get_time();

	/*
	 * A real connection ID is required, because syncrepl associates
	 * pending CSNs with unique ( connection, operation ) tuples.
	 * Setting a fake connection ID will cause slap_get_commit_csn()
	 * to return a stale value.
	 */
	connection_assign_nextid( conn );

	conn->c_conn_state  = 0x01;	/* SLAP_C_ACTIVE */
	conn->c_struct_state = 0x02;	/* SLAP_C_USED */

	conn->c_ssf = conn->c_transport_ssf = 0;
	conn->c_tls_ssf = 0;

	backend_connection_init( conn );

	conn->c_send_ldap_result = slap_send_ldap_result;
	conn->c_send_search_entry = slap_send_search_entry;
	conn->c_send_ldap_extended = slap_send_ldap_extended;
	conn->c_send_search_reference = slap_send_search_reference;

	/* operation object */
	op->o_tag = OpType;
	op->o_protocol = LDAP_VERSION3; 
	BER_BVZERO( &op->o_authmech );
	op->o_time = slap_get_time();
	op->o_do_not_cache = 1;
	op->o_threadctx = ldap_pvt_thread_pool_context();
	op->o_tmpmemctx = NULL;
	op->o_tmpmfuncs = &ch_mfuncs;
	op->o_conn = conn;
	op->o_connid = conn->c_connid;

	rc = slapi_int_pblock_get_operation( pb, op, rs );

	slapi_pblock_set( pb, SLAPI_OPERATION, op );
	slapi_pblock_set( pb, SLAPI_CONNECTION, conn );

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	if ( rc != LDAP_SUCCESS ) {
		slapi_int_connection_destroy( &conn );
		return rc;
	}

	*pConn = conn;

	return LDAP_SUCCESS;
}

void slapi_int_connection_destroy( Connection **pConn )
{
	Connection		*conn = *pConn;
	Operation		*op;
	Slapi_PBlock		*pb;

	if ( conn == NULL ) {
		return;
	}

	op = (Operation *)conn->c_pending_ops.stqh_first;
	pb = SLAPI_OPERATION_PBLOCK( op );

	slap_graduate_commit_csn( op );

	slapi_ch_free_string( &op->o_req_dn.bv_val );
	slapi_ch_free_string( &op->o_req_ndn.bv_val );
	slapi_ch_free( (void **)&op->o_callback );

	if ( conn->c_sb != NULL ) {
		ber_sockbuf_free( conn->c_sb );
	}

	slapi_pblock_set( pb, SLAPI_OPERATION,  NULL );
	slapi_pblock_set( pb, SLAPI_CONNECTION, NULL );

	slapi_ch_free( (void **)&op );
	slapi_ch_free( (void **)pConn );
}

int
slapi_delete_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	Connection		*conn = NULL;
	Operation		*op = NULL;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	rs.sr_err = slapi_int_connection_init( pb, &rs, LDAP_REQ_DELETE, &conn );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );
		return 0;
	}

	op = conn->c_pending_ops.stqh_first;
	rs.sr_err = frontendDB->be_delete( op, &rs );

	slapi_int_connection_destroy( &conn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_add_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	Connection		*conn = NULL;
	Slapi_Entry		*entry = NULL;
	char			*dn = NULL;
	LDAPMod			**mods = NULL;
	Operation		*op = NULL;
	char			textbuf[ SLAP_TEXT_BUFLEN ];
	size_t			textlen = sizeof( textbuf );

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_ADD_ENTRY,     (void **)&entry );
	slapi_pblock_get( pb, SLAPI_ADD_TARGET,    (void **)&dn );
	slapi_pblock_get( pb, SLAPI_MODIFY_MODS,   (void **)&mods );

	if ( entry != NULL ) {
		if ( dn != NULL ) {
			rs.sr_err = LDAP_PARAM_ERROR;
			goto cleanup;
		}

		dn = slapi_entry_get_dn( entry );
		slapi_pblock_set( pb, SLAPI_ADD_TARGET, dn );
	} else if ( mods == NULL || dn == NULL ) {
		rs.sr_err = LDAP_PARAM_ERROR;
		goto cleanup;
	}

	rs.sr_err = slapi_int_connection_init( pb, &rs, LDAP_REQ_ADD, &conn );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	op = (Operation *)conn->c_pending_ops.stqh_first;
	op->ora_e = NULL;
	op->ora_modlist = NULL;

	/*
	 * The caller can specify a new entry, or a target DN and set
	 * of modifications, but not both.
	 */
	op->ora_e = (Entry *)slapi_ch_calloc( 1, sizeof(*entry) );
	ber_dupbv( &op->ora_e->e_name,  &op->o_req_dn );
	ber_dupbv( &op->ora_e->e_nname, &op->o_req_ndn );

	if ( mods != NULL ) {
		/* Entry just contains name; attributes are in modlist */
		op->ora_modlist = slapi_int_ldapmods2modifications( mods );
		if ( op->ora_modlist == NULL ) {
			rs.sr_err = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}
	} else {
		rs.sr_err = slap_entry2mods( entry, &op->ora_modlist,
			&rs.sr_text, textbuf, textlen );
		if ( rs.sr_err != LDAP_SUCCESS )
			goto cleanup;
	}

	rs.sr_err = slap_mods_check( op->ora_modlist, &rs.sr_text,
		textbuf, textlen, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
                goto cleanup;
        }

	rs.sr_err = frontendDB->be_add( op, &rs );
	if ( rs.sr_err == 0 ) {
		if ( op->ora_e != NULL && op->o_private != NULL ) {
			BackendDB	*bd = op->o_bd;

			/* could we use SLAPI_BACKEND instead? */
			op->o_bd = (BackendDB *)op->o_private;
			op->o_private = NULL;
			be_entry_release_w( op, op->ora_e );
			op->ora_e = NULL;
			op->o_bd = bd;
			op->o_private = NULL;
		}
	}

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	slapi_entry_free( op->ora_e );
	slapi_int_mods_free( op->ora_modlist );
	slapi_int_connection_destroy( &conn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_modrdn_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	struct berval		newrdn = BER_BVNULL;
	struct berval		newsupdn = BER_BVNULL;
	struct berval		newSuperiorPretty = BER_BVNULL;
	struct berval		newSuperiorNormalized = BER_BVNULL;
	Connection		*conn = NULL;
	Operation		*op = NULL;

	char			*lnewrdn;
	char			*newsuperior;
	int			deloldrdn;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_MODRDN_NEWRDN,      (void **)&lnewrdn );
	slapi_pblock_get( pb, SLAPI_MODRDN_NEWSUPERIOR, (void **)&newsuperior );
	slapi_pblock_get( pb, SLAPI_MODRDN_DELOLDRDN,   (void **)&deloldrdn );

	rs.sr_err = slapi_int_connection_init( pb, &rs, LDAP_REQ_MODRDN, &conn );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	op = (Operation *)conn->c_pending_ops.stqh_first;

	if ( op->o_req_dn.bv_len == 0 ) {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	newrdn.bv_val = lnewrdn;
	newrdn.bv_len = strlen( lnewrdn );

	rs.sr_err = dnPrettyNormal( NULL, &newrdn, &op->orr_newrdn, &op->orr_nnewrdn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( rdn_validate( &op->orr_nnewrdn ) != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( newsuperior != NULL ) {
		newsupdn.bv_val = (char *)newsuperior;
		newsupdn.bv_len = strlen( newsuperior );

		rs.sr_err = dnPrettyNormal( NULL, &newsupdn, &newSuperiorPretty, &newSuperiorNormalized, NULL );
		if ( rs.sr_err != LDAP_SUCCESS )
			goto cleanup;

		op->orr_newSup = &newSuperiorPretty;
		op->orr_nnewSup = &newSuperiorNormalized;
	} else {
		op->orr_newSup = NULL;
		op->orr_nnewSup = NULL;
	}

	op->orr_deleteoldrdn = deloldrdn;

	rs.sr_err = frontendDB->be_modrdn( op, &rs );

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	slapi_ch_free_string( &op->orr_newrdn.bv_val );
	slapi_ch_free_string( &op->orr_nnewrdn.bv_val );
	slapi_ch_free_string( &newSuperiorPretty.bv_val );
	slapi_ch_free_string( &newSuperiorNormalized.bv_val );

	slapi_int_connection_destroy( &conn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_modify_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	Connection		*conn = NULL;
	Operation		*op = NULL;
	LDAPMod			**mods = NULL;
	char			textbuf[ SLAP_TEXT_BUFLEN ];
	size_t			textlen = sizeof( textbuf );

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_MODIFY_MODS, (void **)&mods );

	if ( mods == NULL ) {
		rs.sr_err = LDAP_PARAM_ERROR ;
		goto cleanup;
	}

	rs.sr_err = slapi_int_connection_init( pb, &rs, LDAP_REQ_MODIFY, &conn );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	op = (Operation *)conn->c_pending_ops.stqh_first;

	if ( op->o_req_ndn.bv_len == 0 ) {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	op->orm_modlist = slapi_int_ldapmods2modifications( mods );

	rs.sr_err = slap_mods_check( op->orm_modlist, &rs.sr_text,
		textbuf, textlen, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
                goto cleanup;
        }

	rs.sr_err = frontendDB->be_modify( op, &rs );

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	slapi_int_mods_free( op->orm_modlist );
	slapi_int_connection_destroy( &conn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

#ifdef LDAP_SLAPI
static int
slapi_int_search_entry_callback( Slapi_Entry *entry, void *callback_data )
{
	int		nentries = 0, i = 0;
	Slapi_Entry	**head = NULL, **tp;
	Slapi_PBlock	*pb = (Slapi_PBlock *)callback_data;

	entry = slapi_entry_dup( entry );
	if ( entry == NULL ) {
		return 1;
	}

	slapi_pblock_get( pb, SLAPI_NENTRIES, &nentries );
	slapi_pblock_get( pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &head );
	
	i = nentries + 1;
	if ( nentries == 0 ) {
		tp = (Slapi_Entry **)slapi_ch_malloc( 2 * sizeof(Slapi_Entry *) );
		if ( tp == NULL ) {
			slapi_entry_free( entry );
			return 1;
		}

		tp[ 0 ] = entry;
	} else {
		tp = (Slapi_Entry **)slapi_ch_realloc( (char *)head,
				sizeof(Slapi_Entry *) * ( i + 1 ) );
		if ( tp == NULL ) {
			slapi_entry_free( entry );
			return 1;
		}
		tp[ i - 1 ] = entry;
	}
	tp[ i ] = NULL;
	          
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, (void *)tp );
	slapi_pblock_set( pb, SLAPI_NENTRIES, (void *)i );

	return LDAP_SUCCESS;
}
#endif /* LDAP_SLAPI */

int
slapi_search_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	return slapi_search_internal_callback_pb( pb,
		(void *)pb,
		NULL,
		slapi_int_search_entry_callback,
		NULL );
#else
	return -1;
#endif
}

int
slapi_search_internal_callback_pb( Slapi_PBlock *pb,
	void *callback_data,
	plugin_result_callback prc,
	plugin_search_entry_callback psec,
	plugin_referral_entry_callback prec )
{
#ifdef LDAP_SLAPI
	Connection		*conn = NULL;
	Operation		*op = NULL;
	Filter			*filter = NULL;
	struct berval		fstr = BER_BVNULL;
	AttributeName		*an = NULL;
	const char		*text = NULL;

	int			scope = LDAP_SCOPE_BASE;
	char			*filStr = NULL;
	char			**attrs = NULL;
	int			attrsonly = 0;
	int			freeFilter = 0;
	int			i;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_SEARCH_SCOPE,     (void **)&scope );
	slapi_pblock_get( pb, SLAPI_SEARCH_FILTER,    (void **)&filter );
	slapi_pblock_get( pb, SLAPI_SEARCH_STRFILTER, (void **)&filStr );
	slapi_pblock_get( pb, SLAPI_SEARCH_ATTRS,     (void **)&attrs );
	slapi_pblock_get( pb, SLAPI_SEARCH_ATTRSONLY, (void **)&attrsonly );

	rs.sr_err = slapi_int_connection_init( pb, &rs, LDAP_REQ_SEARCH, &conn );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* search callback and arguments */
	slapi_pblock_set( pb, SLAPI_X_INTOP_RESULT_CALLBACK,         (void *)prc );
	slapi_pblock_set( pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK,   (void *)psec );
	slapi_pblock_set( pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, (void *)prec );
	slapi_pblock_set( pb, SLAPI_X_INTOP_CALLBACK_DATA,           (void *)callback_data );

	op = (Operation *)conn->c_pending_ops.stqh_first;

	switch ( scope ) {
		case LDAP_SCOPE_BASE:
		case LDAP_SCOPE_ONELEVEL:
		case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_SCOPE_SUBORDINATE
		case LDAP_SCOPE_SUBORDINATE:
#endif
			break;
		default:
			rs.sr_err = LDAP_PROTOCOL_ERROR;
			goto cleanup;
	}

	if ( filter == NULL ) {
		if ( filStr == NULL ) {
			rs.sr_err = LDAP_PARAM_ERROR;
			goto cleanup;
		}

		filter = slapi_str2filter( filStr );
		if ( filter == NULL ) {
			rs.sr_err = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}

		freeFilter = 1;
	}

	filter2bv( filter, &fstr );

	for ( i = 0; attrs != NULL && attrs[i] != NULL; i++ ) {
		; /* count the number of attributes */
	}

	if ( i > 0 ) {
		an = (AttributeName *)slapi_ch_calloc( (i + 1), sizeof(AttributeName) );
		for (i = 0; attrs[i] != 0; i++) {
			an[i].an_desc = NULL;
			an[i].an_oc = NULL;
			an[i].an_oc_exclude = 0;
			an[i].an_name.bv_val = attrs[i];
			an[i].an_name.bv_len = strlen(attrs[i]);
			slap_bv2ad( &an[i].an_name, &an[i].an_desc, &text );
		}
		an[i].an_name.bv_val = NULL;
	}

	rs.sr_type = REP_RESULT;
	rs.sr_err = LDAP_SUCCESS;
	rs.sr_entry = NULL; /* paranoia */
	op->ors_scope = scope;
	op->ors_deref = 0;
	op->ors_slimit = SLAP_NO_LIMIT;
	op->ors_tlimit = SLAP_NO_LIMIT;
	op->ors_attrsonly = attrsonly;
	op->ors_attrs = an;
	op->ors_filter = filter;
	op->ors_filterstr = fstr;

	rs.sr_err = frontendDB->be_search( op, &rs );

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT,            (void *)rs.sr_err );
	slapi_pblock_set( pb, SLAPI_X_INTOP_RESULT_CALLBACK,         NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK,   NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_CALLBACK_DATA,           NULL );

	if ( freeFilter && filter != NULL )
		slapi_filter_free( filter, 1 );
	slapi_ch_free_string( &fstr.bv_val );
	slapi_ch_free( (void **)&an );

	slapi_int_connection_destroy( &conn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/* Wrappers for old API */

void
slapi_search_internal_set_pb( Slapi_PBlock *pb,
	const char *base,
	int scope,
	const char *filter,
	char **attrs,
	int attrsonly,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_SEARCH_TARGET,    (void *)base );
	slapi_pblock_set( pb, SLAPI_SEARCH_SCOPE,     (void *)scope );
	slapi_pblock_set( pb, SLAPI_SEARCH_FILTER,     NULL );
	slapi_pblock_set( pb, SLAPI_SEARCH_STRFILTER, (void *)filter );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRS,     (void *)attrs );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRSONLY, (void *)attrsonly );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,      (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID,  (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY,  (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,    (void *)operation_flags );
#endif /* LDAP_SLAPI */
}

Slapi_PBlock *
slapi_search_internal(
	char *ldn, 
	int scope, 
	char *filStr, 
	LDAPControl **controls, 
	char **attrs, 
	int attrsonly ) 
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL ) {
		return NULL;
	}

	slapi_search_internal_set_pb( pb, ldn, scope, filStr, attrs, attrsonly,
		controls, NULL, NULL, 0 );

	slapi_search_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void
slapi_modify_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPMod **mods,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_MODIFY_TARGET,   (void *)dn );
	slapi_pblock_set( pb, SLAPI_MODIFY_MODS,     (void *)mods );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,     (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,   (void *)operation_flags );
#endif /* LDAP_SLAPI */
}

/* Function : slapi_modify_internal
 *
 * Description:	Plugin functions call this routine to modify an entry 
 *				in the backend directly
 * Return values : LDAP_SUCCESS
 *                 LDAP_PARAM_ERROR
 *                 LDAP_NO_MEMORY
 *                 LDAP_OTHER
 *                 LDAP_UNWILLING_TO_PERFORM
*/
Slapi_PBlock *
slapi_modify_internal(
	char *ldn, 	
	LDAPMod **mods, 
	LDAPControl **controls, 
	int log_change )
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL ) {
		return NULL;
	}

	slapi_modify_internal_set_pb( pb, ldn, mods, controls, NULL, NULL,
		log_change ? SLAPI_OP_FLAG_LOG_CHANGE : 0 );

	slapi_modify_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

int
slapi_add_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPMod **attrs,
	LDAPControl **controls,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_ADD_TARGET,      (void *)dn );
	slapi_pblock_set( pb, SLAPI_MODIFY_MODS,     (void *)attrs );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,     (void *)controls );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,   (void *)operation_flags );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_PBlock *
slapi_add_internal(
	char * dn,
	LDAPMod **attrs,
	LDAPControl **controls,
	int log_changes )
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL )
		return NULL;

	slapi_add_internal_set_pb( pb, dn, attrs, controls, NULL,
		log_changes ? SLAPI_OP_FLAG_LOG_CHANGE : 0 );
	
	slapi_add_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void
slapi_add_entry_internal_set_pb( Slapi_PBlock *pb,
	Slapi_Entry *e,
	LDAPControl **controls,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_ADD_ENTRY,       (void *)e );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,     (void *)controls );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,   (void *)operation_flags );
#endif /* LDAP_SLAPI */
}

Slapi_PBlock * 
slapi_add_entry_internal(
	Slapi_Entry *e, 
	LDAPControl **controls, 
	int log_changes )
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL )
		return NULL;

	slapi_add_entry_internal_set_pb( pb, e, controls, NULL,
		log_changes ? SLAPI_OP_FLAG_LOG_CHANGE : 0 );
	
	slapi_add_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void
slapi_rename_internal_set_pb( Slapi_PBlock *pb,
	const char *olddn,
	const char *newrdn,
	const char *newsuperior,
	int deloldrdn,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_MODRDN_TARGET,      (void *)olddn );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWRDN,      (void *)newrdn );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWSUPERIOR, (void *)newsuperior );
	slapi_pblock_set( pb, SLAPI_MODRDN_DELOLDRDN,   (void *)deloldrdn );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,        (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID,    (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY,    (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,      (void *)operation_flags );
#endif /* LDAP_SLAPI */
}

/* Function : slapi_modrdn_internal
 *
 * Description : Plugin functions call this routine to modify the rdn 
 *				 of an entry in the backend directly
 * Return values : LDAP_SUCCESS
 *                 LDAP_PARAM_ERROR
 *                 LDAP_NO_MEMORY
 *                 LDAP_OTHER
 *                 LDAP_UNWILLING_TO_PERFORM
 *
 * NOTE: This function does not support the "newSuperior" option from LDAP V3.
 */
Slapi_PBlock *
slapi_modrdn_internal(
	char *olddn, 
	char *lnewrdn, 
	int deloldrdn, 
	LDAPControl **controls, 
	int log_change )
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL ) {
		return NULL;
	}

	slapi_rename_internal_set_pb( pb, olddn, lnewrdn, NULL,
		deloldrdn, controls, NULL, NULL,
		log_change ? SLAPI_OP_FLAG_LOG_CHANGE : 0 );

	slapi_modrdn_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

void
slapi_delete_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_TARGET_DN,       (void *)dn );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS,     (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS,   (void *)operation_flags );
#endif /* LDAP_SLAPI */
}

/* Function : slapi_delete_internal
 *
 * Description : Plugin functions call this routine to delete an entry 
 *               in the backend directly
 * Return values : LDAP_SUCCESS
 *                 LDAP_PARAM_ERROR
 *                 LDAP_NO_MEMORY
 *                 LDAP_OTHER
 *                 LDAP_UNWILLING_TO_PERFORM
*/
Slapi_PBlock *
slapi_delete_internal(
	char *ldn, 
	LDAPControl **controls, 
	int log_change )
{
#ifdef LDAP_SLAPI
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if ( pb == NULL )
		return NULL;

	slapi_delete_internal_set_pb( pb, ldn, controls, NULL, NULL,
		log_change ? SLAPI_OP_FLAG_LOG_CHANGE : 0 );

	slapi_delete_internal_pb( pb );

	return pb;
#else
	return NULL;
#endif /* LDAP_SLAPI */
}

