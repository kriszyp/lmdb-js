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
slapi_int_send_ldap_result_shim(
	Operation	*op, 
	SlapReply	*rs )
{
	LDAPControl		**controls = NULL;
	size_t			i;
	plugin_result_callback	prc = NULL;
	void			*callback_data = NULL;

	assert( op->o_pb != NULL );

	slapi_pblock_get( op->o_pb, SLAPI_RESCONTROLS, (void **)&controls );
	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_RESULT_CALLBACK, (void **)&prc );
	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_CALLBACK_DATA, &callback_data );

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

	slapi_pblock_set( op->o_pb, SLAPI_RESCONTROLS, (void *)controls );
	slapi_pblock_set( op->o_pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs->sr_err );

	if ( prc != NULL ) {
		(*prc)( rs->sr_err, callback_data );
	}

	return;
}

static int
slapi_int_send_search_entry_shim(
	Operation	*op,
	SlapReply	*rs )
{
	plugin_search_entry_callback	psec = NULL;
	void				*callback_data = NULL;

	assert( op->o_pb != NULL );

	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK, &psec );
	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_CALLBACK_DATA, &callback_data );

	if ( psec != NULL ) {
		return (*psec)( rs->sr_entry, callback_data );
	}

	return LDAP_SUCCESS;
}

static void
slapi_int_send_ldap_extended_shim(
	Operation	*op,	
	SlapReply	*rs )
{
	assert( op->o_pb != NULL );

	return;
}

static int
slapi_int_send_search_reference_shim(
	Operation	*op,	
	SlapReply	*rs )
{
	int				i, rc = LDAP_SUCCESS;
	plugin_referral_entry_callback	prec = NULL;
	void				*callback_data = NULL;

	assert( op->o_pb != NULL );

	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, &prec );
	slapi_pblock_get( op->o_pb, SLAPI_X_INTOP_CALLBACK_DATA, &callback_data );

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

Connection *
slapi_int_init_connection(
	char *DN, 
	int OpType ) 
{ 
	Connection *pConn;
	Operation *op;
	ber_len_t max = sockbuf_max_incoming;

	pConn = (Connection *) slapi_ch_calloc(1, sizeof(Connection));

	LDAP_STAILQ_INIT( &pConn->c_pending_ops );

	op = (Operation *) slapi_ch_calloc( 1, OPERATION_BUFFER_SIZE );
	op->o_hdr = (Opheader *)(op + 1);
	op->o_controls = (void **)(op->o_hdr + 1);

	pConn->c_pending_ops.stqh_first = op;
	pConn->c_pending_ops.stqh_first->o_pb = NULL;
	pConn->c_pending_ops.stqh_first->o_extensions = NULL;

	/* connection object */
	pConn->c_authmech.bv_val = NULL;
	pConn->c_authmech.bv_len = 0;
	pConn->c_dn.bv_val = NULL;
	pConn->c_dn.bv_len = 0;
	pConn->c_ndn.bv_val = NULL;
	pConn->c_ndn.bv_len = 0;

	pConn->c_listener = &slap_unknown_listener;
	ber_dupbv( &pConn->c_peer_domain, (struct berval *)&slap_unknown_bv );
	ber_dupbv( &pConn->c_peer_name, (struct berval *)&slap_unknown_bv );

	LDAP_STAILQ_INIT( &pConn->c_ops );

	pConn->c_sasl_bind_mech.bv_val = NULL;
	pConn->c_sasl_bind_mech.bv_len = 0;
	pConn->c_sasl_authctx = NULL;
	pConn->c_sasl_sockctx = NULL;
	pConn->c_sasl_extra = NULL;

	pConn->c_sb = ber_sockbuf_alloc( );

	ber_sockbuf_ctrl( pConn->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );

	pConn->c_currentber = NULL;

	/* should check status of thread calls */
	ldap_pvt_thread_mutex_init( &pConn->c_mutex );
	ldap_pvt_thread_mutex_init( &pConn->c_write_mutex );
	ldap_pvt_thread_cond_init( &pConn->c_write_cv );

	ldap_pvt_thread_mutex_lock( &pConn->c_mutex );

	pConn->c_n_ops_received = 0;
	pConn->c_n_ops_executing = 0;
	pConn->c_n_ops_pending = 0;
	pConn->c_n_ops_completed = 0;

	pConn->c_n_get = 0;
	pConn->c_n_read = 0;
	pConn->c_n_write = 0;

	pConn->c_protocol = LDAP_VERSION3; 

	pConn->c_activitytime = pConn->c_starttime = slap_get_time();

	/*
	 * A real connection ID is required, because syncrepl associates
	 * pending CSNs with unique ( connection, operation ) tuples.
	 * Setting a fake connection ID will cause slap_get_commit_csn()
	 * to return a stale value.
	 */
	connection_assign_nextid( pConn );

	pConn->c_conn_state  = 0x01;	/* SLAP_C_ACTIVE */
	pConn->c_struct_state = 0x02;	/* SLAP_C_USED */

	pConn->c_ssf = pConn->c_transport_ssf = 0;
	pConn->c_tls_ssf = 0;

	backend_connection_init( pConn );

	pConn->c_send_ldap_result = slapi_int_send_ldap_result_shim;
	pConn->c_send_search_entry = slapi_int_send_search_entry_shim;
	pConn->c_send_ldap_extended = slapi_int_send_ldap_extended_shim;
	pConn->c_send_search_reference = slapi_int_send_search_reference_shim;

	/* operation object */
	pConn->c_pending_ops.stqh_first->o_tag = OpType;
	pConn->c_pending_ops.stqh_first->o_protocol = LDAP_VERSION3; 
	pConn->c_pending_ops.stqh_first->o_authmech.bv_val = NULL; 
	pConn->c_pending_ops.stqh_first->o_authmech.bv_len = 0; 
	pConn->c_pending_ops.stqh_first->o_time = slap_get_time();
	pConn->c_pending_ops.stqh_first->o_do_not_cache = 1;
	pConn->c_pending_ops.stqh_first->o_threadctx = ldap_pvt_thread_pool_context();
	pConn->c_pending_ops.stqh_first->o_tmpmemctx = NULL;
	pConn->c_pending_ops.stqh_first->o_tmpmfuncs = &ch_mfuncs;
	pConn->c_pending_ops.stqh_first->o_conn = pConn;
	pConn->c_pending_ops.stqh_first->o_connid = pConn->c_connid;

	ldap_pvt_thread_mutex_unlock( &pConn->c_mutex );

	return pConn;
}

void slapi_int_connection_destroy( Connection **pConn )
{
	Connection *conn = *pConn;
	Operation *op;

	if ( pConn == NULL ) {
		return;
	}

	op = (Operation *)conn->c_pending_ops.stqh_first;

	slap_graduate_commit_csn( op );

	if ( op->o_req_dn.bv_val != NULL ) {
		slapi_ch_free( (void **)&op->o_req_dn.bv_val );
	}
	if ( op->o_req_ndn.bv_val != NULL ) {
		slapi_ch_free( (void **)&op->o_req_ndn.bv_val );
	}

	if ( conn->c_sb != NULL ) {
		ber_sockbuf_free( conn->c_sb );
	}
	if ( op != NULL ) {
		slapi_ch_free( (void **)&op );
	}
	slapi_ch_free( (void **)pConn );
}

/*
 * Function : values2obj
 * Convert an array of strings into a BerVarray.
 * the strings.
 */
static int
values2obj_copy(
	char **ppValue,
	BerVarray *bvobj )
{
	int i;
	BerVarray tmpberval;

	if ( ppValue == NULL ) {
		*bvobj = NULL;
		return LDAP_SUCCESS;
	}

	for ( i = 0; ppValue[i] != NULL; i++ )
		; /* EMPTY */

	tmpberval = (BerVarray)slapi_ch_malloc( (i+1) * (sizeof(struct berval)) );
	if ( tmpberval == NULL ) {
		return LDAP_NO_MEMORY;
	}
	for ( i = 0; ppValue[i] != NULL; i++ ) {
		size_t len = strlen( ppValue[i] );

		tmpberval[i].bv_val = slapi_ch_malloc( len + 1 );
		AC_MEMCPY( tmpberval[i].bv_val, ppValue[i], len + 1 );
		tmpberval[i].bv_len = len;
	}
	tmpberval[i].bv_val = NULL;
	tmpberval[i].bv_len = 0;

	*bvobj = tmpberval;

	return LDAP_SUCCESS;
}

static int
bvptr2obj_copy(
	struct berval	**bvptr, 
	BerVarray	*bvobj )
{
	int		i;
	BerVarray	tmpberval;

	if ( bvptr == NULL ) {
		*bvobj = NULL;
		return LDAP_SUCCESS;
	}

	for ( i = 0; bvptr[i] != NULL; i++ )
		; /* EMPTY */

	tmpberval = (BerVarray)slapi_ch_malloc( (i + 1) * sizeof(struct berval));
	if ( tmpberval == NULL ) {
		return LDAP_NO_MEMORY;
	} 

	for ( i = 0; bvptr[i] != NULL; i++ ) {
		tmpberval[i].bv_val = slapi_ch_malloc( bvptr[i]->bv_len );
		tmpberval[i].bv_len = bvptr[i]->bv_len;
		AC_MEMCPY( tmpberval[i].bv_val, bvptr[i]->bv_val, bvptr[i]->bv_len );
	}

	tmpberval[i].bv_val = NULL;
	tmpberval[i].bv_len = 0;

	*bvobj = tmpberval;

	return LDAP_SUCCESS;
}

/*
 * Function : slapi_int_ldapmod_to_entry 
 * convert a dn plus an array of LDAPMod struct ptrs to an entry structure
 * with a link list of the correspondent attributes.
 * Return value : LDAP_SUCCESS
 *                LDAP_NO_MEMORY
 *                LDAP_OTHER
*/
static Entry *
slapi_int_ldapmod_to_entry(
	Connection *pConn,
	char *ldn, 
	LDAPMod **mods )
{
	struct berval		dn = BER_BVNULL;
	Entry			*pEntry=NULL;
	LDAPMod			*pMod;
	struct berval		*bv;
	Operation		*op;

	Modifications		*modlist = NULL;
	Modifications		**modtail = &modlist;
	Modifications		tmp;

	int			rc = LDAP_SUCCESS;
	int			i;

	const char 		*text = NULL;

	op = (Operation *)pConn->c_pending_ops.stqh_first;

	pEntry = (Entry *) ch_calloc( 1, sizeof(Entry) );
	if ( pEntry == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	} 

	dn.bv_val = ldn;
	dn.bv_len = strlen(ldn);

	rc = dnPrettyNormal( NULL, &dn, &pEntry->e_name, &pEntry->e_nname, NULL );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( rc == LDAP_SUCCESS ) {
		for ( i = 0, pMod = mods[0]; rc == LDAP_SUCCESS && pMod != NULL; pMod = mods[++i]) {
			Modifications *mod;

			if ( (pMod->mod_op & LDAP_MOD_BVALUES) != 0 ) {
				/*
				 * Convert an array of pointers to bervals to
				 * an array of bervals. Note that we need to copy the
				 * values too, as the slap_mods_check() will free the
			 	 * original values after prettying; the modifications
				 * being passed in may not have been allocated on the
				 * heap.
				 */
				rc = bvptr2obj_copy( pMod->mod_bvalues, &bv );
				if ( rc != LDAP_SUCCESS ) goto cleanup;
				tmp.sml_type.bv_val = pMod->mod_type;
				tmp.sml_type.bv_len = strlen( pMod->mod_type );
				tmp.sml_values = bv;
				tmp.sml_nvalues = NULL;
		
				mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

				mod->sml_op = LDAP_MOD_ADD;
				mod->sml_flags = 0;
				mod->sml_next = NULL;
				mod->sml_desc = NULL;
				mod->sml_type = tmp.sml_type;
				mod->sml_values = tmp.sml_values;
				mod->sml_nvalues = tmp.sml_nvalues;

				*modtail = mod;
				modtail = &mod->sml_next;

			} else {
				/* attr values are in string format, need to be converted */
				/* to an array of bervals */ 
				if ( pMod->mod_values == NULL ) {
					rc = LDAP_OTHER;
				} else {
					rc = values2obj_copy( pMod->mod_values, &bv );
					if ( rc != LDAP_SUCCESS ) goto cleanup;
					tmp.sml_type.bv_val = pMod->mod_type;
					tmp.sml_type.bv_len = strlen( pMod->mod_type );
					tmp.sml_values = bv;
					tmp.sml_nvalues = NULL;
		
					mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

					mod->sml_op = LDAP_MOD_ADD;
					mod->sml_flags = 0;
					mod->sml_next = NULL;
					mod->sml_desc = NULL;
					mod->sml_type = tmp.sml_type;
					mod->sml_values = tmp.sml_values;
					mod->sml_nvalues = tmp.sml_nvalues;

					*modtail = mod;
					modtail = &mod->sml_next;
				}
			}
		} /* for each LDAPMod */
	}

	op->o_bd = select_backend( &pEntry->e_nname, 0, 0 );
	if ( op->o_bd == NULL ) {
		rc = LDAP_PARTIAL_RESULTS;
	} else {
		int repl_user = be_isupdate_dn( op->o_bd, &op->o_bd->be_rootdn );
        	if ( !op->o_bd->be_update_ndn.bv_len || repl_user ) {
			int	update = !BER_BVISNULL( &op->o_bd->be_update_ndn );
			char	textbuf[ SLAP_TEXT_BUFLEN ];
			size_t	textlen = sizeof( textbuf );

			rc = slap_mods_check( modlist, &text, 
				textbuf, textlen, NULL );

			if ( rc != LDAP_SUCCESS) {
				goto cleanup;
			}

			if ( !update ) {
				rc = slap_mods_no_user_mod_check( op, modlist,
					&text, textbuf, textlen );
				if ( rc != LDAP_SUCCESS) {
					goto cleanup;
				}
			}

			if ( !repl_user ) {
				rc = slap_mods_opattrs( op, modlist, modtail,
					&text, textbuf, textlen, 1 );
				if ( rc != LDAP_SUCCESS) {
					goto cleanup;
				}
			}

			rc = slap_mods2entry( modlist, &pEntry, repl_user,
					      0, &text, textbuf, textlen );
			if (rc != LDAP_SUCCESS) {
				goto cleanup;
			}

		} else {
			rc = LDAP_REFERRAL;
		}
	}

cleanup:;
	if ( modlist != NULL )
		slap_mods_free( modlist );
	if ( rc != LDAP_SUCCESS ) {
		if ( pEntry != NULL ) {
			slapi_entry_free( pEntry );
		}
		pEntry = NULL;
	}

	return( pEntry );
}

static int
slapi_int_get_ctrls( Operation *op, SlapReply *rs, LDAPControl **controls )
{
	LDAPControl **c;
	int rc;

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

int
slapi_delete_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	Connection		*pConn = NULL;
	Operation		*op = NULL;
	struct berval		dn = BER_BVNULL;
	char			*ldn = NULL;
	LDAPControl		**controls = NULL;
	int			manageDsaIt = SLAP_CONTROL_NONE;
	int			operation_flags = 0;
	int			isCritical;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_TARGET_DN, &ldn );
	slapi_pblock_get( pb, SLAPI_REQCONTROLS, &controls );
	slapi_pblock_get( pb, SLAPI_X_INTOP_FLAGS, &operation_flags );

	if ( ldn == NULL ) {
		rs.sr_err = LDAP_PARAM_ERROR; 
		goto cleanup;
	}

	pConn = slapi_int_init_connection( NULL, LDAP_REQ_DELETE );
	if (pConn == NULL) {
		rs.sr_err = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	op->o_pb = pb;

	rs.sr_err = slapi_int_get_ctrls( op, &rs, controls );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	dn.bv_val = ldn;
	dn.bv_len = strlen(ldn);

	rs.sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical) ) {
		manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL; 
	}

	op->o_bd = select_backend( &op->o_req_ndn, manageDsaIt, 1 );
	if ( op->o_bd == NULL ) {
		rs.sr_err = LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_dn = pConn->c_dn = op->o_bd->be_rootdn;
	op->o_ndn = pConn->c_ndn = op->o_bd->be_rootndn;

	if ( op->o_bd->be_delete ) {
		int repl_user = be_isupdate( op );
		if ( !op->o_bd->be_update_ndn.bv_len || repl_user ) {
			slap_callback cb = { NULL, slap_replog_cb, NULL, NULL };
			if ( operation_flags & SLAPI_OP_FLAG_LOG_CHANGE )
				op->o_callback = &cb;

			op->o_bd->be_delete( op, &rs );
        	} else {
			rs.sr_err = LDAP_REFERRAL;
        	}
	} else {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	slapi_int_connection_destroy( &pConn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_add_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	Connection		*pConn = NULL;
	Slapi_Entry		*entry = NULL;
	Slapi_Entry		*argEntry = NULL;
	char			*dn = NULL;
	LDAPMod			**mods = NULL;
	LDAPControl		**controls = NULL;
	int			operation_flags = 0;
	Operation		*op = NULL;

	int			manageDsaIt = SLAP_CONTROL_NONE;
	int			isCritical;
	int			freeEntry = 0;
	int			i;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	pConn = slapi_int_init_connection( NULL, LDAP_REQ_ADD );
	if ( pConn == NULL ) {
		rs.sr_err = LDAP_OTHER;
		goto cleanup;
	}

	slapi_pblock_get( pb, SLAPI_ADD_TARGET, &dn );
	slapi_pblock_get( pb, SLAPI_ADD_ENTRY, &argEntry );
	slapi_pblock_get( pb, SLAPI_MODIFY_MODS, &mods );
	slapi_pblock_get( pb, SLAPI_REQCONTROLS, &controls );
	slapi_pblock_get( pb, SLAPI_X_INTOP_FLAGS, &operation_flags );

	if ( argEntry != NULL ) {
		entry = slapi_entry_dup( argEntry );
		dn = slapi_entry_get_dn( argEntry );
	} else {
		if ( mods == NULL || dn == NULL ) {
			rs.sr_err = LDAP_PARAM_ERROR;
			goto cleanup;
		}

		for ( i = 0; mods[i] != NULL; i++ ) {
			if ( (mods[i]->mod_op & LDAP_MOD_OP ) != LDAP_MOD_ADD ) {
				rs.sr_err = LDAP_OTHER;
				goto cleanup;
			}
		}

		entry = slapi_int_ldapmod_to_entry( pConn, dn, mods );
		if ( entry == NULL ) {
			rs.sr_err = LDAP_OTHER;
			goto cleanup;
		}
	}

	if ( slapi_control_present( controls, LDAP_CONTROL_MANAGEDSAIT,
				NULL, &isCritical ) ) {
		manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL; 
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	op->o_pb = pb;

	rs.sr_err = slapi_int_get_ctrls( op, &rs, controls );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	op->o_bd = select_backend( &entry->e_nname, manageDsaIt, 1 );
	if ( op->o_bd == NULL ) {
		rs.sr_err = LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_dn = pConn->c_dn = op->o_bd->be_rootdn;
	op->o_ndn = pConn->c_ndn = op->o_bd->be_rootndn;
	op->oq_add.rs_e = entry;

	if ( op->o_bd->be_add ) {
		int repl_user = be_isupdate( op );
		if ( !op->o_bd->be_update_ndn.bv_len || repl_user ) {
			slap_callback cb = { NULL, slap_replog_cb, NULL, NULL };

			if ( operation_flags & SLAPI_OP_FLAG_LOG_CHANGE )
				op->o_callback = &cb;

			if ( op->o_bd->be_add( op, &rs ) == LDAP_SUCCESS ) {
				be_entry_release_w( op, entry );
				entry = NULL;
			}
		} else {
			rs.sr_err = LDAP_REFERRAL;
		}
	} else {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	if ( entry != NULL ) {
		slapi_entry_free( entry );
	}

	slapi_int_connection_destroy( &pConn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int
slapi_modrdn_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	struct berval		dn = BER_BVNULL;
	struct berval		newrdn = BER_BVNULL;
	struct berval		newsupdn = BER_BVNULL;
	struct berval		newSuperiorPretty = BER_BVNULL;
	struct berval		newSuperiorNormalized = BER_BVNULL;
	Connection		*pConn = NULL;
	Operation		*op = NULL;
	int			manageDsaIt = SLAP_CONTROL_NONE;
	int			isCritical;

	char			*olddn;
	char			*lnewrdn;
	char			*newsuperior;
	int			deloldrdn;
	LDAPControl		**controls;
	int			operation_flags;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_MODRDN_TARGET, &olddn );
	slapi_pblock_get( pb, SLAPI_MODRDN_NEWRDN, &lnewrdn );
	slapi_pblock_get( pb, SLAPI_MODRDN_NEWSUPERIOR, &newsuperior );
	slapi_pblock_get( pb, SLAPI_MODRDN_DELOLDRDN, &deloldrdn );
	slapi_pblock_get( pb, SLAPI_REQCONTROLS, &controls );
#if 0
	slapi_pblock_get( pb, SLAPI_TARGET_UNIQUEID, uniqueid );
	slapi_pblock_get( pb, SLAPI_PLUGIN_IDENTITY, plugin_identity );
#endif
	slapi_pblock_get( pb, SLAPI_X_INTOP_FLAGS, &operation_flags );

	pConn = slapi_int_init_connection( NULL, LDAP_REQ_MODRDN );
	if ( pConn == NULL) {
		rs.sr_err = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	op->o_pb = pb;

	rs.sr_err = slapi_int_get_ctrls( op, &rs, controls );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical ) ) {
		manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL; 
	}

	dn.bv_val = (char *)olddn;
	dn.bv_len = strlen( olddn );

	rs.sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( op->o_req_dn.bv_len == 0 ) {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	op->o_bd = select_backend( &op->o_req_ndn, manageDsaIt, 1 );
	if ( op->o_bd == NULL ) {
		rs.sr_err =  LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_dn = pConn->c_dn = op->o_bd->be_rootdn;
	op->o_ndn = pConn->c_ndn = op->o_bd->be_rootndn;

	newrdn.bv_val = (char *)lnewrdn;
	newrdn.bv_len = strlen( lnewrdn );

	rs.sr_err = dnPrettyNormal( NULL, &newrdn, &op->oq_modrdn.rs_newrdn, &op->oq_modrdn.rs_nnewrdn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( rdn_validate( &op->oq_modrdn.rs_nnewrdn ) != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( newsuperior != NULL ) {
		newsupdn.bv_val = (char *)newsuperior;
		newsupdn.bv_len = strlen( newsuperior );

		rs.sr_err = dnPrettyNormal( NULL, &newsupdn, &newSuperiorPretty, &newSuperiorNormalized, NULL );
		if ( rs.sr_err != LDAP_SUCCESS )
			goto cleanup;

		op->oq_modrdn.rs_newSup = &newSuperiorPretty;
		op->oq_modrdn.rs_nnewSup = &newSuperiorNormalized;
	} else {
		op->oq_modrdn.rs_newSup = NULL;
		op->oq_modrdn.rs_nnewSup = NULL;
	}

	op->oq_modrdn.rs_deleteoldrdn = deloldrdn;

	if ( op->o_bd->be_modrdn ) {
		int repl_user = be_isupdate( op );
		if ( !op->o_bd->be_update_ndn.bv_len || repl_user ) {
			slap_callback cb = { NULL, slap_replog_cb, NULL, NULL };

			if ( operation_flags & SLAPI_OP_FLAG_LOG_CHANGE )
				op->o_callback = &cb;

			op->o_bd->be_modrdn( op, &rs );
		} else {
			rs.sr_err = LDAP_REFERRAL;
		}
	} else {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	if ( op->oq_modrdn.rs_newrdn.bv_val != NULL )
		slapi_ch_free( (void **)&op->oq_modrdn.rs_newrdn.bv_val );
	if ( op->oq_modrdn.rs_nnewrdn.bv_val != NULL )
		slapi_ch_free( (void **)&op->oq_modrdn.rs_nnewrdn.bv_val );
	if ( newSuperiorPretty.bv_val != NULL )
		slapi_ch_free( (void **)&newSuperiorPretty.bv_val );
	if ( newSuperiorNormalized.bv_val != NULL )
		slapi_ch_free( (void **)&newSuperiorNormalized.bv_val );

	slapi_int_connection_destroy( &pConn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

int slapi_modify_internal_pb( Slapi_PBlock *pb )
{
#ifdef LDAP_SLAPI
	int			i;
	Connection		*pConn = NULL;
	Operation		*op = NULL;

	struct berval dn = BER_BVNULL;

	int			manageDsaIt = SLAP_CONTROL_NONE;
	int			isCritical;
	struct berval		*bv;
	LDAPMod			*pMod;

	Modifications		*modlist = NULL;
	Modifications		**modtail = &modlist;
	Modifications		tmp;

	char			*ldn = NULL;
	LDAPMod			**mods = NULL;
	LDAPControl		**controls = NULL;
	int			operation_flags = 0;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_MODIFY_TARGET, &ldn );
	slapi_pblock_get( pb, SLAPI_MODIFY_MODS, &mods );
	slapi_pblock_get( pb, SLAPI_REQCONTROLS, &controls );
#if 0
	slapi_pblock_get( pb, SLAPI_TARGET_UNIQUEID, uniqueid );
	slapi_pblock_get( pb, SLAPI_PLUGIN_IDENTITY, plugin_identity );
#endif
	slapi_pblock_get( pb, SLAPI_X_INTOP_FLAGS, &operation_flags );

	if ( mods == NULL || *mods == NULL || ldn == NULL ) {
		rs.sr_err = LDAP_PARAM_ERROR ;
		goto cleanup;
	}

	pConn = slapi_int_init_connection( NULL,  LDAP_REQ_MODIFY );
	if ( pConn == NULL ) {
		rs.sr_err = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	op->o_pb = pb;

	rs.sr_err = slapi_int_get_ctrls( op, &rs, controls );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	dn.bv_val = ldn;
	dn.bv_len = strlen( ldn );

	rs.sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical ) ) {
        	manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL; 
	}

	op->o_bd = select_backend( &op->o_req_ndn, manageDsaIt, 1 );
	if ( op->o_bd == NULL ) {
		rs.sr_err = LDAP_PARTIAL_RESULTS;
		goto cleanup;
    	}

	op->o_dn = pConn->c_dn = op->o_bd->be_rootdn;
	op->o_ndn = pConn->c_ndn = op->o_bd->be_rootndn;

	for ( i = 0, pMod = mods[0];
		rs.sr_err == LDAP_SUCCESS && pMod != NULL; 
		pMod = mods[++i] )
	{
		Modifications *mod;

		if ( (pMod->mod_op & LDAP_MOD_BVALUES) != 0 ) {
			/*
			 * attr values are in berval format
			 * convert an array of pointers to bervals
			 * to an array of bervals
			 */
			rs.sr_err = bvptr2obj_copy( pMod->mod_bvalues, &bv );
			if ( rs.sr_err != LDAP_SUCCESS )
				goto cleanup;
			tmp.sml_type.bv_val = pMod->mod_type;
			tmp.sml_type.bv_len = strlen( pMod->mod_type );
			tmp.sml_values = bv;
			tmp.sml_nvalues = NULL;

			mod  = (Modifications *)ch_malloc( sizeof(Modifications) );

			mod->sml_op = pMod->mod_op & LDAP_MOD_OP;
			mod->sml_flags = 0;
			mod->sml_next = NULL;
			mod->sml_desc = NULL;
			mod->sml_type = tmp.sml_type;
			mod->sml_values = tmp.sml_values;
			mod->sml_nvalues = tmp.sml_nvalues;
		} else { 
			rs.sr_err = values2obj_copy( pMod->mod_values, &bv );
			if ( rs.sr_err != LDAP_SUCCESS )
				goto cleanup;
			tmp.sml_type.bv_val = pMod->mod_type;
			tmp.sml_type.bv_len = strlen( pMod->mod_type );
			tmp.sml_values = bv;
			tmp.sml_nvalues = NULL;

			mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

			mod->sml_op = pMod->mod_op & LDAP_MOD_OP;
			mod->sml_flags = 0;
			mod->sml_next = NULL;
			mod->sml_desc = NULL;
			mod->sml_type = tmp.sml_type;
			mod->sml_values = tmp.sml_values;
			mod->sml_nvalues = tmp.sml_nvalues;
		}
		*modtail = mod;
		modtail = &mod->sml_next;

		switch( pMod->mod_op & LDAP_MOD_OP ) {
		case LDAP_MOD_ADD:
		if ( mod->sml_values == NULL ) {
			rs.sr_err = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}

		/* fall through */
		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_INCREMENT:
		break;

		default:
			rs.sr_err = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}
	} 
	*modtail = NULL;

	if ( op->o_req_ndn.bv_len == 0 ) {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	op->oq_modify.rs_modlist = modlist;

	if ( op->o_bd->be_modify ) {
		int repl_user = be_isupdate( op );
		if ( !op->o_bd->be_update_ndn.bv_len || repl_user ) {
			int		update = !BER_BVISEMPTY( &op->o_bd->be_update_ndn );
			const char	*text = NULL;
			char		textbuf[ SLAP_TEXT_BUFLEN ];
			size_t		textlen = sizeof( textbuf );
			slap_callback	cb = { NULL, slap_replog_cb, NULL, NULL };

			rs.sr_err = slap_mods_check( modlist,
				&text, textbuf, textlen, NULL );
			if ( rs.sr_err != LDAP_SUCCESS ) {
				goto cleanup;
			}

			if ( !update ) {
				rs.sr_err = slap_mods_no_user_mod_check( op, modlist,
					&text, textbuf, textlen );
				if ( rs.sr_err != LDAP_SUCCESS ) {
					goto cleanup;
				}
			}

			if ( !repl_user ) {
				rs.sr_err = slap_mods_opattrs( op, modlist,
						modtail, &text, textbuf, 
						textlen, 1 );
				if ( rs.sr_err != LDAP_SUCCESS ) {
					goto cleanup;
				}
			}

			if ( operation_flags & SLAPI_OP_FLAG_LOG_CHANGE )
				op->o_callback = &cb;

			op->o_bd->be_modify( op, &rs );
		} else {
			rs.sr_err = LDAP_REFERRAL;
		}
	} else {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );

	if ( modlist != NULL )
		slap_mods_free( modlist );

	slapi_int_connection_destroy( &pConn );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

#ifdef LDAP_SLAPI
static int
slapi_int_search_entry_callback( Slapi_Entry *entry, void *callback_data )
{
	int nentries = 0, i = 0;
	Slapi_Entry **head = NULL, **tp;
	Slapi_PBlock *pb = (Slapi_PBlock *)callback_data;

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

int slapi_search_internal_pb( Slapi_PBlock *pb )
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

int slapi_search_internal_callback_pb( Slapi_PBlock *pb,
	void *callback_data,
	plugin_result_callback prc,
	plugin_search_entry_callback psec,
	plugin_referral_entry_callback prec )
{
#ifdef LDAP_SLAPI
	Connection		*c;
	Operation		*op = NULL;
	struct berval		dn = BER_BVNULL;
	Filter			*filter = NULL;
	struct berval		fstr = BER_BVNULL;
	AttributeName		*an = NULL;
	const char		*text = NULL;

	int			manageDsaIt = SLAP_CONTROL_NONE;
	int			isCritical;
	int			i;

	char			*ldn = NULL;
	int			scope = LDAP_SCOPE_BASE;
	char			*filStr = NULL;
	LDAPControl		**controls = NULL;
	char			**attrs = NULL;
	char			*uniqueid = NULL;
	int			attrsonly = 0;
	int			operation_flags = 0;
	int			freeFilter = 0;

	SlapReply		rs = { REP_RESULT };

	if ( pb == NULL ) {
		return -1;
	}

	slapi_pblock_get( pb, SLAPI_SEARCH_TARGET, &ldn );
	slapi_pblock_get( pb, SLAPI_SEARCH_SCOPE, &scope );
	slapi_pblock_get( pb, SLAPI_SEARCH_FILTER, &filter );
	slapi_pblock_get( pb, SLAPI_SEARCH_STRFILTER, &filStr );
	slapi_pblock_get( pb, SLAPI_SEARCH_ATTRS, &attrs );
	slapi_pblock_get( pb, SLAPI_SEARCH_ATTRSONLY, &attrsonly );
	slapi_pblock_get( pb, SLAPI_REQCONTROLS, &controls );
	slapi_pblock_get( pb, SLAPI_TARGET_UNIQUEID, &uniqueid );
	slapi_pblock_get( pb, SLAPI_X_INTOP_FLAGS, &operation_flags );

	c = slapi_int_init_connection( NULL, LDAP_REQ_SEARCH );
	if ( c == NULL ) {
		rs.sr_err = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)c->c_pending_ops.stqh_first;
	op->o_pb = pb;

	/* callback and arguments */
	slapi_pblock_set( pb, SLAPI_X_INTOP_RESULT_CALLBACK, prc );
	slapi_pblock_set( pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK, psec );
	slapi_pblock_set( pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, prec );
	slapi_pblock_set( pb, SLAPI_X_INTOP_CALLBACK_DATA, callback_data );

	rs.sr_err = slapi_int_get_ctrls( op, &rs, controls );
	if ( rs.sr_err != LDAP_SUCCESS )
		goto cleanup;

	if ( ldn != NULL ) {
		dn.bv_val = ldn;
		dn.bv_len = strlen(ldn);
	}

	rs.sr_err = dnPrettyNormal( NULL, &dn, &op->o_req_dn, &op->o_req_ndn, NULL );
	if ( rs.sr_err != LDAP_SUCCESS ) {
		goto cleanup;
	}

	if ( scope != LDAP_SCOPE_BASE && 
	     scope != LDAP_SCOPE_ONELEVEL && 
	     scope != LDAP_SCOPE_SUBTREE ) {
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

	if (i > 0) {
		an = (AttributeName *)slapi_ch_calloc( (i + 1), sizeof(AttributeName) );
		for (i = 0; attrs[i] != 0; i++) {
			an[i].an_desc = NULL;
			an[i].an_oc = NULL;
			an[i].an_oc_exclude = 0;
			an[i].an_name.bv_val = slapi_ch_strdup(attrs[i]);
			an[i].an_name.bv_len = strlen(attrs[i]);
			slap_bv2ad( &an[i].an_name, &an[i].an_desc, &text );
		}
		an[i].an_name.bv_val = NULL;
	}

	memset( &rs, 0, sizeof(rs) );
	rs.sr_type = REP_RESULT;
	rs.sr_err = LDAP_SUCCESS;
	rs.sr_entry = NULL; /* paranoia */

	if ( scope == LDAP_SCOPE_BASE ) {
		rs.sr_entry = NULL;

		if ( op->o_req_ndn.bv_len == 0 ) {
			rs.sr_err = root_dse_info( c, &rs.sr_entry, &rs.sr_text );
		}

		if( rs.sr_err != LDAP_SUCCESS ) {
			send_ldap_result( op, &rs );
			goto cleanup;
		} else if ( rs.sr_entry != NULL ) {
			rs.sr_err = test_filter( op, rs.sr_entry, filter );

			if ( rs.sr_err == LDAP_COMPARE_TRUE ) {
				rs.sr_type = REP_SEARCH;
				rs.sr_err = LDAP_SUCCESS;
				rs.sr_attrs = an;
				rs.sr_operational_attrs = NULL;
				rs.sr_flags = REP_ENTRY_MODIFIABLE;

				send_search_entry( op, &rs );
            		}

			entry_free( rs.sr_entry );

			rs.sr_type = REP_RESULT;
			rs.sr_err = LDAP_SUCCESS;

			send_ldap_result( op, &rs );

			goto cleanup;
		}
	}

	if ( !op->o_req_ndn.bv_len && default_search_nbase.bv_len ) {
		slapi_ch_free( (void **)&op->o_req_dn.bv_val );
		slapi_ch_free( (void **)&op->o_req_ndn.bv_val );

		ber_dupbv( &op->o_req_dn, &default_search_base );
		ber_dupbv( &op->o_req_ndn, &default_search_nbase );
	}

	if ( slapi_control_present( controls,
			LDAP_CONTROL_MANAGEDSAIT, NULL, &isCritical ) ) {
		manageDsaIt = isCritical ? SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL; 
	}

	op->o_bd = select_backend( &op->o_req_ndn, manageDsaIt, 1 );
	if ( op->o_bd == NULL ) {
		if ( manageDsaIt > SLAP_CONTROL_NONE ) {
			rs.sr_err = LDAP_NO_SUCH_OBJECT;
		} else {
			rs.sr_err = LDAP_PARTIAL_RESULTS;
		}
		goto cleanup;
	} 

	op->o_dn = c->c_dn = op->o_bd->be_rootdn;
	op->o_ndn = c->c_ndn = op->o_bd->be_rootndn;

	op->oq_search.rs_scope = scope;
	op->oq_search.rs_deref = 0;
	op->oq_search.rs_slimit = SLAP_NO_LIMIT;
	op->oq_search.rs_tlimit = SLAP_NO_LIMIT;
	op->oq_search.rs_attrsonly = attrsonly;
	op->oq_search.rs_attrs = an;
	op->oq_search.rs_filter = filter;
	op->oq_search.rs_filterstr = fstr;

	if ( op->o_bd->be_search != NULL ) {
		(*op->o_bd->be_search)( op, &rs );
	} else {
		rs.sr_err = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:
	slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rs.sr_err );
	slapi_pblock_set( pb, SLAPI_X_INTOP_RESULT_CALLBACK, NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_SEARCH_ENTRY_CALLBACK, NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_REFERRAL_ENTRY_CALLBACK, NULL );
	slapi_pblock_set( pb, SLAPI_X_INTOP_CALLBACK_DATA, NULL );

	if ( freeFilter && filter != NULL )
		slapi_filter_free( filter, 1 );
	if ( fstr.bv_val )
		slapi_ch_free( (void **)&fstr.bv_val );
	if ( an != NULL )
		slapi_ch_free( (void **)&an );

	slapi_int_connection_destroy( &c );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

/* Wrappers for old API */

void slapi_search_internal_set_pb( Slapi_PBlock *pb,
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
	slapi_pblock_set( pb, SLAPI_SEARCH_TARGET, (void *)base );
	slapi_pblock_set( pb, SLAPI_SEARCH_SCOPE, (void *)scope );
	slapi_pblock_set( pb, SLAPI_SEARCH_FILTER, NULL );
	slapi_pblock_set( pb, SLAPI_SEARCH_STRFILTER, (void *)filter );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRS, (void *)attrs );
	slapi_pblock_set( pb, SLAPI_SEARCH_ATTRSONLY, (void *)attrsonly );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );
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

void slapi_modify_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPMod **mods,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_MODIFY_TARGET, (void *)dn );
	slapi_pblock_set( pb, SLAPI_MODIFY_MODS, (void *)mods );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );
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

int slapi_add_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPMod **attrs,
	LDAPControl **controls,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_ADD_TARGET, (void *)dn );
	slapi_pblock_set( pb, SLAPI_MODIFY_MODS, (void *)attrs );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );

	return 0;
#else
	return -1;
#endif /* LDAP_SLAPI */
}

Slapi_PBlock *slapi_add_internal(
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

void slapi_add_entry_internal_set_pb( Slapi_PBlock *pb,
	Slapi_Entry *e,
	LDAPControl **controls,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_ADD_ENTRY, (void *)e );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );
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

void slapi_rename_internal_set_pb( Slapi_PBlock *pb,
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
	slapi_pblock_set( pb, SLAPI_MODRDN_TARGET, (void *)olddn );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWRDN, (void *)newrdn );
	slapi_pblock_set( pb, SLAPI_MODRDN_NEWSUPERIOR, (void *)newsuperior );
	slapi_pblock_set( pb, SLAPI_MODRDN_DELOLDRDN, (void *)deloldrdn );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );
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

void slapi_delete_internal_set_pb( Slapi_PBlock *pb,
	const char *dn,
	LDAPControl **controls,
	const char *uniqueid,
	Slapi_ComponentId *plugin_identity,
	int operation_flags )
{
#ifdef LDAP_SLAPI
	slapi_pblock_set( pb, SLAPI_TARGET_DN, (void *)dn );
	slapi_pblock_set( pb, SLAPI_REQCONTROLS, (void *)controls );
	slapi_pblock_set( pb, SLAPI_TARGET_UNIQUEID, (void *)uniqueid );
	slapi_pblock_set( pb, SLAPI_PLUGIN_IDENTITY, (void *)plugin_identity );
	slapi_pblock_set( pb, SLAPI_X_INTOP_FLAGS, (void *)operation_flags );
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

