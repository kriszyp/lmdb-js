/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is
 * given to IBM Corporation. This software is provided ``as is''
 * without express or implied warranty.
 */

#include "portable.h"
#include "slapi_common.h"
#include <slap.h>
#include <slapi.h>
#include <lber.h>
#include "../../../libraries/liblber/lber-int.h"


int bvptr2obj( struct berval **bvptr, struct berval **bvobj );

static void
internal_result_v3(
	Connection	*conn, 
	Operation	*op, 
	ber_int_t	err,
	const char	*matched, 
	const char	*text, 
	BerVarray	referrals,
	LDAPControl	**ctrls )
{
	return;
}

static int
internal_search_entry(
	Backend		*be, 
	Connection	*conn, 
	Operation	*op, 
	Entry		*e, 
	AttributeName	*attrs, 
	int		attrsonly, 
	LDAPControl	**ctrls ) 
{
	char *ent2str = NULL;
	int nentries = 0, len = 0, i = 0;
	Slapi_Entry **head = NULL, **tp;
	
	ent2str = slapi_entry2str( e, &len );
	if ( ent2str == NULL ) {
		return SLAPD_NO_MEMORY;
	}

	slapi_pblock_get( (Slapi_PBlock *)op->o_pb,
			SLAPI_NENTRIES, &nentries );
	slapi_pblock_get( (Slapi_PBlock *)op->o_pb,
			SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &head );
	
	i = nentries + 1;
	if ( nentries == 0 ) {
		tp = (Slapi_Entry **)slapi_ch_malloc( 2 * sizeof(Slapi_Entry *) );
		if ( tp == NULL ) {
			return SLAPD_NO_MEMORY;
		}

		tp[ 0 ] = (Slapi_Entry *)str2entry( ent2str );
		if ( tp[ 0 ] == NULL ) { 
			return SLAPD_NO_MEMORY;
		}

	} else {
		tp = (Slapi_Entry **)slapi_ch_realloc( (char *)head,
				sizeof(Slapi_Entry *) * ( i + 1 ) );
		if ( tp == NULL ) {
			return SLAPD_NO_MEMORY;
		}
		tp[ i - 1 ] = (Slapi_Entry *)str2entry( ent2str );
		if ( tp[ i - 1 ] == NULL ) { 
			return SLAPD_NO_MEMORY;
		}
	}
	tp[ i ] = NULL;
	          
	slapi_pblock_set( (Slapi_PBlock *)op->o_pb,
			SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, (void *)tp );
	slapi_pblock_set( (Slapi_PBlock *)op->o_pb,
			SLAPI_NENTRIES, (void *)i );
	slapi_ch_free( (void **)&ent2str );

	return LDAP_SUCCESS;
}

static void
internal_search_result(
	Connection	*conn, 
	Operation	*op,
	ber_int_t	err, 
	const char	*matched, 
	const char	*text, 
	BerVarray	refs,
	LDAPControl	**ctrls,
	int		nentries ) 
{
	slapi_pblock_set( (Slapi_PBlock *)op->o_pb,
			SLAPI_NENTRIES, (void *)nentries );

	return;
}

static void
internal_result_ext(
	Connection	*conn, 
	Operation	*op, 
	ber_int_t	errnum, 
	const char	*matched,
	const char	*text,
	BerVarray	refs,
	const char	*rspoid,
	struct berval	*rspdata,
	LDAPControl	**ctrls )
{
	return;
}

static int
internal_search_reference(
	Backend		*be,
	Connection	*conn, 
	Operation	*op, 
	Entry		*e,
	BerVarray	refs,
	LDAPControl	**ctrls,
	BerVarray	*v2refs )
{
	return LDAP_SUCCESS;
}

static Connection *
fakeConnection(
	char *DN, 
	int OpType ) 
{ 
	Connection *pConn, *c;
	ber_len_t max = sockbuf_max_incoming;

	pConn = (Connection *) slapi_ch_calloc(1, sizeof(Connection));
	if (pConn == NULL) {
		return (Connection *)NULL;
	}

	LDAP_STAILQ_INIT( &pConn->c_pending_ops );

	pConn->c_pending_ops.stqh_first =
		(Operation *) slapi_ch_calloc( 1, sizeof(Operation) );
	if ( pConn->c_pending_ops.stqh_first == NULL ) { 
		slapi_ch_free( (void **)&pConn );
		return (Connection *)NULL;
	}

	pConn->c_pending_ops.stqh_first->o_pb = 
		(Slapi_PBlock *) slapi_pblock_new();
	if ( pConn->c_pending_ops.stqh_first->o_pb == NULL ) {
		slapi_ch_free( (void **)&pConn->c_pending_ops.stqh_first );
		slapi_ch_free( (void **)&pConn );
		return (Connection *)NULL;
	}

	c = pConn;

	/* operation object */
	c->c_pending_ops.stqh_first->o_tag = OpType;
	c->c_pending_ops.stqh_first->o_protocol = LDAP_VERSION3; 
	c->c_pending_ops.stqh_first->o_authmech.bv_val = NULL; 
	c->c_pending_ops.stqh_first->o_authmech.bv_len = 0; 
	c->c_pending_ops.stqh_first->o_time = slap_get_time();

	/* connection object */
	c->c_authmech.bv_val = NULL;
	c->c_authmech.bv_len = 0;
	c->c_dn.bv_val = NULL;
	c->c_dn.bv_len = 0;
	c->c_ndn.bv_val = NULL;
	c->c_ndn.bv_len = 0;
	c->c_groups = NULL;

	c->c_listener = NULL;
	c->c_peer_domain.bv_val = NULL;
	c->c_peer_domain.bv_len = 0;
	c->c_peer_name.bv_val = NULL;
	c->c_peer_name.bv_len = 0;

	LDAP_STAILQ_INIT( &c->c_ops );

	c->c_sasl_bind_mech.bv_val = NULL;
	c->c_sasl_bind_mech.bv_len = 0;
	c->c_sasl_context = NULL;
	c->c_sasl_extra = NULL;

	c->c_sb = ber_sockbuf_alloc( );

	ber_sockbuf_ctrl( c->c_sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );

	c->c_currentber = NULL;

	/* should check status of thread calls */
	ldap_pvt_thread_mutex_init( &c->c_mutex );
	ldap_pvt_thread_mutex_init( &c->c_write_mutex );
	ldap_pvt_thread_cond_init( &c->c_write_cv );

	c->c_n_ops_received = 0;
	c->c_n_ops_executing = 0;
	c->c_n_ops_pending = 0;
	c->c_n_ops_completed = 0;

	c->c_n_get = 0;
	c->c_n_read = 0;
	c->c_n_write = 0;

	c->c_protocol = LDAP_VERSION3; 

	c->c_activitytime = c->c_starttime = slap_get_time();

	c->c_connid = 0;

	c->c_conn_state  = 0x01;	/* SLAP_C_ACTIVE */
	c->c_struct_state = 0x02;	/* SLAP_C_USED */

	c->c_ssf = c->c_transport_ssf = 0;
	c->c_tls_ssf = 0;

	backend_connection_init( c );

	pConn->c_send_ldap_result = internal_result_v3;
	pConn->c_send_search_entry = internal_search_entry;
	pConn->c_send_search_result = internal_search_result;
	pConn->c_send_ldap_extended = internal_result_ext;
	pConn->c_send_search_reference = internal_search_reference;

	return pConn;
}

/* 
 * Function : ValuestoBValues 
 * Convert an array of char ptrs to an array of berval ptrs.
 * return value : LDAP_SUCCESS
 *                LDAP_NO_MEMORY
 *                LDAP_OTHER
*/

static int 
ValuesToBValues(
	char **ppValue, 
	struct berval ***pppBV )
{
	int  rc = LDAP_SUCCESS;
	int  i;
	struct berval *pTmpBV;
	struct berval **ppNewBV;

	/* count the number of char ptrs. */
	for ( i = 0; ppValue != NULL && ppValue[i] != NULL; i++ ) {
		;	/* NULL */
	}

	if ( i == 0 ) {
		rc = LDAP_OTHER;
	} else {
		*pppBV = ppNewBV = (struct berval **)slapi_ch_malloc( (i+1)*(sizeof(struct berval *)) );
		if ( *pppBV == NULL ) {
			rc = LDAP_NO_MEMORY;
		} else {
			while ( ppValue != NULL && *ppValue != NULL && rc == LDAP_SUCCESS ) {
				pTmpBV = (struct berval *)slapi_ch_malloc(sizeof(struct berval));
				if ( pTmpBV == NULL) {
					rc = LDAP_NO_MEMORY;
				} else {
					pTmpBV->bv_val = slapi_ch_strdup(*ppValue);
					if ( pTmpBV->bv_val == NULL ) {
						rc = LDAP_NO_MEMORY;
					} else {
						pTmpBV->bv_len = strlen(*ppValue);
						*ppNewBV = pTmpBV;
						ppNewBV++;
					}
					ppValue++;
				}
			}
			/* null terminate the array of berval ptrs */
			*ppNewBV = NULL;
		}
	}
	return( rc );
}


/*
 * Function : LDAPModToEntry 
 * convert a dn plus an array of LDAPMod struct ptrs to an entry structure
 * with a link list of the correspondent attributes.
 * Return value : LDAP_SUCCESS
 *                LDAP_NO_MEMORY
 *                LDAP_OTHER
*/
Entry *
LDAPModToEntry(
	char *ldn, 
	LDAPMod **mods )
{
	struct berval		dn = { 0, NULL };
	Entry			*pEntry=NULL;
	LDAPMod			*pMod;
	struct berval		*bv;
	struct berval		**ppBV;
	Backend			*be;
	Operation		*op;

	Modifications		*modlist = NULL;
	Modifications		**modtail = &modlist;
	Modifications		tmp;

	int			rc = LDAP_SUCCESS;
	int			i;

	const char 		*text = NULL;


	op = (Operation *) slapi_ch_calloc(1, sizeof(Operation));
	if ( pEntry == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}  
	op->o_tag = LDAP_REQ_ADD;

	pEntry = (Entry *) ch_calloc( 1, sizeof(Entry) );
	if ( pEntry == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	} 

	dn.bv_val = slapi_ch_strdup(ldn);
	dn.bv_len = strlen(ldn);

	rc = dnPrettyNormal( NULL, &dn, &pEntry->e_name, &pEntry->e_nname );
	if (rc != LDAP_SUCCESS) goto cleanup;

	if ( rc == LDAP_SUCCESS ) {
		for ( i=0, pMod=mods[0]; rc == LDAP_SUCCESS && pMod != NULL; pMod=mods[++i]) {
			Modifications *mod;
			if ( (pMod->mod_op & LDAP_MOD_BVALUES) != 0 ) {
				/* attr values are in berval format */
				/* convert an array of pointers to bervals to an array of bervals */
				rc = bvptr2obj(pMod->mod_bvalues, &bv);
				if (rc != LDAP_SUCCESS) goto cleanup;
				tmp.sml_type.bv_val = slapi_ch_strdup(pMod->mod_type);
				tmp.sml_type.bv_len = slapi_ch_stlen(pMod->mod_type);
				tmp.sml_bvalues = bv;
		
				mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

				mod->sml_op = LDAP_MOD_ADD;
				mod->sml_next = NULL;
				mod->sml_desc = NULL;
				mod->sml_type = tmp.sml_type;
				mod->sml_bvalues = tmp.sml_bvalues;

				*modtail = mod;
				modtail = &mod->sml_next;

			} else {
				/* attr values are in string format, need to be converted */
				/* to an array of bervals */ 
				if ( pMod->mod_values == NULL ) {
					rc = LDAP_OTHER;
				} else {
					rc = ValuesToBValues( pMod->mod_values, &ppBV );
					if (rc != LDAP_SUCCESS) goto cleanup;
					rc = bvptr2obj(ppBV, &bv);
					if (rc != LDAP_SUCCESS) goto cleanup;
					tmp.sml_type.bv_val = slapi_ch_strdup(pMod->mod_type);
					tmp.sml_type.bv_len = slapi_ch_stlen(pMod->mod_type);
					tmp.sml_bvalues = bv;
		
					mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

					mod->sml_op = LDAP_MOD_ADD;
					mod->sml_next = NULL;
					mod->sml_desc = NULL;
					mod->sml_type = tmp.sml_type;
					mod->sml_bvalues = tmp.sml_bvalues;

					*modtail = mod;
					modtail = &mod->sml_next;

					if ( ppBV != NULL ) {
						ber_bvecfree( ppBV );
					}
				}
			}
		} /* for each LDAPMod */
	}

	be = select_backend(&dn, 0, 0);
	if ( be == NULL ) {
		rc =  LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	if ( be ) {
		int repl_user = be_isupdate(be, &be->be_rootdn );
        	if ( !be->be_update_ndn.bv_len || repl_user ) {
			int update = be->be_update_ndn.bv_len;
			char textbuf[SLAP_TEXT_BUFLEN];
			size_t textlen = sizeof textbuf;

			rc = slap_mods_check( modlist, update, &text, 
					textbuf, textlen );
			if ( rc != LDAP_SUCCESS) {
				goto cleanup;
			}

			if ( !repl_user ) {
				rc = slap_mods_opattrs( be, op,
						modlist, modtail, &text, 
						textbuf, textlen );
				if ( rc != LDAP_SUCCESS) {
					goto cleanup;
				}
			}

			/*
			 * FIXME: slap_mods2entry is declared static 
			 * in servers/slapd/add.c
			 */
			rc = slap_mods2entry( modlist, &pEntry, repl_user,
					&text, textbuf, textlen );
			if (rc != LDAP_SUCCESS) {
				goto cleanup;
			}

		} else {
			rc = LDAP_REFERRAL;
		}
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	if ( dn.bv_val ) slapi_ch_free( (void **)&dn.bv_val );
	if ( op ) slapi_ch_free( (void **)&op );
	if ( modlist != NULL ) slap_mods_free( modlist );
	if ( rc != LDAP_SUCCESS ) {
		if ( pEntry != NULL ) {
			slapi_entry_free( pEntry );
		}
		pEntry = NULL;
	}

	return( pEntry );
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
#if defined(LDAP_SLAPI)
	Backend			*be;
	Connection		*pConn = NULL;
	Operation		*op = NULL;
	Slapi_PBlock		*pPB = NULL;
	Slapi_PBlock		*pSavePB = NULL;

	struct berval dn  = { 0, NULL };
	struct berval pdn = { 0, NULL };
	struct berval ndn = { 0, NULL };

	int				rc=LDAP_SUCCESS;
	int				manageDsaIt = 0;
	int				isCritical;

	if ( ldn == NULL ) {
		rc = LDAP_PARAM_ERROR; 
		goto cleanup;
	}

	pConn = fakeConnection( NULL,  LDAP_REQ_DELETE );
	if (pConn == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	pPB = (Slapi_PBlock *)op->o_pb;
	op->o_ctrls = controls;

	dn.bv_val = slapi_ch_strdup(ldn);
	dn.bv_len = slapi_strlen(ldn);
	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if ( rc != LDAP_SUCCESS ) goto cleanup;

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical) ) {
		manageDsaIt = 1; 
	}

	be = select_backend( &dn, manageDsaIt, 0 );
	if ( be == NULL ) {
		rc =  LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_ndn.bv_val = slapi_ch_strdup(be->be_rootdn.bv_val);
	op->o_ndn.bv_len = be->be_rootdn.bv_len;
	pConn->c_dn.bv_val = slapi_ch_strdup(be->be_rootdn.bv_val);
	pConn->c_dn.bv_len = be->be_rootdn.bv_len;

	suffix_alias( be, &ndn );

	if ( be->be_delete ) {
		int repl_user = be_isupdate( be, &op->o_ndn );
		if ( !be->be_update_ndn.bv_len || repl_user ) {
			rc = (*be->be_delete)( be, pConn, op, &pdn, &ndn );
			if ( rc == 0 ) {
				if (log_change) {
					replog( be, op, &pdn, &ndn, NULL );
				}
				rc = LDAP_SUCCESS;
			} else {
				rc = LDAP_OPERATIONS_ERROR;
			}
        	} else {
			rc = LDAP_REFERRAL;
        	}
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:
	if (pPB != NULL) 
		slapi_pblock_set( pPB, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );

	if (dn.bv_val) slapi_ch_free( (void **)&dn.bv_val );
	if (pdn.bv_val) slapi_ch_free( (void **)&pdn.bv_val );
	if (ndn.bv_val) slapi_ch_free( (void **)&ndn.bv_val );

	if ( pConn != NULL ) {
		if ( pConn->c_dn.bv_val ) slapi_ch_free( (void **)&pConn->c_dn.bv_val );
		if ( op->o_dn.bv_val ) slapi_ch_free( (void **)&op->o_dn.bv_val );
		if ( op ) slapi_ch_free( (void **)&op );
		pSavePB = pPB;
		free( pConn );
	}
	
	return (pSavePB);
#endif /* LDAP_SLAPI */
	return NULL;
}

Slapi_PBlock * 
slapi_add_entry_internal(
	Slapi_Entry *e, 
	LDAPControl **controls, 
	int log_changes ) 
{
#if defined(LDAP_SLAPI)
	Connection		*pConn = NULL;
	Operation		*op = NULL;
	Slapi_PBlock		*pPB = NULL, *pSavePB = NULL;
	Backend			*be;

	int			manageDsaIt = 0;
	int			isCritical;
	int			rc = LDAP_SUCCESS;

	if ( e == NULL ) {
		rc = LDAP_PARAM_ERROR;
		goto cleanup;
	}
	
	pConn = fakeConnection( NULL, LDAP_REQ_ADD );
	if ( pConn == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

	if ( slapi_control_present( controls, LDAP_CONTROL_MANAGEDSAIT,
				NULL, &isCritical ) ) {
		manageDsaIt = 1; 
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	pPB = (Slapi_PBlock *)op->o_pb;
	op->o_ctrls = controls;

	be = select_backend( &e->e_nname, manageDsaIt, 0 );
	if ( be == NULL ) {
		rc = LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_ndn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	op->o_ndn.bv_len = be->be_rootdn.bv_len;
	pConn->c_dn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	pConn->c_dn.bv_len = be->be_rootdn.bv_len;

	if ( be->be_add ) {
		int repl_user = be_isupdate( be, &op->o_ndn );
		if ( !be->be_update_ndn.bv_len || repl_user ){
			if ( (*be->be_add)( be, pConn, op, e ) == 0 ) {
				if ( log_changes ) {
					replog( be, op, &e->e_name, 
							&e->e_nname, e );
				}
				rc = LDAP_SUCCESS;
			}
		} else {
			rc = LDAP_REFERRAL;
		}
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	if ( pPB != NULL ) {
		slapi_pblock_set( pPB, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );
	}

	if ( pConn != NULL ) {
		if ( pConn->c_dn.bv_val ) slapi_ch_free( (void **)&pConn->c_dn.bv_val );
		if ( op ) {
			if ( op->o_ndn.bv_val ) {
				slapi_ch_free( (void **)&op->o_ndn.bv_val );
			}
			free(op);
		}
		pSavePB = pPB;
		free( pConn );
	}
	return( pSavePB );
#endif /* LDAP_SLAPI */
	return NULL;
}


Slapi_PBlock *
slapi_add_internal(
	char *dn, 
	LDAPMod **mods, 
	LDAPControl **controls, 
	int log_changes  ) 
{
#if defined(LDAP_SLAPI)
	LDAPMod			*pMod = NULL;
	Slapi_PBlock		*pb = NULL;
	Entry			*pEntry = NULL;
	int			i, rc=LDAP_SUCCESS;

	if ( mods == NULL || *mods == NULL || dn == NULL || *dn == '\0' ) {
		rc = LDAP_PARAM_ERROR ;
	}

	if ( rc == LDAP_SUCCESS ) {
		for ( i = 0, pMod = mods[0]; pMod != NULL; pMod = mods[++i] ) {
			if ( (pMod->mod_op & ~LDAP_MOD_BVALUES) != LDAP_MOD_ADD ) {
				rc = LDAP_OTHER;
				break;
			}
		}
	}

	if ( rc == LDAP_SUCCESS ) {
		if((pEntry = LDAPModToEntry( dn, mods )) == NULL) {
			rc = LDAP_OTHER;
		}
	}

	if ( rc != LDAP_SUCCESS ) {
		pb = slapi_pblock_new();
		slapi_pblock_set( pb, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );
	} else {
		pb = slapi_add_entry_internal( pEntry, controls, log_changes );
	}

	if ( pEntry ) {
		slapi_entry_free(pEntry);
	}

	return(pb);
#endif /* LDAP_SLAPI */
	return NULL;
}

/* Function : slapi_modrdn_internal
 *
 * Description : Plugin functions call this routine to modify the rdn 
 *				 of an entry in the backend directly
 * Return values : LDAP_SUCCESS
 *                 LDAP_PARAM_ERROR
 *                 LDAP_OPERATIONS_ERROR
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
#if defined(LDAP_SLAPI)
	int			rc = LDAP_SUCCESS;

	struct berval		dn = { 0, NULL };
	struct berval		pdn = { 0, NULL };
	struct berval		ndn = { 0, NULL };

	struct berval		newrdn = { 0, NULL };
	struct berval		pnewrdn = { 0, NULL };
	struct berval		nnewrdn = { 0, NULL };

#if 0 /* currently unused */
	struct berval		newSuperior = { 0, NULL };
#endif
	struct berval		pnewSuperior = { 0, NULL }; 
#if 0 /* currently unused */
	struct berval		nnewSuperior = { 0, NULL }; 
#endif

	struct berval		*pnewS = NULL;
	struct berval		*nnewS = NULL;

	Connection		*pConn = NULL;
	Operation		*op = NULL;
	Slapi_PBlock		*pPB = NULL;
	Slapi_PBlock		*pSavePB = NULL;

	Backend			*be;
#if 0 /* currently unused */
	Backend 		*newSuperior_be = NULL;
#endif

	int			manageDsaIt = 0;
	int			isCritical;
#if 0 /* currently unused */
	const char 		*text = NULL;
#endif

	dn.bv_val = slapi_ch_strdup(olddn);
	dn.bv_len = slapi_ch_stlen(olddn);

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );

	if ( rc != LDAP_SUCCESS ) goto cleanup;

	if ( ndn.bv_len == 0 ) {
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	newrdn.bv_val = slapi_ch_strdup( lnewrdn );
	newrdn.bv_len = slapi_ch_stlen( lnewrdn );

	rc = dnPrettyNormal( NULL, &newrdn, &pnewrdn, &nnewrdn );

	if ( rc != LDAP_SUCCESS ) goto cleanup;

	if ( rdnValidate( &pnewrdn ) != LDAP_SUCCESS ) goto cleanup;

	pConn = fakeConnection( NULL,  LDAP_REQ_MODRDN);
	if ( pConn == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	pPB = (Slapi_PBlock *)op->o_pb;
	op->o_ctrls = controls;

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical ) ) {
		manageDsaIt = 1;
	}

	be = select_backend( &dn, manageDsaIt, 0 );
	if ( be == NULL ) {
		rc =  LDAP_PARTIAL_RESULTS;
		goto cleanup;
	}

	op->o_ndn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	op->o_ndn.bv_len = be->be_rootdn.bv_len;
	pConn->c_dn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	pConn->c_dn.bv_len = be->be_rootdn.bv_len;

	suffix_alias( be, &ndn );

	if ( be->be_modrdn ) {
		int repl_user = be_isupdate( be, &op->o_ndn );
		if ( !be->be_update_ndn.bv_len || repl_user ) {
			rc = (*be->be_modrdn)( be, pConn, op, &pdn, &ndn,
					&pnewrdn, &nnewrdn, deloldrdn, pnewS,
					nnewS );
			if ( rc == 0 ) {
				struct slap_replog_moddn moddn;
				moddn.newrdn = &pnewrdn;
				moddn.deloldrdn = deloldrdn;
				moddn.newsup = &pnewSuperior;
				if ( log_change ) {
					replog( be, op, &pdn, &ndn, &moddn );
				}
				rc = LDAP_SUCCESS;

			} else {
				rc = LDAP_OPERATIONS_ERROR;
			}

		} else {
			rc = LDAP_REFERRAL;
		}

	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	if ( pPB != NULL ) {
		slapi_pblock_set( pPB, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );
	}
	
	if ( dn.bv_val ) ch_free( dn.bv_val );
	if ( pdn.bv_val ) ch_free( pdn.bv_val );
	if ( ndn.bv_val ) ch_free( ndn.bv_val );

	if ( newrdn.bv_val ) ch_free( newrdn.bv_val );
	if ( pnewrdn.bv_val ) ch_free( newrdn.bv_val );
	if ( nnewrdn.bv_val ) ch_free( newrdn.bv_val );

	if ( pConn != NULL ) {
		if ( pConn->c_dn.bv_val ) slapi_ch_free( (void **)&pConn->c_dn.bv_val );
		if ( op ) {
			if ( op->o_dn.bv_val ) slapi_ch_free( (void **)&op->o_dn.bv_val );
			slapi_ch_free( (void **)&op );
		}
		pSavePB = pPB;
		free( pConn );
	}

	return( pSavePB );
#endif /* LDAP_SLAPI */
	return NULL;
}

/* Function : slapi_modify_internal
 *
 * Description:	Plugin functions call this routine to modify an entry 
 *				in the backend directly
 * Return values : LDAP_SUCCESS
 *                 LDAP_PARAM_ERROR
 *                 LDAP_NO_MEMORY
 *                 LDAP_OPERATIONS_ERROR
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
#if defined(LDAP_SLAPI)
	int			i, rc = LDAP_SUCCESS;
	Connection		*pConn = NULL;
	Operation		*op = NULL;
	Slapi_PBlock		*pPB = NULL;
	Slapi_PBlock		*pSavePB = NULL;

	struct berval dn = { 0, NULL };
	struct berval pdn = { 0, NULL };
	struct berval ndn = { 0, NULL };

	int			manageDsaIt = 0;
	int			isCritical;
	Backend			*be;
	struct berval		*bv;
	struct berval   	**ppBV;
	LDAPMod			*pMod;

	Modifications		*modlist = NULL;
	Modifications		**modtail = &modlist;
	Modifications		tmp;

	if ( mods == NULL || *mods == NULL || ldn == NULL ) {
		rc = LDAP_PARAM_ERROR ;
		goto cleanup;
	}

	pConn = fakeConnection( NULL,  LDAP_REQ_MODIFY );
	if ( pConn == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)pConn->c_pending_ops.stqh_first;
	pPB = (Slapi_PBlock *)op->o_pb;
	op->o_ctrls = controls;

	dn.bv_val = slapi_ch_strdup( ldn );
	dn.bv_len = slapi_strlen( ldn );
	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if ( rc != LDAP_SUCCESS ) goto cleanup;

	if ( slapi_control_present( controls, 
			SLAPI_CONTROL_MANAGEDSAIT_OID, NULL, &isCritical ) ) {
        	manageDsaIt = 1;
	}

	be = select_backend( &dn, manageDsaIt, 0 );
	if ( be == NULL ) {
		rc =  LDAP_PARTIAL_RESULTS;
		goto cleanup;
    	}

	op->o_ndn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	op->o_ndn.bv_len = be->be_rootdn.bv_len;
	pConn->c_dn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	pConn->c_dn.bv_len = be->be_rootdn.bv_len;

    	suffix_alias( be, &ndn );

	for ( i = 0, pMod = mods[0]; rc == LDAP_SUCCESS && pMod != NULL; 
			pMod = mods[++i] ) {
		Modifications *mod;
		if ( (pMod->mod_op & LDAP_MOD_BVALUES) != 0 ) {
			/*
			 * attr values are in berval format
			 * convert an array of pointers to bervals
			 * to an array of bervals
			 */
			rc = bvptr2obj( pMod->mod_bvalues, &bv );
			if ( rc != LDAP_SUCCESS ) goto cleanup;
			tmp.sml_type.bv_val = slapi_ch_strdup( pMod->mod_type );
			tmp.sml_type.bv_len = slapi_ch_stlen( pMod->mod_type );
			tmp.sml_bvalues = bv;

			mod  = (Modifications *)ch_malloc( sizeof(Modifications) );

			mod->sml_op = pMod->mod_op;
			mod->sml_next = NULL;
			mod->sml_desc = NULL;
			mod->sml_type = tmp.sml_type;
			mod->sml_bvalues = tmp.sml_bvalues;
		} else { 
			rc = ValuesToBValues( pMod->mod_values, &ppBV );
			if ( rc != LDAP_SUCCESS ) goto cleanup;
			rc = bvptr2obj( ppBV, &bv );
			if ( rc != LDAP_SUCCESS ) goto cleanup;
			tmp.sml_type.bv_val = slapi_ch_strdup( pMod->mod_type );
			tmp.sml_type.bv_len = slapi_ch_stlen( pMod->mod_type );
			tmp.sml_bvalues = bv;

			mod  = (Modifications *) ch_malloc( sizeof(Modifications) );

			mod->sml_op = pMod->mod_op;
			mod->sml_next = NULL;
			mod->sml_desc = NULL;
			mod->sml_type = tmp.sml_type;
			mod->sml_bvalues = tmp.sml_bvalues;

			if ( ppBV != NULL ) {
				ber_bvecfree( ppBV );
			}
		}
		*modtail = mod;
		modtail = &mod->sml_next;

		switch( pMod->mod_op ) {
		case LDAP_MOD_ADD:
		if ( mod->sml_bvalues == NULL ) {
			rc = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}

		/* fall through */
		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE:
		break;

		default:
			rc = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}
	} 
	*modtail = NULL;

	if ( ndn.bv_len == 0 ) {
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto cleanup;
	}

	if ( be->be_modify ) {
		int repl_user = be_isupdate( be, &op->o_ndn );
		if ( !be->be_update_ndn.bv_len || repl_user ) {
			int update = be->be_update_ndn.bv_len;
			const char *text = NULL;
			char textbuf[SLAP_TEXT_BUFLEN];
			size_t textlen = sizeof( textbuf );

			rc = slap_mods_check( modlist, update,
					&text, textbuf, textlen );
			if (rc != LDAP_SUCCESS) {
				goto cleanup;
			}

			if ( !repl_user ) {
				rc = slap_mods_opattrs( be, op, modlist,
						modtail, &text, textbuf, 
						textlen );
				if (rc != LDAP_SUCCESS) {
					goto cleanup;
				}
			}
			rc = (*be->be_modify)( be, pConn, op,
					&pdn, &ndn, modlist );
			if ( rc == 0 ) {
				if ( log_change ) {
					replog( be, op, &pdn, &ndn, modlist );
				}
				rc = LDAP_SUCCESS;
			} else {
				rc = LDAP_OPERATIONS_ERROR;
			}
		} else {
			rc = LDAP_REFERRAL;
		}
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	if ( pPB != NULL ) 
		slapi_pblock_set( pPB, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );

	if ( dn.bv_val ) ch_free( dn.bv_val );
	if ( pdn.bv_val ) ch_free( pdn.bv_val );
	if ( ndn.bv_val ) ch_free( ndn.bv_val );

	if ( modlist != NULL ) slap_mods_free( modlist );

	if ( pConn != NULL ) {
		if ( pConn->c_dn.bv_val ) slapi_ch_free( (void **)&pConn->c_dn.bv_val );
		if ( op ) {
			if ( op->o_dn.bv_val ) slapi_ch_free( (void **)&op->o_dn.bv_val );
			slapi_ch_free( (void **)&op );
		}
		pSavePB = pPB;
		free( pConn );
	}

	return ( pSavePB );

#endif /* LDAP_SLAPI */
	return NULL;
}

Slapi_PBlock *
slapi_search_internal_bind(
	char *bindDN, 
	char *ldn, 
	int scope, 
	char *filStr, 
	LDAPControl **controls, 
	char **attrs, 
	int attrsonly ) 
{	
#if defined(LDAP_SLAPI)
	Backend			*be;
	Connection		*c;
	Operation		*op = NULL;
	Slapi_PBlock		*ptr = NULL;		
	Slapi_PBlock		*pSavePB = NULL;		
	struct berval		dn = { 0, NULL };
	struct berval		pdn = { 0, NULL };
	struct berval		ndn = { 0, NULL };
	Filter			*filter=NULL;
	struct berval		fstr = { 0, NULL };
	AttributeName		*an = NULL;
	const char		*text = NULL;

	int			deref=0;
	int			sizelimit=-1, timelimit=-1;

	int			manageDsaIt = 0; 
	int			isCritical;

	int			i, rc = LDAP_SUCCESS;
	
	c = fakeConnection( NULL, LDAP_REQ_SEARCH );
	if (c == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

	op = (Operation *)c->c_pending_ops.stqh_first;
	ptr = (Slapi_PBlock *)op->o_pb;
	op->o_ctrls = controls;

	dn.bv_val = slapi_ch_strdup(ldn);
	dn.bv_len = slapi_strlen(ldn);

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if (rc != LDAP_SUCCESS) goto cleanup;

	if ( scope != LDAP_SCOPE_BASE && 
		 	scope != LDAP_SCOPE_ONELEVEL && 
		 	scope != LDAP_SCOPE_SUBTREE ) {
		rc = LDAP_PROTOCOL_ERROR;
		goto cleanup;
	}

	filter = slapi_str2filter(filStr);
	if ( filter == NULL ) {
		rc = LDAP_PROTOCOL_ERROR;
		goto cleanup;
	}

	filter2bv( filter, &fstr );

	for ( i = 0; attrs != NULL && attrs[i] != NULL; i++ ) {
		; /* count the number of attributes */
	}

	if (i > 0) {
		an = (AttributeName *)slapi_ch_calloc(1, sizeof(AttributeName));
		for (i = 0; attrs[i] != 0; i++) {
			an[i].an_desc = NULL;
			an[i].an_oc = NULL;
			an[i].an_name.bv_val = slapi_ch_strdup(attrs[i]);
			an[i].an_name.bv_len = slapi_strlen(attrs[i]);
			slap_bv2ad( &an[i].an_name, &an[i].an_desc, &text );
		}
	}

	if ( scope == LDAP_SCOPE_BASE ) {
		Entry *entry = NULL;

		if ( ndn.bv_len == 0 ) {
			rc = root_dse_info( c, &entry, &text );
		}

		if( rc != LDAP_SUCCESS ) {
			send_ldap_result( c, op, rc, NULL, text, NULL, NULL );
			goto cleanup;
		} else if ( entry != NULL ) {
			rc = test_filter( NULL, c, op, entry, filter );

			if( rc == LDAP_COMPARE_TRUE ) {
				send_search_entry( NULL, c, op, entry,
						an, attrsonly, NULL );
            		}

			entry_free( entry );

			send_ldap_result( c, op, LDAP_SUCCESS, 
					NULL, NULL, NULL, NULL );

			rc = LDAP_SUCCESS;

			goto cleanup;
		}
	}

	if ( !ndn.bv_len && default_search_nbase.bv_len ) {
		ch_free( pdn.bv_val );
		ch_free( ndn.bv_val );

		ber_dupbv( &pdn, &default_search_base );
		ber_dupbv( &ndn, &default_search_nbase );
	}

	if ( slapi_control_present( controls,
			LDAP_CONTROL_MANAGEDSAIT, NULL, &isCritical ) ) {
		manageDsaIt = 1;
	}

	be = select_backend( &dn, manageDsaIt, 0 );
	if ( be == NULL ) {
		if ( manageDsaIt == 1 ) {
			rc = LDAP_NO_SUCH_OBJECT;
		} else {
			rc = LDAP_PARTIAL_RESULTS;
		}
		goto cleanup;
	} 

	op->o_ndn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	op->o_ndn.bv_len = be->be_rootdn.bv_len;
	c->c_dn.bv_val = slapi_ch_strdup( be->be_rootdn.bv_val );
	c->c_dn.bv_len = be->be_rootdn.bv_len;

	if ( be->be_search ) {
		rc = (*be->be_search)( be, c, op, &pdn, &ndn,
			scope, deref, sizelimit, timelimit,
			filter, &fstr, an, attrsonly );
		if ( rc == 0 ) {
			rc = LDAP_SUCCESS;
		} else {
			rc = LDAP_OPERATIONS_ERROR;
		}
	} else {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}

cleanup:

	if ( ptr != NULL )
		slapi_pblock_set( ptr, SLAPI_PLUGIN_INTOP_RESULT, (void *)rc );

	if ( dn.bv_val ) free( dn.bv_val );
	if ( ndn.bv_val ) free( ndn.bv_val );
	if ( pdn.bv_val ) free( pdn.bv_val );

	if ( filter ) slapi_filter_free( filter, 1 );
	if ( fstr.bv_val ) free ( fstr.bv_val );

	if ( an != NULL ) free( an );

	if ( c != NULL ) {
		if ( c->c_dn.bv_val ) slapi_ch_free( (void **)&c->c_dn.bv_val );
		if ( op ) {
			if ( op->o_ndn.bv_val ) slapi_ch_free( (void **)&op->o_ndn.bv_val );
			free( op );
		}
		pSavePB = ptr;
		free( c );
    	}
	return( pSavePB );
#endif /* LDAP_SLAPI */
	return NULL;
}

Slapi_PBlock * 
slapi_search_internal(
	char *base,
	int scope,
	char *filStr, 
	LDAPControl **controls,
	char **attrs,
	int attrsonly ) 
{
#if defined(LDAP_SLAPI)
	return slapi_search_internal_bind( NULL, base, scope, filStr,
			controls, attrs, attrsonly );
#endif
	return NULL;
}

