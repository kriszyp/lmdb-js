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
#include <slap.h>
#include <slapi.h>

static slapi_pblock_class_t 
getPBlockClass( int param ) 
{
	switch ( param ) {
	case SLAPI_PLUGIN_TYPE:
	case SLAPI_PLUGIN_ARGC:
	case SLAPI_PLUGIN_VERSION:
	case SLAPI_PLUGIN_OPRETURN:
	case SLAPI_PLUGIN_INTOP_RESULT:
	case SLAPI_CONFIG_LINENO:
	case SLAPI_CONFIG_ARGC:
	case SLAPI_BIND_METHOD:
	case SLAPI_MODRDN_DELOLDRDN:
	case SLAPI_SEARCH_SCOPE:
	case SLAPI_SEARCH_DEREF:
	case SLAPI_SEARCH_SIZELIMIT:
	case SLAPI_SEARCH_TIMELIMIT:
	case SLAPI_SEARCH_ATTRSONLY:
	case SLAPI_NENTRIES:
	case SLAPI_CHANGENUMBER:
	case SLAPI_DBSIZE:
	case SLAPI_REQUESTOR_ISROOT:
	case SLAPI_BE_READONLY:
	case SLAPI_BE_LASTMOD:
	case SLAPI_DB2LDIF_PRINTKEY:
	case SLAPI_LDIF2DB_REMOVEDUPVALS:
	case SLAPI_MANAGEDSAIT:
	case SLAPI_IBM_BROADCAST_BE:
	case SLAPI_IBM_REPLICATE:
	case SLAPI_IBM_CL_MAX_ENTRIES:
	case SLAPI_IBM_CL_FIRST_ENTRY:
	case SLAPI_IBM_CL_LAST_ENTRY:
	case SLAPI_IBM_EVENT_ENABLED:
	case SLAPI_IBM_EVENT_MAXREG:
	case SLAPI_IBM_EVENT_REGPERCONN:
	case SLAPI_REQUESTOR_ISUPDATEDN:
	case SLAPI_X_CONN_IS_UDP:
	case SLAPI_X_CONN_SSF:
	case SLAPI_RESULT_CODE:
		return PBLOCK_CLASS_INTEGER;
		break;

	case SLAPI_CONN_ID:
	case SLAPI_OPERATION_ID:
	case SLAPI_OPINITIATED_TIME:
	case SLAPI_ABANDON_MSGID:
		return PBLOCK_CLASS_LONG_INTEGER;
		break;

	case SLAPI_PLUGIN_DB_INIT_FN:
	case SLAPI_PLUGIN_DESTROY_FN:
	case SLAPI_PLUGIN_DB_BIND_FN:
	case SLAPI_PLUGIN_DB_UNBIND_FN:
	case SLAPI_PLUGIN_DB_SEARCH_FN:
	case SLAPI_PLUGIN_DB_COMPARE_FN:
	case SLAPI_PLUGIN_DB_MODIFY_FN:
	case SLAPI_PLUGIN_DB_MODRDN_FN:
	case SLAPI_PLUGIN_DB_ADD_FN:
	case SLAPI_PLUGIN_DB_DELETE_FN:
	case SLAPI_PLUGIN_DB_ABANDON_FN:
	case SLAPI_PLUGIN_DB_CONFIG_FN:
	case SLAPI_PLUGIN_CLOSE_FN:
	case SLAPI_PLUGIN_DB_FLUSH_FN:
	case SLAPI_PLUGIN_START_FN:
	case SLAPI_PLUGIN_DB_SEQ_FN:
	case SLAPI_PLUGIN_DB_ENTRY_FN:
	case SLAPI_PLUGIN_DB_REFERRAL_FN:
	case SLAPI_PLUGIN_DB_RESULT_FN:
	case SLAPI_PLUGIN_DB_LDIF2DB_FN:
	case SLAPI_PLUGIN_DB_DB2LDIF_FN:
	case SLAPI_PLUGIN_DB_BEGIN_FN:
	case SLAPI_PLUGIN_DB_COMMIT_FN:
	case SLAPI_PLUGIN_DB_ABORT_FN:
	case SLAPI_PLUGIN_DB_ARCHIVE2DB_FN:
	case SLAPI_PLUGIN_DB_DB2ARCHIVE_FN:
	case SLAPI_PLUGIN_DB_NEXT_SEARCH_ENTRY_FN:
	case SLAPI_PLUGIN_DB_FREE_RESULT_SET_FN:
	case SLAPI_PLUGIN_DB_SIZE_FN:
	case SLAPI_PLUGIN_DB_TEST_FN:
	case SLAPI_PLUGIN_DB_NO_ACL:
	case SLAPI_PLUGIN_EXT_OP_FN:
	case SLAPI_PLUGIN_EXT_OP_OIDLIST:
	case SLAPI_PLUGIN_PRE_BIND_FN:
	case SLAPI_PLUGIN_PRE_UNBIND_FN:
	case SLAPI_PLUGIN_PRE_SEARCH_FN:
	case SLAPI_PLUGIN_PRE_COMPARE_FN:
	case SLAPI_PLUGIN_PRE_MODIFY_FN:
	case SLAPI_PLUGIN_PRE_MODRDN_FN:
	case SLAPI_PLUGIN_PRE_ADD_FN:
	case SLAPI_PLUGIN_PRE_DELETE_FN:
	case SLAPI_PLUGIN_PRE_ABANDON_FN:
	case SLAPI_PLUGIN_PRE_ENTRY_FN:
	case SLAPI_PLUGIN_PRE_REFERRAL_FN:
	case SLAPI_PLUGIN_PRE_RESULT_FN:
	case SLAPI_PLUGIN_POST_BIND_FN:
	case SLAPI_PLUGIN_POST_UNBIND_FN:
	case SLAPI_PLUGIN_POST_SEARCH_FN:
	case SLAPI_PLUGIN_POST_COMPARE_FN:
	case SLAPI_PLUGIN_POST_MODIFY_FN:
	case SLAPI_PLUGIN_POST_MODRDN_FN:
	case SLAPI_PLUGIN_POST_ADD_FN:
	case SLAPI_PLUGIN_POST_DELETE_FN:
	case SLAPI_PLUGIN_POST_ABANDON_FN:
	case SLAPI_PLUGIN_POST_ENTRY_FN:
	case SLAPI_PLUGIN_POST_REFERRAL_FN:
	case SLAPI_PLUGIN_POST_RESULT_FN:
	case SLAPI_PLUGIN_MR_FILTER_CREATE_FN:
	case SLAPI_PLUGIN_MR_INDEXER_CREATE_FN:
	case SLAPI_PLUGIN_MR_FILTER_MATCH_FN:
	case SLAPI_PLUGIN_MR_FILTER_INDEX_FN:
	case SLAPI_PLUGIN_MR_FILTER_RESET_FN:
	case SLAPI_PLUGIN_MR_INDEX_FN:
	case SLAPI_PLUGIN_COMPUTE_EVALUATOR_FN:
	case SLAPI_PLUGIN_COMPUTE_SEARCH_REWRITER_FN:
	case SLAPI_PLUGIN_ACL_ALLOW_ACCESS:
	case SLAPI_X_PLUGIN_PRE_GROUP_FN:
	case SLAPI_X_PLUGIN_POST_GROUP_FN:
	case SLAPI_PLUGIN_AUDIT_FN:
		return PBLOCK_CLASS_FUNCTION_POINTER;
		break;

	case SLAPI_BACKEND:
	case SLAPI_CONNECTION:
	case SLAPI_OPERATION:
	case SLAPI_OPERATION_PARAMETERS:
	case SLAPI_OPERATION_TYPE:
	case SLAPI_OPERATION_AUTHTYPE:
	case SLAPI_BE_MONITORDN:
	case SLAPI_BE_TYPE:
	case SLAPI_REQUESTOR_DN:
	case SLAPI_CONN_DN:
	case SLAPI_CONN_CLIENTIP:
	case SLAPI_CONN_SERVERIP:
	case SLAPI_CONN_AUTHTYPE:
	case SLAPI_CONN_AUTHMETHOD:
	case SLAPI_CONN_CERT:
	case SLAPI_X_CONN_CLIENTPATH:
	case SLAPI_X_CONN_SERVERPATH:
	case SLAPI_X_CONN_SASL_CONTEXT:
	case SLAPI_X_CONFIG_ARGV:
	case SLAPI_IBM_CONN_DN_ALT:
	case SLAPI_IBM_CONN_DN_ORIG:
	case SLAPI_IBM_GSSAPI_CONTEXT:
	case SLAPI_PLUGIN_MR_OID:
	case SLAPI_PLUGIN_MR_TYPE:
	case SLAPI_PLUGIN_MR_VALUE:
	case SLAPI_PLUGIN_MR_VALUES:
	case SLAPI_PLUGIN_MR_KEYS:
	case SLAPI_PLUGIN:
	case SLAPI_PLUGIN_PRIVATE:
	case SLAPI_PLUGIN_ARGV:
	case SLAPI_PLUGIN_OBJECT:
	case SLAPI_PLUGIN_DESCRIPTION:
	case SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES:
	case SLAPI_PLUGIN_INTOP_SEARCH_REFERRALS:
	case SLAPI_PLUGIN_MR_FILTER_REUSABLE:
	case SLAPI_PLUGIN_MR_QUERY_OPERATOR:
	case SLAPI_PLUGIN_MR_USAGE:
	case SLAPI_OP_LESS:
	case SLAPI_OP_LESS_OR_EQUAL:
	case SLAPI_PLUGIN_MR_USAGE_INDEX:
	case SLAPI_PLUGIN_SYNTAX_FILTER_AVA:
	case SLAPI_PLUGIN_SYNTAX_FILTER_SUB:
	case SLAPI_PLUGIN_SYNTAX_VALUES2KEYS:
	case SLAPI_PLUGIN_SYNTAX_ASSERTION2KEYS_AVA:
	case SLAPI_PLUGIN_SYNTAX_ASSERTION2KEYS_SUB:
	case SLAPI_PLUGIN_SYNTAX_NAMES:
	case SLAPI_PLUGIN_SYNTAX_OID:
	case SLAPI_PLUGIN_SYNTAX_FLAGS:
	case SLAPI_PLUGIN_SYNTAX_COMPARE:
	case SLAPI_CONFIG_FILENAME:
	case SLAPI_CONFIG_ARGV:
	case SLAPI_TARGET_DN:
	case SLAPI_REQCONTROLS:
	case SLAPI_ENTRY_PRE_OP:
	case SLAPI_ENTRY_POST_OP:
	case SLAPI_RESCONTROLS:
	case SLAPI_ADD_RESCONTROL:
	case SLAPI_ADD_ENTRY:
	case SLAPI_BIND_CREDENTIALS:
	case SLAPI_BIND_SASLMECHANISM:
	case SLAPI_BIND_RET_SASLCREDS:
	case SLAPI_COMPARE_TYPE:
	case SLAPI_COMPARE_VALUE:
	case SLAPI_MODIFY_MODS:
	case SLAPI_MODRDN_NEWRDN:
	case SLAPI_MODRDN_NEWSUPERIOR:
	case SLAPI_SEARCH_FILTER:
	case SLAPI_SEARCH_STRFILTER:
	case SLAPI_SEARCH_ATTRS:
	case SLAPI_SEQ_TYPE:
	case SLAPI_SEQ_ATTRNAME:
	case SLAPI_SEQ_VAL:
	case SLAPI_EXT_OP_REQ_OID:
	case SLAPI_EXT_OP_REQ_VALUE:
	case SLAPI_EXT_OP_RET_OID:
	case SLAPI_EXT_OP_RET_VALUE:
	case SLAPI_MR_FILTER_ENTRY:
	case SLAPI_MR_FILTER_TYPE:
	case SLAPI_MR_FILTER_VALUE:
	case SLAPI_MR_FILTER_OID:
	case SLAPI_MR_FILTER_DNATTRS:
	case SLAPI_LDIF2DB_FILE:
	case SLAPI_PARENT_TXN:
	case SLAPI_TXN:
	case SLAPI_SEARCH_RESULT_SET:
	case SLAPI_SEARCH_RESULT_ENTRY:
	case SLAPI_SEARCH_REFERRALS:
	case SLAPI_LOG_OPERATION:
	case SLAPI_RESULT_TEXT:
	case SLAPI_RESULT_MATCHED:
	case SLAPI_X_GROUP_ENTRY:
	case SLAPI_X_GROUP_ATTRIBUTE:
	case SLAPI_X_GROUP_OPERATION_DN:
	case SLAPI_X_GROUP_TARGET_ENTRY:
	case SLAPI_PLUGIN_AUDIT_DATA:
	case SLAPI_IBM_PBLOCK:
		return PBLOCK_CLASS_POINTER;
		break;
	default:
		break;
	}

	return PBLOCK_CLASS_INVALID;
}

static void
Lock( Slapi_PBlock *pb )
{
	ldap_pvt_thread_mutex_lock(&pb->pblockMutex);
}

static void
unLock( Slapi_PBlock *pb )
{
	ldap_pvt_thread_mutex_unlock(&pb->pblockMutex);
}

static int 
get( Slapi_PBlock *pb, int param, void **val ) 
{	
	int i;
	slapi_pblock_class_t pbClass;

	pbClass = getPBlockClass( param );
	if ( pbClass == PBLOCK_CLASS_INVALID ) {
		return PBLOCK_ERROR;
	}
	
	Lock( pb );

	switch ( pbClass ) {
	case PBLOCK_CLASS_INTEGER:
		*((int *)val) = 0;
		break;
	case PBLOCK_CLASS_LONG_INTEGER:
		*((long *)val) = 0L;
		break;
	case PBLOCK_CLASS_POINTER:
	case PBLOCK_CLASS_FUNCTION_POINTER:
		*val = NULL;
		break;
	}

	for ( i = 0; i < pb->numParams; i++ ) {
		if ( pb->curParams[i] == param ) {
			switch ( pbClass ) {
			case PBLOCK_CLASS_INTEGER:
				*((int *)val) = (int)pb->curVals[i];
				break;
			case PBLOCK_CLASS_LONG_INTEGER:
				*((long *)val) = (long)pb->curVals[i];
				break;
			case PBLOCK_CLASS_POINTER:
			case PBLOCK_CLASS_FUNCTION_POINTER:
				*val = pb->curVals[i];
				break;
			default:
				break;
			}
			break;
	  	}
	}
	unLock( pb );	
	return PBLOCK_SUCCESS;
}

static int 
set( Slapi_PBlock *pb, int param, void *val ) 
{
#if defined(LDAP_SLAPI)
	int i, freeit;
	int addcon = 0;
	slapi_pblock_class_t pbClass;

	pbClass = getPBlockClass( param );
	if ( pbClass == PBLOCK_CLASS_INVALID ) {
		return PBLOCK_ERROR;
	}

	Lock( pb );	

	if ( pb->numParams == PBLOCK_MAX_PARAMS ) {
		unLock( pb );
		return PBLOCK_ERROR; 
	}

	if ( param == SLAPI_ADD_RESCONTROL ) {
		addcon = 1;
		param = SLAPI_RES_CONTROLS;
	}

	switch ( param ) {
        case SLAPI_CONN_DN:
        case SLAPI_CONN_AUTHMETHOD:
        case SLAPI_IBM_CONN_DN_ALT:
        case SLAPI_IBM_CONN_DN_ORIG:
        case SLAPI_RESULT_TEXT:
        case SLAPI_RESULT_MATCHED:
		freeit = 1;
		break;
	default:
		freeit = 0;
		break;
	}
	for( i = 0; i < pb->numParams; i++ ) { 
		if ( pb->curParams[i] == param ) {
			break;
		}
	}

	if ( i >= pb->numParams ) {
		pb->curParams[i] = param;
	  	pb->numParams++;
	}
	if ( addcon ) {
		LDAPControl **ctrls = pb->curVals[i];
		int j;

		if ( ctrls ) {
			for (j=0; ctrls[j]; j++);
			ctrls = ch_realloc( ctrls, (j+2)*sizeof(LDAPControl *) );
		} else {
			ctrls = ch_malloc( 2 * sizeof(LDAPControl *) );
			j = 0;
		}
		ctrls[j] = val;
		ctrls[j+1] = NULL;
		pb->curVals[i] = ctrls;
	} else {
		if ( freeit ) ch_free( pb->curVals[i] );
		pb->curVals[i] = val;
	}

	unLock( pb );	
	return PBLOCK_SUCCESS;
#endif /* LDAP_SLAPI */
	return PBLOCK_ERROR;
}

static void
clearPB( Slapi_PBlock *pb ) 
{
	pb->numParams = 1;
}

static void
checkParams( Slapi_PBlock *pb, int flag ) 
{
	pb->ckParams = flag;
}

static int
deleteParam( Slapi_PBlock *p, int param ) 
{
	int i;

	Lock(p);
	for ( i = 0; i < p->numParams; i++ ) { 
		if ( p->curParams[i] == param ) {
			break;
		}
	}
    
	if (i >= p->numParams ) {
		unLock( p );
		return PBLOCK_ERROR;
	}
	if ( p->numParams > 1 ) {
		p->curParams[i] = p->curParams[p->numParams];
		p->curVals[i] = p->curVals[p->numParams];
	}
	p->numParams--;
	unLock( p );	
	return PBLOCK_SUCCESS;
}

Slapi_PBlock *
slapi_pblock_new() 
{
#if defined(LDAP_SLAPI)
	Slapi_PBlock *pb;

	pb = (Slapi_PBlock *) ch_malloc(sizeof(Slapi_PBlock));
	if ( pb != NULL ) {
		pb->ckParams = TRUE;
		ldap_pvt_thread_mutex_init( &pb->pblockMutex );
		memset( pb->curParams, 0, sizeof(pb->curParams) );
		memset( pb->curVals, 0, sizeof(pb->curVals) );
		pb->curParams[0] = SLAPI_IBM_PBLOCK;
		pb->curVals[0] = NULL;
		pb->numParams = 1;
	}
	return pb;
#endif /* LDAP_SLAPI */
	return NULL;
}

void 
slapi_pblock_destroy( Slapi_PBlock* pb ) 
{
#if defined(LDAP_SLAPI)
	char *str = NULL;
	LDAPControl **rescontrols = NULL;

	get( pb, SLAPI_CONN_DN,(void **)&str );
	if ( str != NULL ) {
		ch_free( str );
		str = NULL;
	}

	get( pb, SLAPI_CONN_AUTHMETHOD, (void **)&str );
	if ( str != NULL ) {
		ch_free( str );
		str = NULL;
	}

	get( pb, SLAPI_IBM_CONN_DN_ALT, (void **)&str );
	if ( str != NULL ) {
		ch_free( str );
		str = NULL;
	}

	get( pb, SLAPI_IBM_CONN_DN_ORIG, (void **)&str );
	if ( str != NULL ) {
		ch_free( str );
	}

	get( pb, SLAPI_RESULT_TEXT, (void **)&str );
	if ( str != NULL ) {
		ch_free( str );
		str = NULL;
	}

	get( pb, SLAPI_RESULT_MATCHED, (void **)&str );
	if ( str != NULL ) {
		ch_free( str );
		str = NULL;
	}

	get( pb, SLAPI_RESCONTROLS, (void **)&rescontrols );
	if ( rescontrols != NULL ) {
		ldap_controls_free( rescontrols );
		rescontrols = NULL;
	}

	ldap_pvt_thread_mutex_destroy( &pb->pblockMutex );

	ch_free( pb ); 
#endif /* LDAP_SLAPI */
}

int 
slapi_pblock_get( Slapi_PBlock *pb, int arg, void *value ) 
{
#if defined(LDAP_SLAPI)
	return get( pb, arg, (void **)value );
#endif /* LDAP_SLAPI */
	return PBLOCK_ERROR;
}

int 
slapi_pblock_set( Slapi_PBlock *pb, int arg, void *value ) 
{
#if defined(LDAP_SLAPI)
	void *pTmp = NULL;

	switch ( arg ) {
        case SLAPI_CONN_DN:
        case SLAPI_CONN_AUTHMETHOD:
        case SLAPI_IBM_CONN_DN_ALT:
        case SLAPI_IBM_CONN_DN_ORIG:
        case SLAPI_RESULT_TEXT:
        case SLAPI_RESULT_MATCHED:
		if ( value != NULL ) {
			pTmp = (void *)slapi_ch_strdup((char *)value);
			if ( pTmp == NULL ) {
				return LDAP_NO_MEMORY;
			}
		}
		break;
	default:
		pTmp = value;
		break;
	}
	return set( pb, arg, pTmp );
#endif /* LDAP_SLAPI */
	return LDAP_NO_MEMORY;
}

void
slapi_pblock_clear( Slapi_PBlock *pb ) 
{
#if defined(LDAP_SLAPI)
   clearPB( pb );
#endif /* LDAP_SLAPI */
}

int 
slapi_pblock_delete_param( Slapi_PBlock *p, int param ) 
{
#if defined(LDAP_SLAPI)
	return deleteParam( p, param );
#endif /* LDAP_SLAPI */
	return PBLOCK_ERROR;
}

void
slapi_pblock_check_params( Slapi_PBlock *pb, int flag ) 
{
#if defined(LDAP_SLAPI)
	checkParams( pb, flag );
#endif /* LDAP_SLAPI */
}

/*
 * OpenLDAP extension
 */
int
slapi_int_pblock_get_first( Backend *be, Slapi_PBlock **pb )
{
#if defined(LDAP_SLAPI)
	assert( pb );
	*pb = (Slapi_PBlock *)be->be_pb;
	return (*pb == NULL ? LDAP_OTHER : LDAP_SUCCESS);
#else /* LDAP_SLAPI */
	return LDAP_OTHER;
#endif /* LDAP_SLAPI */
}

/*
 * OpenLDAP extension
 */
int
slapi_int_pblock_get_next( Slapi_PBlock **pb )
{
#if defined(LDAP_SLAPI)
	assert( pb );
	return slapi_pblock_get( *pb, SLAPI_IBM_PBLOCK, pb );
#else /* LDAP_SLAPI */
	return LDAP_OTHER;
#endif /* LDAP_SLAPI */
}

