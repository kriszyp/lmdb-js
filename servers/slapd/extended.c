/* $OpenLDAP$ */
/* 
 * Copyright 1999-2002 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/*
 * LDAPv3 Extended Operation Request
 *	ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
 *		requestName	 [0] LDAPOID,
 *		requestValue	 [1] OCTET STRING OPTIONAL
 *	}
 *
 * LDAPv3 Extended Operation Response
 *	ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *		COMPONENTS OF LDAPResult,
 *		responseName	 [10] LDAPOID OPTIONAL,
 *		response	 [11] OCTET STRING OPTIONAL
 *	}
 *
 */

#include "portable.h"
#include "slapi_common.h"

#include <stdio.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "slapi.h"
#include "lber_pvt.h"

#define UNSUPPORTED_EXTENDEDOP "unsupported extended operation"

static struct extop_list {
	struct extop_list *next;
	struct berval oid;
	SLAP_EXTOP_MAIN_FN *ext_main;
} *supp_ext_list = NULL;

static SLAP_EXTOP_MAIN_FN whoami_extop;

/* BerVal Constant initializer */

#define	BVC(x)	{sizeof(x)-1, x}

/* this list of built-in extops is for extops that are not part
 * of backends or in external modules.	essentially, this is
 * just a way to get built-in extops onto the extop list without
 * having a separate init routine for each built-in extop.
 */
static struct {
	struct berval oid;
	SLAP_EXTOP_MAIN_FN *ext_main;
} builtin_extops[] = {
#ifdef HAVE_TLS
	{ BVC(LDAP_EXOP_START_TLS), starttls_extop },
#endif
	{ BVC(LDAP_EXOP_MODIFY_PASSWD), passwd_extop },
	{ BVC(LDAP_EXOP_X_WHO_AM_I), whoami_extop },
	{ {0,NULL}, NULL }
};


static struct extop_list *find_extop(
	struct extop_list *list, struct berval *oid );

struct berval *
get_supported_extop (int index)
{
	struct extop_list *ext;

	/* linear scan is slow, but this way doesn't force a
	 * big change on root_dse.c, where this routine is used.
	 */
	for (ext = supp_ext_list; ext != NULL && --index >= 0; ext = ext->next) {
		; /* empty */
	}

	if (ext == NULL) return NULL;

	return &ext->oid ;
}

int
do_extended(
    Connection	*conn,
    Operation	*op
)
{
	int rc = LDAP_SUCCESS;
	struct berval reqoid = {0, NULL};
	struct berval reqdata = {0, NULL};
	ber_tag_t tag;
	ber_len_t len;
	struct extop_list *ext;
	const char *text;
	BerVarray refs;
	char *rspoid;
	struct berval *rspdata;
	LDAPControl **rspctrls;

#if defined(LDAP_SLAPI) 
 	Slapi_PBlock    *pb = op->o_pb;
 	SLAPI_FUNC      funcAddr = NULL;
 	int             extop_rc;
 	int             msg_sent = FALSE;
 	char            *result_msg = "";
#endif /* defined(LDAP_SLAPI) */

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_extended: conn %d\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_extended\n", 0, 0, 0 );
#endif

	if( op->o_protocol < LDAP_VERSION3 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_extended: protocol version (%d) too low.\n", op->o_protocol, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_extended: protocol version (%d) too low\n",
			op->o_protocol, 0 ,0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "requires LDAPv3" );
		rc = -1;
		goto done;
	}

	if ( ber_scanf( op->o_ber, "{m" /*}*/, &reqoid ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_extended: conn %d  ber_scanf failed\n", 
			conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = -1;
		goto done;
	}

#if !defined(LDAP_SLAPI)
	if( !(ext = find_extop(supp_ext_list, &reqoid)) ) {
#else /* defined(LDAP_SLAPI) */
	/* Netscape extended operation */
	getPluginFunc( &reqoid, &funcAddr );

	if( !(ext = find_extop(supp_ext_list, &reqoid)) && !(funcAddr) ) {
#endif /* defined(LDAP_SLAPI) */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_extended: conn %d  unsupported operation \"%s\"\n",
			conn->c_connid, reqoid.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: unsupported operation \"%s\"\n",
			reqoid.bv_val, 0 ,0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_PROTOCOL_ERROR,
			NULL, "unsupported extended operation", NULL, NULL );
		goto done;
	}

	op->o_extendedop = reqoid.bv_val;

	tag = ber_peek_tag( op->o_ber, &len );
	
	if( ber_peek_tag( op->o_ber, &len ) == LDAP_TAG_EXOP_REQ_VALUE ) {
		if( ber_scanf( op->o_ber, "m", &reqdata ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"do_extended: conn %d  ber_scanf failed\n", 
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
#endif
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = -1;
			goto done;
		}
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_extended: conn %d  get_ctrls failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: get_ctrls failed\n", 0, 0 ,0 );
#endif
		return rc;
	} 

	/* check for controls inappropriate for all extended operations */
	if( get_manageDSAit( op ) == SLAP_CRITICAL_CONTROL ) {
		send_ldap_result( conn, op,
			rc = LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
			NULL, "manageDSAit control inappropriate",
			NULL, NULL );
		goto done;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, DETAIL1, 
		"do_extended: conn %d  oid=%d\n.", conn->c_connid, reqoid.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "do_extended: oid=%s\n", reqoid.bv_val, 0 ,0 );
#endif

	rspoid = NULL;
	rspdata = NULL;
	rspctrls = NULL;
	text = NULL;
	refs = NULL;

#if defined(LDAP_SLAPI)
	if (ext != NULL) { /* OpenLDAP extended operation */
#endif /* defined(LDAP_SLAPI) */

		rc = (ext->ext_main)( conn, op,
			  reqoid.bv_val, reqdata.bv_val ? &reqdata : NULL,
			  &rspoid, &rspdata, &rspctrls, &text, &refs );

		if( rc != SLAPD_ABANDON ) {
			if ( rc == LDAP_REFERRAL && refs == NULL ) {
				refs = referral_rewrite( default_referral,
					NULL, NULL, LDAP_SCOPE_DEFAULT );
			}

			send_ldap_extended( conn, op, rc, NULL, text, refs,
				rspoid, rspdata, rspctrls );

			ber_bvarray_free( refs );
		}

		if ( rspoid != NULL ) {
			free( rspoid );
		}

		if ( rspdata != NULL ) {
			ber_bvfree( rspdata );
		}

#if defined( LDAP_SLAPI )
		goto done;  /* end of OpenLDAP extended operation */

	} else { /* start of Netscape extended operation */
		rc = slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_OID,
				(void *)reqoid.bv_val);
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_OPERATIONS_ERROR;
			goto done;
		}

		rc = slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_VALUE,
				(void *)&reqdata);
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_OPERATIONS_ERROR;
			goto done;
		}

		rc = slapi_pblock_set( pb, SLAPI_CONNECTION, (void *)conn );
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_OPERATIONS_ERROR;
			goto done;
		}

		rc = slapi_pblock_set( pb, SLAPI_OPERATION, (void *)op);
		if ( rc != LDAP_SUCCESS ) {
			rc = LDAP_OPERATIONS_ERROR;
			goto done;
		}

		extop_rc = (*funcAddr)( pb );
		if ( extop_rc == SLAPI_PLUGIN_EXTENDED_SENT_RESULT ) {
			msg_sent = TRUE;

		} else if ( extop_rc == SLAPI_PLUGIN_EXTENDED_NOT_HANDLED ) {
			rc = LDAP_PROTOCOL_ERROR;
			result_msg = UNSUPPORTED_EXTENDEDOP;

		} else {
			rc = slapi_pblock_get( pb, SLAPI_EXT_OP_RET_OID,
					&rspoid);
			if ( rc != LDAP_SUCCESS ) {
				goto done2;
			}

			rc = slapi_pblock_get( pb, SLAPI_EXT_OP_RET_VALUE,
					&rspdata);
			if ( rc != LDAP_SUCCESS ) {
				goto done2;
			}

			send_ldap_extended( conn, op, extop_rc, NULL, text,
					refs, rspoid, rspdata, rspctrls );
			msg_sent = TRUE;
		}

done2:;
		if ( rc != LDAP_SUCCESS && msg_sent == FALSE ) {
			send_ldap_result( conn, op, rc, NULL, result_msg,
					NULL, NULL );
		}

		if ( rspoid != NULL ) {
			free( rspoid );
		}

		if ( rspdata != NULL ) {
			ber_bvfree( rspdata );
		}

	} /* end of Netscape extended operation */
#endif /* defined( LDAP_SLAPI ) */

done:
	return rc;
}

int
load_extop(
	const char *ext_oid,
	SLAP_EXTOP_MAIN_FN *ext_main )
{
	struct extop_list *ext;

	if( ext_oid == NULL || *ext_oid == '\0' ) return -1; 
	if(!ext_main) return -1; 

	ext = ch_calloc(1, sizeof(struct extop_list));
	if (ext == NULL)
		return(-1);

	ber_str2bv( ext_oid, 0, 1, &ext->oid );
	if (ext->oid.bv_val == NULL) {
		free(ext);
		return(-1);
	}

	ext->ext_main = ext_main;
	ext->next = supp_ext_list;

	supp_ext_list = ext;

	return(0);
}

int
extops_init (void)
{
	int i;

	for (i = 0; builtin_extops[i].oid.bv_val != NULL; i++) {
		load_extop(builtin_extops[i].oid.bv_val, builtin_extops[i].ext_main);
	}
	return(0);
}

int
extops_kill (void)
{
	struct extop_list *ext;

	/* we allocated the memory, so we have to free it, too. */
	while ((ext = supp_ext_list) != NULL) {
		supp_ext_list = ext->next;
		if (ext->oid.bv_val != NULL)
			ch_free(ext->oid.bv_val);
		ch_free(ext);
	}
	return(0);
}

static struct extop_list *
find_extop( struct extop_list *list, struct berval *oid )
{
	struct extop_list *ext;

	for (ext = list; ext; ext = ext->next) {
		if (bvmatch(&ext->oid, oid))
			return(ext);
	}
	return(NULL);
}


static int
whoami_extop (
	Connection *conn,
	Operation *op,
	const char * reqoid,
	struct berval * reqdata,
	char ** rspoid,
	struct berval ** rspdata,
	LDAPControl ***rspctrls,
	const char ** text,
	BerVarray * refs )
{
	struct berval *bv;

	if ( reqdata != NULL ) {
		/* no request data should be provided */
		*text = "no request data expected";
		return LDAP_PROTOCOL_ERROR;
	}

	{
		int rc;
		struct berval whoami = BER_BVC( LDAP_EXOP_X_WHO_AM_I );

		rc = backend_check_restrictions( conn->c_authz_backend,
			conn, op, &whoami, text );

		if( rc != LDAP_SUCCESS ) return rc;
	}

	bv = (struct berval *) ch_malloc( sizeof(struct berval) );
	if( op->o_dn.bv_len ) {
		bv->bv_len = op->o_dn.bv_len + sizeof("dn:")-1;
		bv->bv_val = ch_malloc( bv->bv_len + 1 );
		AC_MEMCPY( bv->bv_val, "dn:", sizeof("dn:")-1 );
		AC_MEMCPY( &bv->bv_val[sizeof("dn:")-1], op->o_dn.bv_val,
			op->o_dn.bv_len );
		bv->bv_val[bv->bv_len] = '\0';

	} else {
		bv->bv_len = 0;
		bv->bv_val = NULL;
	}

	*rspdata = bv;
	return LDAP_SUCCESS;
}
