/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
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

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "lber_pvt.h"

#ifdef LDAP_SLAPI
#include "slapi.h"
#endif

#define UNSUPPORTED_EXTENDEDOP "unsupported extended operation"

#ifdef LDAP_DEVEL
#define SLAP_EXOP_HIDE 0x0000
#else
#define SLAP_EXOP_HIDE 0x8000
#endif

static struct extop_list {
	struct extop_list *next;
	struct berval oid;
	slap_mask_t flags;
	SLAP_EXTOP_MAIN_FN *ext_main;
} *supp_ext_list = NULL;

static SLAP_EXTOP_MAIN_FN whoami_extop;

/* this list of built-in extops is for extops that are not part
 * of backends or in external modules.	essentially, this is
 * just a way to get built-in extops onto the extop list without
 * having a separate init routine for each built-in extop.
 */
#ifdef LDAP_EXOP_X_CANCEL
const struct berval slap_EXOP_CANCEL = BER_BVC(LDAP_EXOP_X_CANCEL);
#endif
const struct berval slap_EXOP_WHOAMI = BER_BVC(LDAP_EXOP_X_WHO_AM_I);
const struct berval slap_EXOP_MODIFY_PASSWD = BER_BVC(LDAP_EXOP_MODIFY_PASSWD);
const struct berval slap_EXOP_START_TLS = BER_BVC(LDAP_EXOP_START_TLS);

static struct {
	const struct berval *oid;
	slap_mask_t flags;
	SLAP_EXTOP_MAIN_FN *ext_main;
} builtin_extops[] = {
#ifdef LDAP_EXOP_X_CANCEL
	{ &slap_EXOP_CANCEL, SLAP_EXOP_HIDE, cancel_extop },
#endif
	{ &slap_EXOP_WHOAMI, 0, whoami_extop },
	{ &slap_EXOP_MODIFY_PASSWD, 0, passwd_extop },
#ifdef HAVE_TLS
	{ &slap_EXOP_START_TLS, 0, starttls_extop },
#endif
	{ NULL, 0, NULL }
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

	return &ext->oid;
}


int exop_root_dse_info( Entry *e )
{
	AttributeDescription *ad_supportedExtension
		= slap_schema.si_ad_supportedExtension;
	struct berval vals[2];
	struct extop_list *ext;

	vals[1].bv_val = NULL;
	vals[1].bv_len = 0;

	for (ext = supp_ext_list; ext != NULL; ext = ext->next) {
		if( ext->flags & SLAP_EXOP_HIDE ) continue;

		vals[0] = ext->oid;

		if( attr_merge( e, ad_supportedExtension, vals, NULL ) ) {
			return LDAP_OTHER;
		}
	}

	return LDAP_SUCCESS;
}

int
do_extended(
    Operation	*op,
    SlapReply	*rs
)
{
	struct berval reqdata = {0, NULL};
	ber_tag_t tag;
	ber_len_t len;
	struct extop_list *ext = NULL;

#if defined(LDAP_SLAPI) 
 	Slapi_PBlock    *pb = op->o_pb;
 	SLAPI_FUNC      funcAddr = NULL;
 	int             extop_rc;
 	int             msg_sent = FALSE;
#endif /* defined(LDAP_SLAPI) */

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_extended: conn %d\n", op->o_connid, 0, 0 );
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
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "requires LDAPv3" );
		rs->sr_err = -1;
		goto done;
	}

	if ( ber_scanf( op->o_ber, "{m" /*}*/, &op->ore_reqoid ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_extended: conn %d  ber_scanf failed\n", 
			op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
#endif
		send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
		rs->sr_err = -1;
		goto done;
	}

#ifdef LDAP_SLAPI
	getPluginFunc( &op->ore_reqoid, &funcAddr ); /* NS-SLAPI extended operation */
	if( !funcAddr && !(ext = find_extop(supp_ext_list, &op->ore_reqoid )))
#else
	if( !(ext = find_extop(supp_ext_list, &op->ore_reqoid )))
#endif
	{
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_extended: conn %d  unsupported operation \"%s\"\n",
			op->o_connid, op->ore_reqoid.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: unsupported operation \"%s\"\n",
			op->ore_reqoid.bv_val, 0 ,0 );
#endif
		send_ldap_error( op, rs, LDAP_PROTOCOL_ERROR,
			"unsupported extended operation" );
		goto done;
	}

	tag = ber_peek_tag( op->o_ber, &len );
	
	if( ber_peek_tag( op->o_ber, &len ) == LDAP_TAG_EXOP_REQ_VALUE ) {
		if( ber_scanf( op->o_ber, "m", &reqdata ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
			LDAP_LOG( OPERATION, ERR, 
				"do_extended: conn %d  ber_scanf failed\n", 
				op->o_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "do_extended: ber_scanf failed\n", 0, 0 ,0 );
#endif
			send_ldap_discon( op, rs, LDAP_PROTOCOL_ERROR, "decoding error" );
			rs->sr_err = -1;
			goto done;
		}
	}

	if( get_ctrls( op, rs, 1 ) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_extended: conn %d  get_ctrls failed\n", op->o_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_extended: get_ctrls failed\n", 0, 0 ,0 );
#endif
		return rs->sr_err;
	} 

	/* check for controls inappropriate for all extended operations */
	if( get_manageDSAit( op ) == SLAP_CRITICAL_CONTROL ) {
		send_ldap_error( op, rs,
			LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
			"manageDSAit control inappropriate" );
		goto done;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, DETAIL1, 
		"do_extended: conn %d  oid=%s\n.", op->o_connid, op->ore_reqoid.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "do_extended: oid=%s\n", op->ore_reqoid.bv_val, 0 ,0 );
#endif

#if defined(LDAP_SLAPI)
	if ( funcAddr != NULL ) {
		rs->sr_err = slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_OID,
				(void *)op->ore_reqoid.bv_val);
		if ( rs->sr_err != LDAP_SUCCESS ) {
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

		rs->sr_err = slapi_pblock_set( pb, SLAPI_EXT_OP_REQ_VALUE,
				(void *)&reqdata);
		if ( rs->sr_err != LDAP_SUCCESS ) {
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

		rs->sr_err = slapi_int_pblock_set_operation( pb, op );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

		extop_rc = (*funcAddr)( pb );
		if ( extop_rc == SLAPI_PLUGIN_EXTENDED_SENT_RESULT ) {
			msg_sent = TRUE;

		} else if ( extop_rc == SLAPI_PLUGIN_EXTENDED_NOT_HANDLED ) {
			rs->sr_err = LDAP_PROTOCOL_ERROR;
			rs->sr_text = UNSUPPORTED_EXTENDEDOP;

		} else {
			rs->sr_err = slapi_pblock_get( pb, SLAPI_EXT_OP_RET_OID,
					&rs->sr_rspoid);
			if ( rs->sr_err != LDAP_SUCCESS ) {
				goto done2;
			}

			rs->sr_err = slapi_pblock_get( pb, SLAPI_EXT_OP_RET_VALUE,
					&rs->sr_rspdata);
			if ( rs->sr_err != LDAP_SUCCESS ) {
				goto done2;
			}

			rs->sr_err = extop_rc;
			send_ldap_extended( op, rs );
			msg_sent = TRUE;
		}

done2:;
		if ( rs->sr_err != LDAP_SUCCESS && msg_sent == FALSE ) {
			send_ldap_result( op, rs );
		}

		if ( rs->sr_rspoid != NULL ) {
			ch_free( (char *)rs->sr_rspoid );
		}

		if ( rs->sr_rspdata != NULL ) {
			ber_bvfree( rs->sr_rspdata );
		}
	} else { /* start of OpenLDAP extended operation */
#endif /* defined( LDAP_SLAPI ) */
		if (reqdata.bv_val) op->ore_reqdata = &reqdata;
		rs->sr_err = (ext->ext_main)( op, rs );

		if( rs->sr_err != SLAPD_ABANDON ) {
			if ( rs->sr_err == LDAP_REFERRAL && rs->sr_ref == NULL ) {
				rs->sr_ref = referral_rewrite( default_referral,
					NULL, NULL, LDAP_SCOPE_DEFAULT );
				if ( !rs->sr_ref ) rs->sr_ref = default_referral;
				if ( !rs->sr_ref ) {
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					rs->sr_text = "referral missing";
				}
			}

			send_ldap_extended( op, rs );

			if ( rs->sr_ref != default_referral ) {
				ber_bvarray_free( rs->sr_ref );
				rs->sr_ref = NULL;
			}
		}

		if ( rs->sr_rspoid != NULL ) {
			free( (char *)rs->sr_rspoid );
		}

		if ( rs->sr_rspdata != NULL ) {
			ber_bvfree( rs->sr_rspdata );
		}
#ifdef LDAP_SLAPI
	} /* end of OpenLDAP extended operation */
#endif /* LDAP_SLAPI */

done:
	return rs->sr_err;
}

int
load_extop(
	struct berval *ext_oid,
	slap_mask_t ext_flags,
	SLAP_EXTOP_MAIN_FN *ext_main )
{
	struct extop_list *ext;

	if( ext_oid == NULL || ext_oid->bv_val == NULL ||
		ext_oid->bv_val[0] == '\0' || ext_oid->bv_len == 0 ) return -1; 
	if(!ext_main) return -1; 

	ext = ch_calloc(1, sizeof(struct extop_list) + ext_oid->bv_len + 1);
	if (ext == NULL)
		return(-1);

	ext->flags = ext_flags;

	ext->oid.bv_val = (char *)(ext + 1);
	AC_MEMCPY( ext->oid.bv_val, ext_oid->bv_val, ext_oid->bv_len );
	ext->oid.bv_len = ext_oid->bv_len;
	ext->oid.bv_val[ext->oid.bv_len] = '\0';

	ext->ext_main = ext_main;
	ext->next = supp_ext_list;

	supp_ext_list = ext;

	return(0);
}

int
extops_init (void)
{
	int i;

	for (i = 0; builtin_extops[i].oid != NULL; i++) {
		load_extop((struct berval *)builtin_extops[i].oid,
			builtin_extops[i].flags,
			builtin_extops[i].ext_main);
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
	Operation *op,
	SlapReply *rs )
{
	struct berval *bv;

	if ( op->ore_reqdata != NULL ) {
		/* no request data should be provided */
		rs->sr_text = "no request data expected";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_bd = op->o_conn->c_authz_backend;
	if( backend_check_restrictions( op, rs,
		(struct berval *)&slap_EXOP_WHOAMI ) != LDAP_SUCCESS ) {
		return rs->sr_err;
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

	rs->sr_rspdata = bv;
	return LDAP_SUCCESS;
}
