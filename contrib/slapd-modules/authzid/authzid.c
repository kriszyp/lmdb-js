/* vc.c - LDAP Verify Credentials extop (no spec yet) */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2010 The OpenLDAP Foundation.
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
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

/*
 * RFC 3829 Authzid
 */

#include "portable.h"

#include "slap.h"
#include "lutil.h"
#include "ac/string.h"

static int authzid_cid;

static int
authzid_response(
	Operation *op,
	SlapReply *rs )
{
	if ( rs->sr_tag == LDAP_RES_BIND ) {
		LDAPControl **ctrls;
		ber_len_t len = 0;
		int n = 0;

		/* TEMPORARY! */
		if ( rs->sr_err == LDAP_SASL_BIND_IN_PROGRESS ) {
			if ( op->o_ctrlflag[ authzid_cid ] == SLAP_CONTROL_CRITICAL ) {
				return rs->sr_err = LDAP_UNAVAILABLE_CRITICAL_EXTENSION;
			}

			op->o_ctrlflag[ authzid_cid ] = SLAP_CONTROL_IGNORED;

			return SLAP_CB_CONTINUE;
		}
		/* end of TEMPORARY! */

		if ( rs->sr_err != LDAP_SUCCESS ) {
			return SLAP_CB_CONTINUE;
		}

		if ( !BER_BVISEMPTY( &op->o_conn->c_dn ) ) {
			len = STRLENOF("dn:") + op->o_conn->c_dn.bv_len;
		}

		/* save original controls in sc_private;
		 * will be restored by sc_cleanup
		 */
		if ( rs->sr_ctrls != NULL ) {
			op->o_callback->sc_private = rs->sr_ctrls;
			for ( ; rs->sr_ctrls[n] != NULL; n++ )
				;
		}

		ctrls = op->o_tmpalloc( sizeof( LDAPControl * )*( n + 2 ), op->o_tmpmemctx );
		n = 0;
		if ( rs->sr_ctrls ) {
			for ( ; rs->sr_ctrls[n] != NULL; n++ ) {
				ctrls[n] = rs->sr_ctrls[n];
			}
		}

		/* anonymous: "", otherwise "dn:<dn>" */
		ctrls[n] = op->o_tmpalloc( sizeof( LDAPControl ) + len + 1, op->o_tmpmemctx );
		ctrls[n]->ldctl_oid = LDAP_CONTROL_AUTHZID_RESPONSE;
		ctrls[n]->ldctl_iscritical = 0;
		ctrls[n]->ldctl_value.bv_len = len;
		ctrls[n]->ldctl_value.bv_val = (char *)&ctrls[n][1];
		if ( len ) {
			char *ptr;

			ptr = lutil_strcopy( ctrls[n]->ldctl_value.bv_val, "dn:" );
			ptr = lutil_strncopy( ptr, op->o_conn->c_dn.bv_val, op->o_conn->c_dn.bv_len );
		}
		ctrls[n]->ldctl_value.bv_val[len] = '\0';
		ctrls[n + 1] = NULL;

		rs->sr_ctrls = ctrls;
	}

	return SLAP_CB_CONTINUE;
}

static int
authzid_cleanup(
	Operation *op,
	SlapReply *rs )
{
	if ( rs->sr_ctrls ) {
		LDAPControl *ctrl;

		/* if ours, cleanup */
		ctrl = ldap_control_find( LDAP_CONTROL_AUTHZID_RESPONSE, rs->sr_ctrls, NULL );
		if ( ctrl ) {
			op->o_tmpfree( ctrl, op->o_tmpmemctx );
			op->o_tmpfree( rs->sr_ctrls, op->o_tmpmemctx );
		}

		if ( op->o_callback->sc_private != NULL ) {
			rs->sr_ctrls = (LDAPControl **)op->o_callback->sc_private;
			op->o_callback->sc_private = NULL;
		}
	}

	op->o_tmpfree( op->o_callback, op->o_tmpmemctx );
	op->o_callback = NULL;

	return SLAP_CB_CONTINUE;
}

static int
parse_authzid_ctrl(
	Operation	*op,
	SlapReply	*rs,
	LDAPControl	*ctrl )
{
	slap_callback *sc;

	if ( op->o_ctrlflag[ authzid_cid ] != SLAP_CONTROL_NONE ) {
		rs->sr_text = "authzid control specified multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( !BER_BVISNULL( &ctrl->ldctl_value ) ) {
		rs->sr_text = "authzid control value not absent";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_ctrlflag[ authzid_cid ] = ctrl->ldctl_iscritical ?  SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL;

	sc = op->o_callback;
	op->o_callback = op->o_tmpalloc( sizeof( slap_callback ), op->o_tmpmemctx );
	op->o_callback->sc_response = authzid_response;
	op->o_callback->sc_cleanup = authzid_cleanup;
	op->o_callback->sc_private = NULL;
	op->o_callback->sc_next = sc;

	return LDAP_SUCCESS;
}

static int
authzid_initialize( void )
{
	int rc;

	rc = register_supported_control( LDAP_CONTROL_AUTHZID_REQUEST,
		SLAP_CTRL_GLOBAL|SLAP_CTRL_BIND|SLAP_CTRL_HIDE, NULL,
		parse_authzid_ctrl, &authzid_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
			"authzid_initialize: failed to register control %s (%d)\n",
			LDAP_CONTROL_AUTHZID_REQUEST, rc, 0 );
		return rc;
	}

	return rc;
}

int
init_module( int argc, char *argv[] )
{
	return authzid_initialize();
}

