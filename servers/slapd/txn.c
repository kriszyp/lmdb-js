/* txn.c - LDAP Transactions */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2006 The OpenLDAP Foundation.
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

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

#include <lber_pvt.h>
#include <lutil.h>

#ifdef LDAP_X_TXN
const struct berval slap_EXOP_TXN_START = BER_BVC(LDAP_EXOP_X_TXN_START);
const struct berval slap_EXOP_TXN_END = BER_BVC(LDAP_EXOP_X_TXN_END);

int txn_start_extop(
	Operation *op, SlapReply *rs )
{
	struct berval *bv;

	if( op->ore_reqdata != NULL ) {
		rs->sr_text = "no request data expected";
		return LDAP_PROTOCOL_ERROR;
	}

	Statslog( LDAP_DEBUG_STATS, "%s TXN START\n",
		op->o_log_prefix, 0, 0, 0, 0 );

	op->o_bd = op->o_conn->c_authz_backend;
	if( backend_check_restrictions( op, rs,
		(struct berval *)&slap_EXOP_TXN_START ) != LDAP_SUCCESS )
	{
		return rs->sr_err;
	}

	bv = (struct berval *) ch_malloc( sizeof (struct berval) );
	bv->bv_len = 0;
	bv->bv_val = NULL;

	rs->sr_rspdata = bv;
	return LDAP_SUCCESS;
}

int txn_spec_ctrl(
	Operation *op, SlapReply *rs, LDAPControl *ctrl )
{
	if ( !ctrl->ldctl_iscritical ) {
		rs->sr_text = "txnSpec control must be marked critical";
		return LDAP_PROTOCOL_ERROR;
	}
	if( op->o_txnSpec ) {
		rs->sr_text = "txnSpec control provided multiple times";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( ctrl->ldctl_value.bv_val == NULL ) {
		rs->sr_text = "no transaction identifier provided";
		return LDAP_PROTOCOL_ERROR;
	}
	if ( ctrl->ldctl_value.bv_len != 0 ) {
		rs->sr_text = "invalid transaction identifier";
		return LDAP_X_TXN_ID_INVALID;
	}

	op->o_txnSpec = SLAP_CONTROL_CRITICAL;
	return LDAP_SUCCESS;
}

int txn_end_extop(
	Operation *op, SlapReply *rs )
{
	if( op->ore_reqdata == NULL ) {
		rs->sr_text = "request data expected";
		return LDAP_PROTOCOL_ERROR;
	}

	Statslog( LDAP_DEBUG_STATS, "%s TXN END\n",
		op->o_log_prefix, 0, 0, 0, 0 );

	op->o_bd = op->o_conn->c_authz_backend;
	if( backend_check_restrictions( op, rs,
		(struct berval *)&slap_EXOP_TXN_END ) != LDAP_SUCCESS )
	{
		return rs->sr_err;
	}

	rs->sr_text = "not yet implemented";
	return LDAP_UNWILLING_TO_PERFORM;
}

#endif /* LDAP_X_TXN */
