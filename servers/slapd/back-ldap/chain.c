/* chain.c - chain LDAP operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 Howard Chu.
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
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

static int
ldap_chain_response( Operation *op, SlapReply *rs )
{
	slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
	void *private = op->o_bd->be_private;
	slap_callback *sc = op->o_callback;
	LDAPControl **prev = op->o_ctrls;
	LDAPControl **ctrls = NULL, authz;
	int i, nctrls, rc;
	int cache = op->o_do_not_cache;
	char *authzid = NULL;
	BerVarray ref;
	struct berval ndn = op->o_ndn;

	if ( rs->sr_err != LDAP_REFERRAL )
		return SLAP_CB_CONTINUE;

	/* currently we assume only one referral destination.
	 * we'll have to parse this in the future.
	 */
	ref = rs->sr_ref;
	rs->sr_ref = NULL;

	op->o_bd->be_private = on->on_bi.bi_private;
	op->o_callback = NULL;

	/* Chaining is performed by a privileged user on behalf
	 * of a normal user, using the ProxyAuthz control. However,
	 * Binds are done separately, on an anonymous session.
	 */
	if ( op->o_tag != LDAP_REQ_BIND ) {
		for (i=0; prev && prev[i]; i++);
		nctrls = i;

		/* Add an extra NULL slot */
		if (!prev) i++;

		ctrls = op->o_tmpalloc((i+1)*sizeof(LDAPControl *),
			op->o_tmpmemctx);
		for (i=0; i <nctrls; i++)
			ctrls[i] = prev[i];
		ctrls[nctrls] = &authz;
		ctrls[nctrls+1] = NULL;
		authz.ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
		authz.ldctl_iscritical = 1;
		authz.ldctl_value = op->o_dn;
		if ( op->o_dn.bv_len ) {
			authzid = op->o_tmpalloc( op->o_dn.bv_len+4,
				op->o_tmpmemctx );
			strcpy(authzid, "dn: ");
			strcpy(authzid+4, op->o_dn.bv_val);
			authz.ldctl_value.bv_len = op->o_dn.bv_len + 4;
			authz.ldctl_value.bv_val = authzid;
		}
		op->o_ctrls = ctrls;
		op->o_ndn = op->o_bd->be_rootndn;
	}

	switch( op->o_tag ) {
	case LDAP_REQ_BIND: {
		struct berval rndn = op->o_req_ndn;
		Connection *conn = op->o_conn;
		op->o_req_ndn = slap_empty_bv;
		op->o_conn = NULL;
		rc = ldap_back_bind( op, rs );
		op->o_req_ndn = rndn;
		op->o_conn = conn;
		}
		break;
	case LDAP_REQ_ADD:
		rc = ldap_back_add( op, rs );
		break;
	case LDAP_REQ_DELETE:
		rc = ldap_back_delete( op, rs );
		break;
	case LDAP_REQ_MODRDN:
		rc = ldap_back_modrdn( op, rs );
	    	break;
	case LDAP_REQ_MODIFY:
		rc = ldap_back_modify( op, rs );
		break;
	case LDAP_REQ_COMPARE:
		rc = ldap_back_compare( op, rs );
		break;
	case LDAP_REQ_SEARCH:
		rc = ldap_back_search( op, rs );
	    	break;
	case LDAP_REQ_EXTENDED:
		rc = ldap_back_extended( op, rs );
		break;
	default:
		rc = SLAP_CB_CONTINUE;
		break;
	}
	op->o_do_not_cache = cache;
	op->o_ctrls = prev;
	op->o_bd->be_private = private;
	op->o_callback = sc;
	op->o_ndn = ndn;
	if ( ctrls ) op->o_tmpfree( ctrls, op->o_tmpmemctx );
	if ( authzid ) op->o_tmpfree( authzid, op->o_tmpmemctx );
	rs->sr_ref = ref;

	return rc;
}

static int ldap_chain_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	void *private = be->be_private;
	int rc;

	be->be_private = on->on_bi.bi_private;
	rc = ldap_back_db_config( be, fname, lineno, argc, argv );
	be->be_private = private;
	return rc;
}

static int ldap_chain_init(
	BackendDB *be
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	void *private = be->be_private;
	int rc;

	be->be_private = NULL;
	rc = ldap_back_db_init( be );
	on->on_bi.bi_private = be->be_private;
	be->be_private = private;
	return rc;
}

static int ldap_chain_destroy(
	BackendDB *be
)
{
	slap_overinst *on = (slap_overinst *) be->bd_info;
	void *private = be->be_private;
	int rc;

	be->be_private = on->on_bi.bi_private;
	rc = ldap_back_db_destroy( be );
	on->on_bi.bi_private = be->be_private;
	be->be_private = private;
	return rc;
}

static slap_overinst ldapchain;

int ldap_chain_setup()
{
	ldapchain.on_bi.bi_type = "chain";
	ldapchain.on_bi.bi_db_init = ldap_chain_init;
	ldapchain.on_bi.bi_db_config = ldap_chain_config;
	ldapchain.on_bi.bi_db_destroy = ldap_chain_destroy;
	ldapchain.on_response = ldap_chain_response;

	return overlay_register( &ldapchain );
}
