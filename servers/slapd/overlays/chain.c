/* chain.c - chain LDAP operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
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

#if defined(SLAPD_LDAP) 

#ifdef SLAPD_OVER_CHAIN

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"

static BackendInfo *lback;

static int
ldap_chain_chk_referrals( Operation *op, SlapReply *rs )
{
	return LDAP_SUCCESS;
}

static int
ldap_chain_response( Operation *op, SlapReply *rs )
{
	slap_overinst	*on = (slap_overinst *) op->o_bd->bd_info;
	void		*private = op->o_bd->be_private;
	slap_callback	*sc = op->o_callback;
	LDAPControl	**prev = op->o_ctrls;
	LDAPControl	**ctrls = NULL, authz;
	int		i, nctrls, rc = 0;
	int		cache = op->o_do_not_cache;
	char		*authzid = NULL;
	BerVarray	ref;
	struct berval	ndn = op->o_ndn;

	struct ldapinfo	li, *lip = (struct ldapinfo *)on->on_bi.bi_private;

	if ( rs->sr_err != LDAP_REFERRAL && rs->sr_type != REP_SEARCHREF )
		return SLAP_CB_CONTINUE;

	ref = rs->sr_ref;
	rs->sr_ref = NULL;

	op->o_callback = NULL;

	if ( lip->url == NULL ) {
		li = *lip;
		op->o_bd->be_private = &li;

		if ( rs->sr_type != REP_SEARCHREF ) {
			LDAPURLDesc	*srv;
			char		*save_dn;

			/* parse reference and use proto://[host][:port]/ only */
			rc = ldap_url_parse_ext( ref[0].bv_val, &srv );
			if ( rc != LDAP_SUCCESS) {
				/* error */
				return 1;
			}

			/* remove DN essentially because later on 
			 * ldap_initialize() will parse the URL 
			 * as a comma-separated URL list */
			save_dn = srv->lud_dn;
			srv->lud_dn = "";
			li.url = ldap_url_desc2str( srv );
			if ( li.url == NULL ) {
				/* error */
				srv->lud_dn = save_dn;
				ldap_free_urldesc( srv );
				return 1;
			}

			srv->lud_dn = save_dn;
			ldap_free_urldesc( srv );
		}

	} else {
		op->o_bd->be_private = on->on_bi.bi_private;
	}

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
			authzid = op->o_tmpalloc( op->o_dn.bv_len + sizeof("dn:") - 1,
				op->o_tmpmemctx );
			strcpy(authzid, "dn:");
			strcpy(authzid + sizeof("dn:") - 1, op->o_dn.bv_val);
			authz.ldctl_value.bv_len = op->o_dn.bv_len + sizeof("dn:") - 1;
			authz.ldctl_value.bv_val = authzid;
		}
		op->o_ctrls = ctrls;
		op->o_ndn = op->o_bd->be_rootndn;
	}

	switch( op->o_tag ) {
	case LDAP_REQ_BIND: {
		struct berval	rndn = op->o_req_ndn;
		Connection	*conn = op->o_conn;

		op->o_req_ndn = slap_empty_bv;

		op->o_conn = NULL;
		rc = lback->bi_op_bind( op, rs );
		op->o_req_ndn = rndn;
		op->o_conn = conn;
		}
		break;
	case LDAP_REQ_ADD:
		rc = lback->bi_op_add( op, rs );
		break;
	case LDAP_REQ_DELETE:
		rc = lback->bi_op_delete( op, rs );
		break;
	case LDAP_REQ_MODRDN:
		rc = lback->bi_op_modrdn( op, rs );
	    	break;
	case LDAP_REQ_MODIFY:
		rc = lback->bi_op_modify( op, rs );
		break;
	case LDAP_REQ_COMPARE:
		rc = lback->bi_op_compare( op, rs );
		break;
	case LDAP_REQ_SEARCH:
		if ( rs->sr_type == REP_SEARCHREF ) {
			struct berval	*curr = ref,
					odn = op->o_req_dn,
					ondn = op->o_req_ndn;

			rs->sr_type = REP_SEARCH;

			/* copy the private info because we need to modify it */
			for ( ; curr[0].bv_val; curr++ ) {
				LDAPURLDesc	*srv;

				/* parse reference and use proto://[host][:port]/ only */
				rc = ldap_url_parse_ext( curr[0].bv_val, &srv );
				if ( rc != LDAP_SUCCESS) {
					/* error */
					rc = 1;
					goto end_of_searchref;
				}

				ber_str2bv(srv->lud_dn, 0, 0, &op->o_req_dn);
				op->o_req_ndn = op->o_req_dn;

				/* remove DN essentially because later on 
				 * ldap_initialize() will parse the URL 
				 * as a comma-separated URL list */
				srv->lud_dn = "";
				li.url = ldap_url_desc2str( srv );
				if ( li.url == NULL ) {
					/* error */
					srv->lud_dn = op->o_req_dn.bv_val;
					ldap_free_urldesc( srv );
					rc = 1;
					goto end_of_searchref;
				}

				/* FIXME: should we also copy filter and scope?
				 * according to RFC3296, no */

				rc = lback->bi_op_search( op, rs );

				ldap_memfree( li.url );
				li.url = NULL;

				srv->lud_dn = op->o_req_dn.bv_val;
				ldap_free_urldesc( srv );

				if ( rc ) {
					/* error */
					rc = 1;
					goto end_of_searchref;
				}
			}

end_of_searchref:;
			op->o_req_dn = odn;
			op->o_req_ndn = ondn;
			rs->sr_type = REP_SEARCHREF;
			
		} else {
			rc = lback->bi_op_search( op, rs );
		}
	    	break;
	case LDAP_REQ_EXTENDED:
		rc = lback->bi_extended( op, rs );
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
	if ( lip->url == NULL && li.url ) {
		ldap_memfree( li.url );
	}

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
	slap_overinst	*on = (slap_overinst *) be->bd_info;
	void		*private = be->be_private;
	char		*argv0 = NULL;
	int		rc;

	be->be_private = on->on_bi.bi_private;
	if ( strncasecmp( argv[ 0 ], "chain-", sizeof( "chain-" ) - 1 ) == 0 ) {
		argv0 = argv[ 0 ];
		argv[ 0 ] = &argv[ 0 ][ sizeof( "chain-" ) - 1 ];
	}
	rc = lback->bi_db_config( be, fname, lineno, argc, argv );
	if ( argv0 ) {
		argv[ 0 ] = argv0;
	}
	
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
	rc = lback->bi_db_init( be );
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
	rc = lback->bi_db_destroy( be );
	on->on_bi.bi_private = be->be_private;
	be->be_private = private;
	return rc;
}

static slap_overinst ldapchain;

int chain_init()
{
	lback = backend_info("ldap");

	if ( !lback ) return -1;

	ldapchain.on_bi.bi_type = "chain";
	ldapchain.on_bi.bi_db_init = ldap_chain_init;
	ldapchain.on_bi.bi_db_config = ldap_chain_config;
	ldapchain.on_bi.bi_db_destroy = ldap_chain_destroy;
	ldapchain.on_response = ldap_chain_response;

	ldapchain.on_bi.bi_chk_referrals = ldap_chain_chk_referrals;

	return overlay_register( &ldapchain );
}

#if SLAPD_OVER_CHAIN == SLAPD_MOD_DYNAMIC
int init_module(int argc, char *argv[]) {
	return chain_init();
}
#endif /* SLAPD_OVER_CHAIN == SLAPD_MOD_DYNAMIC */

#endif /* SLAPD_OVER_CHAIN */

#endif /* ! defined(SLAPD_LDAP) */
