/* compare.c - ldap backend compare function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Howard Chu.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
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
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_compare(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	struct berval mapped_at = { 0, NULL }, mapped_val = { 0, NULL };
	struct berval mdn = { 0, NULL };
	ber_int_t msgid;
	int freeval = 0;
	dncookie dc;
#ifdef LDAP_BACK_PROXY_AUTHZ 
	LDAPControl **ctrls = NULL;
	int rc = LDAP_SUCCESS;
#endif /* LDAP_BACK_PROXY_AUTHZ */

	lc = ldap_back_getconn(op, rs);
	if (!lc || !ldap_back_dobind( lc, op, rs ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the compare dn, if needed
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "compareDN";
#else
	dc.tofrom = 1;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, &op->o_req_ndn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	if ( op->orc_ava->aa_desc == slap_schema.si_ad_objectClass
		|| op->orc_ava->aa_desc == slap_schema.si_ad_structuralObjectClass ) {
		ldap_back_map(&li->rwmap.rwm_oc, &op->orc_ava->aa_value,
				&mapped_val, BACKLDAP_MAP);
		if (mapped_val.bv_val == NULL || mapped_val.bv_val[0] == '\0') {
			return( -1 );
		}
		mapped_at = op->orc_ava->aa_desc->ad_cname;
	} else {
		ldap_back_map(&li->rwmap.rwm_at,
				&op->orc_ava->aa_desc->ad_cname, &mapped_at, 
				BACKLDAP_MAP);
		if (mapped_at.bv_val == NULL || mapped_at.bv_val[0] == '\0') {
			return( -1 );
		}
		if (op->orc_ava->aa_desc->ad_type->sat_syntax == slap_schema.si_syn_distinguishedName ) {
#ifdef ENABLE_REWRITE
			dc.ctx = "compareAttrDN";
#endif
			ldap_back_dn_massage( &dc, &op->orc_ava->aa_value, &mapped_val );
			if (mapped_val.bv_val == NULL || mapped_val.bv_val[0] == '\0') {
				mapped_val = op->orc_ava->aa_value;
			} else if (mapped_val.bv_val != op->orc_ava->aa_value.bv_val) {
				freeval = 1;
			}
		} else {
			mapped_val = op->orc_ava->aa_value;
		}
	}

#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

	rs->sr_err = ldap_compare_ext( lc->ld, mdn.bv_val,
			mapped_at.bv_val, &mapped_val, 
#ifdef LDAP_BACK_PROXY_AUTHZ
			ctrls,
#else /* ! LDAP_BACK_PROXY_AUTHZ */
			op->o_ctrls,
#endif /* ! LDAP_BACK_PROXY_AUTHZ */
			NULL, &msgid );

#ifdef LDAP_BACK_PROXY_AUTHZ
cleanup:
	if ( ctrls && ctrls != op->o_ctrls ) {
		free( ctrls[ 0 ] );
		free( ctrls );
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */
	
	if ( mdn.bv_val != op->o_req_ndn.bv_val ) {
		free( mdn.bv_val );
	}
	if ( freeval ) {
		free( mapped_val.bv_val );
	}

#ifdef LDAP_BACK_PROXY_AUTHZ
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		return -1;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */
	return( ldap_back_op_result( lc, op, rs, msgid, 1 ) );
}
