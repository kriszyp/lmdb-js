/* extended.c - ldap backend extended routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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
/* This is an altered version */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldap.h"
#include "lber_pvt.h"

BI_op_extended ldap_back_exop_passwd;

static struct exop {
	struct berval *oid;
	BI_op_extended	*extended;
} exop_table[] = {
	{ (struct berval *)&slap_EXOP_MODIFY_PASSWD, ldap_back_exop_passwd },
	{ NULL, NULL }
};

int
ldap_back_extended(
	Operation		*op,
	SlapReply		*rs )
{
	int i;

	for( i=0; exop_table[i].extended != NULL; i++ ) {
		if( ber_bvcmp( exop_table[i].oid, &op->oq_extended.rs_reqoid ) == 0 ) {
#ifdef LDAP_BACK_PROXY_AUTHZ 
			struct ldapconn *lc;
			LDAPControl **oldctrls = NULL;
			int rc;

			/* FIXME: this needs to be called here, so it is
			 * called twice; maybe we could avoid the 
			 * ldap_back_dobind() call inside each extended()
			 * call ... */
			lc = ldap_back_getconn(op, rs);
			if (!lc || !ldap_back_dobind(lc, op, rs) ) {
				return -1;
			}

			oldctrls = op->o_ctrls;
			if ( ldap_back_proxy_authz_ctrl( lc, op, rs, &op->o_ctrls ) ) {
				op->o_ctrls = oldctrls;
				send_ldap_result( op, rs );
				rs->sr_text = NULL;
				return rs->sr_err;
			}

			rc = (exop_table[i].extended)( op, rs );

			if ( op->o_ctrls && op->o_ctrls != oldctrls ) {
				free( op->o_ctrls[ 0 ] );
				free( op->o_ctrls );
			}
			op->o_ctrls = oldctrls;

			return rc;
#else /* ! LDAP_BACK_PROXY_AUTHZ */
			return (exop_table[i].extended)( op, rs );
#endif /* ! LDAP_BACK_PROXY_AUTHZ */
		}
	}

	rs->sr_text = "not supported within naming context";
	return LDAP_UNWILLING_TO_PERFORM;
}

int
ldap_back_exop_passwd(
	Operation		*op,
	SlapReply		*rs )
{
	struct ldapinfo *li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	struct berval id = { 0, NULL };
	struct berval old = { 0, NULL };
	struct berval new = { 0, NULL };
	struct berval dn, mdn = { 0, NULL }, newpw;
	LDAPMessage *res;
	ber_int_t msgid;
	int rc;
	dncookie dc;

	lc = ldap_back_getconn(op, rs);
	if (!lc || !ldap_back_dobind(lc, op, rs) ) {
		return -1;
	}

	rc = slap_passwd_parse( op->oq_extended.rs_reqdata, &id, &old, &new, &rs->sr_text );
	if (rc != LDAP_SUCCESS)
		return rc;
	
	if (id.bv_len) {
		dn = id;
	} else {
		dn = op->o_dn;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( ACL, DETAIL1, "ldap_back_exop_passwd: \"%s\"%s\"\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_back_exop_passwd: \"%s\"%s\n",
		dn.bv_val, id.bv_len ? " (proxy)" : "", 0 );
#endif

	if (dn.bv_len == 0) {
		rs->sr_text = "No password is associated with the Root DSE";
		return LDAP_UNWILLING_TO_PERFORM;
	}
	if (id.bv_len) {
		dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
		dc.conn = op->o_conn;
		dc.rs = rs;
		dc.ctx = "modifyPwd";
#else
		dc.tofrom = 1;
		dc.normalized = 0;
#endif
		if ( ldap_back_dn_massage( &dc, &dn, &mdn ) ) {
			send_ldap_result( op, rs );
			return -1;
		}
	}

	rc = ldap_passwd(lc->ld, id.bv_len ? &mdn : NULL, old.bv_len ? &old : NULL,
		new.bv_len ? &new : NULL, op->o_ctrls, NULL, &msgid);

	if (mdn.bv_val != dn.bv_val) {
		free(mdn.bv_val);
	}

	if (rc == LDAP_SUCCESS) {
		if (ldap_result(lc->ld, msgid, 1, NULL, &res) == -1) {
			ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &rc);
		} else {
			/* sigh. parse twice, because parse_passwd doesn't give
			 * us the err / match / msg info.
			 */
			rc = ldap_parse_result(lc->ld, res, &rs->sr_err, (char **)&rs->sr_matched, (char **)&rs->sr_text,
				NULL, NULL, 0);
			if (rc == LDAP_SUCCESS) {
				if (rs->sr_err == LDAP_SUCCESS) {
					rc = ldap_parse_passwd(lc->ld, res, &newpw);
					if (rc == LDAP_SUCCESS && newpw.bv_val) {
						rs->sr_type = REP_EXTENDED;
						rs->sr_rspdata = slap_passwd_return(&newpw);
						free(newpw.bv_val);
					}
				} else {
					rc = rs->sr_err;
				}
			}
			ldap_msgfree(res);
		}
	}
	if (rc != LDAP_SUCCESS) {
		rs->sr_err = ldap_back_map_result(rs);
		send_ldap_result(op, rs);
		if (rs->sr_matched) free((char *)rs->sr_matched);
		if (rs->sr_text) free((char *)rs->sr_text);
		rs->sr_matched = NULL;
		rs->sr_text = NULL;
		rc = -1;
	}
	return rc;
}
