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
	struct ldapconn	*lc;
	ber_int_t	msgid;
	int		do_retry = 1;
	LDAPControl	**ctrls = NULL;
	int		rc = LDAP_SUCCESS;

	lc = ldap_back_getconn( op, rs );
	if (!lc || !ldap_back_dobind( lc, op, rs ) ) {
		rc = -1;
		goto cleanup;
	}

	ctrls = op->o_ctrls;
#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		rc = -1;
		goto cleanup;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

retry:
	rs->sr_err = ldap_compare_ext( lc->lc_ld, op->o_req_ndn.bv_val,
			op->orc_ava->aa_desc->ad_cname.bv_val,
			&op->orc_ava->aa_value, 
			ctrls, NULL, &msgid );
	rc = ldap_back_op_result( lc, op, rs, msgid, 1 );
	if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
		do_retry = 0;
		if ( ldap_back_retry(lc, op, rs ) ) {
			goto retry;
		}
	}

cleanup:
#ifdef LDAP_BACK_PROXY_AUTHZ
	(void)ldap_back_proxy_authz_ctrl_free( op, &ctrls );
#endif /* LDAP_BACK_PROXY_AUTHZ */
	
	return rc;
}
