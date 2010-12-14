/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2010 The OpenLDAP Foundation.
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
 * This program was orignally developed by Kurt D. Zeilenga for inclusion in
 * OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * LDAP Verify Credentials
 */

int ldap_parse_verify_credentials(
	LDAP *ld,
	LDAPMessage *res,
	struct berval **servercred,
	struct berval **authzid)
{
	int rc;
	char *retoid = NULL;
	struct berval *reqdata = NULL;

	assert(ld != NULL);
	assert(LDAP_VALID(ld));
	assert(res != NULL);
	assert(authzid != NULL);

	*authzid = NULL;

	rc = ldap_parse_extended_result(ld, res, &retoid, &reqdata, 0);

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_whoami");
		return rc;
	}

	ber_memfree(retoid);
	return rc;
}

int
ldap_verify_credentials(LDAP *ld,
	struct berval	*cookie,
	LDAP_CONST char *dn,
	LDAP_CONST char *mechanism,
	struct berval	*cred,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	int				*msgidp)
{
	int rc;
	BerElement *ber;
	struct berval * reqdata;

	assert(ld != NULL);
	assert(LDAP_VALID(ld));
	assert(msgidp != NULL);

	ber = ber_alloc_t(LBER_USE_DER);
	ber_printf(ber, "{");
	if (dn == NULL) dn = "";

	if (mechanism == LDAP_SASL_SIMPLE) {
		assert(!cookie);

		rc = ber_printf(ber, "{istON}",
			3, dn, LDAP_AUTH_SIMPLE, cred);

	} else {
		if (!cred || BER_BVISNULL(cred)) {
			if (cookie) {
				rc = ber_printf(ber, "{t0ist{sN}N}",
					LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE, cookie,
					3, dn, LDAP_AUTH_SASL, mechanism);
			} else {
				rc = ber_printf(ber, "{ist{sN}N}",
					3, dn, LDAP_AUTH_SASL, mechanism);
			}
		} else {
			if (cookie) {
				rc = ber_printf(ber, "{tOist{sON}N}",
					LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE, cookie,
					3, dn, LDAP_AUTH_SASL, mechanism, cred);
			} else {
				rc = ber_printf(ber, "{ist{sON}N}",
					3, dn, LDAP_AUTH_SASL, mechanism, cred);
			}
		}
	}

	ber_flatten(ber, &reqdata);

	rc = ldap_extended_operation(ld, LDAP_EXOP_VERIFY_CREDENTIALS,
		reqdata, sctrls, cctrls, msgidp);

	ber_free(ber, 1);
	return rc;
}

int
ldap_verify_credentials_s(
	LDAP *ld,
	struct berval	*cookie,
	LDAP_CONST char *dn,
	LDAP_CONST char *mechanism,
	struct berval	*cred,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	struct berval	**scred,
	struct berval	**authzid)
{
	int				rc;
	int				msgid;
	LDAPMessage		*res;

	rc = ldap_verify_credentials(ld, cookie, dn, mechanism, cred, sctrls, cctrls, &msgid);
	if (rc != LDAP_SUCCESS) return rc;

	if (ldap_result(ld, msgid, LDAP_MSG_ALL, (struct timeval *) NULL, &res) == -1 || !res) {
		return ld->ld_errno;
	}

	rc = ldap_parse_verify_credentials(ld, res, scred, authzid);
	if (rc != LDAP_SUCCESS) {
		ldap_msgfree(res);
		return rc;
	}

	return( ldap_result2error(ld, res, 1));
}
