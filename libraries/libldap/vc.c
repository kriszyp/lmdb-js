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
 * LDAP Verify Credentials operation
 *
 * The request is an extended request with OID 1.3.6.1.4.1.4203.666.6.5 with value of
 * the BER encoding of:
 *
 * VCRequest ::= SEQUENCE {
 *		Cookie [0] OCTET STRING OPTIONAL,
 *		name	LDAPDN,
 *		authentication	AuthenticationChoice
 * }
 *
 * where LDAPDN and AuthenticationChoice are as defined in RFC 4511.
 *
 * The response is an extended response with no OID and a value of the BER encoding of
 *
 * VCResponse ::= SEQUENCE {
 *		Cookie [0] OCTET STRING OPTIONAL,
 *		serverSaslCreds [1] OCTET STRING OPTIONAL
 *		authzid [2] OCTET STRING OPTIONAL
 * }
 *
 */

int ldap_parse_verify_credentials(
	LDAP *ld,
	LDAPMessage *res,
    struct berval **cookie,
	struct berval **screds,
	struct berval **authzid)
{
	int rc;
	char *retoid = NULL;
	struct berval *retdata = NULL;

	assert(ld != NULL);
	assert(LDAP_VALID(ld));
	assert(res != NULL);
	assert(authzid != NULL);

	*authzid = NULL;

	rc = ldap_parse_extended_result(ld, res, &retoid, &retdata, 0);

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_verify_credentials");
		return rc;
	}

    if (retdata) {
	    ber_tag_t tag;
		ber_len_t len;
	    BerElement * ber = ber_init(retdata);
		if (!ber) {
		    rc = ld->ld_errno = LDAP_NO_MEMORY;
			goto done;
		}

		ber_scanf(ber, "{" /*"}"*/);

		tag = ber_peek_tag(ber, &len);
		if (tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE) {
			ber_scanf(ber, "O", cookie);
		    tag = ber_peek_tag(ber, &len);
		}

		if (tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_SCREDS) {
			ber_scanf(ber, "O", screds);
		    tag = ber_peek_tag(ber, &len);
		}

		if (tag == LDAP_TAG_EXOP_VERIFY_CREDENTIALS_AUTHZID) {
			ber_scanf(ber, "O", authzid);
		}

	    ber_free(ber, 1);
    }

done:
	ber_bvfree(retdata);
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
#if 0
	ber_printf(ber, "{" /*}*/ );
#endif
	if (dn == NULL) dn = "";

	if (mechanism == LDAP_SASL_SIMPLE) {
		assert(!cookie);

		rc = ber_printf(ber, "{istON}",
			3, dn, LDAP_AUTH_SIMPLE, cred);

	} else {
		if (!cred || BER_BVISNULL(cred)) {
			if (cookie) {
				rc = ber_printf(ber, "{tOst{sN}N}",
					LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE, cookie,
					dn, LDAP_AUTH_SASL, mechanism);
			} else {
				rc = ber_printf(ber, "{st{sN}N}",
					dn, LDAP_AUTH_SASL, mechanism);
			}
		} else {
			if (cookie) {
				rc = ber_printf(ber, "{tOst{sON}N}",
					LDAP_TAG_EXOP_VERIFY_CREDENTIALS_COOKIE, cookie,
					dn, LDAP_AUTH_SASL, mechanism, cred);
			} else {
				rc = ber_printf(ber, "{st{sON}N}",
					dn, LDAP_AUTH_SASL, mechanism, cred);
			}
		}
	}
#if 0
	ber_printf(ber, /*{*/ "N}" );
#endif

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
	struct berval	**scookie,
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

	rc = ldap_parse_verify_credentials(ld, res, scookie, scred, authzid);
	if (rc != LDAP_SUCCESS) {
		ldap_msgfree(res);
		return rc;
	}

	return( ldap_result2error(ld, res, 1));
}
