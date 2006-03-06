/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2006 The OpenLDAP Foundation.
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
 * This program was orignally developed by Kurt D. Zeilenga for inclusion
 * in OpenLDAP Software.
 */

/*
 * LDAPv3 Transactions (draft-zeilenga-ldap-txn)
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_log.h"

#ifdef LDAP_X_TXN
int
ldap_txn_start(
	LDAP *ld,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	return ldap_extended_operation( ld, LDAP_EXOP_X_TXN_START,
		NULL, sctrls, cctrls, msgidp );
}

int
ldap_txn_start_s(
	LDAP *ld,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct berval **txnid )
{
	assert( txnid != NULL );

	return ldap_extended_operation_s( ld, LDAP_EXOP_X_TXN_START,
		NULL, sctrls, cctrls, NULL, txnid );
}

int
ldap_txn_end(
	LDAP *ld,
	int commit,
	struct berval *txnid,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	int rc;
	BerElement *txnber = NULL;
	struct berval *txnval = NULL;

	assert( txnid != NULL );

	txnber = ber_alloc_t( LBER_USE_DER );
	ber_printf( txnber, "{io}", commit, txnid );
	ber_flatten( txnber, &txnval );

	rc = ldap_extended_operation( ld, LDAP_EXOP_X_TXN_END,
		txnval, sctrls, cctrls, msgidp );

	ber_free( txnber, 1 );
	return rc;
}

int
ldap_txn_end_s(
	LDAP *ld,
	int commit,
	struct berval *txnid,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *retidp )
{
	int rc, msgid;
	struct berval *retdata = NULL;
	LDAPMessage *res;

	rc = ldap_txn_end( ld, commit, txnid, sctrls, cctrls, &msgid );
	if( rc != LDAP_SUCCESS ) return rc;

	if ( ldap_result( ld, msgid, LDAP_MSG_ALL, (struct timeval *) NULL, &res )
		== -1 )
	{
		return ld->ld_errno;
	}

	rc = ldap_parse_extended_result( ld, res, NULL, &retdata, 0 );
	if( rc != LDAP_SUCCESS ) {
		ldap_msgfree( res );
		return rc;
	}

	/* don't bother parsing the retdata (yet) */
	if( retidp != NULL ) {
		*retidp = 0;
	}

	return ldap_result2error( ld, res, 1 );
}
#endif
