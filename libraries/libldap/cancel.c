/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * LDAPv3 Cancel Operation Request
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_log.h"

int
ldap_cancel(
	LDAP		*ld,
	int		cancelid,
	LDAPControl	**sctrls,
	LDAPControl	**cctrls,
	int		*msgidp )
{
	BerElement *cancelidber = NULL;
	struct berval *cancelidvalp = NULL;
	int rc;

	cancelidber = ber_alloc_t( LBER_USE_DER );
	ber_printf( cancelidber, "{i}", cancelid );
	ber_flatten( cancelidber, &cancelidvalp );
	rc = ldap_extended_operation( ld, LDAP_EXOP_X_CANCEL,
			cancelidvalp, sctrls, cctrls, msgidp );
	ber_free( cancelidber, 1 );
	return rc;
}

int
ldap_cancel_s(
	LDAP		*ld,
	int		cancelid,
	LDAPControl	**sctrls,
	LDAPControl	**cctrls )
{
	BerElement *cancelidber = NULL;
	struct berval *cancelidvalp = NULL;
	int rc;

	cancelidber = ber_alloc_t( LBER_USE_DER );
	ber_printf( cancelidber, "{i}", cancelid );
	ber_flatten( cancelidber, &cancelidvalp );
	rc = ldap_extended_operation_s( ld, LDAP_EXOP_X_CANCEL,
			cancelidvalp, sctrls, cctrls, NULL, NULL );
	ber_free( cancelidber, 1 );
	return rc;
}
