/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2008 The OpenLDAP Foundation.
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

#include <ac/stdlib.h>

#include <ac/time.h>
#include <ac/string.h>

#include "ldap-int.h"

#ifdef LDAP_EXOP_GROUPING_CREATE

int ldap_grouping_create(
	LDAP *ld,
	LDAP_CONST char *grpoid,
	struct berval *grpdata,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	int rc;
	BerElement *ber = NULL;
	struct berval bv = BER_BVNULL;

	Debug( LDAP_DEBUG_TRACE, "ldap_grouping_create\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( grpoid != NULL || *grpoid == '\0' );
	assert( msgidp != NULL );

	/* build the create grouping exop */
	ber = ber_alloc_t( LBER_USE_DER );
	if( ber == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( ld->ld_errno );
	}

	if ( grpdata != NULL ) {
		ber_printf( ber, "{sON}", grpoid, grpdata );
	} else {
		ber_printf( ber, "{sN}", grpoid );
	}

	rc = ber_flatten2( ber, &bv, 0 );
	if( rc < 0 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return( ld->ld_errno );
	}

	rc = ldap_extended_operation( ld, LDAP_EXOP_GROUPING_CREATE,
		&bv, sctrls, cctrls, msgidp );

	ber_free( ber, 1 );
	return rc;
}

int ldap_grouping_create_s(
	LDAP *ld,
	LDAP_CONST char *grpoid,
	struct berval *grpdata,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct berval **retgrpcookiep,
	struct berval **retgrpdatap )
{
    int     rc;
    int     msgid;
    LDAPMessage *res;

	Debug( LDAP_DEBUG_TRACE, "ldap_grouping_create_s\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( grpoid != NULL || *grpoid == '\0' );

    rc = ldap_grouping_create( ld, grpoid, grpdata,
		sctrls, cctrls, &msgid );
    if ( rc != LDAP_SUCCESS ) {
        return rc;
	}
 
    if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 ) {
        return ld->ld_errno;
	}

	if ( retgrpcookiep != NULL ) *retgrpcookiep = NULL;
	if ( retgrpdatap != NULL ) *retgrpdatap = NULL;

#if 0
	rc = ldap_parse_extended_result( ld, res, retoidp, retdatap, 0 );
#else
	rc = LDAP_NOT_SUPPORTED;
#endif

	if( rc != LDAP_SUCCESS ) {
		ldap_msgfree( res );
		return rc;
	}

    return( ldap_result2error( ld, res, 1 ) );
}

int ldap_grouping_end(
	LDAP *ld,
	LDAP_CONST char *grpoid,
	struct berval *grpdata,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	return 0;
}

int ldap_grouping_end_s(
	LDAP *ld,
	LDAP_CONST char *grpoid,
	struct berval *grpdata,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct berval **retgrpdatap )
{
	return 0;
}

#endif
