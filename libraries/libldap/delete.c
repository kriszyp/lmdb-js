/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  delete.c
 */

/*
 * A delete request looks like this:
 *	DelRequet ::= DistinguishedName,
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * ldap_delete_ext - initiate an ldap extended delete operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to delete
 *	sctrls	Server Controls
 *	cctrls	Client Controls
 *	msgidp	Message Id Pointer
 *
 * Example:
 *	rc = ldap_delete( ld, dn, sctrls, cctrls, msgidp );
 */
int
ldap_delete_ext(
	LDAP *ld,
	LDAP_CONST char* dn,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_delete\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( dn != NULL );
	assert( msgidp != NULL );

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( ld->ld_errno );
	}

	if ( ber_printf( ber, "{its", /* '}' */
		++ld->ld_msgid, LDAP_REQ_DELETE, dn ) == -1 )
	{
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return ld->ld_errno;
	}

	if ( ber_printf( ber, /*{*/ "}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* send the message */
	*msgidp = ldap_send_initial_request( ld, LDAP_REQ_DELETE, dn, ber );

	if(*msgidp < 0)
		return ld->ld_errno;

	return LDAP_SUCCESS;
}

int
ldap_delete_ext_s(
	LDAP *ld,
	LDAP_CONST char *dn,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int	msgid;
	int rc;
	LDAPMessage	*res;

	rc = ldap_delete_ext( ld, dn, sctrls, cctrls, &msgid );
	
	if( rc != LDAP_SUCCESS )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}
/*
 * ldap_delete - initiate an ldap (and X.500) delete operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to delete
 *
 * Example:
 *	msgid = ldap_delete( ld, dn );
 */
int
ldap_delete( LDAP *ld, LDAP_CONST char *dn )
{
	int msgid;

	/*
	 * A delete request looks like this:
	 *	DelRequet ::= DistinguishedName,
	 */

	Debug( LDAP_DEBUG_TRACE, "ldap_delete\n", 0, 0, 0 );

	return ldap_delete_ext( ld, dn, NULL, NULL, &msgid ) == LDAP_SUCCESS
		? msgid : -1 ;
}


int
ldap_delete_s( LDAP *ld, LDAP_CONST char *dn )
{
	return ldap_delete_ext_s( ld, dn, NULL, NULL );
}
