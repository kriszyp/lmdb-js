/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  modrdn.c
 */
/*
 * Support for MODIFYDN REQUEST V3 (newSuperior) by:
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 */

/*
 * A modify rdn request looks like this:
 *	ModifyRDNRequest ::= SEQUENCE {
 *		entry		DistinguishedName,
 *		newrdn		RelativeDistinguishedName,
 *		deleteoldrdn	BOOLEAN
 *		newSuperior	[0] DistinguishedName	[v3 only]
 *	}
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * ldap_rename - initiate an ldap extended modifyDN operation.
 *
 * Parameters:
 *	ld				LDAP descriptor
 *	dn				DN of the object to modify
 *	newrdn			RDN to give the object
 *	deleteoldrdn	nonzero means to delete old rdn values from the entry
 *	newSuperior		DN of the new parent if applicable
 *
 * Returns the LDAP error code.
 */

int
ldap_rename(
	LDAP *ld,
	LDAP_CONST char *dn,
	LDAP_CONST char *newrdn,
	int deleteoldrdn,
	LDAP_CONST char *newSuperior,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	int *msgidp )
{
	BerElement	*ber;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_rename\n", 0, 0, 0 );

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		return( LDAP_NO_MEMORY );
	}

	if( newSuperior != NULL ) {
		/* must be version 3 (or greater) */
		if ( ld->ld_version < LDAP_VERSION3 ) {
			ld->ld_errno = LDAP_NOT_SUPPORTED;
			ber_free( ber, 1 );
			return( ld->ld_errno );
		}

		rc = ber_printf( ber, "{it{ssbts}", /* '}' */ 
			++ld->ld_msgid, LDAP_REQ_MODDN,
			dn, newrdn, (ber_int_t) deleteoldrdn,
			LDAP_TAG_NEWSUPERIOR, newSuperior );

	} else {
		rc = ber_printf( ber, "{it{ssb}", /* '}' */ 
			++ld->ld_msgid, LDAP_REQ_MODDN,
			dn, newrdn, (ber_int_t) deleteoldrdn );
	}

	if ( rc < 0 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return ld->ld_errno;
	}

	rc = ber_printf( ber, /*{*/ "}" );
	if ( rc < 0 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* send the message */
	*msgidp = ldap_send_initial_request( ld, LDAP_REQ_MODRDN, dn, ber );
	
	if( *msgidp < 0 ) {
		return( ld->ld_errno );
	}

	return LDAP_SUCCESS;
}


/*
 * ldap_rename2 - initiate an ldap (and X.500) modifyDN operation. Parameters:
 *	(LDAP V3 MODIFYDN REQUEST)
 *	ld		LDAP descriptor
 *	dn		DN of the object to modify
 *	newrdn		RDN to give the object
 *	deleteoldrdn	nonzero means to delete old rdn values from the entry
 *	newSuperior	DN of the new parent if applicable
 *
 * ldap_rename2 uses a U-Mich Style API.  It returns the msgid.
 */

int
ldap_rename2(
	LDAP *ld,
	LDAP_CONST char *dn,
	LDAP_CONST char *newrdn,
	int deleteoldrdn,
	LDAP_CONST char *newSuperior )
{
	int msgid;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_rename2\n", 0, 0, 0 );

	rc = ldap_rename( ld, dn, newrdn, deleteoldrdn, newSuperior,
		NULL, NULL, &msgid );

	return rc == LDAP_SUCCESS ? msgid : -1;
}


/*
 * ldap_modrdn2 - initiate an ldap modifyRDN operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to modify
 *	newrdn		RDN to give the object
 *	deleteoldrdn	nonzero means to delete old rdn values from the entry
 *
 * Example:
 *	msgid = ldap_modrdn( ld, dn, newrdn );
 */
int
ldap_modrdn2( LDAP *ld,
	LDAP_CONST char *dn,
	LDAP_CONST char *newrdn,
	int deleteoldrdn )
{
	return ldap_rename2( ld, dn, newrdn, deleteoldrdn, NULL );
}

int
ldap_modrdn( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *newrdn )
{
	return( ldap_rename2( ld, dn, newrdn, 1, NULL ) );
}


int
ldap_rename_s(
	LDAP *ld,
	LDAP_CONST char *dn,
	LDAP_CONST char *newrdn,
	int deleteoldrdn,
	LDAP_CONST char *newSuperior,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int rc;
	int msgid;
	LDAPMessage *res;

	rc = ldap_rename( ld, dn, newrdn, deleteoldrdn,
		newSuperior, sctrls, cctrls, &msgid );

	if( rc != LDAP_SUCCESS ) {
		return rc;
	}

	rc = ldap_result( ld, msgid, 1, NULL, &res );

	if( rc == -1 ) {
		return ld->ld_errno;
	}

	return ldap_result2error( ld, res, 1 );
}

int
ldap_rename2_s(
	LDAP *ld,
	LDAP_CONST char *dn,
	LDAP_CONST char *newrdn,
	int deleteoldrdn,
	LDAP_CONST char *newSuperior )
{
	return ldap_rename_s( ld, dn, newrdn, deleteoldrdn, newSuperior, NULL, NULL );
}

int
ldap_modrdn2_s( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *newrdn, int deleteoldrdn )
{
	return ldap_rename_s( ld, dn, newrdn, deleteoldrdn, NULL, NULL, NULL );
}

int
ldap_modrdn_s( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *newrdn )
{
	return ldap_rename_s( ld, dn, newrdn, 1, NULL, NULL, NULL );
}

