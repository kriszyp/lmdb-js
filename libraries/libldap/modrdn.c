/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  modrdn.c
 */

#include "portable.h"

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * ldap_modrdn2 - initiate an ldap (and X.500) modifyRDN operation. Parameters:
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
ldap_modrdn2( LDAP *ld, char *dn, char *newrdn, int deleteoldrdn )
{
	BerElement	*ber;

	/*
	 * A modify rdn request looks like this:
	 *	ModifyRDNRequest ::= SEQUENCE {
	 *		entry		DistinguishedName,
	 *		newrdn		RelativeDistinguishedName,
	 *		deleteoldrdn	BOOLEAN
	 *	}
	 */

	Debug( LDAP_DEBUG_TRACE, "ldap_modrdn\n", 0, 0, 0 );

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		return( -1 );
	}

	if ( ber_printf( ber, "{it{ssb}}", ++ld->ld_msgid, LDAP_REQ_MODRDN, dn,
	    newrdn, deleteoldrdn ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

	/* send the message */
	return ( ldap_send_initial_request( ld, LDAP_REQ_MODRDN, dn, ber ));
}

int
ldap_modrdn( LDAP *ld, char *dn, char *newrdn )
{
	return( ldap_modrdn2( ld, dn, newrdn, 1 ) );
}

int
ldap_modrdn2_s( LDAP *ld, char *dn, char *newrdn, int deleteoldrdn )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_modrdn2( ld, dn, newrdn, deleteoldrdn )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

int
ldap_modrdn_s( LDAP *ld, char *dn, char *newrdn )
{
	return( ldap_modrdn2_s( ld, dn, newrdn, 1 ) );
}
