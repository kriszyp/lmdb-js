/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  sbind.c
 */

/*
 *	BindRequest ::= SEQUENCE {
 *		version		INTEGER,
 *		name		DistinguishedName,	 -- who
 *		authentication	CHOICE {
 *			simple		[0] OCTET STRING -- passwd
#ifdef HAVE_KERBEROS
 *			krbv42ldap	[1] OCTET STRING
 *			krbv42dsa	[2] OCTET STRING
#endif
 *			sasl		[3] SaslCredentials	-- LDAPv3
 *		}
 *	}
 *
 *	BindResponse ::= SEQUENCE {
 *		COMPONENTS OF LDAPResult,
 *		serverSaslCreds		OCTET STRING OPTIONAL -- LDAPv3
 *	}
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"


/*
 * ldap_simple_bind - bind to the ldap server (and X.500).  The dn and
 * password of the entry to which to bind are supplied.  The message id
 * of the request initiated is returned.
 *
 * Example:
 *	ldap_simple_bind( ld, "cn=manager, o=university of michigan, c=us",
 *	    "secret" )
 */

int
ldap_simple_bind( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *passwd )
{
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_simple_bind\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if ( dn == NULL )
		dn = "";
	if ( passwd == NULL )
		passwd = "";

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		return( -1 );
	}

	assert( BER_VALID( ber ) );

	/* fill it in */
	if ( ber_printf( ber, "{it{ists}}", ++ld->ld_msgid, LDAP_REQ_BIND,
	    ld->ld_version, dn, LDAP_AUTH_SIMPLE, passwd ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL ) {
		ldap_flush_cache( ld );
	}
#endif /* !LDAP_NOCACHE */

	/* send the message */
	return( ldap_send_initial_request( ld, LDAP_REQ_BIND, dn, ber ));
}

/*
 * ldap_simple_bind - bind to the ldap server (and X.500) using simple
 * authentication.  The dn and password of the entry to which to bind are
 * supplied.  LDAP_SUCCESS is returned upon success, the ldap error code
 * otherwise.
 *
 * Example:
 *	ldap_simple_bind_s( ld, "cn=manager, o=university of michigan, c=us",
 *	    "secret" )
 */

int
ldap_simple_bind_s( LDAP *ld, LDAP_CONST char *dn, LDAP_CONST char *passwd )
{
	int		msgid;
	LDAPMessage	*result;

	Debug( LDAP_DEBUG_TRACE, "ldap_simple_bind_s\n", 0, 0, 0 );

	if ( (msgid = ldap_simple_bind( ld, dn, passwd )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, NULL, &result ) == -1 )
		return( ld->ld_errno );	/* ldap_result sets ld_errno */

	return( ldap_result2error( ld, result, 1 ) );
}
