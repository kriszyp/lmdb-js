/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  kbind.c
 */

#include "portable.h"

#ifdef HAVE_KERBEROS

#include <stdio.h>
#include <stdlib.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"



/*
 * ldap_kerberos_bind1 - initiate a bind to the ldap server using
 * kerberos authentication.  The dn is supplied.  It is assumed the user
 * already has a valid ticket granting ticket.  The msgid of the
 * request is returned on success (suitable for passing to ldap_result()),
 * -1 is returned if there's trouble.
 *
 * Example:
 *	ldap_kerberos_bind1( ld, "cn=manager, o=university of michigan, c=us" )
 */
int
ldap_kerberos_bind1( LDAP *ld, char *dn )
{
	BerElement	*ber;
	char		*cred;
	int		rc, credlen;
#ifdef STR_TRANSLATION
	int		str_translation_on;
#endif /* STR_TRANSLATION */

	/*
	 * The bind request looks like this:
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,
	 *		name		DistinguishedName,
	 *		authentication	CHOICE {
	 *			krbv42ldap	[1] OCTET STRING
	 *			krbv42dsa	[2] OCTET STRING
	 *		}
	 *	}
	 * all wrapped up in an LDAPMessage sequence.
	 */

	Debug( LDAP_DEBUG_TRACE, "ldap_kerberos_bind1\n", 0, 0, 0 );

	if ( dn == NULL )
		dn = "";

	if ( (cred = ldap_get_kerberosv4_credentials( ld, dn, "ldapserver",
	    &credlen )) == NULL ) {
		return( -1 );	/* ld_errno should already be set */
	}

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		free( cred );
		return( -1 );
	}

#ifdef STR_TRANSLATION
	if (( str_translation_on = (( ber->ber_options &
	    LBER_TRANSLATE_STRINGS ) != 0 ))) {	/* turn translation off */
		ber->ber_options &= ~LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	/* fill it in */
	rc = ber_printf( ber, "{it{isto}}", ++ld->ld_msgid, LDAP_REQ_BIND,
	    ld->ld_version, dn, LDAP_AUTH_KRBV41, cred, credlen );

#ifdef STR_TRANSLATION
	if ( str_translation_on ) {	/* restore translation */
		ber->ber_options |= LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	if ( rc == -1 ) {
		free( cred );
		ber_free( ber, 1 );
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return( -1 );
	}

	free( cred );

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL ) {
		ldap_flush_cache( ld );
	}
#endif /* !LDAP_NOCACHE */

	/* send the message */
	return ( ldap_send_initial_request( ld, LDAP_REQ_BIND, dn, ber ));
}

int
ldap_kerberos_bind1_s( LDAP *ld, char *dn )
{
	int		msgid;
	LDAPMessage	*res;

	Debug( LDAP_DEBUG_TRACE, "ldap_kerberos_bind1_s\n", 0, 0, 0 );

	/* initiate the bind */
	if ( (msgid = ldap_kerberos_bind1( ld, dn )) == -1 )
		return( ld->ld_errno );

	/* wait for a result */
	if ( ldap_result( ld, ld->ld_msgid, 1, (struct timeval *) 0, &res )
	    == -1 ) {
		return( ld->ld_errno );	/* ldap_result sets ld_errno */
	}

	return( ldap_result2error( ld, res, 1 ) );
}

/*
 * ldap_kerberos_bind2 - initiate a bind to the X.500 server using
 * kerberos authentication.  The dn is supplied.  It is assumed the user
 * already has a valid ticket granting ticket.  The msgid of the
 * request is returned on success (suitable for passing to ldap_result()),
 * -1 is returned if there's trouble.
 *
 * Example:
 *	ldap_kerberos_bind2( ld, "cn=manager, o=university of michigan, c=us" )
 */
int
ldap_kerberos_bind2( LDAP *ld, char *dn )
{
	BerElement	*ber;
	char		*cred;
	int		rc, credlen;
#ifdef STR_TRANSLATION
	int		str_translation_on;
#endif /* STR_TRANSLATION */

	Debug( LDAP_DEBUG_TRACE, "ldap_kerberos_bind2\n", 0, 0, 0 );

	if ( dn == NULL )
		dn = "";

	if ( (cred = ldap_get_kerberosv4_credentials( ld, dn, "x500dsa", &credlen ))
	    == NULL ) {
		return( -1 );	/* ld_errno should already be set */
	}

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		free( cred );
		return( -1 );
	}

#ifdef STR_TRANSLATION
	if (( str_translation_on = (( ber->ber_options &
	    LBER_TRANSLATE_STRINGS ) != 0 ))) {	/* turn translation off */
		ber->ber_options &= ~LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	/* fill it in */
	rc = ber_printf( ber, "{it{isto}}", ++ld->ld_msgid, LDAP_REQ_BIND,
	    ld->ld_version, dn, LDAP_AUTH_KRBV42, cred, credlen );


#ifdef STR_TRANSLATION
	if ( str_translation_on ) {	/* restore translation */
		ber->ber_options |= LBER_TRANSLATE_STRINGS;
	}
#endif /* STR_TRANSLATION */

	free( cred );

	if ( rc == -1 ) {
		ber_free( ber, 1 );
		ld->ld_errno = LDAP_ENCODING_ERROR;
		return( -1 );
	}

	/* send the message */
	return ( ldap_send_initial_request( ld, LDAP_REQ_BIND, dn, ber ));
}

/* synchronous bind to DSA using kerberos */
int
ldap_kerberos_bind2_s( LDAP *ld, char *dn )
{
	int		msgid;
	LDAPMessage	*res;

	Debug( LDAP_DEBUG_TRACE, "ldap_kerberos_bind2_s\n", 0, 0, 0 );

	/* initiate the bind */
	if ( (msgid = ldap_kerberos_bind2( ld, dn )) == -1 )
		return( ld->ld_errno );

	/* wait for a result */
	if ( ldap_result( ld, ld->ld_msgid, 1, (struct timeval *) 0, &res )
	    == -1 ) {
		return( ld->ld_errno );	/* ldap_result sets ld_errno */
	}

	return( ldap_result2error( ld, res, 1 ) );
}

/* synchronous bind to ldap and DSA using kerberos */
int
ldap_kerberos_bind_s( LDAP *ld, char *dn )
{
	int	err;

	Debug( LDAP_DEBUG_TRACE, "ldap_kerberos_bind_s\n", 0, 0, 0 );

	if ( (err = ldap_kerberos_bind1_s( ld, dn )) != LDAP_SUCCESS )
		return( err );

	return( ldap_kerberos_bind2_s( ld, dn ) );
}


#ifndef AUTHMAN
/*
 * ldap_get_kerberosv4_credentials - obtain kerberos v4 credentials for ldap.
 * The dn of the entry to which to bind is supplied.  It's assumed the
 * user already has a tgt.
 */

char *
ldap_get_kerberosv4_credentials( LDAP *ld, char *who, char *service, int *len )
{
	KTEXT_ST	ktxt;
	int		err;
	char		realm[REALM_SZ], *cred, *krbinstance;

	Debug( LDAP_DEBUG_TRACE, "ldap_get_kerberosv4_credentials\n", 0, 0, 0 );

	if ( (err = krb_get_tf_realm( tkt_string(), realm )) != KSUCCESS ) {
#ifdef LDAP_LIBUI
		fprintf( stderr, "krb_get_tf_realm failed (%s)\n",
		    krb_err_txt[err] );
#endif /* LDAP_LIBUI */
		ld->ld_errno = LDAP_INVALID_CREDENTIALS;
		return( NULL );
	}

#ifdef LDAP_REFERRALS
	krbinstance = ld->ld_defconn->lconn_krbinstance;
#else /* LDAP_REFERRALS */
	krbinstance = ld->ld_host;
#endif /* LDAP_REFERRALS */

	if ( (err = krb_mk_req( &ktxt, service, krbinstance, realm, 0 ))
	    != KSUCCESS ) {
#ifdef LDAP_LIBUI
		fprintf( stderr, "krb_mk_req failed (%s)\n", krb_err_txt[err] );
#endif /* LDAP_LIBUI */
		ld->ld_errno = LDAP_INVALID_CREDENTIALS;
		return( NULL );
	}

	if ( ( cred = malloc( ktxt.length )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( NULL );
	}

	*len = ktxt.length;
	memcpy( cred, ktxt.dat, ktxt.length );

	return( cred );
}

#endif /* !AUTHMAN */
#endif /* HAVE_KERBEROS */
