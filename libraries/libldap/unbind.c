/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  unbind.c
 */

/* An Unbind Request looks like this:
 *
 *	UnbindRequest ::= NULL
 *
 * and has no response.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

int
ldap_unbind_ext(
	LDAP *ld,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int rc;

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	/* check client controls */
	rc = ldap_int_client_controls( ld, cctrls );
	if( rc != LDAP_SUCCESS ) return rc;

	return ldap_ld_free( ld, 1, sctrls, cctrls );
}

int
ldap_unbind_ext_s(
	LDAP *ld,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	return ldap_unbind_ext( ld, sctrls, cctrls );
}

int
ldap_unbind( LDAP *ld )
{
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_unbind\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_unbind\n", 0, 0, 0 );
#endif

	return( ldap_unbind_ext( ld, NULL, NULL ) );
}


int
ldap_ld_free(
	LDAP *ld,
	int close,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	LDAPMessage	*lm, *next;
	int		err = LDAP_SUCCESS;

	/* free LDAP structure and outstanding requests/responses */
	while ( ld->ld_requests != NULL ) {
		ldap_free_request( ld, ld->ld_requests );
	}

	/* free and unbind from all open connections */
	while ( ld->ld_conns != NULL ) {
		ldap_free_connection( ld, ld->ld_conns, 1, close );
	}

	for ( lm = ld->ld_responses; lm != NULL; lm = next ) {
		next = lm->lm_next;
		ldap_msgfree( lm );
	}


	if ( ld->ld_error != NULL ) {
		LDAP_FREE( ld->ld_error );
		ld->ld_error = NULL;
	}

	if ( ld->ld_matched != NULL ) {
		LDAP_FREE( ld->ld_matched );
		ld->ld_matched = NULL;
	}

	if( ld->ld_referrals != NULL) {
		LDAP_VFREE(ld->ld_referrals);
		ld->ld_referrals = NULL;
	}  
    
	if ( ld->ld_abandoned != NULL ) {
		LDAP_FREE( ld->ld_abandoned );
		ld->ld_abandoned = NULL;
	}

	if ( ld->ld_selectinfo != NULL ) {
		ldap_free_select_info( ld->ld_selectinfo );
		ld->ld_selectinfo = NULL;
	}

	if ( ld->ld_options.ldo_defludp != NULL ) {
		ldap_free_urllist( ld->ld_options.ldo_defludp );
		ld->ld_options.ldo_defludp = NULL;
	}

	if ( ld->ld_options.ldo_tm_api != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_tm_api );
		ld->ld_options.ldo_tm_api = NULL;
	}

	if ( ld->ld_options.ldo_tm_net != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_tm_net );
		ld->ld_options.ldo_tm_net = NULL;
	}

#ifdef HAVE_CYRUS_SASL
	if ( ld->ld_options.ldo_def_sasl_mech != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_def_sasl_mech );
		ld->ld_options.ldo_def_sasl_mech = NULL;
	}

	if ( ld->ld_options.ldo_def_sasl_realm != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_def_sasl_realm );
		ld->ld_options.ldo_def_sasl_realm = NULL;
	}

	if ( ld->ld_options.ldo_def_sasl_authcid != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_def_sasl_authcid );
		ld->ld_options.ldo_def_sasl_authcid = NULL;
	}

	if ( ld->ld_options.ldo_def_sasl_authzid != NULL ) {
		LDAP_FREE( ld->ld_options.ldo_def_sasl_authzid );
		ld->ld_options.ldo_def_sasl_authzid = NULL;
	}
#endif

	ber_sockbuf_free( ld->ld_sb );   
   
	LDAP_FREE( (char *) ld );
   
	return( err );
}

int
ldap_unbind_s( LDAP *ld )
{
	return( ldap_unbind_ext( ld, NULL, NULL ) );
}


int
ldap_send_unbind(
	LDAP *ld,
	Sockbuf *sb,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	BerElement	*ber;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_send_unbind\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_send_unbind\n", 0, 0, 0 );
#endif

#ifdef LDAP_CONNECTIONLESS
	if (LDAP_IS_UDP(ld))
		return LDAP_SUCCESS;
#endif
	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
		return( ld->ld_errno );
	}

	/* fill it in */
	if ( ber_printf( ber, "{itn" /*}*/, ++ld->ld_msgid,
	    LDAP_REQ_UNBIND ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* Put Server Controls */
	if( ldap_int_put_controls( ld, sctrls, ber ) != LDAP_SUCCESS ) {
		ber_free( ber, 1 );
		return ld->ld_errno;
	}

	if ( ber_printf( ber, /*{*/ "N}", LDAP_REQ_UNBIND ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	/* send the message */
	if ( ber_flush( sb, ber, 1 ) == -1 ) {
		ld->ld_errno = LDAP_SERVER_DOWN;
		ber_free( ber, 1 );
		return( ld->ld_errno );
	}

	return( LDAP_SUCCESS );
}
