/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  unbind.c
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"


int
ldap_unbind( LDAP *ld )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_unbind\n", 0, 0, 0 );

	return( ldap_ld_free( ld, 1 ));
}


int
ldap_ld_free( LDAP *ld, int close )
{
	LDAPMessage	*lm, *next;
	int		err = LDAP_SUCCESS;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	LDAPRequest	*lr, *nextlr;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	if ( ld->ld_cldapnaddr == 0 ) {
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
		/* free LDAP structure and outstanding requests/responses */
		for ( lr = ld->ld_requests; lr != NULL; lr = nextlr ) {
			nextlr = lr->lr_next;
			ldap_free_request( ld, lr );
		}

		/* free and unbind from all open connections */
		while ( ld->ld_conns != NULL ) {
			ldap_free_connection( ld, ld->ld_conns, 1, close );
		}
#else /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
		if ( close ) {
			err = ldap_send_unbind( ld, &ld->ld_sb );
			ldap_close_connection( &ld->ld_sb );
		}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
	} else {
		int	i;

		for ( i = 0; i < ld->ld_cldapnaddr; ++i ) {
			free( ld->ld_cldapaddrs[ i ] );
		}
		free( ld->ld_cldapaddrs );
	}

	for ( lm = ld->ld_responses; lm != NULL; lm = next ) {
		next = lm->lm_next;
		ldap_msgfree( lm );
	}

#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULL )
		ldap_destroy_cache( ld );
#endif /* !LDAP_NOCACHE */
	if ( ld->ld_error != NULL )
		free( ld->ld_error );
	if ( ld->ld_matched != NULL )
		free( ld->ld_matched );
	if ( ld->ld_host != NULL )
		free( ld->ld_host );
	if ( ld->ld_ufnprefix != NULL )
		free( ld->ld_ufnprefix );
	if ( ld->ld_filtd != NULL )
		ldap_getfilter_free( ld->ld_filtd );
	if ( ld->ld_abandoned != NULL )
		free( ld->ld_abandoned );

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	if ( ld->ld_selectinfo != NULL )
		ldap_free_select_info( ld->ld_selectinfo );
#else
	ber_clear( &(ld->ld_ber), 1 );
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	if ( ld->ld_options.ldo_defbase != NULL )
		free( ld->ld_options.ldo_defbase );

	if ( ld->ld_options.ldo_defhost != NULL )
		free( ld->ld_options.ldo_defhost );

	lber_pvt_sb_destroy( &(ld->ld_sb) );   
   
	free( (char *) ld );
   
	WSACleanup();

	return( err );
}

int
ldap_unbind_s( LDAP *ld )
{
	return( ldap_ld_free( ld, 1 ));
}


int
ldap_send_unbind( LDAP *ld, Sockbuf *sb )
{
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_send_unbind\n", 0, 0, 0 );

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		return( ld->ld_errno );
	}

	/* fill it in */
	if ( ber_printf( ber, "{itn}", ++ld->ld_msgid,
	    LDAP_REQ_UNBIND ) == -1 ) {
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
