/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 *  messages.c
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

LDAPMessage *
ldap_first_message( LDAP *ld, LDAPMessage *chain )
{
	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if ( ld == NULL || chain == NULL ) {
		return NULL;
	}
	
  	return chain;
}

LDAPMessage *
ldap_next_message( LDAP *ld, LDAPMessage *msg )
{
	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if ( ld == NULL || msg == NULL || msg->lm_chain == NULL ) {
		return NULL;
	}

	return( msg->lm_chain );
}

int
ldap_count_messages( LDAP *ld, LDAPMessage *chain )
{
	int	i;

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if ( ld == NULL ) {
		return -1;
	}

	for ( i = 0; chain != NULL; chain = chain->lm_chain ) {
		i++;
	}

	return( i );
}
