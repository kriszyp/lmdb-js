/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

/* ARGSUSED */
LDAPMessage *
ldap_first_message( LDAP *ld, LDAPMessage *chain )
{
	return( ld == NULL || chain == NULLMSG
	   		? NULLMSG : chain );
}

/* ARGSUSED */
LDAPMessage *
ldap_next_message( LDAP *ld, LDAPMessage *msg )
{
	if ( ld == NULL || msg == NULLMSG || msg->lm_chain == NULL ) {
		return NULLMSG;
	}

	return( msg->lm_chain );
}

/* ARGSUSED */
int
ldap_count_messages( LDAP *ld, LDAPMessage *chain )
{
	int	i;

	if ( ld == NULL ) {
		return -1;
	}

	for ( i = 0; chain != NULL; chain = chain->lm_chain ) {
		i++;
	}

	return( i );
}
