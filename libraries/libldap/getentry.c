/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getentry.c
 */

#include "portable.h"

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/* ARGSUSED */
LDAPMessage *
ldap_first_entry( LDAP *ld, LDAPMessage *chain )
{
	if( ld == NULL || chain == NULLMSG ) {
		return NULLMSG;
	}

	return chain->lm_msgtype == LDAP_RES_SEARCH_ENTRY
		? chain
		: ldap_next_entry( ld, chain );
}

/* ARGSUSED */
LDAPMessage *
ldap_next_entry( LDAP *ld, LDAPMessage *entry )
{
	if ( ld == NULL || entry == NULLMSG ) {
		return NULLMSG;
	}

	for ( ; entry != NULLMSG; entry = entry->lm_chain ) {
		if( entry->lm_msgtype == LDAP_RES_SEARCH_ENTRY ) {
			return( entry );
		}
	}

	return( NULLMSG );
}

/* ARGSUSED */
int
ldap_count_entries( LDAP *ld, LDAPMessage *chain )
{
	int	i;

	if ( ld == NULL ) {
		return -1;
	}

	for ( i = 0; chain != NULL; chain = chain->lm_chain ) {
		if( chain->lm_msgtype == LDAP_RES_SEARCH_ENTRY ) {
			i++;
		}
	}

	return( i );
}
