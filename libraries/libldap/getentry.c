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
	return( chain == NULLMSG || chain->lm_msgtype == LDAP_RES_SEARCH_RESULT
	    ? NULLMSG : chain );
}

/* ARGSUSED */
LDAPMessage *ldap_next_entry( LDAP *ld, LDAPMessage *entry )
{
	if ( entry == NULLMSG || entry->lm_chain == NULLMSG
	    || entry->lm_chain->lm_msgtype == LDAP_RES_SEARCH_RESULT )
		return( NULLMSG );

	return( entry->lm_chain );
}

/* ARGSUSED */
int
ldap_count_entries( LDAP *ld, LDAPMessage *chain )
{
	int	i;

	for ( i = 0; chain != NULL && chain->lm_msgtype
	    != LDAP_RES_SEARCH_RESULT; chain = chain->lm_chain )
		i++;

	return( i );
}
