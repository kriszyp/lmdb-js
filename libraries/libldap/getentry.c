/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getentry.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"

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
