/*
 *  references.c
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/* ARGSUSED */
LDAPMessage *
ldap_first_reference( LDAP *ld, LDAPMessage *chain )
{
	if ( ld == NULL || chain == NULLMSG ) {
		return NULLMSG;
	}

	return chain->lm_msgtype == LDAP_RES_SEARCH_REFERENCE
		? chain
		: ldap_next_reference( ld, chain );
}

/* ARGSUSED */
LDAPMessage *
ldap_next_reference( LDAP *ld, LDAPMessage *ref )
{
	if ( ld == NULL || ref == NULLMSG ) {
		return NULLMSG;
	}

	for (
		ref = ref->lm_chain;
		ref != NULLMSG;
		ref = ref->lm_chain )
	{
		if( ref->lm_msgtype == LDAP_RES_SEARCH_REFERENCE ) {
			return( ref );
		}
	}

	return( NULLMSG );
}

/* ARGSUSED */
int
ldap_count_references( LDAP *ld, LDAPMessage *chain )
{
	int	i;

	if ( ld == NULL ) {
		return -1;
	}

	for ( i = 0; chain != NULL; chain = chain->lm_chain ) {
		if( chain->lm_msgtype == LDAP_RES_SEARCH_REFERENCE ) {
			i++;
		}
	}

	return( i );
}
