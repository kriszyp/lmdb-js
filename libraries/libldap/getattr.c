/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getattr.c
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

char *
ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **ber )
{
	long	len;

	Debug( LDAP_DEBUG_TRACE, "ldap_first_attribute\n", 0, 0, 0 );

	if ( (*ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		return( NULL );
	}

	**ber = *entry->lm_ber;

	/* 
	 * Skip past the sequence, dn, sequence of sequence, snarf the
	 * attribute type, and skip the set of values, leaving us
	 * positioned right before the next attribute type/value sequence.
	 */

	len = LDAP_MAX_ATTR_LEN;
	if ( ber_scanf( *ber, "{x{{sx}", ld->ld_attrbuffer, &len )
	    == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( *ber, 0 );
		return( NULL );
	}

	return( ld->ld_attrbuffer );
}

/* ARGSUSED */
char *
ldap_next_attribute( LDAP *ld, LDAPMessage *entry, BerElement *ber )
{
	long	len;

	Debug( LDAP_DEBUG_TRACE, "ldap_next_attribute\n", 0, 0, 0 );

	/* skip sequence, snarf attribute type, skip values */
	len = LDAP_MAX_ATTR_LEN;
	if ( ber_scanf( ber, "{sx}", ld->ld_attrbuffer, &len ) 
	    == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 0 );
		return( NULL );
	}

	return( ld->ld_attrbuffer );
}
