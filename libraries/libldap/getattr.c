/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getattr.c
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
#include "ldap-int.h"

char *
ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **ber )
{
	long	len;

	Debug( LDAP_DEBUG_TRACE, "ldap_first_attribute\n", 0, 0, 0 );

	if ( (*ber = alloc_ber_with_options( ld )) == NULLBER ) {
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
