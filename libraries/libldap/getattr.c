/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getattr.c
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

char *
ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **berout )
{
	ber_tag_t rc;
	ber_len_t len;
	char *attr;
	BerElement *ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_first_attribute\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( entry != NULL );
	assert( berout != NULL );

	ber = ldap_alloc_ber_with_options( ld );
	if( ber == NULL ) {
		return NULL;
	}

	*ber = *entry->lm_ber;

	/* 
	 * Skip past the sequence, dn, sequence of sequence leaving
	 * us at the first attribute.
	 */

	rc = ber_scanf( ber, "{xl{" /*}}*/, &attr, &len );

	if( rc == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 0 );
		return  NULL;
	}

#if 0
	if( len == 0 ) {
		return NULL;
	}
#endif
	
	/* set the length to avoid overrun */
	rc = ber_set_option( ber, LBER_OPT_REMAINING_BYTES, &len );

	if( rc != LBER_OPT_SUCCESS ) {
		ld->ld_errno = LDAP_LOCAL_ERROR;
		ber_free( ber, 0 );
		return NULL;
	}

	/* snatch the first attribute */
	rc = ber_scanf( ber, "{ax}", &attr );
	if( rc == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 0 );
		return NULL;
	}

	*berout = ber;
	return attr;
}

/* ARGSUSED */
char *
ldap_next_attribute( LDAP *ld, LDAPMessage *entry, BerElement *ber )
{
	ber_tag_t rc;
	char *attr;
#if 0
	ber_len_t len;
#endif

	Debug( LDAP_DEBUG_TRACE, "ldap_next_attribute\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( entry != NULL );
	assert( ber != NULL );

#if 0
	rc = ber_get_option( ber, LBER_OPT_REMAINING_BYTES, &len );
	if( rc != LDAP_OPT_SUCCESS ) {
		ld->ld_errno = LDAP_LOCAL_ERROR;
		return NULL;
	}

	/* we're done */
	if( len == 0 ) return NULL;
#endif

	/* skip sequence, snarf attribute type, skip values */
	rc = ber_scanf( ber, "{ax}", &attr ); 
	if( rc == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return NULL;
	}

	return attr;
}
