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
#if LBER_SEQORSET_AVOID_OVERRUN
	int rc;
#endif
	ber_tag_t tag;
	ber_len_t len;
	char *attr;
	BerElement *ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_first_attribute\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( entry != NULL );
	assert( berout != NULL );

	*berout = NULL;

	ber = ldap_alloc_ber_with_options( ld );
	if( ber == NULL ) {
		return NULL;
	}

	*ber = *entry->lm_ber;

	/* 
	 * Skip past the sequence, dn, sequence of sequence leaving
	 * us at the first attribute.
	 */

	tag = ber_scanf( ber, "{xl{" /*}}*/, &attr, &len );
	if( tag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 0 );
		return  NULL;
	}

#if LDAP_SEQORSET_BAILOUT
	if( len == 0 ) {
		return NULL;
	}
#endif
	
#if LBER_SEQORSET_AVOID_OVERRUN
	/* set the length to avoid overrun */
	rc = ber_set_option( ber, LBER_OPT_REMAINING_BYTES, &len );
	if( rc != LBER_OPT_SUCCESS ) {
		ld->ld_errno = LDAP_LOCAL_ERROR;
		ber_free( ber, 0 );
		return NULL;
	}
#endif

	/* snatch the first attribute */
	tag = ber_scanf( ber, "{ax}", &attr );
	if( tag == LBER_ERROR ) {
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
	ber_tag_t tag;
	char *attr;

	Debug( LDAP_DEBUG_TRACE, "ldap_next_attribute\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( entry != NULL );
	assert( ber != NULL );

#if LDAP_SEQORSET_BAILOUT
	if ( ber_pvt_ber_remaining( ber ) == 0 ) {
		return NULL;
	}
#endif

	/* skip sequence, snarf attribute type, skip values */
	tag = ber_scanf( ber, "{ax}", &attr ); 
	if( tag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return NULL;
	}

	return attr;
}
