/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1993 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  cache.c - just shell functions for the now defunct LDAP caching routines
 *		to be deleted in the next "full" release
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

int
ldap_enable_cache( LDAP *ld, long timeout, ber_len_t maxmem )
{
	static int called = 0;
	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );

	if (!(called++)) {
		fprintf( stderr, "ldap_enable_cache: routine is obsoleted.\n");
	}

	return -1;
}

void
ldap_disable_cache( LDAP *ld )
{
}

void
ldap_set_cache_options( LDAP *ld, unsigned long opts )
{
}
	
void
ldap_destroy_cache( LDAP *ld )
{
}

void
ldap_flush_cache( LDAP *ld )
{
}

void
ldap_uncache_request( LDAP *ld, int msgid )
{
}

void
ldap_uncache_entry( LDAP *ld, LDAP_CONST char *dn )
{
}

void
ldap_add_request_to_cache( LDAP *ld, ber_tag_t msgtype, BerElement *request )
{
}

void
ldap_add_result_to_cache( LDAP *ld, LDAPMessage *result )
{
}

int
ldap_check_cache( LDAP *ld, ber_tag_t msgtype, BerElement *request )
{
	return( -1 );
}

