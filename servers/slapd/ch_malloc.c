/* ch_malloc.c - malloc routines that test returns from malloc and friends */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#define CH_FREE 1

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#ifndef CSRIMALLOC

void *
ch_malloc(
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) ber_memalloc( size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ch_malloc of %lu bytes failed\n",
			(long) size, 0, 0 );
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	return( new );
}

void *
ch_realloc(
    void		*block,
    ber_len_t	size
)
{
	void	*new;

	if ( block == NULL ) {
		return( ch_malloc( size ) );
	}

	if( size == 0 ) {
		ch_free( block );
	}

	if ( (new = (void *) ber_memrealloc( block, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ch_realloc of %lu bytes failed\n",
			(long) size, 0, 0 );
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	return( new );
}

void *
ch_calloc(
    ber_len_t	nelem,
    ber_len_t	size
)
{
	void	*new;

	if ( (new = (void *) ber_memcalloc( nelem, size )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ch_calloc of %lu elems of %lu bytes failed\n",
		  (long) nelem, (long) size, 0 );
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	return( new );
}

char *
ch_strdup(
    const char *string
)
{
	char	*new;

	if ( (new = ber_strdup( string )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "ch_strdup(%s) failed\n", string, 0, 0 );
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	return( new );
}

void
ch_free( void *ptr )
{
	ber_memfree( ptr );
}

#endif
