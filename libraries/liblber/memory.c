/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdlib.h>
#include <ac/string.h>

#include "lber-int.h"

BerMemoryFunctions *ber_int_memory_fns = NULL;

void
ber_memfree( void *p )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	assert( p != NULL );

	if( ber_int_memory_fns == NULL ) {
		free( p );
		return;
	}

	assert( ber_int_memory_fns->bmf_free );

	(*ber_int_memory_fns->bmf_free)( p );
}

void *
ber_memalloc( size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	assert( s );

	if( ber_int_memory_fns == NULL ) {
		return malloc( s );
	}

	assert( ber_int_memory_fns->bmf_malloc );

	return (*ber_int_memory_fns->bmf_malloc)( s );
}

void *
ber_memcalloc( size_t n, size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	assert( n && s );

	if( ber_int_memory_fns == NULL ) {
		return calloc( n, s );
	}

	assert( ber_int_memory_fns->bmf_calloc );

	return (*ber_int_memory_fns->bmf_calloc)( n, s );
}

void *
ber_memrealloc( void* p, size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( p == NULL ) {
		return ber_memalloc( s );
	}
	
	if( s == 0 ) {
		ber_memfree( p );
		return NULL;
	}

	if( ber_int_memory_fns == NULL ) {
		return realloc( p, s );
	}

	assert( ber_int_memory_fns->bmf_realloc );

	return (*ber_int_memory_fns->bmf_realloc)( p, s );
}

