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

	/* catch p == NULL when debugging */
	assert( p != NULL );

	/* ignore p == NULL when not debugging */
	if( p == NULL ) {
		return;
	}

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

	/* catch s == 0 when debugging */
	assert( s );

	/* ignore s == 0 when not debugging */
	if( s == 0 ) {
		return NULL;
	}

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

	/* catch s,n == 0 when debugging */
	assert( n && s );

	/* ignore s,n == 0 when not debugging */
	if( n == 0 || s == 0 ) {
		return NULL;
	}

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

	/* realloc(NULL,s) -> malloc(s) */
	if( p == NULL ) {
		return ber_memalloc( s );
	}
	
	/* realloc(p,0) -> free(p) */
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

