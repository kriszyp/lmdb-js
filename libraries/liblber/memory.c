/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdlib.h>
#include <ac/string.h>

#include "lber-int.h"

void
ber_memfree( void *p )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;
	LBER_FREE( p );
}

void *
ber_memalloc( size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;
	return LBER_MALLOC( s );
}

void *
ber_memcalloc( size_t n, size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;
	return LBER_CALLOC( n, s );
}

void *
ber_memrealloc( void* p, size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;
	return LBER_REALLOC( p, s );
}

BER_MEMORY_FN ber_int_realloc = NULL;

void *
ber_int_calloc( size_t n, size_t s )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	{
		size_t size = n * s;
		void *p = (*ber_int_realloc)( NULL, size );
		return p ?  memset( p, 0, size ) : p;
	}
}

