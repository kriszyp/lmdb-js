/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdlib.h>

#include "lber-int.h"

void
ber_memfree( void *p )
{
	LBER_FREE( p );
}

void *
ber_memalloc( size_t s )
{
	return LBER_MALLOC( s );
}

void *
ber_memcalloc( size_t n, size_t s )
{
	return LBER_CALLOC( n, s );
}

void *
ber_memrealloc( void* p, size_t s )
{
	return LBER_REALLOC( p, s );
}

