/* sl_malloc.c - malloc routines using a per-thread slab */
/* $OpenLDAP$ */
/*
 * Copyright 2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"

struct slab_heap {
	void *h_base;
	void *h_last;
	void *h_end;
};

static void
sl_mem_destroy(
	void *key,
	void *data
)
{
	struct slab_heap *sh = data;

	ch_free(sh->h_base);
	ch_free(sh);
}

BER_MEMALLOC_FN sl_malloc;
BER_MEMCALLOC_FN sl_calloc;
BER_MEMREALLOC_FN sl_realloc;
BER_MEMFREE_FN sl_free;


BerMemoryFunctions sl_mfuncs =
	{ sl_malloc, sl_calloc, sl_realloc, sl_free };

void
sl_mem_init()
{
	ber_set_option( NULL, LBER_OPT_MEMORY_FNS, &sl_mfuncs );
}

void *
sl_mem_create(
	ber_len_t size,
	void *ctx
)
{
	struct slab_heap *sh = NULL;
	int pad = 2*sizeof(int)-1;

	ldap_pvt_thread_pool_getkey( ctx, sl_mem_init, (void **)&sh, NULL );

	/* round up to doubleword boundary */
	size += pad;
	size &= ~pad;

	if (!sh) {
		sh = ch_malloc( sizeof(struct slab_heap) );
		sh->h_base = ch_malloc( size );
		ldap_pvt_thread_pool_setkey( ctx, sl_mem_init, (void *)sh, sl_mem_destroy );
	} else if ( size > sh->h_end - sh->h_base ) {
		sh->h_base = ch_realloc( sh->h_base, size );
	}
	sh->h_last = sh->h_base;
	sh->h_end = sh->h_base + size;
	return sh;
}

void *
sl_malloc(
    ber_len_t	size,
    void *ctx
)
{
	struct slab_heap *sh = ctx;
	int pad = 2*sizeof(int)-1;
	ber_len_t *new;

	/* ber_set_option calls us like this */
	if (!ctx) return ber_memalloc_x( size, NULL );

	/* round up to doubleword boundary */
	size += pad + sizeof( ber_len_t );
	size &= ~pad;

	if (sh->h_last + size >= sh->h_end ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			   "sl_malloc: allocation of %lu bytes failed\n", (long)size, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "sl_malloc of %lu bytes failed\n",
			(long) size, 0, 0 );
#endif
		assert( 0 );
		exit( EXIT_FAILURE );
	}
	new = sh->h_last;
	*new++ = size - sizeof(ber_len_t);
	sh->h_last += size;
	
	return( (void *)new );
}

void *
sl_calloc( ber_len_t n, ber_len_t size, void *ctx )
{
	void *new;

	new = sl_malloc( n*size, ctx );
	if ( new ) {
		memset( new, 0, n*size );
	}
	return new;
}

void *
sl_realloc( void *ptr, ber_len_t size, void *ctx )
{
	struct slab_heap *sh = ctx;
	int pad = 2*sizeof(int)-1;
	ber_len_t *p = (ber_len_t *)ptr;
	ber_len_t *new;

	if ( ptr == NULL ) return sl_malloc( size, ctx );

	if ( ptr < sh->h_base || ptr >= sh->h_end ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			   "sl_free: not mine: 0x%lx\n", (long)ptr, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY,
			   "sl_free: not mine: 0x%lx\n", (long)ptr, 0,0 );
#endif
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	if ( size == 0 ) return NULL;

	/* round up to doubleword boundary */
	size += pad + sizeof( ber_len_t );
	size &= ~pad;

	/* We always alloc a new block */
	if (size <= p[-1]) {
		p[-1] = size;
		new = p;
	} else {
		new = sl_malloc( size, ctx );
		AC_MEMCPY( new, ptr, p[-1] );
	}
	return new;
}

void
sl_free( void *ptr, void *ctx )
{
	struct slab_heap *sh = ctx;

	if ( ptr < sh->h_base || ptr >= sh->h_end ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			   "sl_free: not mine: 0x%lx\n", (long)ptr, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY,
			   "sl_free: not mine: 0x%lx\n", (long)ptr, 0,0 );
#endif
		assert( 0 );
		exit( EXIT_FAILURE );
	}
}
