/* sl_malloc.c - malloc routines using a per-thread slab */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
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

void
slap_sl_mem_destroy(
	void *key,
	void *data
)
{
	struct slab_heap *sh = data;

	ber_memfree_x(sh->h_base, NULL);
	ber_memfree_x(sh, NULL);
}

BerMemoryFunctions slap_sl_mfuncs =
	{ slap_sl_malloc, slap_sl_calloc, slap_sl_realloc, slap_sl_free };

void
slap_sl_mem_init()
{
	ber_set_option( NULL, LBER_OPT_MEMORY_FNS, &slap_sl_mfuncs );
}

#ifdef NO_THREADS
static struct slab_heap *slheap;
#endif

void *
slap_sl_mem_create(
	ber_len_t size,
	void *ctx
)
{
	struct slab_heap *sh = NULL;
	int pad = 2*sizeof(int)-1;

#ifdef NO_THREADS
	sh = slheap;
#else
	ldap_pvt_thread_pool_getkey( ctx, (void *)slap_sl_mem_init, (void **)&sh, NULL );
#endif

	/* round up to doubleword boundary */
	size += pad;
	size &= ~pad;

	if (!sh) {
		sh = ch_malloc( sizeof(struct slab_heap) );
		sh->h_base = ch_malloc( size );
#ifdef NO_THREADS
		slheap = sh;
#else
		ldap_pvt_thread_pool_setkey( ctx, (void *)slap_sl_mem_init,
			(void *)sh, slap_sl_mem_destroy );
#endif
	} else if ( size > (char *) sh->h_end - (char *) sh->h_base ) {
		sh->h_base = ch_realloc( sh->h_base, size );
	}
	sh->h_last = sh->h_base;
	sh->h_end = (char *) sh->h_base + size;
	return sh;
}

void
slap_sl_mem_detach(
	void *ctx,
	void *memctx
)
{
#ifdef NO_THREADS
	slheap = NULL;
#else
	/* separate from context */
	ldap_pvt_thread_pool_setkey( ctx, (void *)slap_sl_mem_init, NULL, NULL );
#endif
}

void *
slap_sl_malloc(
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

	if ((char *) sh->h_last + size >= (char *) sh->h_end ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			"slap_sl_malloc of %lu bytes failed, using ch_malloc\n",
			(long)size, 0,0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_sl_malloc of %lu bytes failed, using ch_malloc\n",
			(long)size, 0,0 );
#endif
		return ch_malloc( size );
	}
	new = sh->h_last;
	*new++ = size - sizeof(ber_len_t);
	sh->h_last = (char *) sh->h_last + size;
	
	return( (void *)new );
}

void *
slap_sl_calloc( ber_len_t n, ber_len_t size, void *ctx )
{
	void *new;

	new = slap_sl_malloc( n*size, ctx );
	if ( new ) {
		memset( new, 0, n*size );
	}
	return new;
}

void *
slap_sl_realloc( void *ptr, ber_len_t size, void *ctx )
{
	struct slab_heap *sh = ctx;
	int pad = 2*sizeof(int)-1;
	ber_len_t *p = (ber_len_t *)ptr;
	ber_len_t *new;

	if ( ptr == NULL ) return slap_sl_malloc( size, ctx );

	/* Not our memory? */
	if ( !sh || ptr < sh->h_base || ptr >= sh->h_end ) {
		/* duplicate of ch_realloc behavior, oh well */
		new = ber_memrealloc_x( ptr, size, NULL );
		if (new ) {
			return new;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"ch_realloc: reallocation of %lu bytes failed\n", (long)size, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "ch_realloc of %lu bytes failed\n",
			(long) size, 0, 0 );
#endif
		assert( 0 );
		exit( EXIT_FAILURE );
	}

	if ( size == 0 ) {
		slap_sl_free( ptr, ctx );
		return NULL;
	}

	/* round up to doubleword boundary */
	size += pad + sizeof( ber_len_t );
	size &= ~pad;

	/* Never shrink blocks */
	if (size <= p[-1]) {
		new = p;
	
	/* If reallocing the last block, we can grow it */
	} else if ( (char *)ptr + p[-1] == sh->h_last ) {
		new = p;
		sh->h_last = (char *) sh->h_last + size - p[-1];
		p[-1] = size;
	
	/* Nowhere to grow, need to alloc and copy */
	} else {
		new = slap_sl_malloc( size, ctx );
		AC_MEMCPY( new, ptr, p[-1] );
	}
	return new;
}

void
slap_sl_free( void *ptr, void *ctx )
{
	struct slab_heap *sh = ctx;
	ber_len_t *p = (ber_len_t *)ptr;

	if ( !sh || ptr < sh->h_base || ptr >= sh->h_end ) {
		ber_memfree_x( ptr, NULL );
	} else if ( (char *)ptr + p[-1] == sh->h_last ) {
		p--;
		sh->h_last = p;
	}
}

void *
slap_sl_context( void *ptr )
{
	struct slab_heap *sh = NULL;
	void *ctx;

#ifdef NO_THREADS
	sh = slheap;
#else
	ctx = ldap_pvt_thread_pool_context();

	ldap_pvt_thread_pool_getkey( ctx, (void *)slap_sl_mem_init, (void **)&sh, NULL );
#endif

	if ( sh && ptr >= sh->h_base && ptr <= sh->h_end ) {
		return sh;
	}
	return NULL;
}
