/* sl_malloc.c - malloc routines using a per-thread slab */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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
sl_mem_destroy(
	void *key,
	void *data
)
{
	struct slab_heap *sh = data;

	ber_memfree_x(sh->h_base, NULL);
	ber_memfree_x(sh, NULL);
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
	} else if ( size > (char *) sh->h_end - (char *) sh->h_base ) {
		sh->h_base = ch_realloc( sh->h_base, size );
	}
	sh->h_last = sh->h_base;
	sh->h_end = (char *) sh->h_base + size;
	return sh;
}

void
sl_mem_detach(
	void *ctx,
	void *memctx
)
{
	/* separate from context */
	ldap_pvt_thread_pool_setkey( ctx, sl_mem_init, NULL, NULL );
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

	if ((char *) sh->h_last + size >= (char *) sh->h_end ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, 
			   "sl_malloc of %lu bytes failed, using ch_malloc\n", (long)size, 0,0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			   "sl_malloc of %lu bytes failed, using ch_malloc\n", (long)size, 0,0 );
#endif
		return ch_malloc( size );
	}
	new = sh->h_last;
	*new++ = size - sizeof(ber_len_t);
	sh->h_last = (char *) sh->h_last + size;
	
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
		sl_free( ptr, ctx );
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
		new = sl_malloc( size, ctx );
		AC_MEMCPY( new, ptr, p[-1] );
	}
	return new;
}

void
sl_free( void *ptr, void *ctx )
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

void
sl_release( void *ptr, void *ctx )
{
	struct slab_heap *sh = ctx;

	if ( sh && ptr >= sh->h_base && ptr <= sh->h_end ) {
		sh->h_last = ptr;
	}
}

void *
sl_mark( void *ctx )
{
	struct slab_heap *sh = ctx;
	void *ret = NULL;

	if (sh) ret = sh->h_last;

	return ret;
}

void *
sl_context( void *ptr )
{
	struct slab_heap *sh = NULL;
	void *ctx;

	ctx = ldap_pvt_thread_pool_context();

	ldap_pvt_thread_pool_getkey( ctx, sl_mem_init, (void **)&sh, NULL );

	if ( sh && ptr >= sh->h_base && ptr <= sh->h_end ) {
		return sh;
	}
	return NULL;
}
