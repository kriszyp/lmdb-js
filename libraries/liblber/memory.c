/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>

#include "lber-int.h"

#ifdef LDAP_MEMORY_DEBUG
struct ber_mem_hdr {
	union bmu_align_u {
		size_t	bmu_size_t;
		void *	bmu_voidp;
		double	bmu_double;
		long	bmu_long;
	} ber_align;
#define bm_junk	ber_align.bmu_size_t
};
#define BER_MEM_JUNK 0xddeeddeeU
#endif

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
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = (struct ber_mem_hdr *)
			((char *)p - sizeof(struct ber_mem_hdr));
		assert( mh->bm_junk == BER_MEM_JUNK );
		free( mh );
#else
		free( p );
#endif
		return;
	}

	assert( ber_int_memory_fns->bmf_free );

		
	(*ber_int_memory_fns->bmf_free)( p );
}


void
ber_memvfree( void **vec )
{
	int	i;

	assert(vec != NULL);	/* vec damn better point to something */

	for ( i = 0; vec[i] != NULL; i++ ) {
		LBER_FREE( vec[i] );
	}

	LBER_FREE( vec );
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
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = malloc(s + sizeof(struct ber_mem_hdr));

		if( mh == NULL ) return NULL;

		mh->bm_junk = BER_MEM_JUNK;

		return &mh[1];
#else
		return malloc( s );
#endif
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
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = calloc(1,
			(n * s) + sizeof(struct ber_mem_hdr) );

		mh->bm_junk = BER_MEM_JUNK;
		return &mh[1];
#else
		return calloc( n, s );
#endif
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
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = (struct ber_mem_hdr *)
			((char *)p - sizeof(struct ber_mem_hdr));
		assert( mh->bm_junk == BER_MEM_JUNK );

		p = realloc( mh, s );

		if( p == NULL ) return NULL;

		mh = p;

		return &mh[1];
#else
		return realloc( p, s );
#endif
	}

	assert( ber_int_memory_fns->bmf_realloc );

	return (*ber_int_memory_fns->bmf_realloc)( p, s );
}


void
ber_bvfree( struct berval *bv )
{
	assert(bv != NULL);			/* bv damn better point to something */

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if ( bv->bv_val != NULL )
		LBER_FREE( bv->bv_val );

	LBER_FREE( (char *) bv );
}


void
ber_bvecfree( struct berval **bv )
{
	int	i;

	assert(bv != NULL);			/* bv damn better point to something */

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	for ( i = 0; bv[i] != NULL; i++ )
		ber_bvfree( bv[i] );

	LBER_FREE( (char *) bv );
}


struct berval *
ber_bvdup(
	LDAP_CONST struct berval *bv )
{
	struct berval *new;

	assert( bv != NULL );

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( bv == NULL ) {
		return NULL;
	}


	if(( new = LBER_MALLOC( sizeof(struct berval) )) == NULL ) {
		return NULL;
	}

	if ( bv->bv_val == NULL ) {
		new->bv_val = NULL;
		new->bv_len = 0;
		return new;
	}

	if(( new->bv_val = LBER_MALLOC( bv->bv_len + 1 )) == NULL ) {
		LBER_FREE( new );
		return NULL;
	}

	SAFEMEMCPY( new->bv_val, bv->bv_val, (size_t) bv->bv_len );
	new->bv_val[bv->bv_len] = '\0';
	new->bv_len = bv->bv_len;

	return( new );
}

char *
(ber_strdup)( LDAP_CONST char *s )
{
	char    *p;
	size_t	len = strlen( s ) + 1;

	if ( (p = (char *) LBER_MALLOC( len )) == NULL ) {
		return( NULL );
	}

	SAFEMEMCPY( p, s, len );
	return( p );
}