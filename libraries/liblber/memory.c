/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>

#include "lber-int.h"

#ifdef LDAP_MEMORY_TRACE
# ifndef LDAP_MEMORY_DEBUG
#  define LDAP_MEMORY_DEBUG 1
# endif
#include <stdio.h>
#endif

#if LDAP_MEMORY_DEBUG
/*
 * LDAP_MEMORY_DEBUG should only be enabled for the purposes of
 * debugging memory management within OpenLDAP libraries and slapd.
 * It should only be enabled by an experienced developer as it
 * causes the inclusion of numerous assert()'s, many of which may
 * be triggered by a prefectly valid program.
 *
 * The code behind this macro is subject to change as needed to
 * support this testing.
 */

struct ber_mem_hdr {
	ber_int_t	bm_top;	/* Pattern to detect buf overrun from prev buffer */
	ber_int_t	bm_length; /* Length of user allocated area */
#ifdef LDAP_MEMORY_TRACE
	ber_int_t	bm_sequence; /* Allocation sequence number */
#endif
	union bmu_align_u {	/* Force alignment, pattern to detect back clobber */
		ber_len_t	bmu_len_t;
		ber_tag_t	bmu_tag_t;
		ber_int_t	bmu_int_t;

		size_t	bmu_size_t;
		void *	bmu_voidp;
		double	bmu_double;
		long	bmu_long;
		long	(*bmu_funcp)( double );
		unsigned char	bmu_char[4];
	} ber_align;
#define bm_junk	ber_align.bmu_len_t
#define bm_data	ber_align.bmu_char[1]
#define bm_char	ber_align.bmu_char
};

/* Pattern at top of allocated space */
#define BER_MEM_JUNK 0xdeaddadaU

static const struct ber_mem_hdr ber_int_mem_hdr = { BER_MEM_JUNK, 0, 0 };

/* Note sequence and ber_int_options.lbu_meminuse are counters, but are not
 * thread safe.  If you want to use these values for multithreaded applications,
 * you must put mutexes around them, otherwise they will have incorrect values.
 * When debugging, if you sort the debug output, the sequence number will 
 * put allocations/frees together.  It is then a simple matter to write a script
 * to find any allocations that don't have a buffer free function.
 */
#ifdef LDAP_MEMORY_TRACE
static ber_int_t sequence = 0;
#endif

/* Pattern placed just before user data */
static unsigned char toppattern[4] = { 0xde, 0xad, 0xba, 0xde };
/* Pattern placed just after user data */
static unsigned char endpattern[4] = { 0xd1, 0xed, 0xde, 0xca };

#define mbu_len sizeof(ber_int_mem_hdr.ber_align)

/* Test if pattern placed just before user data is good */
#define testdatatop(val) ( \
	*(val->bm_char+mbu_len-4)==toppattern[0] && \
	*(val->bm_char+mbu_len-3)==toppattern[1] && \
	*(val->bm_char+mbu_len-2)==toppattern[2] && \
	*(val->bm_char+mbu_len-1)==toppattern[3] )

/* Place pattern just before user data */
#define setdatatop(val)	*(val->bm_char+mbu_len-4)=toppattern[0]; \
	*(val->bm_char+mbu_len-3)=toppattern[1]; \
	*(val->bm_char+mbu_len-2)=toppattern[2]; \
	*(val->bm_char+mbu_len-1)=toppattern[3];

/* Test if pattern placed just after user data is good */
#define testend(val) ( 	*((unsigned char *)val+0)==endpattern[0] && \
	*((unsigned char *)val+1)==endpattern[1] && \
	*((unsigned char *)val+2)==endpattern[2] && \
	*((unsigned char *)val+3)==endpattern[3] )

/* Place pattern just after user data */
#define setend(val)  	*((unsigned char *)val+0)=endpattern[0]; \
	*((unsigned char *)val+1)=endpattern[1]; \
	*((unsigned char *)val+2)=endpattern[2]; \
	*((unsigned char *)val+3)=endpattern[3];

#define BER_MEM_BADADDR	((void *) &ber_int_mem_hdr.bm_data)
#define BER_MEM_VALID(p)	do { \
		assert( (p) != BER_MEM_BADADDR );	\
		assert( (p) != (void *) &ber_int_mem_hdr );	\
	} while(0)

#else
#define BER_MEM_VALID(p)	/* no-op */
#endif

BerMemoryFunctions *ber_int_memory_fns = NULL;

#if 0 && defined( LDAP_MEMORY_DEBUG )
void
ber_int_memfree( void **p )
{
	assert( p != NULL );
	BER_MEM_VALID( *p );

	ber_memfree( p );

	*p = BER_MEM_BADADDR;
}
#endif

void
ber_memfree( void *p )
{
    ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( p == NULL ) {
		return;
	}

	BER_MEM_VALID( p );

	if( ber_int_memory_fns == NULL ) {
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = (struct ber_mem_hdr *)
			((char *)p - sizeof(struct ber_mem_hdr));
		assert( mh->bm_top == BER_MEM_JUNK);
		assert( testdatatop( mh));
		assert( testend( (char *)&mh[1] + mh->bm_length) );
		ber_int_options.lbo_meminuse -= mh->bm_length;

#ifdef LDAP_MEMORY_TRACE
		fprintf(stderr, "0x%08x 0x%08x -f- %d ber_memfree %d\n",
			mh->bm_sequence, mh, mh->bm_length, ber_int_options.lbo_meminuse);
#endif
		/* Fill the free space with poison */
		memset( mh, 0xff, mh->bm_length + sizeof(struct ber_mem_hdr) + sizeof(ber_int_t));
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

    ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( vec == NULL ) {
		return;
	}

	BER_MEM_VALID( vec );

	for ( i = 0; vec[i] != NULL; i++ ) {
		LBER_FREE( vec[i] );
	}

	LBER_FREE( vec );
}


void *
ber_memalloc( ber_len_t s )
{
	void *new;
    ber_int_options.lbo_valid = LBER_INITIALIZED;

#ifdef LDAP_MEMORY_DEBUG
	assert( s != 0 );
#endif

	if( s == 0 ) {
		return NULL;
	}

	if( ber_int_memory_fns == NULL ) {
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = malloc(s + sizeof(struct ber_mem_hdr) + sizeof( ber_int_t));
		if( mh == NULL ) return NULL;

		mh->bm_top = BER_MEM_JUNK;
		mh->bm_length = s;
		setdatatop( mh);
		setend( (char *)&mh[1] + mh->bm_length );

		ber_int_options.lbo_meminuse += mh->bm_length;	/* Count mem inuse */

#ifdef LDAP_MEMORY_TRACE
		mh->bm_sequence = sequence++;
		fprintf(stderr, "0x%08x 0x%08x -a- %d ber_memalloc %d\n",
			mh->bm_sequence, mh, mh->bm_length, ber_int_options.lbo_meminuse);
#endif
		/* poison new memory */
		memset( (char *)&mh[1], 0xff, s);

		BER_MEM_VALID( &mh[1] );
		new = &mh[1];
#else
		new = malloc( s );
#endif
	} else {
		new = (*ber_int_memory_fns->bmf_malloc)( s );
	}

	if( new == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
	}

	return new;
}


void *
ber_memcalloc( ber_len_t n, ber_len_t s )
{
	void *new;
    ber_int_options.lbo_valid = LBER_INITIALIZED;

#ifdef LDAP_MEMORY_DEBUG
	assert( n != 0 && s != 0);
#endif

	if( n == 0 || s == 0 ) {
		return NULL;
	}

	if( ber_int_memory_fns == NULL ) {
#ifdef LDAP_MEMORY_DEBUG
		struct ber_mem_hdr *mh = calloc(1,
			(n * s) + sizeof(struct ber_mem_hdr) + sizeof(ber_int_t) );
		if( mh == NULL ) return NULL;

		mh->bm_top = BER_MEM_JUNK;
		mh->bm_length = n*s;
		setdatatop( mh);
		setend( (char *)&mh[1] + mh->bm_length );

		ber_int_options.lbo_meminuse += mh->bm_length;

#ifdef LDAP_MEMORY_TRACE
		mh->bm_sequence = sequence++;
		fprintf(stderr, "0x%08x 0x%08x -a- %d ber_memcalloc %d\n",
			mh->bm_sequence, mh, mh->bm_length, ber_int_options.lbo_meminuse);
#endif
		BER_MEM_VALID( &mh[1] );
		new = &mh[1];
#else
		new = calloc( n, s );
#endif

	} else {
		new = (*ber_int_memory_fns->bmf_calloc)( n, s );
	}

	if( new == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
	}

	return new;
}


void *
ber_memrealloc( void* p, ber_len_t s )
{
	void *new = NULL;
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

	BER_MEM_VALID( p );

	if( ber_int_memory_fns == NULL ) {
#ifdef LDAP_MEMORY_DEBUG
		ber_int_t oldlen;
		struct ber_mem_hdr *mh = (struct ber_mem_hdr *)
			((char *)p - sizeof(struct ber_mem_hdr));
		assert( mh->bm_top == BER_MEM_JUNK);
		assert( testdatatop( mh));
		assert( testend( (char *)&mh[1] + mh->bm_length) );
		oldlen = mh->bm_length;

		p = realloc( mh, s + sizeof(struct ber_mem_hdr) + sizeof(ber_int_t) );
		if( p == NULL ) {
			ber_errno = LBER_ERROR_MEMORY;
			return NULL;
		}

			mh = p;
		mh->bm_length = s;
		setend( (char *)&mh[1] + mh->bm_length );
		if( (s - oldlen) > 0 ) {
			/* poison any new memory */
			memset( (char *)&mh[1] + oldlen, 0xff, s - oldlen);
		}

		assert( mh->bm_top == BER_MEM_JUNK);
		assert( testdatatop( mh));

		ber_int_options.lbo_meminuse += s - oldlen;
#ifdef LDAP_MEMORY_TRACE
		fprintf(stderr, "0x%08x 0x%08x -a- %d ber_memrealloc %d\n",
			mh->bm_sequence, mh, mh->bm_length, ber_int_options.lbo_meminuse);
#endif
			BER_MEM_VALID( &mh[1] );
		return &mh[1];
#else
		new = realloc( p, s );
#endif
	} else {
		new = (*ber_int_memory_fns->bmf_realloc)( p, s );
	}

	if( new == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
	}

	return new;
}


void
ber_bvfree( struct berval *bv )
{
	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( bv == NULL ) {
		return;
	}

	BER_MEM_VALID( bv );

	if ( bv->bv_val != NULL ) {
		LBER_FREE( bv->bv_val );
	}

	LBER_FREE( (char *) bv );
}


void
ber_bvecfree( struct berval **bv )
{
	int	i;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( bv == NULL ) {
		return;
	}

	BER_MEM_VALID( bv );

	for ( i = 0; bv[i] != NULL; i++ ) {
		ber_bvfree( bv[i] );
	}

	LBER_FREE( (char *) bv );
}

int
ber_bvecadd( struct berval ***bvec, struct berval *bv )
{
	ber_len_t i;
	struct berval **new;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( bvec == NULL ) {
		if( bv == NULL ) {
			/* nothing to add */
			return 0;
		}

		*bvec = ber_memalloc( 2 * sizeof(struct berval *) );

		if( *bvec == NULL ) {
			return -1;
		}

		(*bvec)[0] = bv;
		(*bvec)[1] = NULL;

		return 1;
	}

	BER_MEM_VALID( bvec );

	/* count entries */
	for ( i = 0; bvec[i] != NULL; i++ ) {
		/* EMPTY */;
	}

	if( bv == NULL ) {
		return i;
	}

	new = ber_memrealloc( *bvec, (i+2) * sizeof(struct berval *));

	if( new == NULL ) {
		return -1;
	}

	*bvec = new;

	(*bvec)[i++] = bv;
	(*bvec)[i] = NULL;

	return i;
}


struct berval *
ber_bvdup(
	LDAP_CONST struct berval *bv )
{
	struct berval *new;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( bv == NULL ) {
		ber_errno = LBER_ERROR_PARAM;
		return NULL;
	}

	if(( new = LBER_MALLOC( sizeof(struct berval) )) == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
		return NULL;
	}

	if ( bv->bv_val == NULL ) {
		new->bv_val = NULL;
		new->bv_len = 0;
		return new;
	}

	if(( new->bv_val = LBER_MALLOC( bv->bv_len + 1 )) == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
		LBER_FREE( new );
		return NULL;
	}

	AC_MEMCPY( new->bv_val, bv->bv_val, bv->bv_len );
	new->bv_val[bv->bv_len] = '\0';
	new->bv_len = bv->bv_len;

	return new;
}

struct berval *
ber_bvstr(
	LDAP_CONST char *s )
{
	struct berval *new;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( s == NULL ) {
		ber_errno = LBER_ERROR_PARAM;
		return NULL;
	}

	if(( new = LBER_MALLOC( sizeof(struct berval) )) == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
		return NULL;
	}

	new->bv_val = (char *) s;
	new->bv_len = strlen( s );

	return( new );
}

struct berval *
ber_bvstrdup(
	LDAP_CONST char *s )
{
	struct berval *new;
	char *p;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	if( s == NULL ) {
		ber_errno = LBER_ERROR_PARAM;
		return NULL;
	}

	p = LBER_STRDUP( s );

	if( p == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
		return NULL;
	}

	new = ber_bvstr( p );

	if( new == NULL || *p == '\0' ) {
		LBER_FREE( p );
	}

	return new;
}

char *
ber_strdup( LDAP_CONST char *s )
{
	char    *p;
	size_t	len;
	
	ber_int_options.lbo_valid = LBER_INITIALIZED;

#ifdef LDAP_MEMORY_DEBUG
	assert(s != NULL);			/* bv damn better point to something */
#endif

	if( s == NULL ) {
		ber_errno = LBER_ERROR_PARAM;
		return NULL;
	}

	len = strlen( s ) + 1;

	if ( (p = LBER_MALLOC( len )) == NULL ) {
		ber_errno = LBER_ERROR_MEMORY;
		return NULL;
	}

	AC_MEMCPY( p, s, len );
	return p;
}
