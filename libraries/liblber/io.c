/* io.c - ber general i/o routines */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif

#include "lber-int.h"

static long BerRead LDAP_P(( Sockbuf *sb, char *buf, long len ));
static int ber_realloc LDAP_P(( BerElement *ber, unsigned long len ));

#define EXBUFSIZ	1024

/* probably far too large... */
#define MAX_BERBUFSIZE	(128*1024)

#if defined( DOS ) && !defined( _WIN32 ) && (MAX_BERBUFSIZE > 65535)
# undef MAX_BERBUFSIZE
# define MAX_BERBUFSIZE 65535
#endif

static long
BerRead( Sockbuf *sb, char *buf, long len )
{
	int	c;
	long	nread = 0;

	assert( sb != NULL );
	assert( buf != NULL );

	while ( len > 0 ) {
		if ( (c = ber_pvt_sb_read( sb, buf, len )) <= 0 ) {
			if ( nread > 0 )
				break;
			return( c );
		}
		buf+= c;
		nread+=c;
		len-=c;
	}

	return( nread );
}

long
ber_read( BerElement *ber, char *buf, unsigned long len )
{
	unsigned long	actuallen, nleft;

	assert( ber != NULL );
	assert( buf != NULL );

	nleft = ber->ber_end - ber->ber_ptr;
	actuallen = nleft < len ? nleft : len;

	SAFEMEMCPY( buf, ber->ber_ptr, (size_t)actuallen );

	ber->ber_ptr += actuallen;

	return( (long)actuallen );
}

long
ber_write(
	BerElement *ber,
	LDAP_CONST char *buf,
	unsigned long len,
	int nosos )
{
	assert( ber != NULL );
	assert( buf != NULL );

	if ( nosos || ber->ber_sos == NULL ) {
		if ( ber->ber_ptr + len > ber->ber_end ) {
			if ( ber_realloc( ber, len ) != 0 )
				return( -1 );
		}
		SAFEMEMCPY( ber->ber_ptr, buf, (size_t)len );
		ber->ber_ptr += len;
		return( len );
	} else {
		if ( ber->ber_sos->sos_ptr + len > ber->ber_end ) {
			if ( ber_realloc( ber, len ) != 0 )
				return( -1 );
		}
		SAFEMEMCPY( ber->ber_sos->sos_ptr, buf, (size_t)len );
		ber->ber_sos->sos_ptr += len;
		ber->ber_sos->sos_clen += len;
		return( len );
	}
}

static int
ber_realloc( BerElement *ber, unsigned long len )
{
	unsigned long	need, have, total;
	Seqorset	*s;
	long		off;
	char		*oldbuf;

	assert( ber != NULL );
	assert( len > 0 );

	have = (ber->ber_end - ber->ber_buf) / EXBUFSIZ;
	need = (len < EXBUFSIZ ? 1 : (len + (EXBUFSIZ - 1)) / EXBUFSIZ);
	total = have * EXBUFSIZ + need * EXBUFSIZ;

	oldbuf = ber->ber_buf;

	if ( ber->ber_buf == NULL ) {
		if ( (ber->ber_buf = (char *) malloc( (size_t)total )) == NULL )
			return( -1 );
	} else if ( (ber->ber_buf = (char *) realloc( ber->ber_buf,
	    (size_t)total )) == NULL )
		return( -1 );

	ber->ber_end = ber->ber_buf + total;

	/*
	 * If the stinking thing was moved, we need to go through and
	 * reset all the sos and ber pointers.  Offsets would've been
	 * a better idea... oh well.
	 */

	if ( ber->ber_buf != oldbuf ) {
		ber->ber_ptr = ber->ber_buf + (ber->ber_ptr - oldbuf);

		for ( s = ber->ber_sos; s != NULLSEQORSET; s = s->sos_next ) {
			off = s->sos_first - oldbuf;
			s->sos_first = ber->ber_buf + off;

			off = s->sos_ptr - oldbuf;
			s->sos_ptr = ber->ber_buf + off;
		}
	}

	return( 0 );
}

void
ber_free( BerElement *ber, int freebuf )
{
	assert( ber != NULL );

	if ( freebuf && ber->ber_buf != NULL )
		free( ber->ber_buf );
	ber->ber_buf = NULL;
	free( (char *) ber );
}

int
ber_flush( Sockbuf *sb, BerElement *ber, int freeit )
{
	long	nwritten, towrite, rc;	

	assert( sb != NULL );
	assert( ber != NULL );

	if ( ber->ber_rwptr == NULL ) {
		ber->ber_rwptr = ber->ber_buf;
	}
	towrite = ber->ber_ptr - ber->ber_rwptr;

	if ( sb->sb_debug ) {
		ber_log_printf( LDAP_DEBUG_ANY, sb->sb_debug,
			"ber_flush: %ld bytes to sd %ld%s\n", towrite,
		    (long) sb->sb_sd, ber->ber_rwptr != ber->ber_buf ? " (re-flush)"
		    : "" );
		ber_log_bprint( LDAP_DEBUG_PACKETS, sb->sb_debug,
			ber->ber_rwptr, towrite );
	}

#if !defined(MACOS) && !defined(DOS)
	if ( sb->sb_options & (LBER_TO_FILE | LBER_TO_FILE_ONLY) ) {
		rc = write( sb->sb_fd, ber->ber_rwptr, towrite );
		if ( sb->sb_options & LBER_TO_FILE_ONLY ) {
			return( (int)rc );
		}
	}
#endif
	
	nwritten = 0;
	do {
		rc = ber_pvt_sb_write( sb, ber->ber_rwptr, towrite );
		if (rc<=0) {
			return -1;
		}
		towrite -= rc;
		nwritten += rc;
		ber->ber_rwptr += rc;
	} while ( towrite > 0 );

	if ( freeit )
		ber_free( ber, 1 );

	return( 0 );
}

BerElement *
ber_alloc_t( int options )
{
	BerElement	*ber;

	ber = (BerElement *) calloc( 1, sizeof(BerElement) );

	if ( ber == NULLBER )
		return( NULLBER );

	ber->ber_tag = LBER_DEFAULT;
	ber->ber_options = options;
	ber->ber_debug = ber_int_debug;

	return( ber );
}

BerElement *
ber_alloc( void )
{
	return( ber_alloc_t( 0 ) );
}

BerElement *
der_alloc( void )
{
	return( ber_alloc_t( LBER_USE_DER ) );
}

BerElement *
ber_dup( LDAP_CONST BerElement *ber )
{
	BerElement	*new;

	assert( ber != NULL );

	if ( (new = ber_alloc()) == NULL )
		return( NULL );

	*new = *ber;

	return( new );
}


/* OLD U-Mich ber_init() */
void
ber_init_w_nullc( BerElement *ber, int options )
{
	assert( ber != NULL );

	(void) memset( (char *)ber, '\0', sizeof( BerElement ));
	ber->ber_tag = LBER_DEFAULT;
	ber->ber_options = (char) options;
}

/* New C-API ber_init() */
/* This function constructs a BerElement containing a copy
** of the data in the bv argument.
*/
BerElement *
ber_init( struct berval *bv )
{
	BerElement *ber;

	assert( bv != NULL );

	if ( bv == NULL ) {
		return NULL;
	}

	ber = ber_alloc_t( 0 );

	if( ber == NULLBER ) {
		/* allocation failed */
		return ( NULL );
	}

	/* copy the data */
	if ( ( (unsigned int) ber_write ( ber, bv->bv_val, bv->bv_len, 0 )) != bv->bv_len ) {
		/* write failed, so free and return NULL */
		ber_free( ber, 1 );
		return( NULL );
	}

	ber_reset( ber, 1 );	/* reset the pointer to the start of the buffer */

	return ( ber );
}

/* New C-API ber_flatten routine */
/* This routine allocates a struct berval whose contents are a BER
** encoding taken from the ber argument.  The bvPtr pointer pointers to
** the returned berval.
*/
int ber_flatten(
	LDAP_CONST BerElement *ber,
	struct berval **bvPtr)
{
	struct berval *bv;
 
	assert( bvPtr != NULL );

	if(bvPtr == NULL) {
		return( -1 );
	}

	if ( (bv = malloc( sizeof(struct berval))) == NULL ) {
		return( -1 );
	}

	if ( ber == NULL ) {
		/* ber is null, create an empty berval */
		bv->bv_val = NULL;
		bv->bv_len = 0;

	} else {
		/* copy the berval */
		ptrdiff_t len = ber->ber_ptr - ber->ber_buf;

		if ( (bv->bv_val = (char *) malloc( len + 1 )) == NULL ) {
			ber_bvfree( bv );
			return( -1 );
		}

		SAFEMEMCPY( bv->bv_val, ber->ber_buf, (size_t)len );
		bv->bv_val[len] = '\0';
		bv->bv_len = len;
	}
    
	*bvPtr = bv;
	return( 0 );
}

void
ber_reset( BerElement *ber, int was_writing )
{
	assert( ber != NULL );

	if ( was_writing ) {
		ber->ber_end = ber->ber_ptr;
		ber->ber_ptr = ber->ber_buf;
	} else {
		ber->ber_ptr = ber->ber_end;
	}

	ber->ber_rwptr = NULL;
}

#if 0
/* return the tag - LBER_DEFAULT returned means trouble */
static unsigned long
get_tag( Sockbuf *sb )
{
	unsigned char	xbyte;
	unsigned long	tag;
	char		*tagp;
	unsigned int	i;

	assert( sb != NULL );

	if ( ber_pvt_sb_read( sb, (char *) &xbyte, 1 ) != 1 )
		return( LBER_DEFAULT );

	if ( (xbyte & LBER_BIG_TAG_MASK) != LBER_BIG_TAG_MASK )
		return( (unsigned long) xbyte );

	tagp = (char *) &tag;
	tagp[0] = xbyte;
	for ( i = 1; i < sizeof(long); i++ ) {
		if ( ber_pvt_sb_read( sb, (char *) &xbyte, 1 ) != 1 )
			return( LBER_DEFAULT );

		tagp[i] = xbyte;

		if ( ! (xbyte & LBER_MORE_TAG_MASK) )
			break;
	}

	/* tag too big! */
	if ( i == sizeof(long) )
		return( LBER_DEFAULT );

	/* want leading, not trailing 0's */
	return( tag >> (sizeof(long) - i - 1) );
}
#endif

/*
 * A rewrite of ber_get_next that can safely be called multiple times 
 * for the same packet. It will simply continue were it stopped until
 * a full packet is read.
 */

unsigned long
ber_get_next( Sockbuf *sb, unsigned long *len, BerElement *ber )
{
	assert( sb != NULL );
	assert( len != NULL );
	assert( ber != NULL );

	if ( ber->ber_debug ) {
		ber_log_printf( LDAP_DEBUG_TRACE, ber->ber_debug,
			"ber_get_next\n" );
	}
	
	/*
	 * Any ber element looks like this: tag length contents.
	 * Assuming everything's ok, we return the tag byte (we
	 * can assume a single byte), return the length in len,
	 * and the rest of the undecoded element in buf.
	 *
	 * Assumptions:
	 *	1) small tags (less than 128)
	 *	2) definite lengths
	 *	3) primitive encodings used whenever possible
	 */
	
	if (ber->ber_rwptr == NULL) {
		/* assert( ber->ber_buf == NULL ); */
		ber->ber_rwptr = (char *) &ber->ber_tag;
		ber->ber_tag = 0;
	}

#define PTR_IN_VAR( ptr, var )\
(((ptr)>=(char *) &(var)) && ((ptr)< (char *) &(var)+sizeof(var)))
	
	if (PTR_IN_VAR(ber->ber_rwptr, ber->ber_tag)) {
		if (ber->ber_rwptr == (char *) &ber->ber_tag) {
			if (ber_pvt_sb_read( sb, ber->ber_rwptr, 1)<=0)
				return LBER_DEFAULT;
			if ((ber->ber_rwptr[0] & LBER_BIG_TAG_MASK)
				!= LBER_BIG_TAG_MASK) {
				ber->ber_tag = ber->ber_rwptr[0];
				ber->ber_rwptr = (char *) &ber->ber_usertag;
				goto get_lenbyte;
			}
			ber->ber_rwptr++;
		}
		do {
			/* reading the tag... */
			if (ber_pvt_sb_read( sb, ber->ber_rwptr, 1)<=0)
				return LBER_DEFAULT;
			if (! (ber->ber_rwptr[0] & LBER_MORE_TAG_MASK) ) {
				ber->ber_tag>>=sizeof(ber->ber_tag) -
				  ((char *) &ber->ber_tag - ber->ber_rwptr);
				ber->ber_rwptr = (char *) &ber->ber_usertag;
				goto get_lenbyte;
			}
		} while (PTR_IN_VAR(ber->ber_rwptr,ber->ber_tag));
		errno = ERANGE; /* this is a serious error. */
		return LBER_DEFAULT;
	}
get_lenbyte:
	if (ber->ber_rwptr==(char *) &ber->ber_usertag) {
		unsigned char c;
		if (ber_pvt_sb_read( sb, (char *) &c, 1)<=0)
			return LBER_DEFAULT;
		if (c & 0x80U) {
			int len = c & 0x7fU;
			if ( (len==0) || ((unsigned) len>sizeof( ber->ber_len ) ) ) {
				errno = ERANGE;
				return LBER_DEFAULT;
			}
			ber->ber_rwptr = (char *) &ber->ber_len +
				sizeof(ber->ber_len) - len;
			ber->ber_len = 0;
		} else {
			ber->ber_len = c;
			goto fill_buffer;
		}
	}
	if (PTR_IN_VAR(ber->ber_rwptr, ber->ber_len)) {
		int res;
		int to_go;
		to_go = (char *) &ber->ber_len + sizeof( ber->ber_len ) -
			ber->ber_rwptr;
		assert( to_go > 0 );
		res = ber_pvt_sb_read( sb, ber->ber_rwptr, to_go );
		if (res <=0)
			return LBER_DEFAULT;
		ber->ber_rwptr += res;
		if (res==to_go) {
			/* convert length. */
			ber->ber_len = AC_NTOHL( ber->ber_len );
			goto fill_buffer;
		} else {
#if defined( EWOULDBLOCK )
			errno = EWOULDBLOCK;
#elif defined( EAGAIN )
			errno = EAGAIN;
#endif			
			return LBER_DEFAULT;
		}
	}
fill_buffer:	
	/* now fill the buffer. */
	if (ber->ber_buf==NULL) {
		if (ber->ber_len > MAX_BERBUFSIZE) {
			errno = ERANGE;
			return LBER_DEFAULT;
		}
		ber->ber_buf = (char *) malloc( ber->ber_len );
		if (ber->ber_buf==NULL)
			return LBER_DEFAULT;
		ber->ber_rwptr = ber->ber_buf;
		ber->ber_ptr = ber->ber_buf;
		ber->ber_end = ber->ber_buf + ber->ber_len;
	}
	if ((ber->ber_rwptr>=ber->ber_buf) && (ber->ber_rwptr<ber->ber_end)) {
		int res;
		int to_go;
		
		to_go = ber->ber_end - ber->ber_rwptr;
		assert( to_go > 0 );
		
		res = ber_pvt_sb_read( sb, ber->ber_rwptr, to_go );
		if (res<=0)
			return LBER_DEFAULT;
		ber->ber_rwptr+=res;
		
		if (res<to_go) {
#if defined( EWOULDBLOCK )
			errno = EWOULDBLOCK;
#elif defined( EAGAIN )
			errno = EAGAIN;
#endif			
			return LBER_DEFAULT;
		}
		
		ber->ber_rwptr = NULL;
		*len = ber->ber_len;
		if ( ber->ber_debug ) {
			ber_log_printf( LDAP_DEBUG_TRACE, ber->ber_debug,
				"ber_get_next: tag 0x%lx len %ld contents:\n",
				ber->ber_tag, ber->ber_len );
			ber_log_dump( LDAP_DEBUG_BER, ber->ber_debug, ber, 1 );
		}
		return (ber->ber_tag);
	}
	assert( 0 ); /* ber structure is messed up ?*/
	return LBER_DEFAULT;
}

void	ber_clear( BerElement *ber, int freebuf )
{
	assert( ber != NULL );

	if ((freebuf) && (ber->ber_buf))
		free( ber->ber_buf );
	ber->ber_buf = NULL;
	ber->ber_rwptr = NULL;
	ber->ber_end = NULL;
}

