/* decode.c - ber input decoding routines */
/*
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

#include <stdio.h>
#ifdef MACOS
#include <stdlib.h>
#include <stdarg.h>
#include "macos.h"
#else /* MACOS */
#if defined(NeXT) || defined(VMS)
#include <stdlib.h>
#else /* next || vms */
#include <malloc.h>
#endif /* next || vms */
#if defined(BC31) || defined(_WIN32)
#include <stdarg.h>
#else /* BC31 || _WIN32 */
#include <varargs.h>
#endif /* BC31 || _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef PCNFS
#include <tklib.h>
#endif /* PCNFS */
#endif /* MACOS */

#if defined( DOS ) || defined( _WIN32 )
#include "msdos.h"
#endif /* DOS */

#include <string.h>
#include "lber.h"

#ifdef LDAP_DEBUG
int	lber_debug;
#endif

#ifdef NEEDPROTOS
static int ber_getnint( BerElement *ber, long *num, int len );
#endif /* NEEDPROTOS */


/* return the tag - LBER_DEFAULT returned means trouble */
unsigned long
ber_get_tag( BerElement *ber )
{
	unsigned char	xbyte;
	unsigned long	tag;
	char		*tagp;
	int		i;

	if ( ber_read( ber, (char *) &xbyte, 1 ) != 1 )
		return( LBER_DEFAULT );

	if ( (xbyte & LBER_BIG_TAG_MASK) != LBER_BIG_TAG_MASK )
		return( (unsigned long) xbyte );

	tagp = (char *) &tag;
	tagp[0] = xbyte;
	for ( i = 1; i < sizeof(long); i++ ) {
		if ( ber_read( ber, (char *) &xbyte, 1 ) != 1 )
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

unsigned long
ber_skip_tag( BerElement *ber, unsigned long *len )
{
	unsigned long	tag;
	unsigned char	lc;
	int		noctets, diff;
	unsigned long	netlen;

	/*
	 * Any ber element looks like this: tag length contents.
	 * Assuming everything's ok, we return the tag byte (we
	 * can assume a single byte), and return the length in len.
	 *
	 * Assumptions:
	 *	1) definite lengths
	 *	2) primitive encodings used whenever possible
	 */

	/*
	 * First, we read the tag.
	 */

	if ( (tag = ber_get_tag( ber )) == LBER_DEFAULT )
		return( LBER_DEFAULT );

	/*
	 * Next, read the length.  The first byte contains the length of
	 * the length.  If bit 8 is set, the length is the long form,
	 * otherwise it's the short form.  We don't allow a length that's
	 * greater than what we can hold in an unsigned long.
	 */

	*len = netlen = 0;
	if ( ber_read( ber, (char *) &lc, 1 ) != 1 )
		return( LBER_DEFAULT );
	if ( lc & 0x80 ) {
		noctets = (lc & 0x7f);
		if ( noctets > sizeof(unsigned long) )
			return( LBER_DEFAULT );
		diff = sizeof(unsigned long) - noctets;
		if ( ber_read( ber, (char *) &netlen + diff, noctets )
		    != noctets )
			return( LBER_DEFAULT );
		*len = LBER_NTOHL( netlen );
	} else {
		*len = lc;
	}

	return( tag );
}

unsigned long
ber_peek_tag( BerElement *ber, unsigned long *len )
{
	char		*save;
	unsigned long	tag;

	save = ber->ber_ptr;
	tag = ber_skip_tag( ber, len );
	ber->ber_ptr = save;

	return( tag );
}

static int
ber_getnint( BerElement *ber, long *num, int len )
{
	int	diff, sign, i;
	long	netnum;

	/*
	 * The tag and length have already been stripped off.  We should
	 * be sitting right before len bytes of 2's complement integer,
	 * ready to be read straight into an int.  We may have to sign
	 * extend after we read it in.
	 */

	if ( len > sizeof(long) )
		return( -1 );

	netnum = 0;
	diff = sizeof(long) - len;
	/* read into the low-order bytes of netnum */
	if ( ber_read( ber, ((char *) &netnum) + diff, len ) != len )
		return( -1 );

	/* sign extend if necessary */
	sign = ((0x80 << ((len - 1) * 8)) & netnum);
	if ( sign && len < sizeof(long) ) {
		for ( i = sizeof(long) - 1; i > len - 1; i-- ) {
			netnum |= (0xffL << (i * 8));
		}
	}
	*num = LBER_NTOHL( netnum );

	return( len );
}

unsigned long
ber_get_int( BerElement *ber, long *num )
{
	unsigned long	tag, len;

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT )
		return( LBER_DEFAULT );

	if ( ber_getnint( ber, num, (int)len ) != len )
		return( LBER_DEFAULT );
	else
		return( tag );
}

unsigned long
ber_get_stringb( BerElement *ber, char *buf, unsigned long *len )
{
	unsigned long	datalen, tag;
#ifdef STR_TRANSLATION
	char		*transbuf;
#endif /* STR_TRANSLATION */

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT )
		return( LBER_DEFAULT );
	if ( datalen > (*len - 1) )
		return( LBER_DEFAULT );

	if ( ber_read( ber, buf, datalen ) != datalen )
		return( LBER_DEFAULT );

	buf[datalen] = '\0';

#ifdef STR_TRANSLATION
	if ( datalen > 0 && ( ber->ber_options & LBER_TRANSLATE_STRINGS ) != 0
	    && ber->ber_decode_translate_proc != NULL ) {
		transbuf = buf;
		++datalen;
		if ( (*(ber->ber_decode_translate_proc))( &transbuf, &datalen,
		    0 ) != 0 ) {
			return( LBER_DEFAULT );
		}
		if ( datalen > *len ) {
			free( transbuf );
			return( LBER_DEFAULT );
		}
		SAFEMEMCPY( buf, transbuf, datalen );
		free( transbuf );
		--datalen;
	}
#endif /* STR_TRANSLATION */

	*len = datalen;
	return( tag );
}

unsigned long
ber_get_stringa( BerElement *ber, char **buf )
{
	unsigned long	datalen, tag;

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT )
		return( LBER_DEFAULT );

	if ( (*buf = (char *) malloc( (size_t)datalen + 1 )) == NULL )
		return( LBER_DEFAULT );

	if ( ber_read( ber, *buf, datalen ) != datalen )
		return( LBER_DEFAULT );
	(*buf)[datalen] = '\0';

#ifdef STR_TRANSLATION
	if ( datalen > 0 && ( ber->ber_options & LBER_TRANSLATE_STRINGS ) != 0
	    && ber->ber_decode_translate_proc != NULL ) {
		++datalen;
		if ( (*(ber->ber_decode_translate_proc))( buf, &datalen, 1 )
		    != 0 ) {
			free( *buf );
			return( LBER_DEFAULT );
		}
	}
#endif /* STR_TRANSLATION */

	return( tag );
}

unsigned long
ber_get_stringal( BerElement *ber, struct berval **bv )
{
	unsigned long	len, tag;

	if ( (*bv = (struct berval *) malloc( sizeof(struct berval) )) == NULL )
		return( LBER_DEFAULT );

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT )
		return( LBER_DEFAULT );

	if ( ((*bv)->bv_val = (char *) malloc( (size_t)len + 1 )) == NULL )
		return( LBER_DEFAULT );

	if ( ber_read( ber, (*bv)->bv_val, len ) != len )
		return( LBER_DEFAULT );
	((*bv)->bv_val)[len] = '\0';
	(*bv)->bv_len = len;

#ifdef STR_TRANSLATION
	if ( len > 0 && ( ber->ber_options & LBER_TRANSLATE_STRINGS ) != 0
	    && ber->ber_decode_translate_proc != NULL ) {
		++len;
		if ( (*(ber->ber_decode_translate_proc))( &((*bv)->bv_val),
		    &len, 1 ) != 0 ) {
			free( (*bv)->bv_val );
			return( LBER_DEFAULT );
		}
		(*bv)->bv_len = len - 1;
	}
#endif /* STR_TRANSLATION */

	return( tag );
}

unsigned long
ber_get_bitstringa( BerElement *ber, char **buf, unsigned long *blen )
{
	unsigned long	datalen, tag;
	unsigned char	unusedbits;

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT )
		return( LBER_DEFAULT );
	--datalen;

	if ( (*buf = (char *) malloc( (size_t)datalen )) == NULL )
		return( LBER_DEFAULT );

	if ( ber_read( ber, (char *)&unusedbits, 1 ) != 1 )
		return( LBER_DEFAULT );

	if ( ber_read( ber, *buf, datalen ) != datalen )
		return( LBER_DEFAULT );

	*blen = datalen * 8 - unusedbits;
	return( tag );
}

unsigned long
ber_get_null( BerElement *ber )
{
	unsigned long	len, tag;

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT )
		return( LBER_DEFAULT );

	if ( len != 0 )
		return( LBER_DEFAULT );

	return( tag );
}

unsigned long
ber_get_boolean( BerElement *ber, int *boolval )
{
	long	longbool;
	int	rc;

	rc = ber_get_int( ber, &longbool );
	*boolval = longbool;

	return( rc );
}

unsigned long
ber_first_element( BerElement *ber, unsigned long *len, char **last )
{
	/* skip the sequence header, use the len to mark where to stop */
	if ( ber_skip_tag( ber, len ) == LBER_DEFAULT ) {
		return( LBER_DEFAULT );
	}

	*last = ber->ber_ptr + *len;

	if ( *last == ber->ber_ptr ) {
		return( LBER_DEFAULT );
	}

	return( ber_peek_tag( ber, len ) );
}

unsigned long
ber_next_element( BerElement *ber, unsigned long *len, char *last )
{
	if ( ber->ber_ptr == last ) {
		return( LBER_DEFAULT );
	}

	return( ber_peek_tag( ber, len ) );
}

/* VARARGS */
unsigned long
ber_scanf(
#if defined( MACOS ) || defined( BC31 ) || defined( _WIN32 )
	BerElement *ber, char *fmt, ... )
#else
	va_alist )
va_dcl
#endif
{
	va_list		ap;
#if !defined( MACOS ) && !defined( BC31 ) && !defined( _WIN32 )
	BerElement	*ber;
	char		*fmt;
#endif
	char		*last;
	char		*s, **ss, ***sss;
	struct berval 	***bv, **bvp, *bval;
	int		*i, j;
	long		*l, rc, tag;
	unsigned long	len;

#if defined( MACOS ) || defined( BC31 ) || defined( _WIN32 )
	va_start( ap, fmt );
#else
	va_start( ap );
	ber = va_arg( ap, BerElement * );
	fmt = va_arg( ap, char * );
#endif

#ifdef LDAP_DEBUG
	if ( lber_debug & 64 ) {
		fprintf( stderr, "ber_scanf fmt (%s) ber:\n", fmt );
		ber_dump( ber, 1 );
	}
#endif

	for ( rc = 0; *fmt && rc != LBER_DEFAULT; fmt++ ) {
		switch ( *fmt ) {
		case 'a':	/* octet string - allocate storage as needed */
			ss = va_arg( ap, char ** );
			rc = ber_get_stringa( ber, ss );
			break;

		case 'b':	/* boolean */
			i = va_arg( ap, int * );
			rc = ber_get_boolean( ber, i );
			break;

		case 'e':	/* enumerated */
		case 'i':	/* int */
			l = va_arg( ap, long * );
			rc = ber_get_int( ber, l );
			break;

		case 'l':	/* length of next item */
			l = va_arg( ap, long * );
			rc = ber_peek_tag( ber, (unsigned long *)l );
			break;

		case 'n':	/* null */
			rc = ber_get_null( ber );
			break;

		case 's':	/* octet string - in a buffer */
			s = va_arg( ap, char * );
			l = va_arg( ap, long * );
			rc = ber_get_stringb( ber, s, (unsigned long *)l );
			break;

		case 'o':	/* octet string in a supplied berval */
			bval = va_arg( ap, struct berval * );
			ber_peek_tag( ber, &bval->bv_len );
			rc = ber_get_stringa( ber, &bval->bv_val );
			break;

		case 'O':	/* octet string - allocate & include length */
			bvp = va_arg( ap, struct berval ** );
			rc = ber_get_stringal( ber, bvp );
			break;

		case 'B':	/* bit string - allocate storage as needed */
			ss = va_arg( ap, char ** );
			l = va_arg( ap, long * ); /* for length, in bits */
			rc = ber_get_bitstringa( ber, ss, (unsigned long *)l );
			break;

		case 't':	/* tag of next item */
			i = va_arg( ap, int * );
			*i = rc = ber_peek_tag( ber, &len );
			break;

		case 'T':	/* skip tag of next item */
			i = va_arg( ap, int * );
			*i = rc = ber_skip_tag( ber, &len );
			break;

		case 'v':	/* sequence of strings */
			sss = va_arg( ap, char *** );
			*sss = NULL;
			j = 0;
			for ( tag = ber_first_element( ber, &len, &last );
			    tag != LBER_DEFAULT && rc != LBER_DEFAULT;
			    tag = ber_next_element( ber, &len, last ) ) {
				if ( *sss == NULL ) {
					*sss = (char **) malloc(
					    2 * sizeof(char *) );
				} else {
					*sss = (char **) realloc( *sss,
					    (j + 2) * sizeof(char *) );
				}
				rc = ber_get_stringa( ber, &((*sss)[j]) );
				j++;
			}
			if ( j > 0 )
				(*sss)[j] = NULL;
			break;

		case 'V':	/* sequence of strings + lengths */
			bv = va_arg( ap, struct berval *** );
			*bv = NULL;
			j = 0;
			for ( tag = ber_first_element( ber, &len, &last );
			    tag != LBER_DEFAULT && rc != LBER_DEFAULT;
			    tag = ber_next_element( ber, &len, last ) ) {
				if ( *bv == NULL ) {
					*bv = (struct berval **) malloc(
					    2 * sizeof(struct berval *) );
				} else {
					*bv = (struct berval **) realloc( *bv,
					    (j + 2) * sizeof(struct berval *) );
				}
				rc = ber_get_stringal( ber, &((*bv)[j]) );
				j++;
			}
			if ( j > 0 )
				(*bv)[j] = NULL;
			break;

		case 'x':	/* skip the next element - whatever it is */
			if ( (rc = ber_skip_tag( ber, &len )) == LBER_DEFAULT )
				break;
			ber->ber_ptr += len;
			break;

		case '{':	/* begin sequence */
		case '[':	/* begin set */
			if ( *(fmt + 1) != 'v' && *(fmt + 1) != 'V' )
				rc = ber_skip_tag( ber, &len );
			break;

		case '}':	/* end sequence */
		case ']':	/* end set */
			break;

		default:
#ifndef NO_USERINTERFACE
			fprintf( stderr, "unknown fmt %c\n", *fmt );
#endif /* NO_USERINTERFACE */
			rc = LBER_DEFAULT;
			break;
		}
	}

	va_end( ap );

	return( rc );
}

void
ber_bvfree( struct berval *bv )
{
	if ( bv->bv_val != NULL )
		free( bv->bv_val );
	free( (char *) bv );
}

void
ber_bvecfree( struct berval **bv )
{
	int	i;

	for ( i = 0; bv[i] != NULL; i++ )
		ber_bvfree( bv[i] );
	free( (char *) bv );
}

struct berval *
ber_bvdup( struct berval *bv )
{
	struct berval	*new;

	if ( (new = (struct berval *) malloc( sizeof(struct berval) ))
	    == NULL ) {
		return( NULL );
	}
	if ( (new->bv_val = (char *) malloc( bv->bv_len + 1 )) == NULL ) {
		return( NULL );
	}
	SAFEMEMCPY( new->bv_val, bv->bv_val, (size_t) bv->bv_len );
	new->bv_val[bv->bv_len] = '\0';
	new->bv_len = bv->bv_len;

	return( new );
}


#ifdef STR_TRANSLATION
void
ber_set_string_translators( BerElement *ber, BERTranslateProc encode_proc,
	BERTranslateProc decode_proc )
{
    ber->ber_encode_translate_proc = encode_proc;
    ber->ber_decode_translate_proc = decode_proc;
}
#endif /* STR_TRANSLATION */
