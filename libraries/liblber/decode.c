/* decode.c - ber input decoding routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ac/stdlib.h>

#include <ac/stdarg.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "lber-int.h"

static ber_len_t ber_getnint LDAP_P((
	BerElement *ber,
	ber_int_t *num,
	ber_len_t len ));

/* return the tag - LBER_DEFAULT returned means trouble */
ber_tag_t
ber_get_tag( BerElement *ber )
{
	unsigned char	xbyte;
	ber_tag_t	tag;
	unsigned int	i;

	assert( ber != NULL );
	assert( BER_VALID( ber ) );

	if ( ber_read( ber, (char *) &xbyte, 1 ) != 1 ) {
		return LBER_DEFAULT;
	}

	tag = xbyte;

	if ( (xbyte & LBER_BIG_TAG_MASK) != LBER_BIG_TAG_MASK ) {
		return tag;
	}

	for ( i = 1; i < sizeof(ber_tag_t); i++ ) {
		if ( ber_read( ber, (char *) &xbyte, 1 ) != 1 ) {
			return LBER_DEFAULT;
		}

		tag <<= 8;
		tag |= 0x00ffUL & (ber_tag_t) xbyte;

		if ( ! (xbyte & LBER_MORE_TAG_MASK) ) {
			break;
		}
	}

	/* tag too big! */
	if ( i == sizeof(ber_tag_t) ) {
		return LBER_DEFAULT;
	}

	return tag;
}

ber_tag_t
ber_skip_tag( BerElement *ber, ber_len_t *len )
{
	ber_tag_t	tag;
	unsigned char	lc;
	ber_len_t	i, noctets;
	unsigned char netlen[sizeof(ber_len_t)];

	assert( ber != NULL );
	assert( len != NULL );
	assert( BER_VALID( ber ) );

	/*
	 * Any ber element looks like this: tag length contents.
	 * Assuming everything's ok, we return the tag byte (we
	 * can assume a single byte), and return the length in len.
	 *
	 * Assumptions:
	 *	1) definite lengths
	 *	2) primitive encodings used whenever possible
	 */

	*len = 0;

	/*
	 * First, we read the tag.
	 */

	if ( (tag = ber_get_tag( ber )) == LBER_DEFAULT ) {
		return LBER_DEFAULT;
	}

	/*
	 * Next, read the length.  The first byte contains the length of
	 * the length.	If bit 8 is set, the length is the long form,
	 * otherwise it's the short form.  We don't allow a length that's
	 * greater than what we can hold in a ber_len_t.
	 */

	if ( ber_read( ber, (char *) &lc, 1 ) != 1 )
		return LBER_DEFAULT;

	if ( lc & 0x80U ) {
		noctets = (lc & 0x7fU);

		if ( noctets > sizeof(ber_len_t) ) {
			return LBER_DEFAULT;
		}

		if( (unsigned) ber_read( ber, netlen, noctets ) != noctets ) {
			return LBER_DEFAULT;
		}

		for( i = 0; i < noctets; i++ ) {
			*len <<= 8;
			*len |= netlen[i];
		}

	} else {
		*len = lc;
	}

	return tag;
}

ber_tag_t
ber_peek_tag(
	BerElement *ber,
	ber_len_t *len )
{
	/*
	 * This implementation assumes ber_skip_tag() only
	 * modifies ber_ptr field of the BerElement.
	 */

	char *save;
	ber_tag_t	tag;

	save = ber->ber_ptr;
	tag = ber_skip_tag( ber, len );
	ber->ber_ptr = save;

	return tag;
}

static ber_len_t
ber_getnint(
	BerElement *ber,
	ber_int_t *num,
	ber_len_t len )
{
	unsigned char buf[sizeof(ber_int_t)];

	assert( ber != NULL );
	assert( num != NULL );
	assert( BER_VALID( ber ) );

	/*
	 * The tag and length have already been stripped off.  We should
	 * be sitting right before len bytes of 2's complement integer,
	 * ready to be read straight into an int.  We may have to sign
	 * extend after we read it in.
	 */

	if ( len > sizeof(ber_int_t) ) {
		return -1;
	}

	/* read into the low-order bytes of our buffer */
	if ( (ber_len_t) ber_read( ber, (char *) buf, len ) != len ) {
		return -1;
	}

	if( len ) {
		/* sign extend if necessary */
		ber_len_t i;
		ber_int_t netnum = 0x80 & buf[0] ? -1 : 0;

		/* shift in the bytes */
		for( i=0 ; i<len; i++ ) {
			netnum = (netnum << 8 ) | buf[i];
		}

		*num = netnum;

	} else {
		*num = 0;
	}

	return len;
}

ber_tag_t
ber_get_int(
	BerElement *ber,
	ber_int_t *num )
{
	ber_tag_t	tag;
	ber_len_t	len;

	assert( ber != NULL );
	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT ) {
		return LBER_DEFAULT;
	}

	if ( ber_getnint( ber, num, len ) != len ) {
		return LBER_DEFAULT;
	}
	
	return tag;
}

ber_tag_t
ber_get_enum(
	BerElement *ber,
	ber_int_t *num )
{
	return ber_get_int( ber, num );
}

ber_tag_t
ber_get_stringb(
	BerElement *ber,
	char *buf,
	ber_len_t *len )
{
	ber_len_t	datalen;
	ber_tag_t	tag;

	assert( ber != NULL );
	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT ) {
		return LBER_DEFAULT;
	}
	if ( datalen > (*len - 1) ) {
		return LBER_DEFAULT;
	}

	if ( (ber_len_t) ber_read( ber, buf, datalen ) != datalen ) {
		return LBER_DEFAULT;
	}

	buf[datalen] = '\0';

	*len = datalen;
	return tag;
}

ber_tag_t
ber_get_stringa( BerElement *ber, char **buf )
{
	ber_len_t	datalen;
	ber_tag_t	tag;

	assert( ber != NULL );
	assert( buf != NULL );

	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT ) {
		*buf = NULL;
		return LBER_DEFAULT;
	}

	if ( (*buf = (char *) LBER_MALLOC( datalen + 1 )) == NULL ) {
		return LBER_DEFAULT;
	}

	if ( (ber_len_t) ber_read( ber, *buf, datalen ) != datalen ) {
		LBER_FREE( *buf );
		*buf = NULL;
		return LBER_DEFAULT;
	}
	(*buf)[datalen] = '\0';

	return tag;
}

ber_tag_t
ber_get_stringal( BerElement *ber, struct berval **bv )
{
	ber_len_t	len;
	ber_tag_t	tag;

	assert( ber != NULL );
	assert( bv != NULL );

	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT ) {
		*bv = NULL;
		return LBER_DEFAULT;
	}

	*bv = (struct berval *) LBER_MALLOC( sizeof(struct berval) );
	if ( *bv == NULL ) {
		return LBER_DEFAULT;
	}

	if( len == 0 ) {
		(*bv)->bv_val = NULL;
		(*bv)->bv_len = 0;
		return tag;
	}

	(*bv)->bv_val = (char *) LBER_MALLOC( len + 1 );
	if ( (*bv)->bv_val == NULL ) {
		LBER_FREE( *bv );
		*bv = NULL;
		return LBER_DEFAULT;
	}

	if ( (ber_len_t) ber_read( ber, (*bv)->bv_val, len ) != len ) {
		ber_bvfree( *bv );
		*bv = NULL;
		return LBER_DEFAULT;
	}

	((*bv)->bv_val)[len] = '\0';
	(*bv)->bv_len = len;

	return tag;
}

ber_tag_t
ber_get_bitstringa(
	BerElement *ber,
	char **buf,
	ber_len_t *blen )
{
	ber_len_t	datalen;
	ber_tag_t	tag;
	unsigned char	unusedbits;

	assert( ber != NULL );
	assert( buf != NULL );
	assert( blen != NULL );

	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &datalen )) == LBER_DEFAULT ) {
		*buf = NULL;
		return LBER_DEFAULT;
	}
	--datalen;

	if ( (*buf = (char *) LBER_MALLOC( datalen )) == NULL ) {
		return LBER_DEFAULT;
	}

	if ( ber_read( ber, (char *)&unusedbits, 1 ) != 1 ) {
		LBER_FREE( buf );
		*buf = NULL;
		return LBER_DEFAULT;
	}

	if ( (ber_len_t) ber_read( ber, *buf, datalen ) != datalen ) {
		LBER_FREE( buf );
		*buf = NULL;
		return LBER_DEFAULT;
	}

	*blen = datalen * 8 - unusedbits;
	return tag;
}

ber_tag_t
ber_get_null( BerElement *ber )
{
	ber_len_t	len;
	ber_tag_t	tag;

	assert( ber != NULL );
	assert( BER_VALID( ber ) );

	if ( (tag = ber_skip_tag( ber, &len )) == LBER_DEFAULT ) {
		return LBER_DEFAULT;
	}

	if ( len != 0 ) {
		return LBER_DEFAULT;
	}

	return( tag );
}

ber_tag_t
ber_get_boolean(
	BerElement *ber,
	ber_int_t *boolval )
{
	ber_int_t	longbool;
	ber_tag_t	rc;

	assert( ber != NULL );
	assert( boolval != NULL );

	assert( BER_VALID( ber ) );

	rc = ber_get_int( ber, &longbool );
	*boolval = longbool;

	return rc;
}

ber_tag_t
ber_first_element(
	BerElement *ber,
	ber_len_t *len,
	char **last )
{
	assert( ber != NULL );
	assert( len != NULL );
	assert( last != NULL );

	/* skip the sequence header, use the len to mark where to stop */
	if ( ber_skip_tag( ber, len ) == LBER_DEFAULT ) {
		*last = NULL;
		return LBER_DEFAULT;
	}

	*last = ber->ber_ptr + *len;

	if ( *last == ber->ber_ptr ) {
		return LBER_DEFAULT;
	}

	return ber_peek_tag( ber, len );
}

ber_tag_t
ber_next_element(
	BerElement *ber,
	ber_len_t *len,
	LDAP_CONST char *last )
{
	assert( ber != NULL );
	assert( len != NULL );
	assert( last != NULL );

	assert( BER_VALID( ber ) );

	if ( ber->ber_ptr == last ) {
		return LBER_DEFAULT;
	}

	return ber_peek_tag( ber, len );
}

/* VARARGS */
ber_tag_t
ber_scanf ( BerElement *ber,
	LDAP_CONST char *fmt,
	... )
{
	va_list		ap;
	LDAP_CONST char		*fmt_reset;
	char		*last;
	char		*s, **ss, ***sss;
	struct berval	***bv, **bvp, *bval;
	ber_int_t	*i;
	int j;
	ber_len_t	*l;
	ber_tag_t	*t;
	ber_tag_t	rc, tag;
	ber_len_t	len;

	va_start( ap, fmt );

	assert( ber != NULL );
	assert( fmt != NULL );

	assert( BER_VALID( ber ) );

	fmt_reset = fmt;

#ifdef NEW_LOGGING
	LDAP_LOG(( "liblber", LDAP_LEVEL_ENTRY, "ber_scanf fmt (%s) ber:\n", fmt ));
	BER_DUMP(( "liblber", LDAP_LEVEL_DETAIL2, ber, 1 ));
#else
	ber_log_printf( LDAP_DEBUG_TRACE, ber->ber_debug,
		"ber_scanf fmt (%s) ber:\n", fmt );
	ber_log_dump( LDAP_DEBUG_BER, ber->ber_debug, ber, 1 );
#endif

	for ( rc = 0; *fmt && rc != LBER_DEFAULT; fmt++ ) {
		/* When this is modified, remember to update
		 * the error-cleanup code below accordingly. */
		switch ( *fmt ) {
		case '!': { /* Hook */
				BERDecodeCallback *f;
				void *p;

				f = va_arg( ap, BERDecodeCallback * );
				p = va_arg( ap, void * );

				rc = (*f)( ber, p, 0 );
			} break;

		case 'a':	/* octet string - allocate storage as needed */
			ss = va_arg( ap, char ** );
			rc = ber_get_stringa( ber, ss );
			break;

		case 'b':	/* boolean */
			i = va_arg( ap, ber_int_t * );
			rc = ber_get_boolean( ber, i );
			break;

		case 'e':	/* enumerated */
		case 'i':	/* int */
			i = va_arg( ap, ber_int_t * );
			rc = ber_get_int( ber, i );
			break;

		case 'l':	/* length of next item */
			l = va_arg( ap, ber_len_t * );
			rc = ber_peek_tag( ber, l );
			break;

		case 'n':	/* null */
			rc = ber_get_null( ber );
			break;

		case 's':	/* octet string - in a buffer */
			s = va_arg( ap, char * );
			l = va_arg( ap, ber_len_t * );
			rc = ber_get_stringb( ber, s, l );
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
			l = va_arg( ap, ber_len_t * ); /* for length, in bits */
			rc = ber_get_bitstringa( ber, ss, l );
			break;

		case 't':	/* tag of next item */
			t = va_arg( ap, ber_tag_t * );
			*t = rc = ber_peek_tag( ber, &len );
			break;

		case 'T':	/* skip tag of next item */
			t = va_arg( ap, ber_tag_t * );
			*t = rc = ber_skip_tag( ber, &len );
			break;

		case 'v':	/* sequence of strings */
			sss = va_arg( ap, char *** );
			*sss = NULL;
			j = 0;
			for ( tag = ber_first_element( ber, &len, &last );
			    tag != LBER_DEFAULT && rc != LBER_DEFAULT;
			    tag = ber_next_element( ber, &len, last ) )
			{
				*sss = (char **) LBER_REALLOC( *sss,
					(j + 2) * sizeof(char *) );

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
			    tag = ber_next_element( ber, &len, last ) )
			{
				*bv = (struct berval **) LBER_REALLOC( *bv,
					(j + 2) * sizeof(struct berval *) );
		
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
			if( ber->ber_debug ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "liblber", LDAP_LEVEL_ERR,
					   "ber_scanf: unknown fmt %c\n", *fmt ));
#else
				ber_log_printf( LDAP_DEBUG_ANY, ber->ber_debug,
					"ber_scanf: unknown fmt %c\n", *fmt );
#endif
			}
			rc = LBER_DEFAULT;
			break;
		}
	}

	va_end( ap );

	if ( rc == LBER_DEFAULT ) {
	    /*
	     * Error.  Reclaim malloced memory that was given to the caller.
	     * Set allocated pointers to NULL, "data length" outvalues to 0.
	     */
	    va_start( ap, fmt );

	    for ( ; fmt_reset < fmt; fmt_reset++ ) {
		switch ( *fmt_reset ) {
		case '!': { /* Hook */
				BERDecodeCallback *f;
				void *p;

				f = va_arg( ap, BERDecodeCallback * );
				p = va_arg( ap, void * );

				(void) (*f)( ber, p, 1 );
			} break;

		case 'a':	/* octet string - allocate storage as needed */
			ss = va_arg( ap, char ** );
			if ( *ss ) {
				LBER_FREE( *ss );
				*ss = NULL;
			}
			break;

		case 'b':	/* boolean */
		case 'e':	/* enumerated */
		case 'i':	/* int */
			(void) va_arg( ap, int * );
			break;

		case 's':	/* octet string - in a buffer */
			(void) va_arg( ap, char * );
			(void) va_arg( ap, ber_len_t * );
			break;

		case 'l':	/* length of next item */
			(void) va_arg( ap, ber_len_t * );
			break;

		case 't':	/* tag of next item */
		case 'T':	/* skip tag of next item */
			(void) va_arg( ap, ber_tag_t * );
			break;

		case 'o':	/* octet string in a supplied berval */
			bval = va_arg( ap, struct berval * );
			if ( bval->bv_val != NULL ) {
				LBER_FREE( bval->bv_val );
				bval->bv_val = NULL;
			}
			bval->bv_len = 0;
			break;

		case 'O':	/* octet string - allocate & include length */
			bvp = va_arg( ap, struct berval ** );
			if ( *bvp ) {
				ber_bvfree( *bvp );
				*bvp = NULL;
			}
			break;

		case 'B':	/* bit string - allocate storage as needed */
			ss = va_arg( ap, char ** );
			if ( *ss ) {
				LBER_FREE( *ss );
				*ss = NULL;
			}
			*(va_arg( ap, ber_len_t * )) = 0; /* for length, in bits */
			break;

		case 'v':	/* sequence of strings */
			sss = va_arg( ap, char *** );
			if ( *sss ) {
				for (j = 0;  (*sss)[j];	 j++) {
					LBER_FREE( (*sss)[j] );
					(*sss)[j] = NULL;
				}
				LBER_FREE( *sss );
				*sss = NULL;
			}
			break;

		case 'V':	/* sequence of strings + lengths */
			bv = va_arg( ap, struct berval *** );
			if ( *bv ) {
				ber_bvecfree( *bv );
				*bv = NULL;
			}
			break;

		case 'n':	/* null */
		case 'x':	/* skip the next element - whatever it is */
		case '{':	/* begin sequence */
		case '[':	/* begin set */
		case '}':	/* end sequence */
		case ']':	/* end set */
			break;

		default:
			/* format should be good */
			assert( 0 );
		}
	    }

	    va_end( ap );
	}

	return rc;
}
