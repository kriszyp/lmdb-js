/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * Basic UTF-8 routines
 *
 * These routines are not optimized.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_defaults.h"

#define UTF8_ISASCII(u)	( !((u) & ~0x7f) )
#define UCS4_INVALID	0x80000000U

/*
 * return the number of bytes required to hold the
 * NULL-terminated UTF-8 string INCLUDING the
 * termination.
 */
ber_len_t ldap_utf8_bytes( const char * p )
{
	ber_len_t bytes = 0;

	if( p == NULL ) return bytes;

	while( p[bytes++] ) {
		/* EMPTY */ ;
	}

	return bytes;
}

ber_len_t ldap_utf8_chars( const char * p )
{
	/* could be optimized and could check for invalid sequences */
	ber_len_t chars;

	for( chars=0; *p ; chars++ ) {
		int charlen = ldap_utf8_charlen( p );

		if( !charlen ) return chars;

		p = &p[charlen];
	};

	return chars;
}

int ldap_utf8_charlen( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if ((c & 0xfe ) == 0xfc) {
		return 6;
	}

	if ((c & 0xfc ) == 0xf8) {
		return 5;
	}

	if ((c & 0xf8 ) == 0xf0) {
		return 4;
	}

	if ((c & 0xf0 ) == 0xe0) {
		return 3;
	}

	if ((c & 0xe0 ) == 0xc0) {
		return 2;
	}

	if ((c & 0x80 ) == 0x80) {
		/* INVALID */
		return 0;
	}

	return 1;
}

ber_int_t ldap_utf8_to_ucs4( const char * p )
{
	int len, i;
    ber_int_t c = * (const unsigned char *) p;

    if ((c & 0xFE ) == 0xFC) {
        len = 6;
		c &= 0x01;

    } else if ((c & 0xFC ) == 0xF8) {
        len = 5;
		c &= 0x03;

    } else if ((c & 0xF8 ) == 0xF0) {
        len = 4;
		c &= 0x07;

    } else if ((c & 0xF0 ) == 0xE0) {
        len = 3;
		c &= 0x0F;

    } else if ((c & 0xE0 ) == 0xC0) {
        len = 2;
		c &= 0x1F;

    } else if ((c & 0x80 ) == 0x80) {
        return UCS4_INVALID;

    } else {
    	return c;
	}

	for(i=1; i < len; i++) {
		ber_int_t ch = ((const unsigned char *) p)[i];

		if ((ch & 0xc0) != 0x80) {
			return UCS4_INVALID;
		}

		c <<= 6;
		c |= ch & 0x3f;
	}

	return c;
}

int ldap_ucs4_to_utf8( ber_int_t c, char *buf )
{
	int len=0;
	unsigned char* p = buf;
	if(buf == NULL) return 0;

	if ( c < 0 ) {
		/* not a valid Unicode character */

	} else if( c < 0x80 ) {
		p[len++] = c;

	} else if( c < 0x800 ) {
		p[len++] = 0xc0 | ( c >> 6 );
		p[len++] = 0x80 | ( c & 0x3F );

	} else if( c < 0x10000 ) {
		p[len++] = 0xe0 | ( c >> 12 );
		p[len++] = 0x80 | ( (c >> 6) & 0x3F );
		p[len++] = 0x80 | ( c & 0x3F );

	} else if( c < 0x200000 ) {
		p[len++] = 0xf0 | ( c >> 18 );
		p[len++] = 0x80 | ( (c >> 12) & 0x3F );
		p[len++] = 0x80 | ( (c >> 6) & 0x3F );
		p[len++] = 0x80 | ( c & 0x3F );

	} else if( c < 0x400000 ) {
		p[len++] = 0xf8 | ( c >> 24 );
		p[len++] = 0x80 | ( (c >> 18) & 0x3F );
		p[len++] = 0x80 | ( (c >> 12) & 0x3F );
		p[len++] = 0x80 | ( (c >> 6) & 0x3F );
		p[len++] = 0x80 | ( c & 0x3F );

	} else /* if( c < 0x80000000 ) */ {
		p[len++] = 0xfc | ( c >> 30 );
		p[len++] = 0x80 | ( (c >> 24) & 0x3F );
		p[len++] = 0x80 | ( (c >> 18) & 0x3F );
		p[len++] = 0x80 | ( (c >> 12) & 0x3F );
		p[len++] = 0x80 | ( (c >> 6) & 0x3F );
		p[len++] = 0x80 | ( c & 0x3F );
	}

	buf[len] = '\0';
	return len;
}

char* ldap_utf8_next( const char * p )
{
	int len = ldap_utf8_charlen( p );

	return len ? (char *) &p[len] : NULL;
}

char* ldap_utf8_prev( const char * p )
{
	int i;
	const unsigned char *u = p;

	for( i = -1; i >= -6 ; i-- ) {
		if ( u[i] & 0xC0 != 0x80 ) return (char *) &p[i];
	}

	return NULL;
}

int ldap_utf8_isascii( const char * p )
{
	unsigned c = * (const unsigned char *) p;
	return UTF8_ISASCII(c);
}

int ldap_utf8_isdigit( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return c >= '0' && c <= '9';
}

int ldap_utf8_isxdigit( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return ( c >= '0' && c <= '9' )
		|| ( c >= 'A' && c <= 'F' )
		|| ( c >= 'a' && c <= 'f' );
}

int ldap_utf8_isalpha( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return ( c >= 'A' && c <= 'Z' )
		|| ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_isalnum( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return ( c >= '0' && c <= '9' )
		|| ( c >= 'A' && c <= 'Z' )
		|| ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_islower( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_isupper( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	return ( c >= 'A' && c <= 'Z' );
}

int ldap_utf8_isspace( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!UTF8_ISASCII(c)) return 0;

	switch(c) {
	case ' ':
	case '\t':
	case '\n':
	case '\r':
	case '\v':
	case '\f':
		return 1;
	}

	return 0;
}

char* ldap_utf8_fgetc( FILE *s, char *buf )
{
	int i;
	unsigned char *p;
	unsigned int c;
	int len;

	if( s == NULL ) return NULL;

	p = buf;

	c = fgetc( s );
	if( c == EOF ) {
		p[0] = -1;
		return NULL;
	}

	p[0] = c;

	len = ldap_utf8_charlen( buf );

	if( len < 1 ) return NULL;

	for( i = 1; i < len; i++ ) {
		unsigned int c = fgetc( s );
		if( c == EOF ) {
			p[i] = -1;
			return NULL;
		}
		if( c & 0xC0 != 0x80 ) {
			ungetc( c, s );
			p[i] = -1;
			return NULL;
		}
		p[i] = c;
	}

	return buf;
}

ber_len_t (ldap_utf8_strcspn)( const char *str, const char *set )
{
	int len;
	const char *cstr;

	for( cstr = str; *cstr != '\0'; cstr += len ) {
		const char *cset;

		for( cset = set; ; cset += len ) {
			if( ldap_utf8_to_ucs4( cstr ) == ldap_utf8_to_ucs4( cset ) ) {
				return cstr - str;
			} 

			len = ldap_utf8_charlen(cset);
			if( !len ) break;
		}

		len = ldap_utf8_charlen(cstr);
		if( !len ) break;
	}

	return cstr - str;
}

ber_len_t (ldap_utf8_strspn)( const char *str, const char *set )
{
	int len;
	const char *cstr;

	for( cstr = str; *cstr != '\0'; cstr += len ) {
		const char *cset;

		for( cset = set; ; cset += len ) {
			if( *cset == '\0' ) {
				return cstr - str;
			}

			if( ldap_utf8_to_ucs4( cstr ) == ldap_utf8_to_ucs4( cset ) ) {
				break;
			} 

			len = ldap_utf8_charlen(cset);
			if( !len ) break;
		}

		len = ldap_utf8_charlen(cstr);
		if( !len ) break;
	}

	return cstr - str;
}

char *(ldap_utf8_strpbrk)( const char *str, const char *set )
{
	int len;
	const char *cstr;

	for( cstr = str; *cstr != '\0'; cstr += len ) {
		const char *cset;

		for( cset = set; ; cset += len ) {
			if( ldap_utf8_to_ucs4( cstr ) == ldap_utf8_to_ucs4( cset ) ) {
				return cstr;
			} 

			len = ldap_utf8_charlen(cset);
			if( !len ) break;
		}

		len = ldap_utf8_charlen(cstr);
		if( !len ) break;
	}

	return NULL;
}

char *(ldap_utf8_strtok)(char *str, const char *sep, char **last)
{
	char *begin;
	char *end;

	if( last == NULL ) return NULL;

	begin = str ? str : *last;

	begin += ldap_utf8_strspn( begin, sep );

	if( *begin == '\0' ) {
		*last = NULL;
		return NULL;
	}

	end = &begin[ ldap_utf8_strcpn( begin, sep ) ];

	if( *end != '\0' ) {
		int len = ldap_utf8_charlen( end );
		*end = '\0';

		if( len ) {
			end += len;
		} else {
			end = NULL;
		}
	}

	*last = end;
	return begin;
}
