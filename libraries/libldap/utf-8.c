/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/*
 * Basic UTF-8 routines
 *
 * These routines are "dumb".  Though they understand UTF-8,
 * they don't grok Unicode.  That is, they can push bits,
 * but don't have a clue what the bits represent.  That's
 * good enough for use with the LDAP Client SDK.
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

#undef ISASCII
#define ISASCII(uc)	((uc) < 0x100)
#undef UCS4_INVALID
#define UCS4_INVALID	0x80000000U

/*
 * Basic UTF-8 routines
 */

/*
 * return the number of bytes required to hold the
 * NULL-terminated UTF-8 string NOT INCLUDING the
 * termination.
 */
ber_len_t ldap_utf8_bytes( const char * p )
{
	ber_len_t bytes;

	for( bytes=0; p[bytes]; bytes++ ) {
		/* EMPTY */ ;
	}

	return bytes;
}

ber_len_t ldap_utf8_chars( const char * p )
{
	/* could be optimized and could check for invalid sequences */
	ber_len_t chars=0;

	for( ; *p ; LDAP_UTF8_INCR(p) ) {
		chars++;
	};

	return chars;
}

/* return offset to next character */
int ldap_utf8_offset( const char * p )
{
	return LDAP_UTF8_NEXT(p) - p;
}

/*
 * Returns length indicated by first byte.
 *
 * This function should use a table lookup.
 */
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

/* conv UTF-8 to UCS-4, useful for comparisons */
ber_int_t ldap_utf8_to_ucs4( const char * p )
{
    const unsigned char *c = p;
    ber_int_t ch;
	int len, i;
	static unsigned char mask[] = {
		0, 0x7f, 0x1f, 0x0f, 0x07, 0x03, 0x01 };

	len = LDAP_UTF8_CHARLEN(p);

	if( len == 0 ) return UCS4_INVALID;

	ch = c[0] & mask[len];

	for(i=1; i < len; i++) {
		if ((c[i] & 0xc0) != 0x80) {
			return UCS4_INVALID;
		}

		ch <<= 6;
		ch |= c[i] & 0x3f;
	}

	return ch;
}

/* conv UCS-4 to UTF-8, not used */
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
		p[len++] = 0x80 | ( c & 0x3f );

	} else if( c < 0x10000 ) {
		p[len++] = 0xe0 | ( c >> 12 );
		p[len++] = 0x80 | ( (c >> 6) & 0x3f );
		p[len++] = 0x80 | ( c & 0x3f );

	} else if( c < 0x200000 ) {
		p[len++] = 0xf0 | ( c >> 18 );
		p[len++] = 0x80 | ( (c >> 12) & 0x3f );
		p[len++] = 0x80 | ( (c >> 6) & 0x3f );
		p[len++] = 0x80 | ( c & 0x3f );

	} else if( c < 0x400000 ) {
		p[len++] = 0xf8 | ( c >> 24 );
		p[len++] = 0x80 | ( (c >> 18) & 0x3f );
		p[len++] = 0x80 | ( (c >> 12) & 0x3f );
		p[len++] = 0x80 | ( (c >> 6) & 0x3f );
		p[len++] = 0x80 | ( c & 0x3f );

	} else /* if( c < 0x80000000 ) */ {
		p[len++] = 0xfc | ( c >> 30 );
		p[len++] = 0x80 | ( (c >> 24) & 0x3f );
		p[len++] = 0x80 | ( (c >> 18) & 0x3f );
		p[len++] = 0x80 | ( (c >> 12) & 0x3f );
		p[len++] = 0x80 | ( (c >> 6) & 0x3f );
		p[len++] = 0x80 | ( c & 0x3f );
	}

	buf[len] = '\0';
	return len;
}

/*
 * Advance to the next UTF-8 character
 *
 * Ignores length of multibyte character, instead rely on
 * continuation markers to find start of next character.
 * This allows for "resyncing" of when invalid characters
 * are provided provided the start of the next character
 * is appears within the 6 bytes examined.
 */
char* ldap_utf8_next( const char * p )
{
	int i;
	const unsigned char *u = p;

	if( LDAP_UTF8_ISASCII(u) ) {
		return (char *) &p[1];
	}

	for( i=1; i<6; i++ ) {
		if ( u[i] & 0xc0 != 0x80 ) {
			return (char *) &p[i];
		}
	}

	return (char *) &p[i];
}

/*
 * Advance to the previous UTF-8 character
 *
 * Ignores length of multibyte character, instead rely on
 * continuation markers to find start of next character.
 * This allows for "resyncing" of when invalid characters
 * are provided provided the start of the next character
 * is appears within the 6 bytes examined.
 */
char* ldap_utf8_prev( const char * p )
{
	int i;
	const unsigned char *u = p;

	for( i=-1; i>-6 ; i-- ) {
		if ( u[i] & 0xc0 != 0x80 ) {
			return (char *) &p[i];
		}
	}

	return (char *) &p[i];
}

/*
 * Copy one UTF-8 character from src to dst returning
 * number of bytes copied.
 *
 * Ignores length of multibyte character, instead rely on
 * continuation markers to find start of next character.
 * This allows for "resyncing" of when invalid characters
 * are provided provided the start of the next character
 * is appears within the 6 bytes examined.
 */
int ldap_utf8_copy( char* dst, const char *src )
{
	int i;
	const unsigned char *u = src;

	dst[0] = src[0];

	if( LDAP_UTF8_ISASCII(u) ) {
		return 1;
	}

	for( i=1; i<6; i++ ) {
		if ( u[i] & 0xc0 != 0x80 ) {
			return i; 
		}
		dst[i] = src[i];
	}

	return i;
}

/*
 * UTF-8 ctype routines
 * Only deals with characters < 0x100 (ie: US-ASCII)
 */

int ldap_utf8_isascii( const char * p )
{
	unsigned c = * (const unsigned char *) p;
	return ISASCII(c);
}

int ldap_utf8_isdigit( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return c >= '0' && c <= '9';
}

int ldap_utf8_isxdigit( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return ( c >= '0' && c <= '9' )
		|| ( c >= 'A' && c <= 'F' )
		|| ( c >= 'a' && c <= 'f' );
}

int ldap_utf8_isspace( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

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

#ifndef UTF8_ALPHA_CTYPE
/*
 * These are not needed by the C SDK and are
 * not "good enough" for general use.
 */
int ldap_utf8_isalpha( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return ( c >= 'A' && c <= 'Z' )
		|| ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_isalnum( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return ( c >= '0' && c <= '9' )
		|| ( c >= 'A' && c <= 'Z' )
		|| ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_islower( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return ( c >= 'a' && c <= 'z' );
}

int ldap_utf8_isupper( const char * p )
{
	unsigned c = * (const unsigned char *) p;

	if(!ISASCII(c)) return 0;

	return ( c >= 'A' && c <= 'Z' );
}
#endif


/*
 * UTF-8 string routines
 */

/* like strchr() */
char * (ldap_utf8_strchr)( const char *str, const char *chr )
{
	for( ; *str != '\0'; LDAP_UTF8_INCR(str) ) {
		if( ldap_utf8_to_ucs4( str ) == ldap_utf8_to_ucs4( chr ) ) {
			return (char *) str;
		} 
	}

	return NULL;
}

/* like strcspn() but returns number of bytes, not characters */
ber_len_t (ldap_utf8_strcspn)( const char *str, const char *set )
{
	const char *cstr;
	const char *cset;

	for( cstr = str; *cstr != '\0'; LDAP_UTF8_INCR(cstr) ) {
		for( cset = set; *cset != '\0'; LDAP_UTF8_INCR(cset) ) {
			if( ldap_utf8_to_ucs4( cstr ) == ldap_utf8_to_ucs4( cset ) ) {
				return cstr - str;
			} 
		}
	}

	return cstr - str;
}

/* like strspn() but returns number of bytes, not characters */
ber_len_t (ldap_utf8_strspn)( const char *str, const char *set )
{
	const char *cstr;
	const char *cset;

	for( cstr = str; *cstr != '\0'; LDAP_UTF8_INCR(cstr) ) {

		for( cset = set; ; LDAP_UTF8_INCR(cset) ) {
			if( *cset == '\0' ) {
				return cstr - str;
			}

			if( ldap_utf8_to_ucs4( cstr ) == ldap_utf8_to_ucs4( cset ) ) {
				break;
			} 
		}
	}

	return cstr - str;
}

/* like strpbrk(), replaces strchr() as well */
char *(ldap_utf8_strpbrk)( const char *str, const char *set )
{
	for( ; *str != '\0'; LDAP_UTF8_INCR(str) ) {
		const char *cset;

		for( cset = set; *cset != '\0'; LDAP_UTF8_INCR(cset) ) {
			if( ldap_utf8_to_ucs4( str ) == ldap_utf8_to_ucs4( cset ) ) {
				return (char *) str;
			} 
		}
	}

	return NULL;
}

/* like strtok_r(), not strtok() */
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

	end = &begin[ ldap_utf8_strcspn( begin, sep ) ];

	if( *end != '\0' ) {
		char *next = LDAP_UTF8_NEXT( end );
		*end = '\0';
		end = next;
	}

	*last = end;
	return begin;
}
