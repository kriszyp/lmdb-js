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

ber_len_t ldap_utf8_bytes( const char * p )
{
	ber_len_t bytes;

	for( bytes=0; p[bytes] ; bytes++ ) {
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
	unsigned c;

	if ((c & 0xFE ) == 0xFC) {
		return 6;
	}
	if ((c & 0xFC ) == 0xF8) {
		return 5;
	}
	if ((c & 0xF8 ) == 0xF0) {
		return 4;
	}
	if ((c & 0xF0 ) == 0xE0) {
		return 3;
	}
	if ((c & 0xE0 ) == 0xC0) {
		return 2;
	}
	if ((c & 0x80 ) == 0x80) {
		/* INVALID */
		return 0;
	}

	return 1;
}

char* ldap_utf8_next( char * p )
{
	int len = ldap_utf8_charlen( p );

	return len ? &p[len] : NULL;
}

char* ldap_utf8_prev( char * p )
{
	int i;
	unsigned char *u = p;

	for( i = -1; i >= -6 ; i-- ) {
		if ( u[i] & 0xC0 != 0x80 ) return &p[i];
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
