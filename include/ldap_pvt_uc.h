/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/*
 * ldap_pvt_uc.h - Header for Unicode functions.
 * These are meant to be used by the OpenLDAP distribution only.
 */

#ifndef _LDAP_PVT_UC_H
#define _LDAP_PVT_UC_H 1

#include <ldap_cdefs.h>
#include <lber.h>				/* get ber_slen_t */

#ifdef _MSC_VER
#include "../libraries/liblunicode/ucdata/ucdata.h"
#else
#include "../libraries/liblunicode/ucdata.h"
#endif

LDAP_BEGIN_DECL

/*  
 * UTF-8 (in utf-8.c)
 */

typedef ber_int_t ldap_ucs4_t;
#define LDAP_UCS4_INVALID (0x80000000U)

typedef short ldap_ucs2_t;

/* UCDATA uses UCS-2 passed in an unsigned long */
typedef unsigned long ldap_unicode_t;

/* conversion routines  */
LDAP_F( ldap_ucs4_t ) ldap_utf8_to_ucs4( const char * p );
LDAP_F( int ) ldap_ucs4_to_utf8( ldap_ucs4_t c, char *buf );

#define ldap_utf8_to_unicode( p ) ldap_utf8_to_ucs4((p))
#define ldap_unicode_to_utf8( c, buf ) ldap_ucs4_to_ucs4((c),(buf))

/* returns the number of bytes in the UTF-8 string */
LDAP_F (ber_len_t) ldap_utf8_bytes( const char * );
/* returns the number of UTF-8 characters in the string */
LDAP_F (ber_len_t) ldap_utf8_chars( const char * );
/* returns the length (in bytes) of the UTF-8 character */
LDAP_F (int) ldap_utf8_offset( const char * );
/* returns the length (in bytes) indicated by the UTF-8 character */
LDAP_F (int) ldap_utf8_charlen( const char * );
/* copies a UTF-8 character and returning number of bytes copied */
LDAP_F (int) ldap_utf8_copy( char *, const char *);

/* returns pointer of next UTF-8 character in string */
LDAP_F (char*) ldap_utf8_next( const char * );
/* returns pointer of previous UTF-8 character in string */
LDAP_F (char*) ldap_utf8_prev( const char * );

/* primitive ctype routines -- not aware of non-ascii characters */
LDAP_F (int) ldap_utf8_isascii( const char * );
LDAP_F (int) ldap_utf8_isalpha( const char * );
LDAP_F (int) ldap_utf8_isalnum( const char * );
LDAP_F (int) ldap_utf8_isdigit( const char * );
LDAP_F (int) ldap_utf8_isxdigit( const char * );
LDAP_F (int) ldap_utf8_isspace( const char * );

/* span characters not in set, return bytes spanned */
LDAP_F (ber_len_t) ldap_utf8_strcspn( const char* str, const char *set);
/* span characters in set, return bytes spanned */
LDAP_F (ber_len_t) ldap_utf8_strspn( const char* str, const char *set);
/* return first occurance of character in string */
LDAP_F (char *) ldap_utf8_strchr( const char* str, const char *chr);
/* return first character of set in string */
LDAP_F (char *) ldap_utf8_strpbrk( const char* str, const char *set);
/* reentrant tokenizer */
LDAP_F (char*) ldap_utf8_strtok( char* sp, const char* sep, char **last);

/* Optimizations */
#define LDAP_UTF8_ISASCII(p) ( * (const unsigned char *) (p) < 0x80 )
#define LDAP_UTF8_CHARLEN(p) ( LDAP_UTF8_ISASCII(p) \
	? 1 : ldap_utf8_charlen((p)) )
#define LDAP_UTF8_OFFSET(p) ( LDAP_UTF8_ISASCII(p) \
	? 1 : ldap_utf8_offset((p)) )

#define LDAP_UTF8_COPY(d,s) (	LDAP_UTF8_ISASCII(s) \
	? (*(d) = *(s), 1) : ldap_utf8_copy((d),(s)) )

#define LDAP_UTF8_NEXT(p) (	LDAP_UTF8_ISASCII(p) \
	? (char *)(p)+1 : ldap_utf8_next((p)) )

#define LDAP_UTF8_INCR(p) ((p) = LDAP_UTF8_NEXT(p))

/* For symmetry */
#define LDAP_UTF8_PREV(p) (ldap_utf8_prev((p)))
#define LDAP_UTF8_DECR(p) ((p)=LDAP_UTF8_PREV((p)))


/* these probably should be renamed */
LDAP_LUNICODE_F(int) ucstrncmp(
	const ldap_unicode_t *,
	const ldap_unicode_t *,
	ber_len_t );

LDAP_LUNICODE_F(int) ucstrncasecmp(
	const ldap_unicode_t *,
	const ldap_unicode_t *,
	ber_len_t );

LDAP_LUNICODE_F(ldap_unicode_t *) ucstrnchr(
	const ldap_unicode_t *,
	ber_len_t,
	ldap_unicode_t );

LDAP_LUNICODE_F(ldap_unicode_t *) ucstrncasechr(
	const ldap_unicode_t *,
	ber_len_t,
	ldap_unicode_t );

LDAP_LUNICODE_F(void) ucstr2upper(
	ldap_unicode_t *,
	ber_len_t );

#define UTF8_CASEFOLD 1
#define UTF8_NOCASEFOLD 0

LDAP_LUNICODE_F(char *) UTF8normalize(
	const char *,
	char casefold );

LDAP_END_DECL

#endif

