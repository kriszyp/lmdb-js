/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/*
 * ldap-pvt.h - Header for ldap_pvt_ functions. These are meant to be used
 * 		by the OpenLDAP distribution only.
 */

#ifndef _LDAP_PVT_H
#define _LDAP_PVT_H 1

#include <ldap_cdefs.h>
#include <lber.h>				/* get ber_slen_t */

LDAP_BEGIN_DECL

LIBLDAP_F ( int )
ldap_pvt_domain2dn LDAP_P((
	LDAP_CONST char *domain,
	char **dn ));

struct hostent;	/* avoid pulling in <netdb.h> */

LIBLDAP_F( char * )
ldap_pvt_ctime LDAP_P((
	const time_t *tp,
	char *buf ));

LIBLDAP_F( int )
ldap_pvt_gethostbyname_a LDAP_P((
	const char *name, 
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr ));

LIBLDAP_F( int )
ldap_pvt_gethostbyaddr_a LDAP_P((
	const char *addr,
	int len,
	int type,
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr ));


/* charray.c */

LIBLDAP_F( int )
ldap_charray_add LDAP_P((
    char	***a,
    char	*s ));

LIBLDAP_F( int )
ldap_charray_merge LDAP_P((
    char	***a,
    char	**s ));

LIBLDAP_F( void )
ldap_charray_free LDAP_P(( char **a ));

LIBLDAP_F( int )
ldap_charray_inlist LDAP_P((
    char	**a,
    char	*s ));

LIBLDAP_F( char ** )
ldap_charray_dup LDAP_P(( char **a ));

LIBLDAP_F( char ** )
ldap_str2charray LDAP_P((
	const char *str,
	const char *brkstr ));

/* url.c */
LIBLDAP_F (void) ldap_pvt_hex_unescape LDAP_P(( char *s ));
LIBLDAP_F (int) ldap_pvt_unhex( int c );

/* these macros assume 'x' is an ASCII x */
#define LDAP_DNSEPARATOR(c)	((c) == ',' || (c) == ';')
#define LDAP_SEPARATOR(c)	((c) == ',' || (c) == ';' || (c) == '+')
#define LDAP_SPACE(c)		((c) == ' ' || (c) == '\n')

#define LDAP_LOWER(c)		( (c) >= 'a' && (c) <= 'z' )
#define LDAP_UPPER(c)		( (c) >= 'A' && (c) <= 'Z' )
#define LDAP_ALPHA(c)		( LDAP_LOWER(c) || LDAP_UPPER(c) )
#define LDAP_DIGIT(c)		( (c) >= '0' && (c) <= '9' )
#define LDAP_ALNUM(c)		( LDAP_ALPHA(c) || LDAP_DIGIT(c) )

#define LDAP_LEADKEYCHAR(c)	( LDAP_ALPHA(c) )
#define LDAP_KEYCHAR(c)		( LDAP_ALNUM(c) || (c) == '-' )
#define LDAP_LEADOIDCHAR(c)	( LDAP_DIGIT(c) )
#define LDAP_OIDCHAR(c)		( LDAP_DIGIT(c) || (c) == '.' )

#define LDAP_LEADATTRCHAR(c)	( LDAP_LEADKEYCHAR(c) || LDAP_LEADOIDCHAR(c) )
#define LDAP_ATTRCHAR(c)		( LDAP_KEYCHAR((c)) || (c) == '.' )

#define LDAP_NEEDSESCAPE(c)	((c) == '\\' || (c) == '"')

#ifdef HAVE_CYRUS_SASL
/* sasl.c */

#include <sasl.h>
#include <ldap.h> 

LIBLDAP_F (int) ldap_pvt_sasl_init LDAP_P(( void )); /* clientside init */
LIBLDAP_F (int) ldap_pvt_sasl_install LDAP_P(( Sockbuf *, void * ));
LIBLDAP_F (int) ldap_pvt_sasl_bind LDAP_P(( LDAP *, LDAP_CONST char *,
	LDAP_CONST char *, LDAP_CONST sasl_callback_t *, LDAPControl **,
	LDAPControl ** ));
LIBLDAP_F (int) ldap_pvt_sasl_get_option LDAP_P(( LDAP *ld, int option,
	void *arg ));
LIBLDAP_F (int) ldap_pvt_sasl_set_option LDAP_P(( LDAP *ld, int option,
	void *arg ));
#endif /* HAVE_CYRUS_SASL */

/* search.c */
LIBLDAP_F( char * )
ldap_pvt_find_wildcard LDAP_P((	const char *s ));

LIBLDAP_F( ber_slen_t )
ldap_pvt_filter_value_unescape LDAP_P(( char *filter ));

/* string.c */
LIBLDAP_F( char * )
ldap_pvt_str2upper LDAP_P(( char *str ));

LIBLDAP_F( char * )
ldap_pvt_str2lower LDAP_P(( char *str ));

/* tls.c */
struct ldapoptions;

LIBLDAP_F (int) ldap_pvt_tls_init LDAP_P(( void ));
LIBLDAP_F (int) ldap_pvt_tls_config LDAP_P(( struct ldapoptions *lo, int option, const char *arg ));
LIBLDAP_F (int) ldap_pvt_tls_connect LDAP_P(( Sockbuf *sb, void *ctx_arg ));
LIBLDAP_F (int) ldap_pvt_tls_accept LDAP_P(( Sockbuf *sb, void *ctx_arg ));
LIBLDAP_F (int) ldap_pvt_tls_get_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));
LIBLDAP_F (int) ldap_pvt_tls_set_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));
LIBLDAP_F (int) ldap_pvt_tls_inplace LDAP_P(( Sockbuf *sb ));
LIBLDAP_F (int) ldap_pvt_tls_start LDAP_P(( Sockbuf *sb, void *ctx_arg ));

/*  
 * UTF-8 (in utf-8.c)
 */

typedef ber_int_t ldap_ucs4_t;
typedef short ldap_ucs2_t;
typedef ldap_ucs2_t ldap_unicode_t;

/* returns the number of bytes in the UTF-8 string */
LIBLDAP_F (ber_len_t) ldap_utf8_bytes( const char * );
/* returns the number of UTF-8 characters in the string */
LIBLDAP_F (ber_len_t) ldap_utf8_chars( const char * );
/* returns the length (in bytes) of the UTF-8 character */
LIBLDAP_F (int) ldap_utf8_offset( const char * );
/* returns the length (in bytes) indicated by the UTF-8 character */
LIBLDAP_F (int) ldap_utf8_charlen( const char * );
/* copies a UTF-8 character and returning number of bytes copied */
LIBLDAP_F (int) ldap_utf8_copy( char *, const char *);

/* returns pointer of next UTF-8 character in string */
LIBLDAP_F (char*) ldap_utf8_next( const char * );
/* returns pointer of previous UTF-8 character in string */
LIBLDAP_F (char*) ldap_utf8_prev( const char * );

/* primitive ctype routines -- not aware of non-ascii characters */
LIBLDAP_F (int) ldap_utf8_isascii( const char * );
LIBLDAP_F (int) ldap_utf8_isalpha( const char * );
LIBLDAP_F (int) ldap_utf8_isalnum( const char * );
LIBLDAP_F (int) ldap_utf8_isdigit( const char * );
LIBLDAP_F (int) ldap_utf8_isxdigit( const char * );
LIBLDAP_F (int) ldap_utf8_isspace( const char * );

/* span characters not in set, return bytes spanned */
LIBLDAP_F (ber_len_t) ldap_utf8_strcspn( const char* str, const char *set);
/* span characters in set, return bytes spanned */
LIBLDAP_F (ber_len_t) ldap_utf8_strspn( const char* str, const char *set);
/* return first occurance of character in string */
LIBLDAP_F (char *) ldap_utf8_strchr( const char* str, const char *chr);
/* return first character of set in string */
LIBLDAP_F (char *) ldap_utf8_strpbrk( const char* str, const char *set);
/* reentrant tokenizer */
LIBLDAP_F (char*) ldap_utf8_strtok( char* sp, const char* sep, char **last);

/* Optimizations */
#define LDAP_UTF8_ISASCII(p) ( * (const unsigned char *) (p) < 0x100 )
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

LDAP_END_DECL

#endif

