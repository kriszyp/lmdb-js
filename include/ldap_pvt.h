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
 * ldap-pvt.h - Header for ldap_pvt_ functions. These are meant to be used
 * 		by the OpenLDAP distribution only.
 */

#ifndef _LDAP_PVT_H
#define _LDAP_PVT_H 1

#include <ldap_cdefs.h>
#include <lber.h>				/* get ber_slen_t */

LDAP_BEGIN_DECL

#define LDAP_PROTO_TCP 1
#define LDAP_PROTO_UDP 2
#define LDAP_PROTO_IPC 3

LDAP_F ( int )
ldap_pvt_url_scheme2proto LDAP_P((
	const char * ));
LDAP_F ( int )
ldap_pvt_url_scheme2tls LDAP_P((
	const char * ));


LDAP_F ( int )
ldap_pvt_domain2dn LDAP_P((
	LDAP_CONST char *domain,
	char **dn ));

struct hostent;	/* avoid pulling in <netdb.h> */

LDAP_F( char * )
ldap_pvt_ctime LDAP_P((
	const time_t *tp,
	char *buf ));

LDAP_F( char *) ldap_pvt_get_fqdn LDAP_P(( char * ));

LDAP_F( int )
ldap_pvt_gethostbyname_a LDAP_P((
	const char *name, 
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr ));

LDAP_F( int )
ldap_pvt_gethostbyaddr_a LDAP_P((
	const char *addr,
	int len,
	int type,
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr ));


/* charray.c */

LDAP_F( int )
ldap_charray_add LDAP_P((
    char	***a,
    char	*s ));

LDAP_F( int )
ldap_charray_merge LDAP_P((
    char	***a,
    char	**s ));

LDAP_F( void )
ldap_charray_free LDAP_P(( char **a ));

LDAP_F( int )
ldap_charray_inlist LDAP_P((
    char	**a,
    char	*s ));

LDAP_F( char ** )
ldap_charray_dup LDAP_P(( char **a ));

LDAP_F( char ** )
ldap_str2charray LDAP_P((
	const char *str,
	const char *brkstr ));

LDAP_F( char * )
ldap_charray2str LDAP_P((
	char **array, const char* sep ));

/* url.c */
LDAP_F (void) ldap_pvt_hex_unescape LDAP_P(( char *s ));
LDAP_F (int) ldap_pvt_unhex( int c );

/* these macros assume 'x' is an ASCII x */
#define LDAP_DNSEPARATOR(c)	((c) == ',' || (c) == ';')
#define LDAP_SEPARATOR(c)	((c) == ',' || (c) == ';' || (c) == '+')
#define LDAP_SPACE(c)		((c) == ' ' || (c) == '\t' || (c) == '\n')

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
#define LDAP_ATTRCHAR(c)		( LDAP_KEYCHAR(c) || LDAP_OIDCHAR(c) )

#define LDAP_NEEDSESCAPE(c)	((c) == '\\' || (c) == '"')

#ifdef HAVE_CYRUS_SASL
/* cyrus.c */
struct sasl_security_properties; /* avoid pulling in <sasl.h> */
LDAP_F (int) ldap_pvt_sasl_secprops LDAP_P((
	const char *in,
	struct sasl_security_properties *secprops ));

LDAP_F (void *) ldap_pvt_sasl_mutex_new LDAP_P((void));
LDAP_F (int) ldap_pvt_sasl_mutex_lock LDAP_P((void *mutex));
LDAP_F (int) ldap_pvt_sasl_mutex_unlock LDAP_P((void *mutex));
LDAP_F (void) ldap_pvt_sasl_mutex_dispose LDAP_P((void *mutex));

struct sockbuf; /* avoid pulling in <lber.h> */
LDAP_F (int) ldap_pvt_sasl_install LDAP_P(( struct sockbuf *, void * ));
#endif /* HAVE_CYRUS_SASL */

#define LDAP_PVT_SASL_LOCAL_SSF	52	/* SSF for Unix Domain Sockets */

/* search.c */
LDAP_F( char * )
ldap_pvt_find_wildcard LDAP_P((	const char *s ));

LDAP_F( ber_slen_t )
ldap_pvt_filter_value_unescape LDAP_P(( char *filter ));

/* string.c */
LDAP_F( char * )
ldap_pvt_str2upper LDAP_P(( char *str ));

LDAP_F( char * )
ldap_pvt_str2lower LDAP_P(( char *str ));

/* tls.c */
struct ldapoptions;
struct ldap;

LDAP_F (int) ldap_pvt_tls_init LDAP_P(( void ));
LDAP_F (int) ldap_pvt_tls_connect LDAP_P(( struct ldap *ld, Sockbuf *sb, void *ctx_arg ));
LDAP_F (int) ldap_pvt_tls_accept LDAP_P(( Sockbuf *sb, void *ctx_arg ));
LDAP_F (void *) ldap_pvt_tls_sb_handle LDAP_P(( Sockbuf *sb ));
LDAP_F (void *) ldap_pvt_tls_get_handle LDAP_P(( struct ldap *ld ));
LDAP_F (const char *) ldap_pvt_tls_get_peer LDAP_P(( void *handle ));
LDAP_F (int) ldap_pvt_tls_get_strength LDAP_P(( void *handle ));
LDAP_F (int) ldap_pvt_tls_inplace LDAP_P(( Sockbuf *sb ));
LDAP_F (int) ldap_pvt_tls_start LDAP_P(( struct ldap *ld, Sockbuf *sb, void *ctx_arg ));

LDAP_F (int) ldap_pvt_tls_get_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));
LDAP_F (int) ldap_pvt_tls_set_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));

/*  
 * UTF-8 (in utf-8.c)
 */

typedef ber_int_t ldap_ucs4_t;
typedef short ldap_ucs2_t;
typedef ldap_ucs2_t ldap_unicode_t;

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

