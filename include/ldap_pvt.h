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

struct hostent;	/* avoid pulling in <netdb.h> */

#ifdef __MINGW32__
#   undef LDAP_F_PRE
#   ifdef LIBLDAP_DECL
#	define LDAP_F_PRE	extern __declspec(LIBLDAP_DECL)
#   else
#	define LDAP_F_PRE	extern
#   endif
#endif

LDAP_F( char * )
ldap_pvt_ctime LDAP_P((
	const time_t *tp,
	char *buf ));

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
	char *str,
	char *brkstr ));

/* url.c */
void ldap_pvt_hex_unescape LDAP_P(( char *s ));
int ldap_pvt_unhex( int c );

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

/* search.c */
LDAP_F( char * )
ldap_pvt_find_wildcard LDAP_P((	char *s ));

LDAP_F( ber_slen_t )
ldap_pvt_filter_value_unescape LDAP_P(( char *filter ));

/* string.c */
LDAP_F( char * )
ldap_pvt_str2upper LDAP_P(( char *str ));

LDAP_F( char * )
ldap_pvt_str2lower LDAP_P(( char *str ));

/* tls.c */
struct ldapoptions;

int ldap_pvt_tls_init LDAP_P(( void ));
int ldap_pvt_tls_config LDAP_P(( struct ldapoptions *lo, int option, const char *arg ));
int ldap_pvt_tls_connect LDAP_P(( Sockbuf *sb, void *ctx_arg ));
int ldap_pvt_tls_accept LDAP_P(( Sockbuf *sb, void *ctx_arg ));
int ldap_pvt_tls_get_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));
int ldap_pvt_tls_set_option LDAP_P(( struct ldapoptions *lo, int option, void *arg ));

LDAP_END_DECL

#endif

