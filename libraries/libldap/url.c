/* LIBLDAP url.c -- LDAP URL (RFC 2255) related routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 */


/*
 *  LDAP URLs look like this:
 *    ldap[is]://host:port[/[dn[?[attributes][?[scope][?[filter][?exts]]]]]]
 *
 *  where:
 *   attributes is a comma separated list
 *   scope is one of these three strings:  base one sub (default=base)
 *   filter is an string-represented filter as in RFC 2254
 *
 *  e.g.,  ldap://host:port/dc=com?o,cn?base?(o=openldap)?extension
 *
 *  We also tolerate URLs that look like: <ldapurl> and <URL:ldapurl>
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/* local functions */
static const char* skip_url_prefix LDAP_P((
	const char *url,
	int *enclosedp,
	const char **scheme ));

int ldap_pvt_url_scheme2proto( const char *scheme )
{
	assert( scheme );

	if( scheme == NULL ) {
		return -1;
	}

	if( strcmp("ldap", scheme) == 0 ) {
		return LDAP_PROTO_TCP;
	}

	if( strcmp("ldapi", scheme) == 0 ) {
		return LDAP_PROTO_IPC;
	}

	if( strcmp("ldaps", scheme) == 0 ) {
		return LDAP_PROTO_TCP;
	}
#ifdef LDAP_CONNECTIONLESS
	if( strcmp("cldap", scheme) == 0 ) {
		return LDAP_PROTO_UDP;
	}
#endif

	return -1;
}

int ldap_pvt_url_scheme_port( const char *scheme, int port )
{
	assert( scheme );

	if( port ) return port;
	if( scheme == NULL ) return port;

	if( strcmp("ldap", scheme) == 0 ) {
		return LDAP_PORT;
	}

	if( strcmp("ldapi", scheme) == 0 ) {
		return -1;
	}

	if( strcmp("ldaps", scheme) == 0 ) {
		return LDAPS_PORT;
	}

#ifdef LDAP_CONNECTIONLESS
	if( strcmp("cldap", scheme) == 0 ) {
		return LDAP_PORT;
	}
#endif

	return -1;
}

int
ldap_pvt_url_scheme2tls( const char *scheme )
{
	assert( scheme );

	if( scheme == NULL ) {
		return -1;
	}

	return strcmp("ldaps", scheme) == 0;
}

int
ldap_is_ldap_url( LDAP_CONST char *url )
{
	int	enclosed;
	const char * scheme;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &scheme ) == NULL ) {
		return 0;
	}

	return 1;
}

int
ldap_is_ldaps_url( LDAP_CONST char *url )
{
	int	enclosed;
	const char * scheme;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &scheme ) == NULL ) {
		return 0;
	}

	return strcmp(scheme, "ldaps") == 0;
}

int
ldap_is_ldapi_url( LDAP_CONST char *url )
{
	int	enclosed;
	const char * scheme;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &scheme ) == NULL ) {
		return 0;
	}

	return strcmp(scheme, "ldapi") == 0;
}

#ifdef LDAP_CONNECTIONLESS
int
ldap_is_ldapc_url( LDAP_CONST char *url )
{
	int	enclosed;
	const char * scheme;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &scheme ) == NULL ) {
		return 0;
	}

	return strcmp(scheme, "cldap") == 0;
}
#endif

static const char*
skip_url_prefix(
	const char *url,
	int *enclosedp,
	const char **scheme )
{
	/*
 	 * return non-zero if this looks like a LDAP URL; zero if not
 	 * if non-zero returned, *urlp will be moved past "ldap://" part of URL
 	 */
	const char *p;

	if ( url == NULL ) {
		return( NULL );
	}

	p = url;

	/* skip leading '<' (if any) */
	if ( *p == '<' ) {
		*enclosedp = 1;
		++p;
	} else {
		*enclosedp = 0;
	}

	/* skip leading "URL:" (if any) */
	if ( strncasecmp( p, LDAP_URL_URLCOLON, LDAP_URL_URLCOLON_LEN ) == 0 ) {
		p += LDAP_URL_URLCOLON_LEN;
	}

	/* check for "ldap://" prefix */
	if ( strncasecmp( p, LDAP_URL_PREFIX, LDAP_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldap://" prefix and return success */
		p += LDAP_URL_PREFIX_LEN;
		*scheme = "ldap";
		return( p );
	}

	/* check for "ldaps://" prefix */
	if ( strncasecmp( p, LDAPS_URL_PREFIX, LDAPS_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldaps://" prefix and return success */
		p += LDAPS_URL_PREFIX_LEN;
		*scheme = "ldaps";
		return( p );
	}

	/* check for "ldapi://" prefix */
	if ( strncasecmp( p, LDAPI_URL_PREFIX, LDAPI_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldapi://" prefix and return success */
		p += LDAPI_URL_PREFIX_LEN;
		*scheme = "ldapi";
		return( p );
	}

#ifdef LDAP_CONNECTIONLESS
	/* check for "cldap://" prefix */
	if ( strncasecmp( p, LDAPC_URL_PREFIX, LDAPC_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "cldap://" prefix and return success */
		p += LDAPC_URL_PREFIX_LEN;
		*scheme = "cldap";
		return( p );
	}
#endif

	return( NULL );
}


static int str2scope( const char *p )
{
	if ( strcasecmp( p, "one" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( p, "onelevel" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( p, "base" ) == 0 ) {
		return LDAP_SCOPE_BASE;

	} else if ( strcasecmp( p, "sub" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;

	} else if ( strcasecmp( p, "subtree" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;

#ifdef LDAP_SCOPE_SUBORDINATE
	} else if ( strcasecmp( p, "subordinate" ) == 0 ) {
		return LDAP_SCOPE_SUBORDINATE;

	} else if ( strcasecmp( p, "children" ) == 0 ) {
		return LDAP_SCOPE_SUBORDINATE;
#endif
	}

	return( -1 );
}

static int hex_escape( char *buf, const char *s, int list )
{
	int i;
	int pos;
	static const char hex[] = "0123456789ABCDEF";

	if( s == NULL ) return 0;

	for( pos=0,i=0; s[i]; i++ ) {
		int escape = 0;
		switch( s[i] ) {
			case ',':
				escape = list;
				break;
			case '%':
			case '?':
			case ' ':
			case '<':
			case '>':
			case '"':
			case '#':
			case '{':
			case '}':
			case '|':
			case '\\':
			case '^':
			case '~':
			case '`':
			case '[':
			case ']':
				escape = 1;
				break;

			default:
				escape = s[i] < 0x20 || 0x1f >= s[i];
		}

		if( escape ) {
			buf[pos++] = '%';
			buf[pos++] = hex[ (s[i] >> 4) & 0x0f ];
			buf[pos++] = hex[ s[i] & 0x0f ];
		} else {
			buf[pos++] = s[i];
		}
	}

	buf[pos] = '\0';
	return pos;
}

static int hex_escape_args( char *buf, char **s )
{
	int pos;
	int i;

	if( s == NULL ) return 0;

	pos = 0;
	for( i=0; s[i] != NULL; i++ ) {
		if( pos ) {
			buf[pos++] = ',';
		}
		pos += hex_escape( &buf[pos], s[i], 1 );
	}

	return pos;
}

char * ldap_url_desc2str( LDAPURLDesc *u )
{
	char *s;
	int i;
	int sep = 0;
	int sofar;
	size_t len = 0;
	if( u == NULL ) return NULL;

	if( u->lud_exts ) {
		for( i=0; u->lud_exts[i]; i++ ) {
			len += strlen( u->lud_exts[i] ) + 1;
		}
		if( !sep ) sep = 5;
	}

	if( u->lud_filter ) {
		len += strlen( u->lud_filter );
		if( !sep ) sep = 4;
	}
	if ( len ) len++; /* ? */

	switch( u->lud_scope ) {
		case LDAP_SCOPE_BASE:
		case LDAP_SCOPE_ONELEVEL:
		case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_FEATURE_SUBORDINATE_SCOPE
		case LDAP_SCOPE_SUBORDINATE:
#endif
			len += sizeof("subordinate");
			if( !sep ) sep = 3;
			break;

		default:
			if ( len ) len++; /* ? */
	}

	if( u->lud_attrs ) {
		for( i=0; u->lud_attrs[i]; i++ ) {
			len += strlen( u->lud_attrs[i] ) + 1;
		}
		if( !sep ) sep = 2;
	} else if ( len ) len++; /* ? */

	if( u->lud_dn ) {
		len += strlen( u->lud_dn ) + 1;
		if( !sep ) sep = 1;
	};

	if( u->lud_port ) {
		len += sizeof(":65535") - 1;
	}

	if( u->lud_host ) {
		len+=strlen( u->lud_host );
	}

	len += strlen( u->lud_scheme ) + sizeof("://");

	/* allocate enough to hex escape everything -- overkill */
	s = LDAP_MALLOC( 3*len );

	if( s == NULL ) return NULL;

	if( u->lud_port ) {
		sprintf( s,	"%s://%s:%d%n", u->lud_scheme,
			u->lud_host, u->lud_port, &sofar );
	} else {
		sprintf( s,	"%s://%s%n", u->lud_scheme,
			u->lud_host, &sofar );
	}
	
	if( sep < 1 ) goto done;
	s[sofar++] = '/';

	sofar += hex_escape( &s[sofar], u->lud_dn, 0 );

	if( sep < 2 ) goto done;
	s[sofar++] = '?';

	sofar += hex_escape_args( &s[sofar], u->lud_attrs );

	if( sep < 3 ) goto done;
	s[sofar++] = '?';

	switch( u->lud_scope ) {
	case LDAP_SCOPE_BASE:
		strcpy( &s[sofar], "base" );
		sofar += sizeof("base") - 1;
		break;
	case LDAP_SCOPE_ONELEVEL:
		strcpy( &s[sofar], "one" );
		sofar += sizeof("one") - 1;
		break;
	case LDAP_SCOPE_SUBTREE:
		strcpy( &s[sofar], "sub" );
		sofar += sizeof("sub") - 1;
		break;
#ifdef LDAP_FEATURE_SUBORDINATE_SCOPE
	case LDAP_SCOPE_SUBORDINATE:
		strcpy( &s[sofar], "children" );
		sofar += sizeof("children") - 1;
		break;
#endif
	}

	if( sep < 4 ) goto done;
	s[sofar++] = '?';

	sofar += hex_escape( &s[sofar], u->lud_filter, 0 );

	if( sep < 5 ) goto done;
	s[sofar++] = '?';

	sofar += hex_escape_args( &s[sofar], u->lud_exts );

done:
	s[sofar] = '\0';
	return s;
}

int
ldap_url_parse_ext( LDAP_CONST char *url_in, LDAPURLDesc **ludpp )
{
/*
 *  Pick apart the pieces of an LDAP URL.
 */

	LDAPURLDesc	*ludp;
	char	*p, *q, *r;
	int		i, enclosed;
	const char *scheme = NULL;
	const char *url_tmp;
	char *url;

	if( url_in == NULL || ludpp == NULL ) {
		return LDAP_URL_ERR_PARAM;
	}

#ifndef LDAP_INT_IN_KERNEL
	/* Global options may not be created yet
	 * We can't test if the global options are initialized
	 * because a call to LDAP_INT_GLOBAL_OPT() will try to allocate
	 * the options and cause infinite recursion
	 */
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_url_parse_ext(%s)\n", url_in, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_url_parse_ext(%s)\n", url_in, 0, 0 );
#endif
#endif

	*ludpp = NULL;	/* pessimistic */

	url_tmp = skip_url_prefix( url_in, &enclosed, &scheme );

	if ( url_tmp == NULL ) {
		return LDAP_URL_ERR_BADSCHEME;
	}

	assert( scheme );

	/* make working copy of the remainder of the URL */
	url = LDAP_STRDUP( url_tmp );
	if ( url == NULL ) {
		return LDAP_URL_ERR_MEM;
	}

	if ( enclosed ) {
		p = &url[strlen(url)-1];

		if( *p != '>' ) {
			LDAP_FREE( url );
			return LDAP_URL_ERR_BADENCLOSURE;
		}

		*p = '\0';
	}

	/* allocate return struct */
	ludp = (LDAPURLDesc *)LDAP_CALLOC( 1, sizeof( LDAPURLDesc ));

	if ( ludp == NULL ) {
		LDAP_FREE( url );
		return LDAP_URL_ERR_MEM;
	}

	ludp->lud_next = NULL;
	ludp->lud_host = NULL;
	ludp->lud_port = 0;
	ludp->lud_dn = NULL;
	ludp->lud_attrs = NULL;
	ludp->lud_scope = LDAP_SCOPE_DEFAULT;
	ludp->lud_filter = NULL;
	ludp->lud_exts = NULL;

	ludp->lud_scheme = LDAP_STRDUP( scheme );

	if ( ludp->lud_scheme == NULL ) {
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_MEM;
	}

	/* scan forward for '/' that marks end of hostport and begin. of dn */
	p = strchr( url, '/' );

	if( p != NULL ) {
		/* terminate hostport; point to start of dn */
		*p++ = '\0';
	}

	/* IPv6 syntax with [ip address]:port */
	if ( *url == '[' ) {
		r = strchr( url, ']' );
		if ( r == NULL ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADURL;
		}
		*r++ = '\0';
		q = strchr( r, ':' );
	} else {
		q = strchr( url, ':' );
	}

	if ( q != NULL ) {
		char	*next;

		*q++ = '\0';
		ldap_pvt_hex_unescape( q );

		if( *q == '\0' ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADURL;
		}

		ludp->lud_port = strtol( q, &next, 10 );
		if ( next == NULL || next[0] != '\0' ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADURL;
		}
	}

	ldap_pvt_hex_unescape( url );

	/* If [ip address]:port syntax, url is [ip and we skip the [ */
	ludp->lud_host = LDAP_STRDUP( url + ( *url == '[' ) );

	if( ludp->lud_host == NULL ) {
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_MEM;
	}

	/*
	 * Kludge.  ldap://111.222.333.444:389??cn=abc,o=company
	 *
	 * On early Novell releases, search references/referrals were returned
	 * in this format, i.e., the dn was kind of in the scope position,
	 * but the required slash is missing. The whole thing is illegal syntax,
	 * but we need to account for it. Fortunately it can't be confused with
	 * anything real.
	 */
	if( (p == NULL) && (q != NULL) && ((q = strchr( q, '?')) != NULL)) {
		q++;		
		/* ? immediately followed by question */
		if( *q == '?') {
			q++;
			if( *q != '\0' ) {
				/* parse dn part */
				ldap_pvt_hex_unescape( q );
				ludp->lud_dn = LDAP_STRDUP( q );
			} else {
				ludp->lud_dn = LDAP_STRDUP( "" );
			}

			if( ludp->lud_dn == NULL ) {
				LDAP_FREE( url );
				ldap_free_urldesc( ludp );
				return LDAP_URL_ERR_MEM;
			}
		}
	}

	if( p == NULL ) {
		LDAP_FREE( url );
		*ludpp = ludp;
		return LDAP_URL_SUCCESS;
	}

	/* scan forward for '?' that may marks end of dn */
	q = strchr( p, '?' );

	if( q != NULL ) {
		/* terminate dn part */
		*q++ = '\0';
	}

	if( *p != '\0' ) {
		/* parse dn part */
		ldap_pvt_hex_unescape( p );
		ludp->lud_dn = LDAP_STRDUP( p );
	} else {
		ludp->lud_dn = LDAP_STRDUP( "" );
	}

	if( ludp->lud_dn == NULL ) {
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_MEM;
	}

	if( q == NULL ) {
		/* no more */
		LDAP_FREE( url );
		*ludpp = ludp;
		return LDAP_URL_SUCCESS;
	}

	/* scan forward for '?' that may marks end of attributes */
	p = q;
	q = strchr( p, '?' );

	if( q != NULL ) {
		/* terminate attributes part */
		*q++ = '\0';
	}

	if( *p != '\0' ) {
		/* parse attributes */
		ldap_pvt_hex_unescape( p );
		ludp->lud_attrs = ldap_str2charray( p, "," );

		if( ludp->lud_attrs == NULL ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADATTRS;
		}
	}

	if ( q == NULL ) {
		/* no more */
		LDAP_FREE( url );
		*ludpp = ludp;
		return LDAP_URL_SUCCESS;
	}

	/* scan forward for '?' that may marks end of scope */
	p = q;
	q = strchr( p, '?' );

	if( q != NULL ) {
		/* terminate the scope part */
		*q++ = '\0';
	}

	if( *p != '\0' ) {
		/* parse the scope */
		ldap_pvt_hex_unescape( p );
		ludp->lud_scope = str2scope( p );

		if( ludp->lud_scope == -1 ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADSCOPE;
		}
	}

	if ( q == NULL ) {
		/* no more */
		LDAP_FREE( url );
		*ludpp = ludp;
		return LDAP_URL_SUCCESS;
	}

	/* scan forward for '?' that may marks end of filter */
	p = q;
	q = strchr( p, '?' );

	if( q != NULL ) {
		/* terminate the filter part */
		*q++ = '\0';
	}

	if( *p != '\0' ) {
		/* parse the filter */
		ldap_pvt_hex_unescape( p );

		if( ! *p ) {
			/* missing filter */
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADFILTER;
		}

		ludp->lud_filter = LDAP_STRDUP( p );

		if( ludp->lud_filter == NULL ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_MEM;
		}
	}

	if ( q == NULL ) {
		/* no more */
		LDAP_FREE( url );
		*ludpp = ludp;
		return LDAP_URL_SUCCESS;
	}

	/* scan forward for '?' that may marks end of extensions */
	p = q;
	q = strchr( p, '?' );

	if( q != NULL ) {
		/* extra '?' */
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_BADURL;
	}

	/* parse the extensions */
	ludp->lud_exts = ldap_str2charray( p, "," );

	if( ludp->lud_exts == NULL ) {
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_BADEXTS;
	}

	for( i=0; ludp->lud_exts[i] != NULL; i++ ) {
		ldap_pvt_hex_unescape( ludp->lud_exts[i] );

		if( *ludp->lud_exts[i] == '!' ) {
			/* count the number of critical extensions */
			ludp->lud_crit_exts++;
		}
	}

	if( i == 0 ) {
		/* must have 1 or more */
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_BADEXTS;
	}

	/* no more */
	*ludpp = ludp;
	LDAP_FREE( url );
	return LDAP_URL_SUCCESS;
}

int
ldap_url_parse( LDAP_CONST char *url_in, LDAPURLDesc **ludpp )
{
	int rc = ldap_url_parse_ext( url_in, ludpp );

	if( rc != LDAP_URL_SUCCESS ) {
		return rc;
	}

	if ((*ludpp)->lud_scope == LDAP_SCOPE_DEFAULT) {
		(*ludpp)->lud_scope = LDAP_SCOPE_BASE;
	}

	if ((*ludpp)->lud_host != NULL && *(*ludpp)->lud_host == '\0') {
		LDAP_FREE( (*ludpp)->lud_host );
		(*ludpp)->lud_host = NULL;
	}

	if ((*ludpp)->lud_port == 0) {
		if( strcmp((*ludpp)->lud_scheme, "ldap") == 0 ) {
			(*ludpp)->lud_port = LDAP_PORT;
#ifdef LDAP_CONNECTIONLESS
		} else if( strcmp((*ludpp)->lud_scheme, "cldap") == 0 ) {
			(*ludpp)->lud_port = LDAP_PORT;
#endif
		} else if( strcmp((*ludpp)->lud_scheme, "ldaps") == 0 ) {
			(*ludpp)->lud_port = LDAPS_PORT;
		}
	}

	return rc;
}

LDAPURLDesc *
ldap_url_dup ( LDAPURLDesc *ludp )
{
	LDAPURLDesc *dest;

	if ( ludp == NULL ) {
		return NULL;
	}

	dest = LDAP_MALLOC( sizeof(LDAPURLDesc) );
	if (dest == NULL)
		return NULL;
	
	*dest = *ludp;
	dest->lud_scheme = NULL;
	dest->lud_host = NULL;
	dest->lud_dn = NULL;
	dest->lud_filter = NULL;
	dest->lud_attrs = NULL;
	dest->lud_exts = NULL;
	dest->lud_next = NULL;

	if ( ludp->lud_scheme != NULL ) {
		dest->lud_scheme = LDAP_STRDUP( ludp->lud_scheme );
		if (dest->lud_scheme == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	if ( ludp->lud_host != NULL ) {
		dest->lud_host = LDAP_STRDUP( ludp->lud_host );
		if (dest->lud_host == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	if ( ludp->lud_dn != NULL ) {
		dest->lud_dn = LDAP_STRDUP( ludp->lud_dn );
		if (dest->lud_dn == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	if ( ludp->lud_filter != NULL ) {
		dest->lud_filter = LDAP_STRDUP( ludp->lud_filter );
		if (dest->lud_filter == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	if ( ludp->lud_attrs != NULL ) {
		dest->lud_attrs = ldap_charray_dup( ludp->lud_attrs );
		if (dest->lud_attrs == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	if ( ludp->lud_exts != NULL ) {
		dest->lud_exts = ldap_charray_dup( ludp->lud_exts );
		if (dest->lud_exts == NULL) {
			ldap_free_urldesc(dest);
			return NULL;
		}
	}

	return dest;
}

LDAPURLDesc *
ldap_url_duplist (LDAPURLDesc *ludlist)
{
	LDAPURLDesc *dest, *tail, *ludp, *newludp;

	dest = NULL;
	tail = NULL;
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		newludp = ldap_url_dup(ludp);
		if (newludp == NULL) {
			ldap_free_urllist(dest);
			return NULL;
		}
		if (tail == NULL)
			dest = newludp;
		else
			tail->lud_next = newludp;
		tail = newludp;
	}
	return dest;
}

int
ldap_url_parselist (LDAPURLDesc **ludlist, const char *url )
{
	return ldap_url_parselist_ext( ludlist, url, ", " );
}

int
ldap_url_parselist_ext (LDAPURLDesc **ludlist, const char *url, const char *sep )
{
	int i, rc;
	LDAPURLDesc *ludp;
	char **urls;

	assert( ludlist != NULL );
	assert( url != NULL );

	*ludlist = NULL;

	urls = ldap_str2charray(url, sep);
	if (urls == NULL)
		return LDAP_URL_ERR_MEM;

	/* count the URLs... */
	for (i = 0; urls[i] != NULL; i++) ;
	/* ...and put them in the "stack" backward */
	while (--i >= 0) {
		rc = ldap_url_parse( urls[i], &ludp );
		if ( rc != 0 ) {
			ldap_charray_free(urls);
			ldap_free_urllist(*ludlist);
			*ludlist = NULL;
			return rc;
		}
		ludp->lud_next = *ludlist;
		*ludlist = ludp;
	}
	ldap_charray_free(urls);
	return LDAP_URL_SUCCESS;
}

int
ldap_url_parsehosts(
	LDAPURLDesc **ludlist,
	const char *hosts,
	int port )
{
	int i;
	LDAPURLDesc *ludp;
	char **specs, *p;

	assert( ludlist != NULL );
	assert( hosts != NULL );

	*ludlist = NULL;

	specs = ldap_str2charray(hosts, ", ");
	if (specs == NULL)
		return LDAP_NO_MEMORY;

	/* count the URLs... */
	for (i = 0; specs[i] != NULL; i++) /* EMPTY */;

	/* ...and put them in the "stack" backward */
	while (--i >= 0) {
		ludp = LDAP_CALLOC( 1, sizeof(LDAPURLDesc) );
		if (ludp == NULL) {
			ldap_charray_free(specs);
			ldap_free_urllist(*ludlist);
			*ludlist = NULL;
			return LDAP_NO_MEMORY;
		}
		ludp->lud_port = port;
		ludp->lud_host = specs[i];
		specs[i] = NULL;
		p = strchr(ludp->lud_host, ':');
		if (p != NULL) {
			/* more than one :, IPv6 address */
			if ( strchr(p+1, ':') != NULL ) {
				/* allow [address] and [address]:port */
				if ( *ludp->lud_host == '[' ) {
					p = LDAP_STRDUP(ludp->lud_host+1);
					/* copied, make sure we free source later */
					specs[i] = ludp->lud_host;
					ludp->lud_host = p;
					p = strchr( ludp->lud_host, ']' );
					if ( p == NULL )
						return LDAP_PARAM_ERROR;
					*p++ = '\0';
					if ( *p != ':' ) {
						if ( *p != '\0' )
							return LDAP_PARAM_ERROR;
						p = NULL;
					}
				} else {
					p = NULL;
				}
			}
			if (p != NULL) {
				char	*next;

				*p++ = 0;
				ldap_pvt_hex_unescape(p);
				ludp->lud_port = strtol( p, &next, 10 );
				if ( next == NULL || next[0] != '\0' ) {
					return LDAP_PARAM_ERROR;
				}
			}
		}
		ldap_pvt_hex_unescape(ludp->lud_host);
		ludp->lud_scheme = LDAP_STRDUP("ldap");
		ludp->lud_next = *ludlist;
		*ludlist = ludp;
	}

	/* this should be an array of NULLs now */
	/* except entries starting with [ */
	ldap_charray_free(specs);
	return LDAP_SUCCESS;
}

char *
ldap_url_list2hosts (LDAPURLDesc *ludlist)
{
	LDAPURLDesc *ludp;
	int size;
	char *s, *p, buf[32];	/* big enough to hold a long decimal # (overkill) */

	if (ludlist == NULL)
		return NULL;

	/* figure out how big the string is */
	size = 1;	/* nul-term */
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		size += strlen(ludp->lud_host) + 1;		/* host and space */
		if (strchr(ludp->lud_host, ':'))        /* will add [ ] below */
			size += 2;
		if (ludp->lud_port != 0)
			size += sprintf(buf, ":%d", ludp->lud_port);
	}
	s = LDAP_MALLOC(size);
	if (s == NULL)
		return NULL;

	p = s;
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		if (strchr(ludp->lud_host, ':')) {
			p += sprintf(p, "[%s]", ludp->lud_host);
		} else {
			strcpy(p, ludp->lud_host);
			p += strlen(ludp->lud_host);
		}
		if (ludp->lud_port != 0)
			p += sprintf(p, ":%d", ludp->lud_port);
		*p++ = ' ';
	}
	if (p != s)
		p--;	/* nuke that extra space */
	*p = 0;
	return s;
}

char *
ldap_url_list2urls(
	LDAPURLDesc *ludlist )
{
	LDAPURLDesc *ludp;
	int size;
	char *s, *p, buf[32];	/* big enough to hold a long decimal # (overkill) */

	if (ludlist == NULL)
		return NULL;

	/* figure out how big the string is */
	size = 1;	/* nul-term */
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		size += strlen(ludp->lud_scheme);
		if ( ludp->lud_host ) {
			size += strlen(ludp->lud_host);
			/* will add [ ] below */
			if (strchr(ludp->lud_host, ':'))
				size += 2;
		}
		size += sizeof(":/// ");

		if (ludp->lud_port != 0) {
			size += sprintf(buf, ":%d", ludp->lud_port);
		}
	}

	s = LDAP_MALLOC(size);
	if (s == NULL) {
		return NULL;
	}

	p = s;
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		p += sprintf(p, "%s://", ludp->lud_scheme);
		if ( ludp->lud_host ) {
			p += sprintf(p, strchr(ludp->lud_host, ':') 
					? "[%s]" : "%s", ludp->lud_host);
		}
		if (ludp->lud_port != 0)
			p += sprintf(p, ":%d", ludp->lud_port);
		*p++ = '/';
		*p++ = ' ';
	}
	if (p != s)
		p--;	/* nuke that extra space */
	*p = 0;
	return s;
}

void
ldap_free_urllist( LDAPURLDesc *ludlist )
{
	LDAPURLDesc *ludp, *next;

	for (ludp = ludlist; ludp != NULL; ludp = next) {
		next = ludp->lud_next;
		ldap_free_urldesc(ludp);
	}
}

void
ldap_free_urldesc( LDAPURLDesc *ludp )
{
	if ( ludp == NULL ) {
		return;
	}
	
	if ( ludp->lud_scheme != NULL ) {
		LDAP_FREE( ludp->lud_scheme );
	}

	if ( ludp->lud_host != NULL ) {
		LDAP_FREE( ludp->lud_host );
	}

	if ( ludp->lud_dn != NULL ) {
		LDAP_FREE( ludp->lud_dn );
	}

	if ( ludp->lud_filter != NULL ) {
		LDAP_FREE( ludp->lud_filter);
	}

	if ( ludp->lud_attrs != NULL ) {
		LDAP_VFREE( ludp->lud_attrs );
	}

	if ( ludp->lud_exts != NULL ) {
		LDAP_VFREE( ludp->lud_exts );
	}

	LDAP_FREE( ludp );
}

static int
ldap_int_unhex( int c )
{
	return( c >= '0' && c <= '9' ? c - '0'
	    : c >= 'A' && c <= 'F' ? c - 'A' + 10
	    : c - 'a' + 10 );
}

void
ldap_pvt_hex_unescape( char *s )
{
	/*
	 * Remove URL hex escapes from s... done in place.  The basic concept for
	 * this routine is borrowed from the WWW library HTUnEscape() routine.
	 */
	char	*p;

	for ( p = s; *s != '\0'; ++s ) {
		if ( *s == '%' ) {
			if ( *++s == '\0' ) {
				break;
			}
			*p = ldap_int_unhex( *s ) << 4;
			if ( *++s == '\0' ) {
				break;
			}
			*p++ += ldap_int_unhex( *s );
		} else {
			*p++ = *s;
		}
	}

	*p = '\0';
}


