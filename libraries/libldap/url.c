/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1996 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  LIBLDAP url.c -- LDAP URL (RFC 2255) related routines
 *
 *  LDAP URLs look like this:
 *    ldap[s]://host:port[/[dn[?[attributes][?[scope][?[filter][?exts]]]]]]
 *
 *  where:
 *   attributes is a comma separated list
 *   scope is one of these three strings:  base one sub (default=base)
 *   filter is an string-represented filter as in RFC 2254
 *
 *  e.g.,  ldap://host:port/dc=com?o,cn?base?o=openldap?extension
 *
 *  We also tolerate URLs that look like: <ldapurl> and <URL:ldapurl>
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"


/* local functions */
static const char* skip_url_prefix LDAP_P((
	const char *url,
	int *enclosedp,
	unsigned long *properties,
	int *protocol));


int
ldap_is_ldap_url( LDAP_CONST char *url )
{
	int	enclosed, protocol;
	unsigned long properties;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &properties, &protocol) == NULL ) {
		return 0;
	}

	return !(properties & LDAP_URL_USE_SSL);
}

int
ldap_is_ldaps_url( LDAP_CONST char *url )
{
	int	enclosed, protocol;
	unsigned long properties;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &properties, &protocol) == NULL ) {
		return 0;
	}

	return (properties & LDAP_URL_USE_SSL);
}

static const char*
skip_url_prefix(
	const char *url,
	int *enclosedp,
	unsigned long *properties,
	int *protocol
	)
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
	if ( strncasecmp( p, LDAP_URL_URLCOLON, LDAP_URL_URLCOLON_LEN ) == 0 )
	{
		p += LDAP_URL_URLCOLON_LEN;
	}

	*properties = 0;

	/* check for "ldap://" prefix */
	if ( strncasecmp( p, LDAP_URL_PREFIX, LDAP_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldap://" prefix and return success */
		p += LDAP_URL_PREFIX_LEN;
		*protocol = LDAP_PROTO_TCP;
		return( p );
	}

	/* check for "ldaps://" prefix */
	if ( strncasecmp( p, LDAPS_URL_PREFIX, LDAPS_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldaps://" prefix and return success */
		p += LDAPS_URL_PREFIX_LEN;
		*protocol = LDAP_PROTO_TCP;
		*properties |= LDAP_URL_USE_SSL;
		return( p );
	}

	/* check for "ldapi://" prefix */
	if ( strncasecmp( p, LDAPI_URL_PREFIX, LDAPI_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldapi://" prefix and return success */
		p += LDAPI_URL_PREFIX_LEN;
		*protocol = LDAP_PROTO_LOCAL;
		return( p );
	}

	/* check for "ldapis://" prefix: should this be legal? */
	if ( strncasecmp( p, LDAPIS_URL_PREFIX, LDAPIS_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldapis://" prefix and return success */
		p += LDAPIS_URL_PREFIX_LEN;
		*protocol = LDAP_PROTO_LOCAL;
		*properties |= LDAP_URL_USE_SSL;
		return( p );
	}

	return( NULL );
}


static int str2scope( const char *p )
{
	if ( strcasecmp( p, "one" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( p, "onetree" ) == 0 ) {
		return LDAP_SCOPE_ONELEVEL;

	} else if ( strcasecmp( p, "base" ) == 0 ) {
		return LDAP_SCOPE_BASE;

	} else if ( strcasecmp( p, "sub" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;

	} else if ( strcasecmp( p, "subtree" ) == 0 ) {
		return LDAP_SCOPE_SUBTREE;
	}

	return( -1 );
}


int
ldap_url_parse( LDAP_CONST char *url_in, LDAPURLDesc **ludpp )
{
/*
 *  Pick apart the pieces of an LDAP URL.
 */

	LDAPURLDesc	*ludp;
	char	*p, *q;
	int		i, enclosed, protocol;
	unsigned long properties;
	const char *url_tmp;
	char *url;

	if( url_in == NULL && ludpp == NULL ) {
		return LDAP_URL_ERR_PARAM;
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_url_parse(%s)\n", url_in, 0, 0 );

	*ludpp = NULL;	/* pessimistic */

	url_tmp = skip_url_prefix( url_in, &enclosed, &properties, &protocol );

	if ( url_tmp == NULL ) {
		return LDAP_URL_ERR_NOTLDAP;
	}

	/* make working copy of the remainder of the URL */
	if (( url = LDAP_STRDUP( url_tmp )) == NULL ) {
		return( LDAP_URL_ERR_MEM );
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
	ludp->lud_filter = NULL;
	ludp->lud_properties = properties;
	ludp->lud_protocol = protocol;
	ludp->lud_scope = LDAP_SCOPE_BASE;

	ludp->lud_filter = LDAP_STRDUP("(objectClass=*)");

	if( ludp->lud_filter == NULL ) {
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

	if (( q = strchr( url, ':' )) != NULL ) {
		*q++ = '\0';
		ldap_pvt_hex_unescape( q );

		if( *q == '\0' ) {
			LDAP_FREE( url );
			ldap_free_urldesc( ludp );
			return LDAP_URL_ERR_BADURL;
		}

		ludp->lud_port = atoi( q );
	}

	ldap_pvt_hex_unescape( url );
	ludp->lud_host = LDAP_STRDUP( url );

	if( ludp->lud_host == NULL ) {
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_MEM;
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

		LDAP_FREE( ludp->lud_filter );
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
	}

	if( i == 0 ) {
		/* must have 1 or more */
		ldap_charray_free( ludp->lud_exts );
		LDAP_FREE( url );
		ldap_free_urldesc( ludp );
		return LDAP_URL_ERR_BADEXTS;
	}

	/* no more */
	*ludpp = ludp;
	LDAP_FREE( url );
	return LDAP_URL_SUCCESS;
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
	dest->lud_next = NULL;

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
	int i, rc;
	LDAPURLDesc *ludp;
	char **urls;

	*ludlist = NULL;

	if (url == NULL)
		return LDAP_PARAM_ERROR;

	urls = ldap_str2charray((char *)url, ", ");
	if (urls == NULL)
		return LDAP_NO_MEMORY;

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
	return LDAP_SUCCESS;
}

int
ldap_url_parsehosts (LDAPURLDesc **ludlist, const char *hosts )
{
	int i;
	LDAPURLDesc *ludp;
	char **specs, *p;

	*ludlist = NULL;

	if (hosts == NULL)
		return LDAP_PARAM_ERROR;

	specs = ldap_str2charray((char *)hosts, ", ");
	if (specs == NULL)
		return LDAP_NO_MEMORY;

	/* count the URLs... */
	for (i = 0; specs[i] != NULL; i++) ;
	/* ...and put them in the "stack" backward */
	while (--i >= 0) {
		ludp = LDAP_CALLOC( 1, sizeof(LDAPURLDesc) );
		if (ludp == NULL) {
			ldap_charray_free(specs);
			ldap_free_urllist(*ludlist);
			*ludlist = NULL;
			return LDAP_NO_MEMORY;
		}
		ludp->lud_host = specs[i];
		specs[i] = NULL;
		p = strchr(ludp->lud_host, ':');
		if (p != NULL) {
			*p++ = 0;
			ldap_pvt_hex_unescape(p);
			ludp->lud_port = atoi(p);
		}
		ldap_pvt_hex_unescape(ludp->lud_host);
		ludp->lud_protocol = LDAP_PROTO_TCP;
		ludp->lud_properties = 0;
		ludp->lud_next = *ludlist;
		*ludlist = ludp;
	}

	/* this should be an array of NULLs now */
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
		if (ludp->lud_port != 0)
			size += sprintf(buf, ":%d", ludp->lud_port);
	}
	s = LDAP_MALLOC(size);
	if (s == NULL)
		return NULL;

	p = s;
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		strcpy(p, ludp->lud_host);
		p += strlen(ludp->lud_host);
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
ldap_url_list2urls (LDAPURLDesc *ludlist)
{
	LDAPURLDesc *ludp;
	int size;
	char *s, *p, buf[32];	/* big enough to hold a long decimal # (overkill) */

	if (ludlist == NULL)
		return NULL;

	/* figure out how big the string is */
	size = 1;	/* nul-term */
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		size += strlen(ludp->lud_host) + 1 + sizeof("ldapis:///");	/* prefix, host, /, and space */
		if (ludp->lud_port != 0)
			size += sprintf(buf, ":%d", ludp->lud_port);
	}
	s = LDAP_MALLOC(size);
	if (s == NULL)
		return NULL;

	p = s;
	for (ludp = ludlist; ludp != NULL; ludp = ludp->lud_next) {
		p += sprintf(p, "ldap%s://%s", (ludp->lud_properties & LDAP_URL_USE_SSL) ? "s" : "", ludp->lud_host);
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



int
ldap_url_search( LDAP *ld, LDAP_CONST char *url, int attrsonly )
{
	int		err;
	LDAPURLDesc	*ludp;
	BerElement	*ber;

	if ( ldap_url_parse( url, &ludp ) != 0 ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return( -1 );
	}

	ber = ldap_build_search_req( ld, ludp->lud_dn, ludp->lud_scope,
	    ludp->lud_filter, ludp->lud_attrs, attrsonly, NULL, NULL,
		-1, -1 );

	if ( ber == NULL ) {
		err = -1;
	} else {
		err = ldap_send_server_request(
					ld, ber, ld->ld_msgid, NULL,
					(ludp->lud_host != NULL || ludp->lud_port != 0)
						? ludp : NULL,
					NULL, 1 );
	}

	ldap_free_urldesc( ludp );
	return( err );
}


int
ldap_url_search_st( LDAP *ld, LDAP_CONST char *url, int attrsonly,
	struct timeval *timeout, LDAPMessage **res )
{
	int	msgid;

	if (( msgid = ldap_url_search( ld, url, attrsonly )) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ldap_result( ld, msgid, 1, timeout, res ) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ld->ld_errno == LDAP_TIMEOUT ) {
		(void) ldap_abandon( ld, msgid );
		ld->ld_errno = LDAP_TIMEOUT;
		return( ld->ld_errno );
	}

	return( ldap_result2error( ld, *res, 0 ));
}


int
ldap_url_search_s(
	LDAP *ld, LDAP_CONST char *url, int attrsonly, LDAPMessage **res )
{
	int	msgid;

	if (( msgid = ldap_url_search( ld, url, attrsonly )) == -1 ) {
		return( ld->ld_errno );
	}

	if ( ldap_result( ld, msgid, 1, (struct timeval *)NULL, res ) == -1 ) {
		return( ld->ld_errno );
	}

	return( ldap_result2error( ld, *res, 0 ));
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
			if ( *++s != '\0' ) {
				*p = ldap_pvt_unhex( *s ) << 4;
			}
			if ( *++s != '\0' ) {
				*p++ += ldap_pvt_unhex( *s );
			}
		} else {
			*p++ = *s;
		}
	}

	*p = '\0';
}


int
ldap_pvt_unhex( int c )
{
	return( c >= '0' && c <= '9' ? c - '0'
	    : c >= 'A' && c <= 'F' ? c - 'A' + 10
	    : c - 'a' + 10 );
}
