/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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
	int *ldaps ));


int
ldap_is_ldap_url( LDAP_CONST char *url )
{
	int	enclosed;
	int ldaps;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &ldaps) == NULL ) {
		return 0;
	}

	return !ldaps;
}

int
ldap_is_ldaps_url( LDAP_CONST char *url )
{
	int	enclosed;
	int ldaps;

	if( url == NULL ) {
		return 0;
	}

	if( skip_url_prefix( url, &enclosed, &ldaps) == NULL ) {
		return 0;
	}

	return ldaps;
}

static const char*
skip_url_prefix(
	const char *url,
	int *enclosedp,
	int *ldaps )
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

	/* check for "ldap://" prefix */
	if ( strncasecmp( p, LDAP_URL_PREFIX, LDAP_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldap://" prefix and return success */
		p += LDAP_URL_PREFIX_LEN;
		*ldaps = 0;
		return( p );
	}

	/* check for "ldaps://" prefix */
	if ( strncasecmp( p, LDAPS_URL_PREFIX, LDAPS_URL_PREFIX_LEN ) == 0 ) {
		/* skip over "ldaps://" prefix and return success */
		p += LDAPS_URL_PREFIX_LEN;
		*ldaps = 1;
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
	int		i, enclosed, ldaps;
	const char *url_tmp;
	char *url;

	if( url_in == NULL && ludpp == NULL ) {
		return LDAP_URL_ERR_PARAM;
	}

	Debug( LDAP_DEBUG_TRACE, "ldap_url_parse(%s)\n", url_in, 0, 0 );

	*ludpp = NULL;	/* pessimistic */

	url_tmp = skip_url_prefix( url_in, &enclosed, &ldaps );

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

	ludp->lud_host = NULL;
	ludp->lud_port = 0;
    ludp->lud_dn = NULL;
    ludp->lud_attrs = NULL;
    ludp->lud_filter = NULL;
	ludp->lud_ldaps = ldaps;
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
	LDAPServer	*srv = NULL;

	if ( ldap_url_parse( url, &ludp ) != 0 ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return( -1 );
	}

	ber = ldap_build_search_req( ld, ludp->lud_dn, ludp->lud_scope,
	    ludp->lud_filter, ludp->lud_attrs, attrsonly, NULL, NULL,
		-1, -1 );

	if ( ber == NULL ) {
		return( -1 );
	}

	err = 0;

	if ( ludp->lud_host != NULL || ludp->lud_port != 0 ) {
		if (( srv = (LDAPServer *)LDAP_CALLOC( 1, sizeof( LDAPServer )))
		    == NULL || ( srv->lsrv_host = LDAP_STRDUP( ludp->lud_host ==
		    NULL ? ld->ld_defhost : ludp->lud_host )) == NULL ) {
			if ( srv != NULL ) {
				LDAP_FREE( srv );
			}
			ld->ld_errno = LDAP_NO_MEMORY;
			err = -1;
		} else {
			if ( ludp->lud_port == 0 ) {
				srv->lsrv_port = ldap_int_global_options.ldo_defport;
			} else {
				srv->lsrv_port = ludp->lud_port;
			}
		}
	}

	if ( err != 0 ) {
		ber_free( ber, 1 );
	} else {
		err = ldap_send_server_request( ld, ber, ld->ld_msgid, NULL, srv,
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
