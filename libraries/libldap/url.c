/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1996 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  LIBLDAP url.c -- LDAP URL related routines
 *
 *  LDAP URLs look like this:
 *    l d a p : / / hostport / dn [ ? attributes [ ? scope [ ? filter ] ] ]
 *
 *  where:
 *   attributes is a comma separated list
 *   scope is one of these three strings:  base one sub (default=base)
 *   filter is an string-represented filter as in RFC 1558
 *
 *  e.g.,  ldap://ldap.itd.umich.edu/c=US?o,description?one?o=umich
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
static const char* skip_url_prefix LDAP_P(( const char *url, int *enclosedp ));
static void hex_unescape LDAP_P(( char *s ));
static int unhex( char c );


int
ldap_is_ldap_url( LDAP_CONST char *url )
{
	int	enclosed;

	return( url != NULL && skip_url_prefix( url, &enclosed ) != NULL );
}


static const char*
skip_url_prefix( const char *url, int *enclosedp )
{
/*
 * return non-zero if this looks like a LDAP URL; zero if not
 * if non-zero returned, *urlp will be moved past "ldap://" part of URL
 */
	char* p;

	if ( url == NULL ) {
		return( NULL );
	}

	p = (char *) url;

	/* skip leading '<' (if any) */
	if ( *p == '<' ) {
		*enclosedp = 1;
		++p;
	} else {
		*enclosedp = 0;
	}

	/* skip leading "URL:" (if any) */
	if ( strlen( p ) >= LDAP_URL_URLCOLON_LEN
		&& strncasecmp( p, LDAP_URL_URLCOLON, LDAP_URL_URLCOLON_LEN ) == 0 )
	{
		p += LDAP_URL_URLCOLON_LEN;
	}

	/* check for missing "ldap://" prefix */
	if ( strlen( p ) < LDAP_URL_PREFIX_LEN ||
	    strncasecmp( p, LDAP_URL_PREFIX, LDAP_URL_PREFIX_LEN ) != 0 ) {
		return( NULL );
	}

	/* skip over "ldap://" prefix and return success */
	p += LDAP_URL_PREFIX_LEN;
	return( p );
}



int
ldap_url_parse( LDAP_CONST char *url_in, LDAPURLDesc **ludpp )
{
/*
 *  Pick apart the pieces of an LDAP URL.
 */

	LDAPURLDesc	*ludp;
	char		*attrs, *p, *q;
	int		enclosed, i, nattrs;
	const char *url_tmp;
	char *url;

	Debug( LDAP_DEBUG_TRACE, "ldap_url_parse(%s)\n", url_in, 0, 0 );

	*ludpp = NULL;	/* pessimistic */

	url_tmp = skip_url_prefix( url_in, &enclosed );

	if ( url_tmp == NULL ) {
		return( LDAP_URL_ERR_NOTLDAP );
	}

	/* make working copy of the remainder of the URL */
	if (( url = LDAP_STRDUP( url_tmp )) == NULL ) {
		return( LDAP_URL_ERR_MEM );
	}

	/* allocate return struct */
	if (( ludp = (LDAPURLDesc *)LDAP_CALLOC( 1, sizeof( LDAPURLDesc )))
	    == NULLLDAPURLDESC )
	{
		LDAP_FREE( url );
		return( LDAP_URL_ERR_MEM );
	}


	if ( enclosed && *((p = url + strlen( url ) - 1)) == '>' ) {
		*p = '\0';
	}

	/* set defaults */
	ludp->lud_scope = LDAP_SCOPE_BASE;
	ludp->lud_filter = "(objectClass=*)";

	/* lud_string is the only malloc'd string space we use */
	ludp->lud_string = url;

	/* scan forward for '/' that marks end of hostport and begin. of dn */
	if (( ludp->lud_dn = strchr( url, '/' )) == NULL ) {
		ldap_free_urldesc( ludp );
		return( LDAP_URL_ERR_NODN );
	}

	/* terminate hostport; point to start of dn */
	*ludp->lud_dn++ = '\0';

	if (( p = strchr( url, ':' )) != NULL ) {
		*p++ = '\0';
		ludp->lud_port = atoi( p );
	}

	if ( *url == '\0' ) {
		ludp->lud_host = NULL;
	} else {
		ludp->lud_host = url;
		hex_unescape( ludp->lud_host );
	}

	/* scan for '?' that marks end of dn and beginning of attributes */
	if (( attrs = strchr( ludp->lud_dn, '?' )) != NULL ) {
		/* terminate dn; point to start of attrs. */
		*attrs++ = '\0';

		/* scan for '?' that marks end of attrs and begin. of scope */
		if (( p = strchr( attrs, '?' )) != NULL ) {
			/*
			 * terminate attrs; point to start of scope and scan for
			 * '?' that marks end of scope and begin. of filter
			 */
			*p++ = '\0';

			if (( q = strchr( p, '?' )) != NULL ) {
				/* terminate scope; point to start of filter */
				*q++ = '\0';
				if ( *q != '\0' ) {
					ludp->lud_filter = q;
					hex_unescape( ludp->lud_filter );
				}
			}

			if ( strcasecmp( p, "one" ) == 0 ) {
				ludp->lud_scope = LDAP_SCOPE_ONELEVEL;
			} else if ( strcasecmp( p, "base" ) == 0 ) {
				ludp->lud_scope = LDAP_SCOPE_BASE;
			} else if ( strcasecmp( p, "sub" ) == 0 ) {
				ludp->lud_scope = LDAP_SCOPE_SUBTREE;
			} else if ( *p != '\0' ) {
				ldap_free_urldesc( ludp );
				return( LDAP_URL_ERR_BADSCOPE );
			}
		}
	}

	if ( *ludp->lud_dn == '\0' ) {
		ludp->lud_dn = NULL;
	} else {
		hex_unescape( ludp->lud_dn );
	}

	/*
	 * if attrs list was included, turn it into a null-terminated array
	 */
	if ( attrs != NULL && *attrs != '\0' ) {
		for ( nattrs = 1, p = attrs; *p != '\0'; ++p ) {
		    if ( *p == ',' ) {
			    ++nattrs;
		    }
		}

		if (( ludp->lud_attrs = (char **)LDAP_CALLOC( nattrs + 1,
		    sizeof( char * ))) == NULL ) {
			ldap_free_urldesc( ludp );
			return( LDAP_URL_ERR_MEM );
		}

		for ( i = 0, p = attrs; i < nattrs; ++i ) {
			ludp->lud_attrs[ i ] = p;
			if (( p = strchr( p, ',' )) != NULL ) {
				*p++ ='\0';
			}
			hex_unescape( ludp->lud_attrs[ i ] );
		}
	}

	*ludpp = ludp;

	return( 0 );
}


void
ldap_free_urldesc( LDAPURLDesc *ludp )
{
	if ( ludp != NULLLDAPURLDESC ) {
		if ( ludp->lud_string != NULL ) {
			LDAP_FREE( ludp->lud_string );
		}
		if ( ludp->lud_attrs != NULL ) {
			LDAP_FREE( ludp->lud_attrs );
		}
		LDAP_FREE( ludp );
	}
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


static void
hex_unescape( char *s )
{
/*
 * Remove URL hex escapes from s... done in place.  The basic concept for
 * this routine is borrowed from the WWW library HTUnEscape() routine.
 */
	char	*p;

	for ( p = s; *s != '\0'; ++s ) {
		if ( *s == '%' ) {
			if ( *++s != '\0' ) {
				*p = unhex( *s ) << 4;
			}
			if ( *++s != '\0' ) {
				*p++ += unhex( *s );
			}
		} else {
			*p++ = *s;
		}
	}

	*p = '\0';
}


static int
unhex( char c )
{
	return( c >= '0' && c <= '9' ? c - '0'
	    : c >= 'A' && c <= 'F' ? c - 'A' + 10
	    : c - 'a' + 10 );
}
