/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 * Copyright (c) 1993, 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * dsparse.c:  parsing routines used by display template and search 
 * preference file library routines for LDAP clients.
 *
 * 7 March 1994 by Mark C Smith
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "ldap-int.h"

static int next_line LDAP_P(( char **bufp, ber_len_t *blenp, char **linep ));
static char *next_token LDAP_P(( char ** sp ));


int
ldap_int_next_line_tokens( char **bufp, ber_len_t *blenp, char ***toksp )
{
    char	*p, *line, *token, **toks;
    int		rc, tokcnt;

    *toksp = NULL;

    if (( rc = next_line( bufp, blenp, &line )) <= 0 ) {
	return( rc );
    }

    if (( toks = (char **)LDAP_CALLOC( 1, sizeof( char * ))) == NULL ) {
	LBER_FREE( line );
	return( -1 );
    }
    tokcnt = 0;

    p = line;
    while (( token = next_token( &p )) != NULL ) {
	if (( toks = (char **)LDAP_REALLOC( toks, ( tokcnt + 2 ) *
		sizeof( char * ))) == NULL ) {
	    LBER_FREE( (char *)toks );
	    LBER_FREE( line );
	    return( -1 );
	}
	toks[ tokcnt ] = token;
	toks[ ++tokcnt ] = NULL;
    }

    if ( tokcnt == 1 && strcasecmp( toks[ 0 ], "END" ) == 0 ) {
	tokcnt = 0;
	LDAP_VFREE( toks );
	toks = NULL;
    }

    LBER_FREE( line );

    if ( tokcnt == 0 ) {
	if ( toks != NULL ) {
	    LBER_FREE( (char *)toks );
	}
    } else {
	*toksp = toks;
    }

    return( tokcnt );
}


static int
next_line( char **bufp, ber_len_t *blenp, char **linep )
{
    char	*linestart, *line, *p;
    ber_slen_t	plen;

    linestart = *bufp;
    p = *bufp;
    plen = *blenp;

    do {
	for ( linestart = p; plen > 0; ++p, --plen ) {
	    if ( *p == '\r' ) {
		if ( plen > 1 && *(p+1) == '\n' ) {
		    ++p;
		    --plen;
		}
		break;
	    }

	    if ( *p == '\n' ) {
		if ( plen > 1 && *(p+1) == '\r' ) {
		    ++p;
		    --plen;
		}
		break;
	    }
	}
	++p;
	--plen;
    } while ( plen > 0 && ( *linestart == '#' || linestart + 1 == p ));


    *bufp = p;
    *blenp = plen;


    if ( plen <= 0 ) {
	*linep = NULL;
	return( 0 );	/* end of file */
    }

    if (( line = LDAP_MALLOC( p - linestart )) == NULL ) {
	*linep = NULL;
	return( -1 );	/* fatal error */
    }

    (void) memcpy( line, linestart, p - linestart );
    line[ p - linestart - 1 ] = '\0';
    *linep = line;
    return( strlen( line ));
}


static char *
next_token( char **sp )
{
    int		in_quote = 0;
    char	*p, *tokstart, *t;

    if ( **sp == '\0' ) {
	return( NULL );
    }

    p = *sp;

    while ( isspace( (unsigned char) *p )) {	/* skip leading white space */
	++p;
    }

    if ( *p == '\0' ) {
	return( NULL );
    }

    if ( *p == '\"' ) {
	in_quote = 1;
	++p;
    }
    t = tokstart = p;

    for ( ;; ) {
	if ( *p == '\0' || ( isspace( (unsigned char) *p ) && !in_quote )) {
	    if ( *p != '\0' ) {
		++p;
	    }
	    *t++ = '\0';		/* end of token */
	    break;
	}

	if ( *p == '\"' ) {
	    in_quote = !in_quote;
	    ++p;
	} else {
	    *t++ = *p++;
	}
    }

    *sp = p;

    if ( t == tokstart ) {
	return( NULL );
    }

    return( LDAP_STRDUP( tokstart ));
}
