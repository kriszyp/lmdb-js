/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
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
 * searchpref.c:  search preferences library routines for LDAP clients
 * 17 May 1994 by Gordon Good
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "ldap-int.h"
#include "srchpref.h"

#include "ldap-int.h"

static void free_searchobj LDAP_P(( struct ldap_searchobj *so ));
static int read_next_searchobj LDAP_P(( char **bufp, ber_len_t *blenp,
	struct ldap_searchobj **sop, int soversion ));


static const char *const	sobjoptions[] = {
    "internal",
    NULL
};


static const unsigned long	sobjoptvals[] = {
    LDAP_SEARCHOBJ_OPT_INTERNAL,
};


int
ldap_init_searchprefs( char *file, struct ldap_searchobj **solistp )
{
    FILE	*fp;
    char	*buf;
    long	rlen, len;
    int		rc, eof;

    if (( fp = fopen( file, "r" )) == NULL ) {
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    if ( fseek( fp, 0L, SEEK_END ) != 0 ) {	/* move to end to get len */
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    len = ftell( fp );

    if ( fseek( fp, 0L, SEEK_SET ) != 0 ) {	/* back to start of file */
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    if (( buf = LDAP_MALLOC( (size_t)len )) == NULL ) {
	fclose( fp );
	return( LDAP_SEARCHPREF_ERR_MEM );
    }

    rlen = fread( buf, 1, (size_t)len, fp );
    eof = feof( fp );
    fclose( fp );

    if ( rlen != len && !eof ) {	/* error:  didn't get the whole file */
	LDAP_FREE( buf );
	return( LDAP_SEARCHPREF_ERR_FILE );
    }

    rc = ldap_init_searchprefs_buf( buf, rlen, solistp );
    LDAP_FREE( buf );

    return( rc );
}


int
ldap_init_searchprefs_buf(
	char *buf,
	ber_len_t buflen,
	struct ldap_searchobj **solistp )
{
    int				rc = -1, version;
    char			**toks;
    struct ldap_searchobj	*prevso, *so;

    *solistp = prevso = NULL;

    if ( next_line_tokens( &buf, &buflen, &toks ) != 2 ||
	    strcasecmp( toks[ 0 ], "version" ) != 0 ) {
	free_strarray( toks );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    version = atoi( toks[ 1 ] );
    free_strarray( toks );
    if ( version != LDAP_SEARCHPREF_VERSION &&
	    version != LDAP_SEARCHPREF_VERSION_ZERO ) {
	return( LDAP_SEARCHPREF_ERR_VERSION );
    }

    while ( buflen > 0 && ( rc = read_next_searchobj( &buf, &buflen, &so,
	    version )) == 0 && so != NULL ) {
	if ( prevso == NULL ) {
	    *solistp = so;
	} else {
	    prevso->so_next = so;
	}
	prevso = so;
    }

    if ( rc != 0 ) {
	ldap_free_searchprefs( *solistp );
    }

    return( rc );
}
	    


void
ldap_free_searchprefs( struct ldap_searchobj *solist )
{
    struct ldap_searchobj	*so, *nextso;

    if ( solist != NULL ) {
	for ( so = solist; so != NULL; so = nextso ) {
	    nextso = so->so_next;
	    free_searchobj( so );
	}
    }
    /* XXX XXX need to do some work here */
}


static void
free_searchobj( struct ldap_searchobj *so )
{
    if ( so != NULL ) {
	if ( so->so_objtypeprompt != NULL ) {
	    LDAP_FREE(  so->so_objtypeprompt );
	}
	if ( so->so_prompt != NULL ) {
	    LDAP_FREE(  so->so_prompt );
	}
	if ( so->so_filterprefix != NULL ) {
	    LDAP_FREE(  so->so_filterprefix );
	}
	if ( so->so_filtertag != NULL ) {
	    LDAP_FREE(  so->so_filtertag );
	}
	if ( so->so_defaultselectattr != NULL ) {
	    LDAP_FREE(  so->so_defaultselectattr );
	}
	if ( so->so_defaultselecttext != NULL ) {
	    LDAP_FREE(  so->so_defaultselecttext );
	}
	if ( so->so_salist != NULL ) {
	    struct ldap_searchattr *sa, *nextsa;
	    for ( sa = so->so_salist; sa != NULL; sa = nextsa ) {
		nextsa = sa->sa_next;
		if ( sa->sa_attrlabel != NULL ) {
		    LDAP_FREE( sa->sa_attrlabel );
		}
		if ( sa->sa_attr != NULL ) {
		    LDAP_FREE( sa->sa_attr );
		}
		if ( sa->sa_selectattr != NULL ) {
		    LDAP_FREE( sa->sa_selectattr );
		}
		if ( sa->sa_selecttext != NULL ) {
		    LDAP_FREE( sa->sa_selecttext );
		}
		LDAP_FREE( sa );
	    }
	}
	if ( so->so_smlist != NULL ) {
	    struct ldap_searchmatch *sm, *nextsm;
	    for ( sm = so->so_smlist; sm != NULL; sm = nextsm ) {
		nextsm = sm->sm_next;
		if ( sm->sm_matchprompt != NULL ) {
		    LDAP_FREE( sm->sm_matchprompt );
		}
		if ( sm->sm_filter != NULL ) {
		    LDAP_FREE( sm->sm_filter );
		}
		LDAP_FREE( sm );
	    }
	}
	LDAP_FREE( so );
    }
}



struct ldap_searchobj *
ldap_first_searchobj( struct ldap_searchobj *solist )
{
    return( solist );
}


struct ldap_searchobj *
ldap_next_searchobj( struct ldap_searchobj *solist, struct ldap_searchobj *so )
{
    return( so == NULL ? so : so->so_next );
}



static int
read_next_searchobj(
	char **bufp,
	ber_len_t *blenp,
	struct ldap_searchobj **sop,
	int soversion )
{
    int				i, j, tokcnt;
    char			**toks;
    struct ldap_searchobj	*so;
    struct ldap_searchattr	**sa;
    struct ldap_searchmatch	**sm;

    *sop = NULL;

    /*
     * Object type prompt comes first
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	return( tokcnt == 0 ? 0 : LDAP_SEARCHPREF_ERR_SYNTAX );
    }

    if (( so = (struct ldap_searchobj *)LDAP_CALLOC( 1,
	    sizeof( struct ldap_searchobj ))) == NULL ) {
	free_strarray( toks );
	return(  LDAP_SEARCHPREF_ERR_MEM );
    }
    so->so_objtypeprompt = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * if this is post-version zero, options come next
     */
    if ( soversion > LDAP_SEARCHPREF_VERSION_ZERO ) {
	if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) < 1 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	for ( i = 0; toks[ i ] != NULL; ++i ) {
	    for ( j = 0; sobjoptions[ j ] != NULL; ++j ) {
		if ( strcasecmp( toks[ i ], sobjoptions[ j ] ) == 0 ) {
		    so->so_options |= sobjoptvals[ j ];
		}
	    }
	}
	free_strarray( toks );
    }

    /*
     * "Fewer choices" prompt is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_prompt = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * Filter prefix for "More Choices" searching is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_filterprefix = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * "Fewer Choices" filter tag comes next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_filtertag = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * Selection (disambiguation) attribute comes next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_defaultselectattr = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * Label for selection (disambiguation) attribute
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    so->so_defaultselecttext = toks[ 0 ];
    LDAP_FREE( (char *)toks );

    /*
     * Search scope is next
     */
    if (( tokcnt = next_line_tokens( bufp, blenp, &toks )) != 1 ) {
	free_strarray( toks );
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    if ( !strcasecmp(toks[ 0 ], "subtree" )) {
	so->so_defaultscope = LDAP_SCOPE_SUBTREE;
    } else if ( !strcasecmp(toks[ 0 ], "onelevel" )) {
	so->so_defaultscope = LDAP_SCOPE_ONELEVEL;
    } else if ( !strcasecmp(toks[ 0 ], "base" )) {
	so->so_defaultscope = LDAP_SCOPE_BASE;
    } else {
	ldap_free_searchprefs( so );
	return( LDAP_SEARCHPREF_ERR_SYNTAX );
    }
    free_strarray( toks );


    /*
     * "More Choices" search option list comes next
     */
    sa = &( so->so_salist );
    while (( tokcnt = next_line_tokens( bufp, blenp, &toks )) > 0 ) {
	if ( tokcnt < 5 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	if (( *sa = ( struct ldap_searchattr * ) LDAP_CALLOC( 1,
		sizeof( struct ldap_searchattr ))) == NULL ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return(  LDAP_SEARCHPREF_ERR_MEM );
	}
	( *sa )->sa_attrlabel = toks[ 0 ];
	( *sa )->sa_attr = toks[ 1 ];
	( *sa )->sa_selectattr = toks[ 3 ];
	( *sa )->sa_selecttext = toks[ 4 ];
	/* Deal with bitmap */
	( *sa )->sa_matchtypebitmap = 0;
	for ( i = strlen( toks[ 2 ] ) - 1, j = 0; i >= 0; i--, j++ ) {
	    if ( toks[ 2 ][ i ] == '1' ) {
		( *sa )->sa_matchtypebitmap |= (1 << j);
	    }
	}
	LDAP_FREE( toks[ 2 ] );
	LDAP_FREE( ( char * ) toks );
	sa = &(( *sa )->sa_next);
    }
    *sa = NULL;

    /*
     * Match types are last
     */
    sm = &( so->so_smlist );
    while (( tokcnt = next_line_tokens( bufp, blenp, &toks )) > 0 ) {
	if ( tokcnt < 2 ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return( LDAP_SEARCHPREF_ERR_SYNTAX );
	}
	if (( *sm = ( struct ldap_searchmatch * ) LDAP_CALLOC( 1,
		sizeof( struct ldap_searchmatch ))) == NULL ) {
	    free_strarray( toks );
	    ldap_free_searchprefs( so );
	    return(  LDAP_SEARCHPREF_ERR_MEM );
	}
	( *sm )->sm_matchprompt = toks[ 0 ];
	( *sm )->sm_filter = toks[ 1 ];
	LDAP_FREE( ( char * ) toks );
	sm = &(( *sm )->sm_next );
    }
    *sm = NULL;

    *sop = so;
    return( 0 );
}
