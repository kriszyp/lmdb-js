/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1993 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  getfilter.c -- optional add-on to libldap
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/regex.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "ldap-int.h"

static int break_into_words LDAP_P((
	/* LDAP_CONST */ char *str,
	LDAP_CONST char *delims,
	char ***wordsp ));

#define FILT_MAX_LINE_LEN	1024

LDAPFiltDesc *
ldap_init_getfilter( LDAP_CONST char *fname )
{
    FILE		*fp;
    char		*buf;
    long		rlen, len;
    int 		eof;
    LDAPFiltDesc	*lfdp;

    if (( fp = fopen( fname, "r" )) == NULL ) {
	return( NULL );
    }

    if ( fseek( fp, 0L, SEEK_END ) != 0 ) {	/* move to end to get len */
	fclose( fp );
	return( NULL );
    }

    len = ftell( fp );

    if ( fseek( fp, 0L, SEEK_SET ) != 0 ) {	/* back to start of file */
	fclose( fp );
	return( NULL );
    }

    if (( buf = LDAP_MALLOC( (size_t)len )) == NULL ) {
	fclose( fp );
	return( NULL );
    }

    rlen = fread( buf, 1, (size_t)len, fp );
    eof = feof( fp );
    fclose( fp );

    if ( rlen != len && !eof ) {	/* error:  didn't get the whole file */
	LDAP_FREE( buf );
	return( NULL );
    }


    lfdp = ldap_init_getfilter_buf( buf, rlen );
    LDAP_FREE( buf );

    return( lfdp );
}


LDAPFiltDesc *
ldap_init_getfilter_buf( char *buf, ber_len_t buflen )
{
    LDAPFiltDesc	*lfdp;
    LDAPFiltList	*flp, *nextflp;
    LDAPFiltInfo	*fip, *nextfip;
    char			*tag, **tok;
    int				tokcnt, i;
	int				rc;
	regex_t			re;

    if (( lfdp = (LDAPFiltDesc *)LDAP_CALLOC( 1, sizeof( LDAPFiltDesc))) == NULL ) {
	return( NULL );
    }

    flp = nextflp = NULL;
    fip = NULL;
    tag = NULL;

    while ( buflen > 0 && ( tokcnt = ldap_int_next_line_tokens( &buf, &buflen, &tok ))
	    > 0 ) {

	switch( tokcnt ) {
	case 1:		/* tag line */
	    if ( tag != NULL ) {
		LDAP_FREE( tag );
	    }
	    tag = tok[ 0 ];
	    LDAP_FREE( tok );
	    break;
	case 4:
	case 5:		/* start of filter info. list */
	    if (( nextflp = (LDAPFiltList *)LDAP_CALLOC( 1, sizeof( LDAPFiltList )))
		    == NULL ) {
		ldap_getfilter_free( lfdp );
		return( NULL );
	    }
	    nextflp->lfl_tag = LDAP_STRDUP( tag );
	    nextflp->lfl_pattern = tok[ 0 ];
	    if ( (rc = regcomp( &re, nextflp->lfl_pattern, 0 )) != 0 ) {
		char error[512];
		regerror(rc, &re, error, sizeof(error));
		ldap_getfilter_free( lfdp );
		Debug( LDAP_DEBUG_ANY, "ldap_init_get_filter_buf: "
			"bad regular expression %s, %s\n",
			nextflp->lfl_pattern, error, 0 );
		errno = EINVAL;
		LDAP_VFREE( tok );
		return( NULL );
	    }
		regfree(&re);
		
	    nextflp->lfl_delims = tok[ 1 ];
	    nextflp->lfl_ilist = NULL;
	    nextflp->lfl_next = NULL;
	    if ( flp == NULL ) {	/* first one */
		lfdp->lfd_filtlist = nextflp;
	    } else {
		flp->lfl_next = nextflp;
	    }
	    flp = nextflp;
	    fip = NULL;
	    for ( i = 2; i < 5; ++i ) {
		tok[ i - 2 ] = tok[ i ];
	    }
	    /* fall through */

	case 2:
	case 3:		/* filter, desc, and optional search scope */
	    if ( nextflp != NULL ) { /* add to info list */
		if (( nextfip = (LDAPFiltInfo *)LDAP_CALLOC( 1,
			sizeof( LDAPFiltInfo ))) == NULL ) {
		    ldap_getfilter_free( lfdp );
		    LDAP_VFREE( tok );
		    return( NULL );
		}
		if ( fip == NULL ) {	/* first one */
		    nextflp->lfl_ilist = nextfip;
		} else {
		    fip->lfi_next = nextfip;
		}
		fip = nextfip;
		nextfip->lfi_next = NULL;
		nextfip->lfi_filter = tok[ 0 ];
		nextfip->lfi_desc = tok[ 1 ];
		if ( tok[ 2 ] != NULL ) {
		    if ( strcasecmp( tok[ 2 ], "subtree" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_SUBTREE;
		    } else if ( strcasecmp( tok[ 2 ], "onelevel" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_ONELEVEL;
		    } else if ( strcasecmp( tok[ 2 ], "base" ) == 0 ) {
			nextfip->lfi_scope = LDAP_SCOPE_BASE;
		    } else {
			LDAP_VFREE( tok );
			ldap_getfilter_free( lfdp );
			errno = EINVAL;
			return( NULL );
		    }
		    LDAP_FREE( tok[ 2 ] );
		    tok[ 2 ] = NULL;
		} else {
		    nextfip->lfi_scope = LDAP_SCOPE_SUBTREE;	/* default */
		}
		nextfip->lfi_isexact = ( strchr( tok[ 0 ], '*' ) == NULL &&
			strchr( tok[ 0 ], '~' ) == NULL );
		LDAP_FREE( tok );
	    }
	    break;

	default:
	    LDAP_VFREE( tok );
	    ldap_getfilter_free( lfdp );
	    errno = EINVAL;
	    return( NULL );
	}
    }

    if ( tag != NULL ) {
	LDAP_FREE( tag );
    }

    return( lfdp );
}


void
ldap_setfilteraffixes( LDAPFiltDesc *lfdp, LDAP_CONST char *prefix, LDAP_CONST char *suffix )
{
    if ( lfdp->lfd_filtprefix != NULL ) {
	LDAP_FREE( lfdp->lfd_filtprefix );
    }
    lfdp->lfd_filtprefix = ( prefix == NULL ) ? NULL : LDAP_STRDUP( prefix );

    if ( lfdp->lfd_filtsuffix != NULL ) {
	LDAP_FREE( lfdp->lfd_filtsuffix );
    }
    lfdp->lfd_filtsuffix = ( suffix == NULL ) ? NULL : LDAP_STRDUP( suffix );
}


LDAPFiltInfo *
ldap_getfirstfilter(
	LDAPFiltDesc *lfdp,
	/* LDAP_CONST */ char *tagpat,
	/* LDAP_CONST */ char *value )
{
    LDAPFiltList	*flp;
	int				rc;
	regex_t			re;

    if ( lfdp->lfd_curvalcopy != NULL ) {
	LDAP_FREE( lfdp->lfd_curvalcopy );
	LDAP_FREE( lfdp->lfd_curvalwords );
    }

    lfdp->lfd_curval = value;
    lfdp->lfd_curfip = NULL;

	for ( flp = lfdp->lfd_filtlist; flp != NULL; flp = flp->lfl_next ) {
		/* compile tagpat, continue if we fail */
		if (regcomp(&re, tagpat, REG_EXTENDED|REG_NOSUB) != 0)
			continue;

		/* match tagpattern and tag, continue if we fail */
		rc = regexec(&re, flp->lfl_tag, 0, NULL, 0);
		regfree(&re);
		if (rc != 0)
			continue;

		/* compile flp->ifl_pattern, continue if we fail */
		if (regcomp(&re, flp->lfl_pattern, REG_EXTENDED|REG_NOSUB) != 0)
			continue;

		/* match ifl_pattern and lfd_curval, continue if we fail */
		rc = regexec(&re, lfdp->lfd_curval, 0, NULL, 0);
		regfree(&re);
		if (rc != 0)
			continue;

		/* we successfully compiled both patterns and matched both values */
		lfdp->lfd_curfip = flp->lfl_ilist;
		break;
    }

    if ( lfdp->lfd_curfip == NULL ) {
	return( NULL );
    }

    if (( lfdp->lfd_curvalcopy = LDAP_STRDUP( value )) == NULL ) {
	return( NULL );
    }

    if ( break_into_words( lfdp->lfd_curvalcopy, flp->lfl_delims,
		&lfdp->lfd_curvalwords ) < 0 ) {
	LDAP_FREE( lfdp->lfd_curvalcopy );
	lfdp->lfd_curvalcopy = NULL;
	return( NULL );
    }

    return( ldap_getnextfilter( lfdp ));
}


LDAPFiltInfo *
ldap_getnextfilter( LDAPFiltDesc *lfdp )
{
    LDAPFiltInfo	*fip;

    fip = lfdp->lfd_curfip;

    if ( fip == NULL ) {
	return( NULL );
    }

    lfdp->lfd_curfip = fip->lfi_next;

    ldap_build_filter( lfdp->lfd_filter, LDAP_FILT_MAXSIZ, fip->lfi_filter,
	    lfdp->lfd_filtprefix, lfdp->lfd_filtsuffix, NULL,
	    lfdp->lfd_curval, lfdp->lfd_curvalwords );
    lfdp->lfd_retfi.lfi_filter = lfdp->lfd_filter;
    lfdp->lfd_retfi.lfi_desc = fip->lfi_desc;
    lfdp->lfd_retfi.lfi_scope = fip->lfi_scope;
    lfdp->lfd_retfi.lfi_isexact = fip->lfi_isexact;

    return( &lfdp->lfd_retfi );
}


void
ldap_build_filter(
	char *filtbuf,
	ber_len_t buflen,
	LDAP_CONST char *pattern,
	LDAP_CONST char *prefix,
	LDAP_CONST char *suffix,
	LDAP_CONST char *attr,
	LDAP_CONST char *value,
	char **valwords )
{
	const char *p;
	char *f;
	size_t	slen;
	int	i, wordcount, wordnum, endwordnum;
	
	if ( valwords == NULL ) {
	    wordcount = 0;
	} else {
	    for ( wordcount = 0; valwords[ wordcount ] != NULL; ++wordcount ) {
		;
	    }
	}

	f = filtbuf;

	if ( prefix != NULL ) {
	    strcpy( f, prefix );
	    f += strlen( prefix );
	}

	for ( p = pattern; *p != '\0'; ++p ) {
	    if ( *p == '%' ) {
		++p;
		if ( *p == 'v' ) {
		    if ( LDAP_DIGIT( (unsigned char) p[1] )) {
			++p;
			wordnum = *p - '1';
			if ( *(p+1) == '-' ) {
			    ++p;
			    if ( LDAP_DIGIT( (unsigned char) p[1] )) {
				++p;
				endwordnum = *p - '1';	/* e.g., "%v2-4" */
				if ( endwordnum > wordcount - 1 ) {
				    endwordnum = wordcount - 1;
				}
			    } else {
				endwordnum = wordcount - 1;  /* e.g., "%v2-" */
			    }
			} else {
			    endwordnum = wordnum;	/* e.g., "%v2" */
			}

			if ( wordcount > 0 ) {
			    for ( i = wordnum; i <= endwordnum; ++i ) {
				if ( i > wordnum ) {  /* add blank btw words */
				    *f++ = ' ';
				}
				slen = strlen( valwords[ i ] );
				AC_MEMCPY( f, valwords[ i ], slen );
				f += slen;
			    }
			}
		    } else if ( *(p+1) == '$' ) {
			++p;
			if ( wordcount > 0 ) {
			    wordnum = wordcount - 1;
			    slen = strlen( valwords[ wordnum ] );
			    AC_MEMCPY( f, valwords[ wordnum ], slen );
			    f += slen;
			}
		    } else if ( value != NULL ) {
			slen = strlen( value );
			AC_MEMCPY( f, value, slen );
			f += slen;
		    }
		} else if ( *p == 'a' && attr != NULL ) {
		    slen = strlen( attr );
		    AC_MEMCPY( f, attr, slen );
		    f += slen;
		} else {
		    *f++ = *p;
		}
	    } else {
		*f++ = *p;
	    }
		
	    if ( (size_t) (f - filtbuf) > buflen ) {
		/* sanity check */
		--f;
		break;
	    }
	}

	if ( suffix != NULL && ( (size_t) (f - filtbuf) < buflen ) )
	{
	    strcpy( f, suffix );
	} else {
	    *f = '\0';
	}
}


static int
break_into_words( /* LDAP_CONST */ char *str, LDAP_CONST char *delims, char ***wordsp )
{
    char	*word, **words;
    int		count;
    char        *tok_r;	

    if (( words = (char **)LDAP_CALLOC( 1, sizeof( char * ))) == NULL ) {
	return( -1 );
    }
    count = 0;
    words[ count ] = NULL;

    word = ldap_pvt_strtok( str, delims, &tok_r );
    while ( word != NULL ) {
	if (( words = (char **)LDAP_REALLOC( words,
		( count + 2 ) * sizeof( char * ))) == NULL ) {
	    return( -1 );
	}

	words[ count ] = word;
	words[ ++count ] = NULL;
	word = ldap_pvt_strtok( NULL, delims, &tok_r );
    }
	
    *wordsp = words;
    return( count );
}
