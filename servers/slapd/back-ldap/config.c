/* config.c - ldap backend configuration file routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* This is an altered version */
/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: ldap backend info is null!\n",
		    fname, lineno );
		return( 1 );
	}

	/* server address to query (depricated, use "uri" directive) */
	if ( strcasecmp( argv[0], "server" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing address in \"server <address>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if (li->url != NULL)
			ch_free(li->url);
		li->url = ch_calloc(strlen(argv[1]) + 9, sizeof(char));
		if (li->url != NULL) {
			strcpy(li->url, "ldap://");
			strcat(li->url, argv[1]);
			strcat(li->url, "/");
		}

	/* URI of server to query (preferred over "server" directive) */
	} else if ( strcasecmp( argv[0], "uri" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing address in \"uri <address>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		if (li->url != NULL)
			ch_free(li->url);
		li->url = ch_strdup(argv[1]);

	/* name to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "binddn" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing name in \"binddn <name>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->binddn = ch_strdup(argv[1]);

	/* password to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "bindpw" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing password in \"bindpw <password>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		li->bindpw = ch_strdup(argv[1]);
	
	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[0], "rebind-as-user" ) == 0 ) {
		if (argc != 1) {
			fprintf( stderr,
	"%s: line %d: rebind-as-user takes no arguments\n",
			    fname, lineno );
			return( 1 );
		}
		li->savecred = 1;
	
	/* dn massaging */
	} else if ( strcasecmp( argv[0], "suffixmassage" ) == 0 ) {
		BackendDB *tmp_be;
		struct berval bvnc, *nvnc = NULL, *pvnc = NULL, 
			brnc, *nrnc = NULL, *prnc = NULL;
		int rc;
		
		/*
		 * syntax:
		 * 
		 * 	suffixmassage <suffix> <massaged suffix>
		 *
		 * the <suffix> field must be defined as a valid suffix
		 * (or suffixAlias?) for the current database;
		 * the <massaged suffix> shouldn't have already been
		 * defined as a valid suffix or suffixAlias for the 
		 * current server
		 */
		if ( argc != 3 ) {
 			fprintf( stderr, "%s: line %d: syntax is"
				       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
				fname, lineno );
			return( 1 );
		}
		
		ber_str2bv( argv[1], 0, 0, &bvnc );
		pvnc = (struct berval *)ber_memalloc( sizeof( struct berval ) );
		nvnc = (struct berval *)ber_memalloc( sizeof( struct berval ) );
		if ( dnPrettyNormal( NULL, &bvnc, pvnc, nvnc ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, bvnc.bv_val );
			return( 1 );
		}
		tmp_be = select_backend( nvnc, 0, 0 );
		if ( tmp_be != NULL && tmp_be != be ) {
			fprintf( stderr, "%s: line %d: suffix already in use"
				       " by another backend in"
				       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
				fname, lineno );
			ber_bvfree( nvnc );
			ber_bvfree( pvnc );
			return( 1 );
		}

		ber_str2bv( argv[2], 0, 0, &brnc );
		prnc = (struct berval *)ber_memalloc( sizeof( struct berval ) );
		nrnc = (struct berval *)ber_memalloc( sizeof( struct berval ) );
		if ( dnPrettyNormal( NULL, &brnc, prnc, nrnc ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, brnc.bv_val );
			ber_bvfree( nvnc );
			ber_bvfree( pvnc );
			return( 1 );
		}

#if 0
		tmp_be = select_backend( &nrnc, 0, 0 );
		if ( tmp_be != NULL ) {
			fprintf( stderr, "%s: line %d: massaged suffix"
				       " already in use by another backend in" 
			       	       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
                                fname, lineno );
			ber_bvfree( nvnc );
			ber_bvfree( pvnc );
			ber_bvfree( nrnc );
			ber_bvfree( prnc );
                        return( 1 );
		}
#endif

#ifdef ENABLE_REWRITE
		/*
		 * The suffix massaging is emulated by means of the
		 * rewrite capabilities
		 * FIXME: no extra rewrite capabilities should be added
		 * to the database
		 */
	 	rc = suffix_massage_config( li->rwinfo, pvnc, nvnc, prnc, nrnc );

		ber_bvfree( nvnc );
		ber_bvfree( pvnc );
		ber_bvfree( nrnc );
		ber_bvfree( prnc );

		return( rc );

#else /* !ENABLE_REWRITE */
		ber_bvecadd( &li->suffix_massage, pvnc );
		ber_bvecadd( &li->suffix_massage, nvnc );
		
		ber_bvecadd( &li->suffix_massage, prnc );
		ber_bvecadd( &li->suffix_massage, nrnc );
#endif /* !ENABLE_REWRITE */

	/* rewrite stuff ... */
 	} else if ( strncasecmp( argv[0], "rewrite", 7 ) == 0 ) {
#ifdef ENABLE_REWRITE
 		return rewrite_parse( li->rwinfo, fname, lineno, argc, argv );

#else /* !ENABLE_REWRITE */
		fprintf( stderr, "%s: line %d: rewrite capabilities "
				"are not enabled\n", fname, lineno );
#endif /* !ENABLE_REWRITE */
		
	/* objectclass/attribute mapping */
	} else if ( strcasecmp( argv[0], "map" ) == 0 ) {
		struct ldapmap *map;
		struct ldapmapping *mapping;
		char *src, *dst;

		if ( argc < 3 || argc > 4 ) {
			fprintf( stderr,
	"%s: line %d: syntax is \"map {objectclass | attribute} {<source> | *} [<dest> | *]\"\n",
				fname, lineno );
			return( 1 );
		}

		if ( strcasecmp( argv[1], "objectclass" ) == 0 ) {
			map = &li->oc_map;
		} else if ( strcasecmp( argv[1], "attribute" ) == 0 ) {
			map = &li->at_map;
		} else {
			fprintf( stderr, "%s: line %d: syntax is "
				"\"map {objectclass | attribute} {<source> | *} "
					"[<dest> | *]\"\n",
				fname, lineno );
			return( 1 );
		}

		if ( strcasecmp( argv[2], "*" ) != 0 ) {
			src = argv[2];
			if ( argc < 4 )
				dst = "";
			else if ( strcasecmp( argv[3], "*" ) == 0 )
				dst = src;
			else
				dst = argv[3];
		} else {
			if ( argc < 4 ) {
				map->drop_missing = 1;
				return 0;
			}
			if ( strcasecmp( argv[3], "*" ) == 0 ) {
				map->drop_missing = 0;
				return 0;
			}

			src = argv[3];
			dst = src;
		}

		if ( ( map == &li->at_map )
			&& ( strcasecmp( src, "objectclass" ) == 0
				|| strcasecmp( dst, "objectclass" ) == 0 ) )
		{
			fprintf( stderr,
				"%s: line %d: objectclass attribute cannot be mapped\n",
				fname, lineno );
		}

		mapping = (struct ldapmapping *)ch_calloc( 2,
			sizeof(struct ldapmapping) );
		if ( mapping == NULL ) {
			fprintf( stderr,
				"%s: line %d: out of memory\n",
				fname, lineno );
			return( 1 );
		}
		ber_str2bv( src, 0, 1, &mapping->src );
		ber_str2bv( dst, 0, 1, &mapping->dst );
		if ( *dst != 0 ) {
			mapping[1].src = mapping->dst;
			mapping[1].dst = mapping->src;
		} else {
			mapping[1].src = mapping->src;
			mapping[1].dst = mapping->dst;
		}

		if ( avl_find( map->map, (caddr_t)mapping, mapping_cmp ) != NULL ||
			avl_find( map->remap, (caddr_t)&mapping[1], mapping_cmp ) != NULL)
		{
			fprintf( stderr,
				"%s: line %d: duplicate mapping found (ignored)\n",
				fname, lineno );
			return 0;
		}

		avl_insert( &map->map, (caddr_t)mapping,
					mapping_cmp, mapping_dup );
		avl_insert( &map->remap, (caddr_t)&mapping[1],
					mapping_cmp, mapping_dup );

	/* anything else */
	} else {
		fprintf( stderr, "%s: line %d: unknown directive \"%s\" "
			"in ldap database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}
	return 0;
}

#ifdef ENABLE_REWRITE
static char *
suffix_massage_regexize( const char *s )
{
	char *res, *ptr;
	const char *p, *r;
	int i;

	for ( i = 0, p = s; 
			( r = strchr( p, ',' ) ) != NULL; 
			p = r + 1, i++ )
		;

	res = ch_calloc( sizeof( char ), strlen( s ) + 4 + 4*i + 1 );

	ptr = slap_strcopy( res, "(.*)" );
	for ( i = 0, p = s;
			( r = strchr( p, ',' ) ) != NULL;
			p = r + 1 , i++ ) {
		ptr = slap_strncopy( ptr, p, r - p + 1 );
		ptr = slap_strcopy( ptr, "[ ]?" );

		if ( r[ 1 ] == ' ' ) {
			r++;
		}
	}
	slap_strcopy( ptr, p );

	return res;
}

static char *
suffix_massage_patternize( const char *s )
{
	ber_len_t	len;
	char		*res;

	len = strlen( s );

	res = ch_calloc( sizeof( char ), len + sizeof( "%1" ) );
	if ( res == NULL ) {
		return NULL;
	}

	strcpy( res, "%1" );
	strcpy( res + sizeof( "%1" ) - 1, s );

	return res;
}

int
suffix_massage_config( 
		struct rewrite_info *info,
		struct berval *pvnc,
		struct berval *nvnc,
		struct berval *prnc,
		struct berval *nrnc
)
{
	char *rargv[ 5 ];
	int line = 0;

	rargv[ 0 ] = "rewriteEngine";
	rargv[ 1 ] = "on";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "default";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( pvnc->bv_val );
	rargv[ 2 ] = suffix_massage_patternize( prnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );
	
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchResult";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );
	
	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( prnc->bv_val );
	rargv[ 2 ] = suffix_massage_patternize( pvnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );

	/*
	 * the filter should be rewritten as
	 * 
	 * rewriteRule
	 * 	"(.*)member=([^)]+),o=Foo Bar,[ ]?c=US(.*)"
	 * 	"%1member=%2,dc=example,dc=com%3"
	 *
	 * where "o=Foo Bar, c=US" is the virtual naming context,
	 * and "dc=example, dc=com" is the real naming context
	 */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchFilter";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

#if 1 /* rewrite filters */
	{
		/*
		 * Note: this is far more optimistic than desirable:
		 * for any AVA value ending with the virtual naming
		 * context the terminal part will be replaced by the
		 * real naming context; a better solution would be to
		 * walk the filter looking for DN-valued attributes,
		 * and only rewrite those that require rewriting
		 */
		char vbuf[LDAP_FILT_MAXSIZ], rbuf[LDAP_FILT_MAXSIZ];

		snprintf( vbuf, sizeof( vbuf ), "(.*)%s\\)(.*)", nvnc->bv_val );
		snprintf( rbuf, sizeof( rbuf ), "%%1%s)%%2", nrnc->bv_val );
		
		rargv[ 0 ] = "rewriteRule";
		rargv[ 1 ] = vbuf;
		rargv[ 2 ] = rbuf;
		rargv[ 3 ] = ":";
		rargv[ 4 ] = NULL;
		rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	}
#endif /* rewrite filters */

#if 0 /*  "matched" is not normalized */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDn";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResult";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
#else /* normalize "matched" */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDn";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( prnc->bv_val );
	rargv[ 2 ] = suffix_massage_patternize( nvnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );
#endif /* normalize "matched" */

	return 0;
}
#endif /* ENABLE_REWRITE */
