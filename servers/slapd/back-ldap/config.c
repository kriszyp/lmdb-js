/* config.c - ldap backend configuration file routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
	
	/* dn massaging */
	} else if ( strcasecmp( argv[0], "suffixmassage" ) == 0 ) {
#ifndef ENABLE_REWRITE
		struct berval *bd2, *nd2;
#endif /* ENABLE_REWRITE */
		BackendDB *tmp_be;
		struct berval bdn, ndn;
		
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
		
		bdn.bv_val = argv[1];
		bdn.bv_len = strlen(bdn.bv_val);
		if ( dnNormalize2( NULL, &bdn, &ndn ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, bdn.bv_val );
			return( 1 );
		}
		tmp_be = select_backend( &ndn, 0, 0 );
		free( ndn.bv_val );
		if ( tmp_be != NULL && tmp_be != be ) {
			fprintf( stderr, "%s: line %d: suffix already in use"
				       " by another backend in"
				       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
				fname, lineno );
			return( 1 );						
		}

		bdn.bv_val = argv[2];
		bdn.bv_len = strlen(bdn.bv_val);
		if ( dnNormalize2( NULL, &bdn, &ndn ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, bdn.bv_val );
			return( 1 );
		}
		tmp_be = select_backend( &ndn, 0, 0 );
		free( ndn.bv_val );
		if ( tmp_be != NULL ) {
			fprintf( stderr, "%s: line %d: massaged suffix"
				       " already in use by another backend in" 
			       	       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
                                fname, lineno );
                        return( 1 );
		}

#ifdef ENABLE_REWRITE
		/*
		 * The suffix massaging is emulated by means of the
		 * rewrite capabilities
		 * FIXME: no extra rewrite capabilities should be added
		 * to the database
		 */
	 	return suffix_massage_config( li->rwinfo, argc, argv );
#else /* !ENABLE_REWRITE */
		bd2 = ber_bvstrdup( argv[1] );
		ber_bvecadd( &li->suffix_massage, bd2 );
		nd2 = NULL;
		dnNormalize( NULL, bd2, &nd2 );
		ber_bvecadd( &li->suffix_massage, nd2 );
		
		bd2 = ber_bvstrdup( argv[2] );
		ber_bvecadd( &li->suffix_massage, bd2 );
		nd2 = NULL;
		dnNormalize( NULL, bd2, &nd2 );
		ber_bvecadd( &li->suffix_massage, nd2 );
#endif /* !ENABLE_REWRITE */

#ifdef ENABLE_REWRITE
	/* rewrite stuff ... */
 	} else if ( strncasecmp( argv[0], "rewrite", 7 ) == 0 ) {
 		return rewrite_parse( li->rwinfo, fname, lineno, argc, argv );
#endif /* ENABLE_REWRITE */
		
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

int
mapping_cmp ( const void *c1, const void *c2 )
{
	struct ldapmapping *map1 = (struct ldapmapping *)c1;
	struct ldapmapping *map2 = (struct ldapmapping *)c2;
	int rc = map1->src.bv_len - map2->src.bv_len;
	if (rc) return rc;
	return ( strcasecmp(map1->src.bv_val, map2->src.bv_val) );
}

int
mapping_dup ( void *c1, void *c2 )
{
	struct ldapmapping *map1 = (struct ldapmapping *)c1;
	struct ldapmapping *map2 = (struct ldapmapping *)c2;

	return( ( strcasecmp(map1->src.bv_val, map2->src.bv_val) == 0 ) ? -1 : 0 );
}

void
ldap_back_map ( struct ldapmap *map, struct berval *s, struct berval *bv,
	int remap )
{
	Avlnode *tree;
	struct ldapmapping *mapping, fmapping;

	if (remap)
		tree = map->remap;
	else
		tree = map->map;

	bv->bv_len = 0;
	bv->bv_val = NULL;
	fmapping.src = *s;
	mapping = (struct ldapmapping *)avl_find( tree, (caddr_t)&fmapping, mapping_cmp );
	if (mapping != NULL) {
		if ( mapping->dst.bv_val )
			*bv = mapping->dst;
		return;
	}

	if (!map->drop_missing)
		*bv = *s;

	return;
}

char *
ldap_back_map_filter(
		struct ldapmap *at_map,
		struct ldapmap *oc_map,
		struct berval *f,
		int remap
)
{
	char *nf, *p, *q, *s, c;
	int len, extra, plen, in_quote;
	struct berval m, tmp;

	if (f == NULL)
		return(NULL);

	len = f->bv_len;
	extra = len;
	len *= 2;
	nf = ch_malloc( len + 1 );
	if (nf == NULL)
		return(NULL);

	/* this loop assumes the filter ends with one
	 * of the delimiter chars -- probably ')'.
	 */

	s = nf;
	q = NULL;
	in_quote = 0;
	for (p = f->bv_val; (c = *p); p++) {
		if (c == '"') {
			in_quote = !in_quote;
			if (q != NULL) {
				plen = p - q;
				AC_MEMCPY(s, q, plen);
				s += plen;
				q = NULL;
			}
			*s++ = c;
		} else if (in_quote) {
			/* ignore everything in quotes --
			 * what about attrs in DNs?
			 */
			*s++ = c;
		} else if (c != '(' && c != ')'
			&& c != '=' && c != '>' && c != '<'
			&& c != '|' && c != '&')
		{
			if (q == NULL)
				q = p;
		} else {
			if (q != NULL) {
				*p = 0;
				tmp.bv_len = p - q;
				tmp.bv_val = q;
				ldap_back_map(at_map, &tmp, &m, remap);
				if (m.bv_val == NULL)
					ldap_back_map(oc_map, &tmp, &m, remap);
				if (m.bv_val == NULL) {
					m = tmp;
				}
				extra += p - q;
				plen = m.bv_len;
				extra -= plen;
				if (extra < 0) {
					while (extra < 0) {
						extra += len;
						len *= 2;
					}
					s -= (long)nf;
					nf = ch_realloc(nf, len + 1);
					if (nf == NULL) {
						free(nf);
						return(NULL);
					}
					s += (long)nf;
				}
				AC_MEMCPY(s, m.bv_val, plen);
				s += plen;
				*p = c;
				q = NULL;
			}
			*s++ = c;
		}
	}
	*s = 0;
	return(nf);
}

char **
ldap_back_map_attrs(
		struct ldapmap *at_map,
		AttributeName *an,
		int remap
)
{
	int i;
	char **na;
	struct berval mapped;

	if (an == NULL)
		return(NULL);

	for (i = 0; an[i].an_name.bv_val; i++) {
		/*  */
	}

	na = (char **)ch_calloc( i + 1, sizeof(char *) );
	if (na == NULL)
		return(NULL);

	for (i = 0; an[i].an_name.bv_val; i++) {
		ldap_back_map(at_map, &an[i].an_name, &mapped, remap);
		if (mapped.bv_val != NULL) {
			na[i] = mapped.bv_val;
			i++;
		}
	}
	return(na);
}

#ifdef ENABLE_REWRITE
static char *
suffix_massage_regexize( const char *s )
{
	char *res, *p, *r;
	int i;

	for ( i = 0, p = ( char * )s; 
			( r = strchr( p, ',' ) ) != NULL; 
			p = r + 1, i++ )
		;

	res = ch_calloc( sizeof( char ), strlen( s ) + 4 + 4*i + 1 );

	strcpy( res, "(.*)" );
	for ( i = 0, p = ( char * )s;
			( r = strchr( p, ',' ) ) != NULL;
			p = r + 1 , i++ ) {
		strncat( res, p, r - p + 1 );
		strcat( res, "[ ]?" );

		if ( r[ 1 ] == ' ' ) {
			r++;
		}
	}
	strcat( res, p );

	return res;
}

static char *
suffix_massage_patternize( const char *s, int normalize )
{
	char *res;

	res = ch_calloc( sizeof( char ), strlen( s ) + sizeof("%1") );

	sprintf( res, "%%1%s", s );

	if ( normalize ) {
		char *out = dn_normalize( res + (sizeof("%1")-1) );
		if ( out != res + 2 ) {
			strcpy( res + 2, out );
			free( out );
		}
	}

	return res;
}

int
suffix_massage_config( 
		struct rewrite_info *info,
		int argc,
		char **argv
)
{
	char *rargv[ 5 ];

	rargv[ 0 ] = "rewriteEngine";
	rargv[ 1 ] = "on";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 1, 2, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "default";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 2, 2, rargv );

	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( argv[ 1 ] );
	rargv[ 2 ] = suffix_massage_patternize( argv[ 2 ], 0 );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 3, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );
	
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchResult";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 4, 2, rargv );
	
	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( argv[ 2 ] );
	rargv[ 2 ] = suffix_massage_patternize( argv[ 1 ], 0 );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 5, 4, rargv );
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
	rewrite_parse( info, "<suffix massage>", 6, 2, rargv );

#if 0 /*  matched is not normalized */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDn";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResult";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 7, 4, rargv );
#else /* normalize matched */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDn";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 7, 2, rargv );

	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( argv[ 2 ] );
	rargv[ 2 ] = suffix_massage_patternize( argv[ 1 ], 1 );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", 8, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );
#endif /* normalize matched */

	return 0;
}
#endif /* ENABLE_REWRITE */
