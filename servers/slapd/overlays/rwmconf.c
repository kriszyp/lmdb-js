/* rwmconf.c - rewrite/map configuration file routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Howard Chu.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#ifdef SLAPD_OVER_RWM

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "rwm.h"
#include "lutil.h"

int
rwm_map_config(
		struct ldapmap	*oc_map,
		struct ldapmap	*at_map,
		const char	*fname,
		int		lineno,
		int		argc,
		char		**argv )
{
	struct ldapmap		*map;
	struct ldapmapping	*mapping;
	char			*src, *dst;
	int			is_oc = 0;

	if ( argc < 3 || argc > 4 ) {
		fprintf( stderr,
	"%s: line %d: syntax is \"map {objectclass | attribute} [<local> | *] {<foreign> | *}\"\n",
			fname, lineno );
		return 1;
	}

	if ( strcasecmp( argv[1], "objectclass" ) == 0 ) {
		map = oc_map;
		is_oc = 1;

	} else if ( strcasecmp( argv[1], "attribute" ) == 0 ) {
		map = at_map;

	} else {
		fprintf( stderr, "%s: line %d: syntax is "
			"\"map {objectclass | attribute} [<local> | *] "
			"{<foreign> | *}\"\n",
			fname, lineno );
		return 1;
	}

	if ( strcmp( argv[2], "*" ) == 0 ) {
		if ( argc < 4 || strcmp( argv[3], "*" ) == 0 ) {
			map->drop_missing = ( argc < 4 );
			return 0;
		}
		src = dst = argv[3];

	} else if ( argc < 4 ) {
		src = "";
		dst = argv[2];

	} else {
		src = argv[2];
		dst = ( strcmp( argv[3], "*" ) == 0 ? src : argv[3] );
	}

	if ( ( map == at_map )
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
		return 1;
	}
	ber_str2bv( src, 0, 1, &mapping->src );
	ber_str2bv( dst, 0, 1, &mapping->dst );
	mapping[1].src = mapping->dst;
	mapping[1].dst = mapping->src;

	/*
	 * schema check
	 */
	if ( is_oc ) {
		if ( src[0] != '\0' ) {
			if ( oc_bvfind( &mapping->src ) == NULL ) {
				fprintf( stderr,
	"%s: line %d: warning, source objectClass '%s' "
	"should be defined in schema\n",
					fname, lineno, src );

				/*
				 * FIXME: this should become an err
				 */
			}
		}

		if ( oc_bvfind( &mapping->dst ) == NULL ) {
			fprintf( stderr,
	"%s: line %d: warning, destination objectClass '%s' "
	"is not defined in schema\n",
				fname, lineno, dst );
		}
	} else {
		int			rc;
		const char		*text = NULL;
		AttributeDescription	*ad = NULL;

		if ( src[0] != '\0' ) {
			rc = slap_bv2ad( &mapping->src, &ad, &text );
			if ( rc != LDAP_SUCCESS ) {
				fprintf( stderr,
	"%s: line %d: warning, source attributeType '%s' "
	"should be defined in schema\n",
					fname, lineno, src );

				/*
				 * FIXME: this should become an err
				 */
			}

			ad = NULL;
		}

		rc = slap_bv2ad( &mapping->dst, &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr,
	"%s: line %d: warning, destination attributeType '%s' "
	"is not defined in schema\n",
				fname, lineno, dst );
		}
	}

	if ( (src[0] != '\0' && avl_find( map->map, (caddr_t)mapping, rwm_mapping_cmp ) != NULL)
			|| avl_find( map->remap, (caddr_t)&mapping[1], rwm_mapping_cmp ) != NULL)
	{
		fprintf( stderr,
			"%s: line %d: duplicate mapping found (ignored)\n",
			fname, lineno );
		/* FIXME: free stuff */
		goto error_return;
	}

	if ( src[0] != '\0' ) {
		avl_insert( &map->map, (caddr_t)mapping,
					rwm_mapping_cmp, rwm_mapping_dup );
	}
	avl_insert( &map->remap, (caddr_t)&mapping[1],
				rwm_mapping_cmp, rwm_mapping_dup );

	return 0;

error_return:;
	if ( mapping ) {
		ch_free( mapping->src.bv_val );
		ch_free( mapping->dst.bv_val );
		ch_free( mapping );
	}

	return 1;
}

#ifdef ENABLE_REWRITE
static char *
rwm_suffix_massage_regexize( const char *s )
{
	char *res, *ptr;
	const char *p, *r;
	int i;

	for ( i = 0, p = s; 
			( r = strchr( p, ',' ) ) != NULL; 
			p = r + 1, i++ )
		;

	res = ch_calloc( sizeof( char ), strlen( s ) + 4 + 4*i + 1 );

	ptr = lutil_strcopy( res, "(.*)" );
	for ( i = 0, p = s;
			( r = strchr( p, ',' ) ) != NULL;
			p = r + 1 , i++ ) {
		ptr = lutil_strncopy( ptr, p, r - p + 1 );
		ptr = lutil_strcopy( ptr, "[ ]?" );

		if ( r[ 1 ] == ' ' ) {
			r++;
		}
	}
	lutil_strcopy( ptr, p );

	return res;
}

static char *
rwm_suffix_massage_patternize( const char *s )
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
rwm_suffix_massage_config( 
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
	rargv[ 1 ] = rwm_suffix_massage_regexize( pvnc->bv_val );
	rargv[ 2 ] = rwm_suffix_massage_patternize( prnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );
	
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchResultDN";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );
	
	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = rwm_suffix_massage_regexize( prnc->bv_val );
	rargv[ 2 ] = rwm_suffix_massage_patternize( pvnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResultDN";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchAttrDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResultDN";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	return 0;
}
#endif /* ENABLE_REWRITE */

#endif /* SLAPD_OVER_RWM */
