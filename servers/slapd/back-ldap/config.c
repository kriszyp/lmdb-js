/* config.c - ldap backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
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

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"
#include "lutil.h"

static SLAP_EXTOP_MAIN_FN ldap_back_exop_whoami;

static int
parse_idassert( BackendDB *be, const char *fname, int lineno,
		int argc, char **argv );

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
		LDAPURLDesc	tmplud;

		if (argc != 2) {
			fprintf( stderr, "%s: line %d: "
				"missing uri "
				"in \"uri <uri>\" line\n",
				fname, lineno );
			return( 1 );
		}
		if ( li->url != NULL ) {
			ch_free( li->url );
		}
		if ( li->lud != NULL ) {
			ldap_free_urldesc( li->lud );
		}

		if ( ldap_url_parse( argv[ 1 ], &li->lud ) != LDAP_URL_SUCCESS ) {
			fprintf( stderr, "%s: line %d: "
				"unable to parse uri \"%s\" "
				"in \"uri <uri>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

		if ( ( li->lud->lud_dn != NULL && li->lud->lud_dn[0] != '\0' )
				|| li->lud->lud_attrs != NULL
				|| li->lud->lud_filter != NULL
				|| li->lud->lud_exts != NULL )
		{
			fprintf( stderr, "%s: line %d: "
				"warning, only protocol, "
				"host and port allowed "
				"in \"uri <uri>\" line\n",
				fname, lineno );
		}

#if 0
		tmplud = *lud;
		tmplud.lud_dn = "";
		tmplud.lud_attrs = NULL;
		tmplud.lud_filter = NULL;
		if ( !ldap_is_ldapi_url( argv[ 1 ] ) ) {
			tmplud.lud_exts = NULL;
			tmplud.lud_crit_exts = 0;
		}
		
		li->url = ldap_url_desc2str( &tmplud );
		if ( li->url == NULL ) {
			fprintf( stderr, "%s: line %d: "
				"unable to rebuild uri \"%s\" "
				"in \"uri <uri>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}
#else
		li->url = ch_strdup( argv[ 1 ] );
#endif

	/* name to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "binddn" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing name in \"binddn <name>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->binddn );

	/* password to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "bindpw" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing password in \"bindpw <password>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->bindpw );

#ifdef LDAP_BACK_PROXY_AUTHZ
	/* name to use for proxyAuthz propagation */
	} else if ( strcasecmp( argv[0], "proxyauthzdn" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing name in \"proxyauthzdn <name>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->proxyauthzdn );

	/* password to use for proxyAuthz propagation */
	} else if ( strcasecmp( argv[0], "proxyauthzpw" ) == 0 ) {
		if (argc != 2) {
			fprintf( stderr,
	"%s: line %d: missing password in \"proxyauthzpw <password>\" line\n",
			    fname, lineno );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->proxyauthzpw );

	/* identity assertion stuff... */
	} else if ( strncasecmp( argv[0], "idassert-", STRLENOF( "idassert-" ) ) == 0 ) {
		return parse_idassert( be, fname, lineno, argc, argv );
#endif /* LDAP_BACK_PROXY_AUTHZ */

	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[0], "rebind-as-user" ) == 0 ) {
		if (argc != 1) {
			fprintf( stderr,
	"%s: line %d: rebind-as-user takes no arguments\n",
			    fname, lineno );
			return( 1 );
		}
		li->savecred = 1;
	
	/* intercept exop_who_am_i? */
	} else if ( strcasecmp( argv[0], "proxy-whoami" ) == 0 ) {
		if (argc != 1) {
			fprintf( stderr,
	"%s: line %d: proxy-whoami takes no arguments\n",
			    fname, lineno );
			return( 1 );
		}
		load_extop( (struct berval *)&slap_EXOP_WHOAMI,
			0, ldap_back_exop_whoami );
	
	/* dn massaging */
	} else if ( strcasecmp( argv[0], "suffixmassage" ) == 0 ) {
		BackendDB *tmp_be;
		struct berval bvnc, nvnc, pvnc, brnc, nrnc, prnc;
#ifdef ENABLE_REWRITE
		int rc;
#endif /* ENABLE_REWRITE */
		
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
		if ( dnPrettyNormal( NULL, &bvnc, &pvnc, &nvnc, NULL ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, bvnc.bv_val );
			return( 1 );
		}
		tmp_be = select_backend( &nvnc, 0, 0 );
		if ( tmp_be != NULL && tmp_be != be ) {
			fprintf( stderr, "%s: line %d: suffix already in use"
				       " by another backend in"
				       " \"suffixMassage <suffix>"
				       " <massaged suffix>\"\n",
				fname, lineno );
			free( nvnc.bv_val );
			free( pvnc.bv_val );
			return( 1 );
		}

		ber_str2bv( argv[2], 0, 0, &brnc );
		if ( dnPrettyNormal( NULL, &brnc, &prnc, &nrnc, NULL ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: suffix DN %s is invalid\n",
				fname, lineno, brnc.bv_val );
			free( nvnc.bv_val );
			free( pvnc.bv_val );
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
			free( nvnc.bv_val );
			free( pvnc.bv_val );
			free( nrnc.bv_val );
			free( prnc.bv_val );
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
	 	rc = suffix_massage_config( li->rwmap.rwm_rw,
				&pvnc, &nvnc, &prnc, &nrnc );
		free( nvnc.bv_val );
		free( pvnc.bv_val );
		free( nrnc.bv_val );
		free( prnc.bv_val );

		return( rc );

#else /* !ENABLE_REWRITE */
		ber_bvarray_add( &li->rwmap.rwm_suffix_massage, &pvnc );
		ber_bvarray_add( &li->rwmap.rwm_suffix_massage, &nvnc );
		
		ber_bvarray_add( &li->rwmap.rwm_suffix_massage, &prnc );
		ber_bvarray_add( &li->rwmap.rwm_suffix_massage, &nrnc );
#endif /* !ENABLE_REWRITE */

	/* rewrite stuff ... */
 	} else if ( strncasecmp( argv[0], "rewrite", 7 ) == 0 ) {
#ifdef ENABLE_REWRITE
 		return rewrite_parse( li->rwmap.rwm_rw,
				fname, lineno, argc, argv );

#else /* !ENABLE_REWRITE */
		fprintf( stderr, "%s: line %d: rewrite capabilities "
				"are not enabled\n", fname, lineno );
#endif /* !ENABLE_REWRITE */
		
	/* objectclass/attribute mapping */
	} else if ( strcasecmp( argv[0], "map" ) == 0 ) {
		return ldap_back_map_config( &li->rwmap.rwm_oc,
				&li->rwmap.rwm_at,
				fname, lineno, argc, argv );

	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}
	return 0;
}

int
ldap_back_map_config(
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
				goto error_return;
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
				goto error_return;
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

	if ( (src[0] != '\0' && avl_find( map->map, (caddr_t)mapping, mapping_cmp ) != NULL)
			|| avl_find( map->remap, (caddr_t)&mapping[1], mapping_cmp ) != NULL)
	{
		fprintf( stderr,
			"%s: line %d: duplicate mapping found (ignored)\n",
			fname, lineno );
		goto error_return;
	}

	if ( src[0] != '\0' ) {
		avl_insert( &map->map, (caddr_t)mapping,
					mapping_cmp, mapping_dup );
	}
	avl_insert( &map->remap, (caddr_t)&mapping[1],
				mapping_cmp, mapping_dup );

	return 0;

error_return:;
	if ( mapping ) {
		ch_free( mapping->src.bv_val );
		ch_free( mapping->dst.bv_val );
		ch_free( mapping );
	}

	return 1;
}

static int
ldap_back_exop_whoami(
	Operation *op,
	SlapReply *rs )
{
	struct berval *bv = NULL;

	if ( op->oq_extended.rs_reqdata != NULL ) {
		/* no request data should be provided */
		rs->sr_text = "no request data expected";
		return rs->sr_err = LDAP_PROTOCOL_ERROR;
	}

	rs->sr_err = backend_check_restrictions( op, rs, 
			(struct berval *)&slap_EXOP_WHOAMI );
	if( rs->sr_err != LDAP_SUCCESS ) return rs->sr_err;

	/* if auth'd by back-ldap and request is proxied, forward it */
	if ( op->o_conn->c_authz_backend && !strcmp(op->o_conn->c_authz_backend->be_type, "ldap" ) && !dn_match(&op->o_ndn, &op->o_conn->c_ndn)) {
		struct ldapconn *lc;

		LDAPControl c, *ctrls[2] = {NULL, NULL};
		LDAPMessage *res;
		Operation op2 = *op;
		ber_int_t msgid;

		ctrls[0] = &c;
		op2.o_ndn = op->o_conn->c_ndn;
		lc = ldap_back_getconn(&op2, rs);
		if (!lc || !ldap_back_dobind( lc, op, rs )) {
			return -1;
		}
		c.ldctl_oid = LDAP_CONTROL_PROXY_AUTHZ;
		c.ldctl_iscritical = 1;
		c.ldctl_value.bv_val = ch_malloc(op->o_ndn.bv_len+4);
		c.ldctl_value.bv_len = op->o_ndn.bv_len + 3;
		strcpy(c.ldctl_value.bv_val, "dn:");
		strcpy(c.ldctl_value.bv_val+3, op->o_ndn.bv_val);

		rs->sr_err = ldap_whoami(lc->ld, ctrls, NULL, &msgid);
		if (rs->sr_err == LDAP_SUCCESS) {
			if (ldap_result(lc->ld, msgid, 1, NULL, &res) == -1) {
				ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err);
			} else {
				rs->sr_err = ldap_parse_whoami(lc->ld, res, &bv);
				ldap_msgfree(res);
			}
		}
		ch_free(c.ldctl_value.bv_val);
		if (rs->sr_err != LDAP_SUCCESS) {
			rs->sr_err = slap_map_api2result( rs );
		}
	} else {
	/* else just do the same as before */
		bv = (struct berval *) ch_malloc( sizeof(struct berval) );
		if( op->o_dn.bv_len ) {
			bv->bv_len = op->o_dn.bv_len + sizeof("dn:") - 1;
			bv->bv_val = ch_malloc( bv->bv_len + 1 );
			AC_MEMCPY( bv->bv_val, "dn:", sizeof("dn:") - 1 );
			AC_MEMCPY( &bv->bv_val[sizeof("dn:") - 1], op->o_dn.bv_val,
				op->o_dn.bv_len );
			bv->bv_val[bv->bv_len] = '\0';
		} else {
			bv->bv_len = 0;
			bv->bv_val = NULL;
		}
	}

	rs->sr_rspdata = bv;
	return rs->sr_err;
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

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResult";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchAttrDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchResult";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	return 0;
}
#endif /* ENABLE_REWRITE */

#ifdef LDAP_BACK_PROXY_AUTHZ
static int
parse_idassert(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;

	if ( strcasecmp( argv[0], "idassert-mode" ) == 0 ) {
		if ( argc != 2 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, CRIT, 
				"%s: line %d: illegal args number %d in \"idassert-mode <args>\" line.\n",
				fname, lineno, argc );
#else
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: illegal args number %d in \"idassert-mode <args>\" line.\n",
				fname, lineno, argc );
#endif
			return 1;
		}

		if ( strcasecmp( argv[1], "none" ) == 0 ) {
			/* will proxyAuthz as client's identity only if bound */
			li->idassert_mode = LDAP_BACK_IDASSERT_NONE;

		} else if ( strcasecmp( argv[1], "self" ) == 0 ) {
			/* will proxyAuthz as client's identity */
			li->idassert_mode = LDAP_BACK_IDASSERT_SELF;

		} else if ( strcasecmp( argv[1], "anonymous" ) == 0 ) {
			/* will proxyAuthz as anonymous */
			li->idassert_mode = LDAP_BACK_IDASSERT_ANONYMOUS;

		} else if ( strcasecmp( argv[1], "proxyid" ) == 0 ) {
			/* will not proxyAuthz */
			li->idassert_mode = LDAP_BACK_IDASSERT_PROXYID;

		} else {
			struct berval	dn;
			int		rc;

			/* will proxyAuthz as argv[1] */
			li->idassert_mode = LDAP_BACK_IDASSERT_OTHER;
			
			ber_str2bv( argv[1], 0, 0, &dn );

			rc = dnNormalize( 0, NULL, NULL, &dn, &li->idassert_dn, NULL );
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: idassert DN \"%s\" is invalid.\n",
					fname, lineno, argv[1] );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: idassert DN \"%s\" is invalid\n",
					fname, lineno, argv[1] );
#endif
				return 1;
			}
		}

	} else if ( strcasecmp( argv[0], "idassert-authz" ) == 0 ) {
		struct berval	rule;

		ber_str2bv( argv[1], 0, 1, &rule );

		ber_bvarray_add( &li->idassert_authz, &rule );

	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}
#endif /* LDAP_BACK_PROXY_AUTHZ */
