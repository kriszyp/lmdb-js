/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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
#include "../back-ldap/back-ldap.h"
#undef ldap_debug       /* silence a warning in ldap-int.h */
#include "../../../libraries/libldap/ldap-int.h"
#include "back-meta.h"

static struct metatarget *
new_target( void )
{
	struct metatarget *lt;
        struct ldapmapping *mapping;

	lt = ch_calloc( sizeof( struct metatarget ), 1 );
	if ( lt == NULL ) {
		return NULL;
	}

	lt->rwmap.rwm_rw = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
	if ( lt->rwmap.rwm_rw == NULL ) {
		free( lt );
                return NULL;
	}

	ldap_back_map_init( &lt->rwmap.rwm_at, &mapping );

	return lt;
}

int
meta_back_db_config(
		BackendDB	*be,
		const char	*fname,
		int		lineno,
		int		argc,
		char		**argv
)
{
	struct metainfo *li = ( struct metainfo * )be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, 
	"%s: line %d: meta backend info is null!\n",
		    fname, lineno );
		return 1;
	}

	/* URI of server to query */
	if ( strcasecmp( argv[ 0 ], "uri" ) == 0 ) {
		int 		i = li->ntargets;
#if 0
		int 		j;
#endif /* uncomment if uri MUST be a branch of suffix */
		LDAPURLDesc 	*ludp, *tmpludp;
		struct berval	dn;
		int		rc;
		
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing address"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}
		
		++li->ntargets;

		li->targets = ch_realloc( li->targets, 
			sizeof( struct metatarget *)*li->ntargets );
		if ( li->targets == NULL ) {
			fprintf( stderr,
	"%s: line %d: out of memory while storing server name"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}

		if ( ( li->targets[ i ] = new_target() ) == NULL ) {
			fprintf( stderr,
	"%s: line %d: unable to init server"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}

		/*
		 * uri MUST be legal!
		 */
		if ( ldap_url_parselist_ext( &ludp, argv[ 1 ], "\t" ) != LDAP_SUCCESS ) {
			fprintf( stderr,
	"%s: line %d: unable to parse URI"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}

		/*
		 * uri MUST have the <dn> part!
		 */
		if ( ludp->lud_dn == NULL || ludp->lud_dn[ 0 ] == '\0' ) {
			fprintf( stderr,
	"%s: line %d: missing <naming context> "
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}

		/*
		 * copies and stores uri and suffix
		 */
		dn.bv_val = ludp->lud_dn;
		dn.bv_len = strlen( ludp->lud_dn );

		rc = dnPrettyNormal( NULL, &dn, &li->targets[ i ]->psuffix,
			&li->targets[ i ]->suffix, NULL );
		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: "
					"target '%s' DN is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

		ludp->lud_dn[ 0 ] = '\0';

		for ( tmpludp = ludp->lud_next; tmpludp; tmpludp = tmpludp->lud_next ) {
			if ( tmpludp->lud_dn != NULL && tmpludp->lud_dn[ 0 ] != '\0' ) {
				fprintf( stderr, "%s: line %d: "
						"multiple URIs must have "
						"no DN part\n",
					fname, lineno );
				return( 1 );

			}
		}

		li->targets[ i ]->uri = ldap_url_list2urls( ludp );
		ldap_free_urllist( ludp );
		if ( li->targets[ i ]->uri == NULL) {
			fprintf( stderr, "%s: line %d: no memory?\n",
					fname, lineno );
			return( 1 );
		}
		
		/*
		 * uri MUST be a branch of suffix!
		 */
#if 0 /* too strict a constraint */
		if ( select_backend( &li->targets[ i ]->suffix, 0, 0 ) != be ) {
			fprintf( stderr,
	"%s: line %d: <naming context> of URI does not refer to current backend"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}
#else
		/*
		 * uri MUST be a branch of a suffix!
		 */
		if ( select_backend( &li->targets[ i ]->suffix, 0, 0 ) == NULL ) {
			fprintf( stderr,
	"%s: line %d: <naming context> of URI does not resolve to a backend"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno );
			return 1;
		}
#endif

#if 0
		/*
		 * uri MUST not be used by other URIs!
		 *
		 * FIXME: this limitation may be removed,
		 * or worked out, at least, in some manner
		 */
		for ( j = 0; j < i-1; j++ ) {
			if ( dn_match( &li->targets[ i ]->suffix,
					&li->targets[ j ]->suffix ) ) {
				fprintf( stderr,
	"%s: line %d: naming context \"%s\" already used"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
					fname, lineno, last+1 );
				return 1;
			}
		}
#endif

#if 0
		fprintf(stderr, "%s: line %d: URI \"%s\", suffix \"%s\"\n",
			fname, lineno, li->targets[ i ]->uri, 
			li->targets[ i ]->psuffix.bv_val );
#endif
		
	/* default target directive */
	} else if ( strcasecmp( argv[ 0 ], "default-target" ) == 0 ) {
		int 		i = li->ntargets-1;
		
		if ( argc == 1 ) {
 			if ( i < 0 ) {
				fprintf( stderr,
	"%s: line %d: \"default-target\" alone need be"
       	" inside a \"uri\" directive\n",
					fname, lineno );
				return 1;
			}
			li->defaulttarget = i;
		} else {
			if ( strcasecmp( argv[ 1 ], "none" ) == 0 ) {
				if ( i >= 0 ) {
					fprintf( stderr,
	"%s: line %d: \"default-target none\""
       	" should go before uri definitions\n",
						fname, lineno );
				}
				li->defaulttarget = META_DEFAULT_TARGET_NONE;
			} else {
				int n = atoi( argv[ 1 ] );
				if ( n < 1 || n >= i ) {
					fprintf( stderr,
	"%s: line %d: illegal target number %d\n",
						fname, lineno, n );
					return 1;
				}
				li->defaulttarget = n-1;
			}
		}
		
	/* ttl of dn cache */
	} else if ( strcasecmp( argv[ 0 ], "dncache-ttl" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing ttl in \"dncache-ttl <ttl>\" line\n",
				fname, lineno );
			return 1;
		}
		
		if ( strcasecmp( argv[ 1 ], "forever" ) == 0 ) {
			li->cache.ttl = META_DNCACHE_FOREVER;
		} else if ( strcasecmp( argv[ 1 ], "disabled" ) == 0 ) {
			li->cache.ttl = META_DNCACHE_DISABLED;
		} else {
			li->cache.ttl = atol( argv[ 1 ] );
		}

	/* network timeout when connecting to ldap servers */
	} else if ( strcasecmp( argv[ 0 ], "network-timeout" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing network timeout in \"network-timeout <seconds>\" line\n",
				fname, lineno );
			return 1;
		}
		li->network_timeout = atol(argv[ 1 ]);

	/* name to use for meta_back_group */
	} else if ( strcasecmp( argv[ 0 ], "binddn" ) == 0 ) {
		int 		i = li->ntargets-1;
		struct berval	dn;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}
		
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing name in \"binddn <name>\" line\n",
				fname, lineno );
			return 1;
		}

		dn.bv_val = argv[ 1 ];
		dn.bv_len = strlen( argv[ 1 ] );
		if ( dnNormalize( 0, NULL, NULL, &dn, &li->targets[ i ]->binddn,
			NULL ) != LDAP_SUCCESS )
		{
			fprintf( stderr, "%s: line %d: "
					"bind DN '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

	/* password to use for meta_back_group */
	} else if ( strcasecmp( argv[ 0 ], "bindpw" ) == 0 ) {
		int 		i = li->ntargets-1;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}
		
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing password in \"bindpw <password>\" line\n",
			    fname, lineno );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0L, 1, &li->targets[ i ]->bindpw );
		
	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[0], "rebind-as-user" ) == 0 ) {
		if (argc != 1) {
			fprintf( stderr,
	"%s: line %d: rebind-as-user takes no arguments\n",
			    fname, lineno );
			return( 1 );
		}
		li->savecred = 1;
	
	/* name to use as pseudo-root dn */
	} else if ( strcasecmp( argv[ 0 ], "pseudorootdn" ) == 0 ) {
		int 		i = li->ntargets-1;
		struct berval	dn;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}
		
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing name in \"pseudorootdn <name>\" line\n",
				fname, lineno );
			return 1;
		}

		dn.bv_val = argv[ 1 ];
		dn.bv_len = strlen( argv[ 1 ] );
		if ( dnNormalize( 0, NULL, NULL, &dn,
			&li->targets[ i ]->pseudorootdn, NULL ) != LDAP_SUCCESS )
		{
			fprintf( stderr, "%s: line %d: "
					"pseudoroot DN '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

	/* password to use as pseudo-root */
	} else if ( strcasecmp( argv[ 0 ], "pseudorootpw" ) == 0 ) {
		int 		i = li->ntargets-1;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}
		
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing password in \"pseudorootpw <password>\" line\n",
			    fname, lineno );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0L, 1, &li->targets[ i ]->pseudorootpw );
	
	/* dn massaging */
	} else if ( strcasecmp( argv[ 0 ], "suffixmassage" ) == 0 ) {
		BackendDB 	*tmp_be;
		int 		i = li->ntargets-1;
		struct berval	dn, nvnc, pvnc, nrnc, prnc;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}
		
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
 			fprintf( stderr,
	"%s: line %d: syntax is \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno );
			return 1;
		}

		dn.bv_val = argv[ 1 ];
		dn.bv_len = strlen( argv[ 1 ] );
		if ( dnPrettyNormal( NULL, &dn, &pvnc, &nvnc, NULL ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: "
					"suffix '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return 1;
		}
		
		tmp_be = select_backend( &nvnc, 0, 0 );
		if ( tmp_be != NULL && tmp_be != be ) {
			fprintf( stderr, 
	"%s: line %d: suffix already in use by another backend in"
	" \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;						
		}

		dn.bv_val = argv[ 2 ];
		dn.bv_len = strlen( argv[ 2 ] );
		if ( dnPrettyNormal( NULL, &dn, &prnc, &nrnc, NULL ) != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: "
					"massaged suffix '%s' is invalid\n",
					fname, lineno, argv[ 2 ] );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;
		}
	
#if 0	
		tmp_be = select_backend( &nrnc, 0, 0 );
		if ( tmp_be != NULL ) {
			fprintf( stderr,
	"%s: line %d: massaged suffix already in use by another backend in" 
	" \"suffixMassage <suffix> <massaged suffix>\"\n",
                                fname, lineno );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			free( prnc.bv_val );
			free( nrnc.bv_val );
                        return 1;
		}
#endif
		
		/*
		 * The suffix massaging is emulated by means of the
		 * rewrite capabilities
		 * FIXME: no extra rewrite capabilities should be added
		 * to the database
		 */
	 	return suffix_massage_config( li->targets[ i ]->rwmap.rwm_rw,
				&pvnc, &nvnc, &prnc, &nrnc );
		
	/* rewrite stuff ... */
 	} else if ( strncasecmp( argv[ 0 ], "rewrite", 7 ) == 0 ) {
		int 		i = li->ntargets-1;

		if ( i < 0 ) {
 			if ( strcasecmp( argv[0], "rewriteEngine" ) == 0 ) {
				li->rwinfo = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
			}
			return rewrite_parse(li->rwinfo, fname, lineno,
					argc, argv); 
		}
		
 		return rewrite_parse( li->targets[ i ]->rwmap.rwm_rw, fname, lineno,
				argc, argv );

	/* objectclass/attribute mapping */
	} else if ( strcasecmp( argv[ 0 ], "map" ) == 0 ) {
		int 		i = li->ntargets-1;

		if ( i < 0 ) {
			fprintf( stderr,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno );
			return 1;
		}

		return ldap_back_map_config( &li->targets[ i ]->rwmap.rwm_oc, 
				&li->targets[ i ]->rwmap.rwm_at,
				fname, lineno, argc, argv );
	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}
	return 0;
}

