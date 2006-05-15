/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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
#include "lutil.h"
#include "../back-ldap/back-ldap.h"
#undef ldap_debug       /* silence a warning in ldap-int.h */
#include "../../../libraries/libldap/ldap-int.h"
#include "back-meta.h"

static int
meta_back_new_target( 
	metatarget_t	**mtp )
{
        struct ldapmapping	*mapping;
	char			*rargv[ 3 ];
	metatarget_t		*mt;

	*mtp = NULL;

	mt = ch_calloc( sizeof( metatarget_t ), 1 );

	mt->mt_rwmap.rwm_rw = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
	if ( mt->mt_rwmap.rwm_rw == NULL ) {
		ch_free( mt );
		return -1;
	}


	/*
	 * the filter rewrite as a string must be disabled
	 * by default; it can be re-enabled by adding rules;
	 * this creates an empty rewriteContext
	 */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchFilter";
	rargv[ 2 ] = NULL;
	rewrite_parse( mt->mt_rwmap.rwm_rw, "<suffix massage>", 1, 2, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "default";
	rargv[ 2 ] = NULL;
	rewrite_parse( mt->mt_rwmap.rwm_rw, "<suffix massage>", 1, 2, rargv );

	ldap_back_map_init( &mt->mt_rwmap.rwm_at, &mapping );

	ldap_pvt_thread_mutex_init( &mt->mt_uri_mutex );

	*mtp = mt;

	return 0;
}

static int
check_true_false( char *str )
{
	if ( strcasecmp( str, "true" ) == 0 || strcasecmp( str, "yes" ) == 0 ) {
		return 1;
	}

	if ( strcasecmp( str, "false" ) == 0 || strcasecmp( str, "no" ) == 0 ) {
		return 0;
	}

	return -1;
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
	metainfo_t	*mi = ( metainfo_t * )be->be_private;

	assert( mi != NULL );

	/* URI of server to query */
	if ( strcasecmp( argv[ 0 ], "uri" ) == 0 ) {
		int 		i = mi->mi_ntargets;
#if 0
		int 		j;
#endif /* uncomment if uri MUST be a branch of suffix */
		LDAPURLDesc 	*ludp, *tmpludp;
		struct berval	dn;
		int		rc;
		int		c;

		metatarget_t	*mt;
		
		switch ( argc ) {
		case 1:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing URI "
	"in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;

		case 2:
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: too many args "
	"in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( be->be_nsuffix == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: the suffix must be defined before any target.\n",
				fname, lineno, 0 );
			return 1;
		}
		
		++mi->mi_ntargets;

		mi->mi_targets = ( metatarget_t ** )ch_realloc( mi->mi_targets, 
			sizeof( metatarget_t * ) * mi->mi_ntargets );
		if ( mi->mi_targets == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: out of memory while storing server name"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( meta_back_new_target( &mi->mi_targets[ i ] ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to init server"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		mt = mi->mi_targets[ i ];

		mt->mt_rebind_f = mi->mi_rebind_f;
		mt->mt_urllist_f = mi->mi_urllist_f;
		mt->mt_urllist_p = mt;

		mt->mt_nretries = mi->mi_nretries;
		mt->mt_flags = mi->mi_flags;
		mt->mt_version = mi->mi_version;
		mt->mt_network_timeout = mi->mi_network_timeout;
		mt->mt_bind_timeout = mi->mi_bind_timeout;
		for ( c = 0; c < LDAP_BACK_OP_LAST; c++ ) {
			mt->mt_timeout[ c ] = mi->mi_timeout[ c ];
		}

		/*
		 * uri MUST be legal!
		 */
		if ( ldap_url_parselist_ext( &ludp, argv[ 1 ], "\t",
			LDAP_PVT_URL_PARSE_NONE ) != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse URI"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		/*
		 * uri MUST have the <dn> part!
		 */
		if ( ludp->lud_dn == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing <naming context> "
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;

		} else if ( ludp->lud_dn[ 0 ] == '\0' ) {
			int	j = -1;

			for ( j = 0; !BER_BVISNULL( &be->be_nsuffix[ j ] ); j++ ) {
				if ( BER_BVISEMPTY( &be->be_nsuffix[ j ] ) ) {
					break;
				}
			}

			if ( BER_BVISNULL( &be->be_nsuffix[ j ] ) ) {
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing <naming context> "
		" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
					fname, lineno, 0 );
				return 1;
			}
		}

		/*
		 * copies and stores uri and suffix
		 */
		ber_str2bv( ludp->lud_dn, 0, 0, &dn );
		rc = dnPrettyNormal( NULL, &dn, &mt->mt_psuffix,
			&mt->mt_nsuffix, NULL );
		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
				"target \"%s\" DN is invalid\n",
				fname, lineno, argv[ 1 ] );
			return( 1 );
		}

		ludp->lud_dn[ 0 ] = '\0';

		switch ( ludp->lud_scope ) {
		case LDAP_SCOPE_DEFAULT:
			mt->mt_scope = LDAP_SCOPE_SUBTREE;
			break;

		case LDAP_SCOPE_SUBTREE:
		case LDAP_SCOPE_SUBORDINATE:
			mt->mt_scope = ludp->lud_scope;
			break;

		default:
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
				"invalid scope for target \"%s\"\n",
				fname, lineno, argv[ 1 ] );
			return( 1 );
		}

		/* check all, to apply the scope check on the first one */
		for ( tmpludp = ludp; tmpludp; tmpludp = tmpludp->lud_next ) {
			if ( tmpludp->lud_dn != NULL && tmpludp->lud_dn[ 0 ] != '\0' ) {
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"multiple URIs must have "
					"no DN part\n",
					fname, lineno, 0 );
				return( 1 );

			}
		}

		mt->mt_uri = ldap_url_list2urls( ludp );
		ldap_free_urllist( ludp );
		if ( mt->mt_uri == NULL) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: no memory?\n",
				fname, lineno, 0 );
			return( 1 );
		}
		
		/*
		 * uri MUST be a branch of suffix!
		 */
#if 0 /* too strict a constraint */
		if ( select_backend( &mt->mt_nsuffix, 0, 0 ) != be ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: <naming context> of URI does not refer to current backend"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}
#else
		/*
		 * uri MUST be a branch of a suffix!
		 */
		if ( select_backend( &mt->mt_nsuffix, 0, 0 ) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: <naming context> of URI does not resolve to a backend"
	" in \"uri <protocol>://<server>[:port]/<naming context>\" line\n",
				fname, lineno, 0 );
			return 1;
		}
#endif

	/* subtree-exclude */
	} else if ( strcasecmp( argv[ 0 ], "subtree-exclude" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;
		struct berval	dn, ndn;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}
		
		switch ( argc ) {
		case 1:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing DN in \"subtree-exclude <DN>\" line\n",
			    fname, lineno, 0 );
			return 1;

		case 2:
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: too many args in \"subtree-exclude <DN>\" line\n",
			    fname, lineno, 0 );
			return 1;
		}

		ber_str2bv( argv[ 1 ], 0, 0, &dn );
		if ( dnNormalize( 0, NULL, NULL, &dn, &ndn, NULL )
			!= LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"subtree-exclude DN=\"%s\" is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

		if ( !dnIsSuffix( &ndn, &mi->mi_targets[ i ]->mt_nsuffix ) ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"subtree-exclude DN=\"%s\" "
					"must be subtree of target\n",
					fname, lineno, argv[ 1 ] );
			ber_memfree( ndn.bv_val );
			return( 1 );
		}

		if ( mi->mi_targets[ i ]->mt_subtree_exclude != NULL ) {
			int		j;

			for ( j = 0; !BER_BVISNULL( &mi->mi_targets[ i ]->mt_subtree_exclude[ j ] ); j++ )
			{
				if ( dnIsSuffix( &mi->mi_targets[ i ]->mt_subtree_exclude[ j ], &ndn ) ) {
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
							"subtree-exclude DN=\"%s\" "
							"is suffix of another subtree-exclude\n",
							fname, lineno, argv[ 1 ] );
					/* reject, because it might be superior
					 * to more than one subtree-exclude */
					ber_memfree( ndn.bv_val );
					return( 1 );

				} else if ( dnIsSuffix( &ndn, &mi->mi_targets[ i ]->mt_subtree_exclude[ j ] ) ) {
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
							"another subtree-exclude is suffix of "
							"subtree-exclude DN=\"%s\"\n",
							fname, lineno, argv[ 1 ] );
					ber_memfree( ndn.bv_val );
					return( 0 );
				}
			}
		}

		ber_bvarray_add( &mi->mi_targets[ i ]->mt_subtree_exclude, &ndn );

	/* default target directive */
	} else if ( strcasecmp( argv[ 0 ], "default-target" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;
		
		if ( argc == 1 ) {
 			if ( i < 0 ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"default-target\" alone need be"
       	" inside a \"uri\" directive\n",
					fname, lineno, 0 );
				return 1;
			}
			mi->mi_defaulttarget = i;

		} else {
			if ( strcasecmp( argv[ 1 ], "none" ) == 0 ) {
				if ( i >= 0 ) {
					Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"default-target none\""
       	" should go before uri definitions\n",
						fname, lineno, 0 );
				}
				mi->mi_defaulttarget = META_DEFAULT_TARGET_NONE;

			} else {
				
				if ( lutil_atoi( &mi->mi_defaulttarget, argv[ 1 ] ) != 0
					|| mi->mi_defaulttarget < 0
					|| mi->mi_defaulttarget >= i - 1 )
				{
					Debug( LDAP_DEBUG_ANY,
	"%s: line %d: illegal target number %d\n",
						fname, lineno, mi->mi_defaulttarget );
					return 1;
				}
			}
		}
		
	/* ttl of dn cache */
	} else if ( strcasecmp( argv[ 0 ], "dncache-ttl" ) == 0 ) {
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing ttl in \"dncache-ttl <ttl>\" line\n",
				fname, lineno, 0 );
			return 1;
		}
		
		if ( strcasecmp( argv[ 1 ], "forever" ) == 0 ) {
			mi->mi_cache.ttl = META_DNCACHE_FOREVER;

		} else if ( strcasecmp( argv[ 1 ], "disabled" ) == 0 ) {
			mi->mi_cache.ttl = META_DNCACHE_DISABLED;

		} else {
			unsigned long	t;

			if ( lutil_parse_time( argv[ 1 ], &t ) != 0 ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse ttl \"%s\" in \"dncache-ttl <ttl>\" line\n",
					fname, lineno, argv[ 1 ] );
				return 1;
			}
			mi->mi_cache.ttl = (time_t)t;
		}

	/* network timeout when connecting to ldap servers */
	} else if ( strcasecmp( argv[ 0 ], "network-timeout" ) == 0 ) {
		unsigned long	t;
		time_t		*tp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_network_timeout
				: &mi->mi_network_timeout;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing network timeout in \"network-timeout <seconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( lutil_parse_time( argv[ 1 ], &t ) ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse timeout \"%s\" in \"network-timeout <seconds>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;

		}

		*tp = (time_t)t;

	/* idle timeout when connecting to ldap servers */
	} else if ( strcasecmp( argv[ 0 ], "idle-timeout" ) == 0 ) {
		unsigned long	t;

		switch ( argc ) {
		case 1:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing timeout value in \"idle-timeout <seconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		case 2:
			break;
		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: extra cruft after timeout value in \"idle-timeout <seconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( lutil_parse_time( argv[ 1 ], &t ) ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse timeout \"%s\" in \"idle-timeout <seconds>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;

		}

		mi->mi_idle_timeout = (time_t)t;

	/* conn ttl */
	} else if ( strcasecmp( argv[ 0 ], "conn-ttl" ) == 0 ) {
		unsigned long	t;

		switch ( argc ) {
		case 1:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing ttl value in \"conn-ttl <seconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		case 2:
			break;
		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: extra cruft after ttl value in \"conn-ttl <seconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( lutil_parse_time( argv[ 1 ], &t ) ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse ttl \"%s\" in \"conn-ttl <seconds>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;

		}

		mi->mi_conn_ttl = (time_t)t;

	/* bind timeout when connecting to ldap servers */
	} else if ( strcasecmp( argv[ 0 ], "bind-timeout" ) == 0 ) {
		unsigned long	t;
		struct timeval	*tp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_bind_timeout
				: &mi->mi_bind_timeout;

		switch ( argc ) {
		case 1:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing timeout value in \"bind-timeout <microseconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		case 2:
			break;
		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: extra cruft after timeout value in \"bind-timeout <microseconds>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( lutil_atoul( &t, argv[ 1 ] ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse timeout \"%s\" in \"bind-timeout <microseconds>\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;

		}

		tp->tv_sec = t/1000000;
		tp->tv_usec = t%1000000;

	/* name to use for meta_back_group */
	} else if ( strcasecmp( argv[ 0 ], "acl-authcDN" ) == 0
			|| strcasecmp( argv[ 0 ], "binddn" ) == 0 )
	{
		int 		i = mi->mi_ntargets - 1;
		struct berval	dn;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}
		
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing name in \"binddn <name>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 0 ], "binddn" ) == 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
				"\"binddn\" statement is deprecated; "
				"use \"acl-authcDN\" instead\n",
				fname, lineno, 0 );
			/* FIXME: some day we'll need to throw an error */
		}

		ber_str2bv( argv[ 1 ], 0, 0, &dn );
		if ( dnNormalize( 0, NULL, NULL, &dn, &mi->mi_targets[ i ]->mt_binddn,
			NULL ) != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"bind DN '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

	/* password to use for meta_back_group */
	} else if ( strcasecmp( argv[ 0 ], "acl-passwd" ) == 0
			|| strcasecmp( argv[ 0 ], "bindpw" ) == 0 )
	{
		int 		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}
		
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing password in \"bindpw <password>\" line\n",
			    fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 0 ], "bindpw" ) == 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
				"\"bindpw\" statement is deprecated; "
				"use \"acl-passwd\" instead\n",
				fname, lineno, 0 );
			/* FIXME: some day we'll need to throw an error */
		}

		ber_str2bv( argv[ 1 ], 0L, 1, &mi->mi_targets[ i ]->mt_bindpw );
		
	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[ 0 ], "rebind-as-user" ) == 0 ) {
		if ( argc > 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"rebind-as-user {NO|yes}\" takes 1 argument.\n",
			    fname, lineno, 0 );
			return( 1 );
		}

		if ( argc == 1 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: deprecated use of \"rebind-as-user {FALSE|true}\" with no arguments.\n",
			    fname, lineno, 0 );
			mi->mi_flags |= LDAP_BACK_F_SAVECRED;

		} else {
			switch ( check_true_false( argv[ 1 ] ) ) {
			case 0:
				mi->mi_flags &= ~LDAP_BACK_F_SAVECRED;
				break;

			case 1:
				mi->mi_flags |= LDAP_BACK_F_SAVECRED;
				break;

			default:
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"rebind-as-user {FALSE|true}\" unknown argument \"%s\".\n",
				    fname, lineno, argv[ 1 ] );
				return 1;
			}
		}

	} else if ( strcasecmp( argv[ 0 ], "chase-referrals" ) == 0 ) {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"chase-referrals {TRUE|false}\" needs 1 argument.\n",
				fname, lineno, 0 );
			return( 1 );
		}

		/* this is the default; we add it because the default might change... */
		switch ( check_true_false( argv[ 1 ] ) ) {
		case 1:
			*flagsp |= LDAP_BACK_F_CHASE_REFERRALS;
			break;

		case 0:
			*flagsp &= ~LDAP_BACK_F_CHASE_REFERRALS;
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: \"chase-referrals {TRUE|false}\": unknown argument \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return( 1 );
		}
	
	} else if ( strcasecmp( argv[ 0 ], "tls" ) == 0 ) {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: \"tls <what>\" needs 1 argument.\n",
				fname, lineno, 0 );
			return( 1 );
		}

		/* start */
		if ( strcasecmp( argv[ 1 ], "start" ) == 0 ) {
			*flagsp |= ( LDAP_BACK_F_USE_TLS | LDAP_BACK_F_TLS_CRITICAL );
	
		/* try start tls */
		} else if ( strcasecmp( argv[ 1 ], "try-start" ) == 0 ) {
			*flagsp &= ~LDAP_BACK_F_TLS_CRITICAL;
			*flagsp |= LDAP_BACK_F_USE_TLS;
	
		/* propagate start tls */
		} else if ( strcasecmp( argv[ 1 ], "propagate" ) == 0 ) {
			*flagsp |= ( LDAP_BACK_F_PROPAGATE_TLS | LDAP_BACK_F_TLS_CRITICAL );
		
		/* try start tls */
		} else if ( strcasecmp( argv[ 1 ], "try-propagate" ) == 0 ) {
			*flagsp &= ~LDAP_BACK_F_TLS_CRITICAL;
			*flagsp |= LDAP_BACK_F_PROPAGATE_TLS;

		} else {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: \"tls <what>\": unknown argument \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return( 1 );
		}

	} else if ( strcasecmp( argv[ 0 ], "t-f-support" ) == 0 ) {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
		"%s: line %d: \"t-f-support {FALSE|true|discover}\" needs 1 argument.\n",
				fname, lineno, 0 );
			return( 1 );
		}

		switch ( check_true_false( argv[ 1 ] ) ) {
		case 0:
			*flagsp &= ~(LDAP_BACK_F_SUPPORT_T_F|LDAP_BACK_F_SUPPORT_T_F_DISCOVER);
			break;

		case 1:
			*flagsp |= LDAP_BACK_F_SUPPORT_T_F;
			break;

		default:
			if ( strcasecmp( argv[ 1 ], "discover" ) == 0 ) {
				*flagsp |= LDAP_BACK_F_SUPPORT_T_F_DISCOVER;

			} else {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unknown value \"%s\" for \"t-f-support {no|yes|discover}\".\n",
					fname, lineno, argv[ 1 ] );
				return 1;
			}
			break;
		}

	/* onerr? */
	} else if ( strcasecmp( argv[ 0 ], "onerr" ) == 0 ) {
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"onerr {CONTINUE|stop}\" takes 1 argument\n",
				fname, lineno, 0 );
			return( 1 );
		}

		if ( strcasecmp( argv[ 1 ], "continue" ) == 0 ) {
			mi->mi_flags &= ~META_BACK_F_ONERR_STOP;

		} else if ( strcasecmp( argv[ 1 ], "stop" ) == 0 ) {
			mi->mi_flags |= META_BACK_F_ONERR_STOP;

		} else {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"onerr {CONTINUE|stop}\": invalid arg \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

	/* bind-defer? */
	} else if ( strcasecmp( argv[ 0 ], "pseudoroot-bind-defer" ) == 0 ) {
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"pseudoroot-bind-defer {FALSE|true}\" takes 1 argument\n",
				fname, lineno, 0 );
			return( 1 );
		}

		switch ( check_true_false( argv[ 1 ] ) ) {
		case 0:
			mi->mi_flags &= ~META_BACK_F_DEFER_ROOTDN_BIND;
			break;

		case 1:
			mi->mi_flags |= META_BACK_F_DEFER_ROOTDN_BIND;
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"pseudoroot-bind-defer {FALSE|true}\": invalid arg \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

	/* single-conn? */
	} else if ( strcasecmp( argv[ 0 ], "single-conn" ) == 0 ) {
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"single-conn {FALSE|true}\" takes 1 argument\n",
				fname, lineno, 0 );
			return( 1 );
		}

		if ( mi->mi_ntargets > 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"single-conn\" must appear before target definitions\n",
				fname, lineno, 0 );
			return( 1 );
		}

		switch ( check_true_false( argv[ 1 ] ) ) {
		case 0:
			mi->mi_flags &= ~LDAP_BACK_F_SINGLECONN;
			break;

		case 1:
			mi->mi_flags |= LDAP_BACK_F_SINGLECONN;
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"single-conn {FALSE|true}\": invalid arg \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

	} else if ( strcasecmp( argv[ 0 ], "timeout" ) == 0 ) {
		char	*sep;
		time_t	*tv = mi->mi_ntargets ?
				mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_timeout
				: mi->mi_timeout;
		int	c;

		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: \"timeout [{add|delete|modify|modrdn}=]<val> [...]\" takes at least 1 argument\n",
				fname, lineno, 0 );
			return( 1 );
		}

		for ( c = 1; c < argc; c++ ) {
			time_t		*t = NULL;
			unsigned long	val;

			sep = strchr( argv[ c ], '=' );
			if ( sep != NULL ) {
				size_t	len = sep - argv[ c ];

				if ( strncasecmp( argv[ c ], "add", len ) == 0 ) {
					t = &tv[ LDAP_BACK_OP_ADD ];
				} else if ( strncasecmp( argv[ c ], "delete", len ) == 0 ) {
					t = &tv[ LDAP_BACK_OP_DELETE ];
				} else if ( strncasecmp( argv[ c ], "modify", len ) == 0 ) {
					t = &tv[ LDAP_BACK_OP_MODIFY ];
				} else if ( strncasecmp( argv[ c ], "modrdn", len ) == 0 ) {
					t = &tv[ LDAP_BACK_OP_MODRDN ];
				} else {
					char	buf[ SLAP_TEXT_BUFLEN ];
					snprintf( buf, sizeof( buf ),
						"unknown operation \"%s\" for timeout #%d",
						argv[ c ], c );
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: %s.\n",
						fname, lineno, buf );
					return 1;
				}
				sep++;
	
			} else {
				sep = argv[ c ];
			}
	
			if ( lutil_parse_time( sep, &val ) != 0 ) {
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: unable to parse value \"%s\" for timeout.\n",
					fname, lineno, sep );
				return 1;
			}
		
			if ( t ) {
				*t = (time_t)val;
	
			} else {
				int	i;
	
				for ( i = 0; i < LDAP_BACK_OP_LAST; i++ ) {
					tv[ i ] = (time_t)val;
				}
			}
		}
	
	/* name to use as pseudo-root dn */
	} else if ( strcasecmp( argv[ 0 ], "pseudorootdn" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;
		struct berval	dn;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}
		
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing name in \"pseudorootdn <name>\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		dn.bv_val = argv[ 1 ];
		dn.bv_len = strlen( argv[ 1 ] );
		if ( dnNormalize( 0, NULL, NULL, &dn,
			&mi->mi_targets[ i ]->mt_pseudorootdn, NULL ) != LDAP_SUCCESS )
		{
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"pseudoroot DN '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return( 1 );
		}

	/* password to use as pseudo-root */
	} else if ( strcasecmp( argv[ 0 ], "pseudorootpw" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}
		
		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing password in \"pseudorootpw <password>\" line\n",
			    fname, lineno, 0 );
			return 1;
		}
		ber_str2bv( argv[ 1 ], 0L, 1, &mi->mi_targets[ i ]->mt_pseudorootpw );
	
	/* dn massaging */
	} else if ( strcasecmp( argv[ 0 ], "suffixmassage" ) == 0 ) {
		BackendDB 	*tmp_be;
		int 		i = mi->mi_ntargets - 1, rc;
		struct berval	dn, nvnc, pvnc, nrnc, prnc;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
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
 			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: syntax is \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno, 0 );
			return 1;
		}

		ber_str2bv( argv[ 1 ], 0, 0, &dn );
		if ( dnPrettyNormal( NULL, &dn, &pvnc, &nvnc, NULL ) != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"suffix '%s' is invalid\n",
					fname, lineno, argv[ 1 ] );
			return 1;
		}
		
		tmp_be = select_backend( &nvnc, 0, 0 );
		if ( tmp_be != NULL && tmp_be != be ) {
			Debug( LDAP_DEBUG_ANY, 
	"%s: line %d: suffix already in use by another backend in"
	" \"suffixMassage <suffix> <massaged suffix>\"\n",
				fname, lineno, 0 );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;						
		}

		ber_str2bv( argv[ 2 ], 0, 0, &dn );
		if ( dnPrettyNormal( NULL, &dn, &prnc, &nrnc, NULL ) != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: "
				"massaged suffix '%s' is invalid\n",
				fname, lineno, argv[ 2 ] );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;
		}
	
#if 0	
		tmp_be = select_backend( &nrnc, 0, 0 );
		if ( tmp_be != NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: massaged suffix already in use by another backend in" 
	" \"suffixMassage <suffix> <massaged suffix>\"\n",
                                fname, lineno, 0 );
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
	 	rc = suffix_massage_config( mi->mi_targets[ i ]->mt_rwmap.rwm_rw,
				&pvnc, &nvnc, &prnc, &nrnc );

		free( pvnc.bv_val );
		free( nvnc.bv_val );
		free( prnc.bv_val );
		free( nrnc.bv_val );

		return rc;
		
	/* rewrite stuff ... */
 	} else if ( strncasecmp( argv[ 0 ], "rewrite", 7 ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: line %d: \"rewrite\" "
				"statement outside target definition.\n",
				fname, lineno, 0 );
			return 1;
		}
		
 		return rewrite_parse( mi->mi_targets[ i ]->mt_rwmap.rwm_rw,
				fname, lineno, argc, argv );

	/* objectclass/attribute mapping */
	} else if ( strcasecmp( argv[ 0 ], "map" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need \"uri\" directive first\n",
				fname, lineno, 0 );
			return 1;
		}

		return ldap_back_map_config( &mi->mi_targets[ i ]->mt_rwmap.rwm_oc, 
				&mi->mi_targets[ i ]->mt_rwmap.rwm_at,
				fname, lineno, argc, argv );

	} else if ( strcasecmp( argv[ 0 ], "nretries" ) == 0 ) {
		int 		i = mi->mi_ntargets - 1;
		int		nretries = META_RETRY_UNDEFINED;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need value in \"nretries <value>\"\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( strcasecmp( argv[ 1 ], "forever" ) == 0 ) {
			nretries = META_RETRY_FOREVER;

		} else if ( strcasecmp( argv[ 1 ], "never" ) == 0 ) {
			nretries = META_RETRY_NEVER;

		} else {
			if ( lutil_atoi( &nretries, argv[ 1 ] ) != 0 ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse value \"%s\" in \"nretries <value>\"\n",
					fname, lineno, argv[ 1 ] );
				return 1;
			}
		}

		if ( i < 0 ) {
			mi->mi_nretries = nretries;

		} else {
			mi->mi_targets[ i ]->mt_nretries = nretries;
		}

	} else if ( strcasecmp( argv[ 0 ], "protocol-version" ) == 0 ) {
		int	*version = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_version
				: &mi->mi_version;

		if ( argc != 2 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: need value in \"protocol-version <version>\"\n",
				fname, lineno, 0 );
			return 1;
		}

		if ( lutil_atoi( version, argv[ 1 ] ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unable to parse version \"%s\" in \"protocol-version <version>\"\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

		if ( *version != 0 && ( *version < LDAP_VERSION_MIN || *version > LDAP_VERSION_MAX ) ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: unsupported version \"%s\" in \"protocol-version <version>\"\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

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
		Debug( LDAP_DEBUG_ANY,
	"%s: line %d: syntax is \"map {objectclass | attribute} [<local> | *] {<foreign> | *}\"\n",
			fname, lineno, 0 );
		return 1;
	}

	if ( strcasecmp( argv[ 1 ], "objectclass" ) == 0 ) {
		map = oc_map;
		is_oc = 1;

	} else if ( strcasecmp( argv[ 1 ], "attribute" ) == 0 ) {
		map = at_map;

	} else {
		Debug( LDAP_DEBUG_ANY, "%s: line %d: syntax is "
			"\"map {objectclass | attribute} [<local> | *] "
			"{<foreign> | *}\"\n",
			fname, lineno, 0 );
		return 1;
	}

	if ( strcmp( argv[ 2 ], "*" ) == 0 ) {
		if ( argc < 4 || strcmp( argv[ 3 ], "*" ) == 0 ) {
			map->drop_missing = ( argc < 4 );
			return 0;
		}
		src = dst = argv[ 3 ];

	} else if ( argc < 4 ) {
		src = "";
		dst = argv[ 2 ];

	} else {
		src = argv[ 2 ];
		dst = ( strcmp( argv[ 3 ], "*" ) == 0 ? src : argv[ 3 ] );
	}

	if ( ( map == at_map )
			&& ( strcasecmp( src, "objectclass" ) == 0
			|| strcasecmp( dst, "objectclass" ) == 0 ) )
	{
		Debug( LDAP_DEBUG_ANY,
			"%s: line %d: objectclass attribute cannot be mapped\n",
			fname, lineno, 0 );
	}

	mapping = (struct ldapmapping *)ch_calloc( 2,
		sizeof(struct ldapmapping) );
	if ( mapping == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"%s: line %d: out of memory\n",
			fname, lineno, 0 );
		return 1;
	}
	ber_str2bv( src, 0, 1, &mapping[ 0 ].src );
	ber_str2bv( dst, 0, 1, &mapping[ 0 ].dst );
	mapping[ 1 ].src = mapping[ 0 ].dst;
	mapping[ 1 ].dst = mapping[ 0 ].src;

	/*
	 * schema check
	 */
	if ( is_oc ) {
		if ( src[ 0 ] != '\0' ) {
			if ( oc_bvfind( &mapping[ 0 ].src ) == NULL ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: warning, source objectClass '%s' "
	"should be defined in schema\n",
					fname, lineno, src );

				/*
				 * FIXME: this should become an err
				 */
				goto error_return;
			}
		}

		if ( oc_bvfind( &mapping[ 0 ].dst ) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: warning, destination objectClass '%s' "
	"is not defined in schema\n",
				fname, lineno, dst );
		}
	} else {
		int			rc;
		const char		*text = NULL;
		AttributeDescription	*ad = NULL;

		if ( src[ 0 ] != '\0' ) {
			rc = slap_bv2ad( &mapping[ 0 ].src, &ad, &text );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: warning, source attributeType '%s' "
	"should be defined in schema\n",
					fname, lineno, src );

				/*
				 * FIXME: this should become an err
				 */
				/*
				 * we create a fake "proxied" ad 
				 * and add it here.
				 */

				rc = slap_bv2undef_ad( &mapping[ 0 ].src,
						&ad, &text, SLAP_AD_PROXIED );
				if ( rc != LDAP_SUCCESS ) {
					char	buf[ SLAP_TEXT_BUFLEN ];

					snprintf( buf, sizeof( buf ),
						"source attributeType \"%s\": %d (%s)",
						src, rc, text ? text : "" );
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: %s\n",
						fname, lineno, buf );
					goto error_return;
				}
			}

			ad = NULL;
		}

		rc = slap_bv2ad( &mapping[ 0 ].dst, &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: line %d: warning, destination attributeType '%s' "
	"is not defined in schema\n",
				fname, lineno, dst );

			/*
			 * we create a fake "proxied" ad 
			 * and add it here.
			 */

			rc = slap_bv2undef_ad( &mapping[ 0 ].dst,
					&ad, &text, SLAP_AD_PROXIED );
			if ( rc != LDAP_SUCCESS ) {
				char	buf[ SLAP_TEXT_BUFLEN ];

				snprintf( buf, sizeof( buf ),
					"source attributeType \"%s\": %d (%s)\n",
					dst, rc, text ? text : "" );
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: %s\n",
					fname, lineno, buf );
				return 1;
			}
		}
	}

	if ( (src[ 0 ] != '\0' && avl_find( map->map, (caddr_t)&mapping[ 0 ], mapping_cmp ) != NULL)
			|| avl_find( map->remap, (caddr_t)&mapping[ 1 ], mapping_cmp ) != NULL)
	{
		Debug( LDAP_DEBUG_ANY,
			"%s: line %d: duplicate mapping found.\n",
			fname, lineno, 0 );
		goto error_return;
	}

	if ( src[ 0 ] != '\0' ) {
		avl_insert( &map->map, (caddr_t)&mapping[ 0 ],
					mapping_cmp, mapping_dup );
	}
	avl_insert( &map->remap, (caddr_t)&mapping[ 1 ],
				mapping_cmp, mapping_dup );

	return 0;

error_return:;
	if ( mapping ) {
		ch_free( mapping[ 0 ].src.bv_val );
		ch_free( mapping[ 0 ].dst.bv_val );
		ch_free( mapping );
	}

	return 1;
}


#ifdef ENABLE_REWRITE
static char *
suffix_massage_regexize( const char *s )
{
	char *res, *ptr;
	const char *p, *r;
	int i;

	if ( s[ 0 ] == '\0' ) {
		return ch_strdup( "^(.+)$" );
	}

	for ( i = 0, p = s; 
			( r = strchr( p, ',' ) ) != NULL; 
			p = r + 1, i++ )
		;

	res = ch_calloc( sizeof( char ),
			strlen( s )
			+ STRLENOF( "((.+),)?" )
			+ STRLENOF( "[ ]?" ) * i
			+ STRLENOF( "$" ) + 1 );

	ptr = lutil_strcopy( res, "((.+),)?" );
	for ( i = 0, p = s;
			( r = strchr( p, ',' ) ) != NULL;
			p = r + 1 , i++ ) {
		ptr = lutil_strncopy( ptr, p, r - p + 1 );
		ptr = lutil_strcopy( ptr, "[ ]?" );

		if ( r[ 1 ] == ' ' ) {
			r++;
		}
	}
	ptr = lutil_strcopy( ptr, p );
	ptr[ 0 ] = '$';
	ptr++;
	ptr[ 0 ] = '\0';

	return res;
}

static char *
suffix_massage_patternize( const char *s, const char *p )
{
	ber_len_t	len;
	char		*res, *ptr;

	len = strlen( p );

	if ( s[ 0 ] == '\0' ) {
		len++;
	}

	res = ch_calloc( sizeof( char ), len + STRLENOF( "%1" ) + 1 );
	if ( res == NULL ) {
		return NULL;
	}

	ptr = lutil_strcopy( res, ( p[ 0 ] == '\0' ? "%2" : "%1" ) );
	if ( s[ 0 ] == '\0' ) {
		ptr[ 0 ] = ',';
		ptr++;
	}
	lutil_strcopy( ptr, p );

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
	rargv[ 2 ] = suffix_massage_patternize( pvnc->bv_val, prnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );

	if ( BER_BVISEMPTY( pvnc ) ) {
		rargv[ 0 ] = "rewriteRule";
		rargv[ 1 ] = "^$";
		rargv[ 2 ] = prnc->bv_val;
		rargv[ 3 ] = ":";
		rargv[ 4 ] = NULL;
		rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	}
	
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchEntryDN";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

	rargv[ 0 ] = "rewriteRule";
	rargv[ 1 ] = suffix_massage_regexize( prnc->bv_val );
	rargv[ 2 ] = suffix_massage_patternize( prnc->bv_val, pvnc->bv_val );
	rargv[ 3 ] = ":";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	ch_free( rargv[ 1 ] );
	ch_free( rargv[ 2 ] );

	if ( BER_BVISEMPTY( prnc ) ) {
		rargv[ 0 ] = "rewriteRule";
		rargv[ 1 ] = "^$";
		rargv[ 2 ] = pvnc->bv_val;
		rargv[ 3 ] = ":";
		rargv[ 4 ] = NULL;
		rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	}
	
	/* backward compatibility */
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchResult";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchEntryDN";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );
	
	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "matchedDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchEntryDN";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "searchAttrDN";
	rargv[ 2 ] = "alias";
	rargv[ 3 ] = "searchEntryDN";
	rargv[ 4 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 4, rargv );

	/* NOTE: this corresponds to #undef'ining RWM_REFERRAL_REWRITE;
	 * see servers/slapd/overlays/rwm.h for details */
        rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "referralAttrDN";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );

	rargv[ 0 ] = "rewriteContext";
	rargv[ 1 ] = "referralDN";
	rargv[ 2 ] = NULL;
	rewrite_parse( info, "<suffix massage>", ++line, 2, rargv );
	
	return 0;
}
#endif /* ENABLE_REWRITE */

