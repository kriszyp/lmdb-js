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
#undef ldap_debug
/* for advanced URL parsing */
#include "../../../libraries/libldap/ldap-int.h"

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
		char		**argv )
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: ldap backend info is null!\n",
				fname, lineno );
		return 1;
	}

	/* server address to query (depricated, use "uri" directive) */
	if ( strcasecmp( argv[0], "server" ) == 0 ) {
		ber_len_t	l;

		fprintf( stderr,
	"%s: line %d: \"server <address>\" directive is deprecated\n",
					fname, lineno );

		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing address in \"server <address>\" line\n",
					fname, lineno );
			return 1;
		}
		if ( li->url != NULL ) {
			ch_free( li->url );
		}
		l = strlen( argv[1] ) + STRLENOF( "ldap:///") + 1;
		li->url = ch_calloc( l, sizeof( char ) );
		if ( li->url == NULL ) {
			fprintf( stderr, "%s: line %d: malloc failed\n" );
			return 1;
		}

		snprintf( li->url, l, "ldap://%s/", argv[1] );

	/* URI of server to query (preferred over "server" directive) */
	} else if ( strcasecmp( argv[0], "uri" ) == 0 ) {
		LDAPURLDesc	*tmpludp;
		int		urlrc;

		if ( argc != 2 ) {
			fprintf( stderr, "%s: line %d: "
					"missing uri "
					"in \"uri <uri>\" line\n",
					fname, lineno );
			return 1;
		}
		if ( li->url != NULL ) {
			ch_free( li->url );
		}
		if ( li->lud != NULL ) {
			ldap_free_urllist( li->lud );
		}

#if 0
		/* PARANOID: DN and more are not required nor allowed */
		urlrc = ldap_url_parselist_ext( &li->lud, argv[ 1 ], "\t" );
#else
		urlrc =  ldap_url_parselist( &li->lud, argv[ 1 ] );
#endif
		if ( urlrc != LDAP_URL_SUCCESS ) {
			char	*why;

			switch ( urlrc ) {
			case LDAP_URL_ERR_MEM:
				why = "no memory";
				break;
			case LDAP_URL_ERR_PARAM:
		  		why = "parameter is bad";
				break;
			case LDAP_URL_ERR_BADSCHEME:
				why = "URL doesn't begin with \"[c]ldap[si]://\"";
				break;
			case LDAP_URL_ERR_BADENCLOSURE:
				why = "URL is missing trailing \">\"";
				break;
			case LDAP_URL_ERR_BADURL:
				why = "URL is bad";
			case LDAP_URL_ERR_BADHOST:
				why = "host/port is bad";
				break;
			case LDAP_URL_ERR_BADATTRS:
				why = "bad (or missing) attributes";
				break;
			case LDAP_URL_ERR_BADSCOPE:
				why = "scope string is invalid (or missing)";
				break;
			case LDAP_URL_ERR_BADFILTER:
				why = "bad or missing filter";
				break;
			case LDAP_URL_ERR_BADEXTS:
				why = "bad or missing extensions";
				break;
			default:
				why = "unknown reason";
				break;
			}
			fprintf( stderr, "%s: line %d: "
					"unable to parse uri \"%s\" "
					"in \"uri <uri>\" line: %s\n",
					fname, lineno, argv[ 1 ], why );
			return 1;
		}

		for ( tmpludp = li->lud; tmpludp; tmpludp = tmpludp->lud_next ) {
			if ( ( tmpludp->lud_dn != NULL
						&& tmpludp->lud_dn[0] != '\0' )
					|| tmpludp->lud_attrs != NULL
					|| tmpludp->lud_filter != NULL
					|| tmpludp->lud_exts != NULL )
			{
				fprintf( stderr, "%s: line %d: "
						"warning, only protocol, "
						"host and port allowed "
						"in \"uri <uri>\" statement "
						"for \"%s\"\n",
						fname, lineno, argv[1] );
			}
		}

#if 0
		for ( tmpludp = li->lud; tmpludp; tmpludp = tmpludp->lud_next ) {
			LDAPURLDesc	tmplud;
			char		*tmpurl;
			ber_len_t	oldlen = 0, len;

			tmplud = *tmpludp;
			tmplud.lud_dn = "";
			tmplud.lud_attrs = NULL;
			tmplud.lud_filter = NULL;
			if ( !ldap_is_ldapi_url( argv[ 1 ] ) ) {
				tmplud.lud_exts = NULL;
				tmplud.lud_crit_exts = 0;
			}

			tmpurl = ldap_url_desc2str( &tmplud );

			if ( tmpurl == NULL ) {
				fprintf( stderr, "%s: line %d: "
					"unable to rebuild uri "
					"in \"uri <uri>\" statement "
					"for \"%s\"\n",
					fname, lineno, argv[ 1 ] );
				return 1;
			}

			len = strlen( tmpurl );
			if ( li->url ) {
				oldlen = strlen( li->url ) + STRLENOF( " " );
			}
			li->url = ch_realloc( li->url, oldlen + len + 1);
			if ( oldlen ) {
				li->url[oldlen - 1] = " ";
			}
			AC_MEMCPY( &li->url[oldlen], tmpurl, len + 1 );
			ch_free( tmpurl );
		}
#else
		li->url = ch_strdup( argv[ 1 ] );
#endif

	/* name to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "acl-authcdn" ) == 0
			|| strcasecmp( argv[0], "binddn" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing name in \"%s <name>\" line\n",
					fname, lineno, argv[0] );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->acl_authcDN );

	/* password to use for ldap_back_group */
	} else if ( strcasecmp( argv[0], "acl-passwd" ) == 0
			|| strcasecmp( argv[0], "bindpw" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing password in \"%s <password>\" line\n",
					fname, lineno, argv[0] );
			return( 1 );
		}
		ber_str2bv( argv[1], 0, 1, &li->acl_passwd );

#ifdef LDAP_BACK_PROXY_AUTHZ
	/* identity assertion stuff... */
	} else if ( strncasecmp( argv[0], "idassert-", STRLENOF( "idassert-" ) ) == 0
			|| strncasecmp( argv[0], "proxyauthz", STRLENOF( "proxyauthz" ) ) == 0 ) {
		return parse_idassert( be, fname, lineno, argc, argv );
#endif /* LDAP_BACK_PROXY_AUTHZ */

	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[0], "rebind-as-user" ) == 0 ) {
		if ( argc != 1 ) {
			fprintf( stderr,
	"%s: line %d: rebind-as-user takes no arguments\n",
					fname, lineno );
			return( 1 );
		}
		li->savecred = 1;
	
	/* intercept exop_who_am_i? */
	} else if ( strcasecmp( argv[0], "proxy-whoami" ) == 0 ) {
		if ( argc != 1 ) {
			fprintf( stderr,
	"%s: line %d: proxy-whoami takes no arguments\n",
					fname, lineno );
			return( 1 );
		}
		load_extop( (struct berval *)&slap_EXOP_WHOAMI,
				0, ldap_back_exop_whoami );
	
	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}

static int
ldap_back_exop_whoami(
		Operation	*op,
		SlapReply	*rs )
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
		int do_retry = 1;

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

retry:
		rs->sr_err = ldap_whoami(lc->lc_ld, ctrls, NULL, &msgid);
		if (rs->sr_err == LDAP_SUCCESS) {
			if (ldap_result(lc->lc_ld, msgid, 1, NULL, &res) == -1) {
				ldap_get_option(lc->lc_ld, LDAP_OPT_ERROR_NUMBER,
					&rs->sr_err);
				if ( rs->sr_err == LDAP_SERVER_DOWN && do_retry ) {
					do_retry = 0;
					if ( ldap_back_retry( lc, op, rs ) )
						goto retry;
				}
				ldap_back_freeconn( op, lc );
				lc = NULL;

			} else {
				rs->sr_err = ldap_parse_whoami(lc->lc_ld, res, &bv);
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
		if ( !BER_BVISEMPTY( &op->o_dn ) ) {
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

	/* identity assertion mode */
	if ( strcasecmp( argv[0], "idassert-mode" ) == 0 ) {
		if ( argc < 2 ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: illegal args number %d in \"idassert-mode <args> [<flag> [...]]\" line.\n",
				fname, lineno, argc );
			return 1;
		}

		if ( strcasecmp( argv[1], "legacy" ) == 0 ) {
			/* will proxyAuthz as client's identity only if bound */
			li->idassert_mode = LDAP_BACK_IDASSERT_LEGACY;

		} else if ( strcasecmp( argv[1], "self" ) == 0 ) {
			/* will proxyAuthz as client's identity */
			li->idassert_mode = LDAP_BACK_IDASSERT_SELF;

		} else if ( strcasecmp( argv[1], "anonymous" ) == 0 ) {
			/* will proxyAuthz as anonymous */
			li->idassert_mode = LDAP_BACK_IDASSERT_ANONYMOUS;

		} else if ( strcasecmp( argv[1], "none" ) == 0 ) {
			/* will not proxyAuthz */
			li->idassert_mode = LDAP_BACK_IDASSERT_NOASSERT;

		} else {
			struct berval	id;
			int		rc;

			/* will proxyAuthz as argv[1] */
			ber_str2bv( argv[1], 0, 0, &id );

			if ( strncasecmp( id.bv_val, "u:", STRLENOF( "u:" ) ) == 0 ) {
				/* force lowercase... */
				id.bv_val[0] = 'u';
				li->idassert_mode = LDAP_BACK_IDASSERT_OTHERID;
				ber_dupbv( &li->idassert_authzID, &id );

			} else {
				struct berval	dn;

				/* default is DN? */
				if ( strncasecmp( id.bv_val, "dn:", STRLENOF( "dn:" ) ) == 0 ) {
					id.bv_val += STRLENOF( "dn:" );
					id.bv_len -= STRLENOF( "dn:" );
				}

				rc = dnNormalize( 0, NULL, NULL, &id, &dn, NULL );
				if ( rc != LDAP_SUCCESS ) {
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: idassert ID \"%s\" is not a valid DN\n",
						fname, lineno, argv[1] );
					return 1;
				}

				li->idassert_authzID.bv_len = STRLENOF( "dn:" ) + dn.bv_len;
				li->idassert_authzID.bv_val = ch_malloc( li->idassert_authzID.bv_len + 1 );
				AC_MEMCPY( li->idassert_authzID.bv_val, "dn:", STRLENOF( "dn:" ) );
				AC_MEMCPY( &li->idassert_authzID.bv_val[ STRLENOF( "dn:" ) ], dn.bv_val, dn.bv_len + 1 );
				ch_free( dn.bv_val );

				li->idassert_mode = LDAP_BACK_IDASSERT_OTHERDN;
			}
		}

		for ( argc -= 2, argv += 2; argc--; argv++ ) {
			if ( strcasecmp( argv[0], "override" ) == 0 ) {
				li->idassert_flags |= LDAP_BACK_AUTH_OVERRIDE;

			} else {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: unknown flag \"%s\" "
					"in \"idassert-mode <args> "
					"[<flags>]\" line.\n",
					fname, lineno, argv[0] );
				return 1;
			}
		}

	/* name to use for proxyAuthz propagation */
	} else if ( strcasecmp( argv[0], "idassert-authcdn" ) == 0
			|| strcasecmp( argv[0], "proxyauthzdn" ) == 0 )
	{
		struct berval	dn;
		int		rc;

		/* FIXME: "proxyauthzdn" is no longer documented, and
		 * temporarily supported for backwards compatibility */

		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing name in \"%s <name>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		if ( !BER_BVISNULL( &li->idassert_authcDN ) ) {
			fprintf( stderr, "%s: line %d: "
					"authcDN already defined; replacing...\n",
					fname, lineno );
			ch_free( li->idassert_authcDN.bv_val );
		}
		
		ber_str2bv( argv[1], 0, 0, &dn );
		rc = dnNormalize( 0, NULL, NULL, &dn, &li->idassert_authcDN, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: idassert ID \"%s\" is not a valid DN\n",
				fname, lineno, argv[1] );
			return 1;
		}

	/* password to use for proxyAuthz propagation */
	} else if ( strcasecmp( argv[0], "idassert-passwd" ) == 0
			|| strcasecmp( argv[0], "proxyauthzpw" ) == 0 )
	{
		/* FIXME: "proxyauthzpw" is no longer documented, and
		 * temporarily supported for backwards compatibility */

		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing password in \"%s <password>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		if ( !BER_BVISNULL( &li->idassert_passwd ) ) {
			fprintf( stderr, "%s: line %d: "
					"passwd already defined; replacing...\n",
					fname, lineno );
			ch_free( li->idassert_passwd.bv_val );
		}
		
		ber_str2bv( argv[1], 0, 1, &li->idassert_passwd );

	/* rules to accept identity assertion... */
	} else if ( strcasecmp( argv[0], "idassert-authzFrom" ) == 0 ) {
		struct berval	rule;

		ber_str2bv( argv[1], 0, 1, &rule );

		ber_bvarray_add( &li->idassert_authz, &rule );

	} else if ( strcasecmp( argv[0], "idassert-method" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing method in \"%s <method>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		if ( strcasecmp( argv[1], "none" ) == 0 ) {
			/* FIXME: is this useful? */
			li->idassert_authmethod = LDAP_AUTH_NONE;

			if ( argc != 2 ) {
				fprintf( stderr,
	"%s: line %d: trailing args in \"%s %s ...\" line ignored\"\n",
					fname, lineno, argv[0], argv[1] );
			}

		} else if ( strcasecmp( argv[1], "simple" ) == 0 ) {
			li->idassert_authmethod = LDAP_AUTH_SIMPLE;

			if ( argc != 2 ) {
				fprintf( stderr,
	"%s: line %d: trailing args in \"%s %s ...\" line ignored\"\n",
					fname, lineno, argv[0], argv[1] );
			}

		} else if ( strcasecmp( argv[1], "sasl" ) == 0 ) {
#ifdef HAVE_CYRUS_SASL
			int	arg;

			for ( arg = 2; arg < argc; arg++ ) {
				if ( strncasecmp( argv[arg], "mech=", STRLENOF( "mech=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "mech=" );

					if ( !BER_BVISNULL( &li->idassert_sasl_mech ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL mech already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_sasl_mech.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->idassert_sasl_mech );

				} else if ( strncasecmp( argv[arg], "realm=", STRLENOF( "realm=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "realm=" );

					if ( !BER_BVISNULL( &li->idassert_sasl_realm ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL realm already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_sasl_realm.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->idassert_sasl_realm );

				} else if ( strncasecmp( argv[arg], "authcdn=", STRLENOF( "authcdn=" ) ) == 0 ) {
					char		*val = argv[arg] + STRLENOF( "authcdn=" );
					struct berval	dn;
					int		rc;

					if ( !BER_BVISNULL( &li->idassert_authcDN ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL authcDN already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_authcDN.bv_val );
					}
					if ( strncasecmp( argv[arg], "dn:", STRLENOF( "dn:" ) ) == 0 ) {
						val += STRLENOF( "dn:" );
					}

					ber_str2bv( val, 0, 0, &dn );
					rc = dnNormalize( 0, NULL, NULL, &dn, &li->idassert_authcDN, NULL );
					if ( rc != LDAP_SUCCESS ) {
						Debug( LDAP_DEBUG_ANY,
							"%s: line %d: SASL authcdn \"%s\" is not a valid DN\n",
							fname, lineno, val );
						return 1;
					}

				} else if ( strncasecmp( argv[arg], "authcid=", STRLENOF( "authcid=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "authcid=" );

					if ( !BER_BVISNULL( &li->idassert_authcID ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL authcID already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_authcID.bv_val );
					}
					if ( strncasecmp( argv[arg], "u:", STRLENOF( "u:" ) ) == 0 ) {
						val += STRLENOF( "u:" );
					}
					ber_str2bv( val, 0, 1, &li->idassert_authcID );

				} else if ( strncasecmp( argv[arg], "cred=", STRLENOF( "cred=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "cred=" );

					if ( !BER_BVISNULL( &li->idassert_passwd ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL cred already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_passwd.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->idassert_passwd );

				} else if ( strncasecmp( argv[arg], "authz=", STRLENOF( "authz=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "authz=" );

					if ( strcasecmp( val, "proxyauthz" ) == 0 ) {
						li->idassert_flags &= ~LDAP_BACK_AUTH_NATIVE_AUTHZ;

					} else if ( strcasecmp( val, "native" ) == 0 ) {
						li->idassert_flags |= LDAP_BACK_AUTH_NATIVE_AUTHZ;

					} else {
						fprintf( stderr, "%s: line %s: "
							"unknown authz mode \"%s\"\n",
							fname, lineno, val );
						return 1;
					}

				} else {
					fprintf( stderr, "%s: line %d: "
							"unknown SASL parameter %s\n",
		    					fname, lineno, argv[arg] );
					return 1;
				}
			}

			li->idassert_authmethod = LDAP_AUTH_SASL;

#else /* !HAVE_CYRUS_SASL */
			fprintf( stderr, "%s: line %d: "
					"compile --with-cyrus-sasl to enable SASL auth\n",
					fname, lineno );
			return 1;
#endif /* !HAVE_CYRUS_SASL */

		} else {
			fprintf( stderr, "%s: line %d: "
					"unhandled idassert-method method %s\n",
					fname, lineno, argv[1] );
			return 1;
		}

	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}
#endif /* LDAP_BACK_PROXY_AUTHZ */
