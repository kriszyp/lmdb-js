/* config.c - ldap backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2005 The OpenLDAP Foundation.
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
#include <ac/ctype.h>
#include <ac/socket.h>

#include "slap.h"
#include "config.h"
#include "back-ldap.h"
#include "lutil.h"
#include "ldif.h"
#undef ldap_debug
/* for advanced URL parsing */
#include "../../../libraries/libldap/ldap-int.h"

static SLAP_EXTOP_MAIN_FN ldap_back_exop_whoami;

static ConfigDriver ldap_back_cf_gen;

enum {
	LDAP_BACK_CFG_URI = 1,
	LDAP_BACK_CFG_TLS,
	LDAP_BACK_CFG_ACL_AUTHCDN,
	LDAP_BACK_CFG_ACL_PASSWD,
	LDAP_BACK_CFG_ACL_METHOD,
	LDAP_BACK_CFG_ACL_BIND,
	LDAP_BACK_CFG_IDASSERT_MODE,
	LDAP_BACK_CFG_IDASSERT_AUTHCDN,
	LDAP_BACK_CFG_IDASSERT_PASSWD,
	LDAP_BACK_CFG_IDASSERT_AUTHZFROM,
	LDAP_BACK_CFG_IDASSERT_METHOD,
	LDAP_BACK_CFG_IDASSERT_BIND,
	LDAP_BACK_CFG_REBIND,
	LDAP_BACK_CFG_CHASE,
	LDAP_BACK_CFG_T_F,
	LDAP_BACK_CFG_WHOAMI,
	LDAP_BACK_CFG_REWRITE
};

static ConfigTable ldapcfg[] = {
	{ "uri", "uri", 2, 2, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_URI,
		ldap_back_cf_gen, "( OLcfgDbAt:0.14 "
			"NAME 'olcDbURI' "
			"DESC 'URI (list) for remote DSA' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "tls", "what", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_TLS,
		ldap_back_cf_gen, "( OLcfgDbAt:3.1 "
			"NAME 'olcDbStartTLS' "
			"DESC 'StartTLS' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "acl-authcDN", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_ACL_AUTHCDN,
		ldap_back_cf_gen, "( OLcfgDbAt:3.2 "
			"NAME 'olcDbACLAuthcDn' "
			"DESC 'Remote ACL administrative identity' "
			"OBSOLETE "
			"SYNTAX OMsDN "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated; aliases "acl-authcDN" */
	{ "binddn", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_ACL_AUTHCDN,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "acl-passwd", "cred", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_ACL_PASSWD,
		ldap_back_cf_gen, "( OLcfgDbAt:3.3 "
			"NAME 'olcDbACLPasswd' "
			"DESC 'Remote ACL administrative identity credentials' "
			"OBSOLETE "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated; aliases "acl-passwd" */
	{ "bindpw", "cred", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_ACL_PASSWD,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "acl-bind", "args", 2, 0, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_ACL_BIND,
		ldap_back_cf_gen, "( OLcfgDbAt:3.4 "
			"NAME 'olcDbACLBind' "
			"DESC 'Remote ACL administrative identity auth bind configuration' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated; aliases "acl-bind" */
	{ "acl-method", "args", 2, 0, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_ACL_BIND,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "idassert-authcDN", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_AUTHCDN,
		ldap_back_cf_gen, "( OLcfgDbAt:3.5 "
			"NAME 'olcDbIDAssertAuthcDn' "
			"DESC 'Remote Identity Assertion administrative identity' "
			"OBSOLETE "
			"SYNTAX OMsDN "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated; partially aliases "idassert-authcDN" */
	{ "proxyauthzdn", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_AUTHCDN,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "idassert-passwd", "cred", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_PASSWD,
		ldap_back_cf_gen, "( OLcfgDbAt:3.6 "
			"NAME 'olcDbIDAssertPasswd' "
			"DESC 'Remote Identity Assertion administrative identity credentials' "
			"OBSOLETE "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated; partially aliases "idassert-passwd" */
	{ "proxyauthzpw", "cred", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_PASSWD,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "idassert-bind", "args", 2, 0, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_BIND,
		ldap_back_cf_gen, "( OLcfgDbAt:3.7 "
			"NAME 'olcDbIDAssertBind' "
			"DESC 'Remote Identity Assertion administrative identity auth bind configuration' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "idassert-method", "args", 2, 0, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_BIND,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "idassert-mode", "mode>|u:<user>|[dn:]<DN", 2, 0, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_MODE,
		ldap_back_cf_gen, "( OLcfgDbAt:3.8 "
			"NAME 'olcDbIDAssertMode' "
			"DESC 'Remote Identity Assertion mode' "
			"OBSOLETE "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE)",
		NULL, NULL },
	{ "idassert-authzFrom", "authzRule", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_AUTHZFROM,
		ldap_back_cf_gen, "( OLcfgDbAt:3.9 "
			"NAME 'olcDbIDAssertAuthzFrom' "
			"DESC 'Remote Identity Assertion authz rules' "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )",
		NULL, NULL },
	{ "rebind-as-user", "NO|yes", 1, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_REBIND,
		ldap_back_cf_gen, "( OLcfgDbAt:3.10 "
			"NAME 'olcDbRebindAsUser' "
			"DESC 'Rebind as user' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "chase-referrals", "YES|no", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_CHASE,
		ldap_back_cf_gen, "( OLcfgDbAt:3.11 "
			"NAME 'olcDbChaseReferrals' "
			"DESC 'Chase referrals' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "t-f-support", "NO|yes|discover", 2, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_T_F,
		ldap_back_cf_gen, "( OLcfgDbAt:3.12 "
			"NAME 'olcDbTFSupport' "
			"DESC 'Absolute filters support' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "proxy-whoami", "NO|yes", 1, 2, 0,
		ARG_BERVAL|ARG_MAGIC|LDAP_BACK_CFG_WHOAMI,
		ldap_back_cf_gen, "( OLcfgDbAt:3.13 "
			"NAME 'olcDbProxyWhoAmI' "
			"DESC 'Proxy whoAmI exop' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "suffixmassage", "[virtual]> <real", 2, 3, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_REWRITE,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "map", "attribute|objectClass> [*|<local>] *|<remote", 3, 4, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_REWRITE,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ "rewrite", "<arglist>", 2, 4, STRLENOF( "rewrite" ),
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_REWRITE,
		ldap_back_cf_gen, NULL, NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};

static ConfigOCs ldapocs[] = {
	{ "( OLcfgDbOc:3.1 "
		"NAME 'olcLDAPConfig' "
		"DESC 'LDAP backend configuration' "
		"SUP olcDatabaseConfig "
		"MUST olcDbURI "
		"MAY ( olcDbStartTLS "
			"$ olcDbACLAuthcDn "
			"$ olcDbACLPasswd "
			"$ olcDbACLBind "
			"$ olcDbIDAssertAuthcDn "
			"$ olcDbIDAssertPasswd "
			"$ olcDbIDAssertBind "
			"$ olcDbIDAssertMode "
			"$ olcDbIDAssertAuthzFrom "
			"$ olcDbRebindAsUser "
			"$ olcDbChaseReferrals "
			"$ olcDbTFSupport "
			"$ olcDbProxyWhoAmI "
		") )",
		 	Cft_Database, ldapcfg},
	{ NULL, 0, NULL }
};

#define	LDAP_BACK_C_NO			(0x0U)
#define	LDAP_BACK_C_YES			(0x1U)
static slap_verbmasks yn_mode[] = {
	{ BER_BVC( "yes" ),		LDAP_BACK_C_YES},
	{ BER_BVC( "no" ),		LDAP_BACK_C_NO },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks idassert_mode[] = {
	{ BER_BVC("self"),		LDAP_BACK_IDASSERT_SELF },
	{ BER_BVC("anonymous"),		LDAP_BACK_IDASSERT_ANONYMOUS },
	{ BER_BVC("none"),		LDAP_BACK_IDASSERT_NOASSERT },
	{ BER_BVC("legacy"),		LDAP_BACK_IDASSERT_LEGACY },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks tls_mode[] = {
	{ BER_BVC( "propagate" ),	LDAP_BACK_F_TLS_PROPAGATE_MASK },
	{ BER_BVC( "try-propagate" ),	LDAP_BACK_F_PROPAGATE_TLS },
	{ BER_BVC( "start" ),		LDAP_BACK_F_TLS_USE_MASK },
	{ BER_BVC( "try-start" ),	LDAP_BACK_F_USE_TLS },
	{ BER_BVC( "none" ),		LDAP_BACK_C_NO },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks t_f_mode[] = {
	{ BER_BVC( "yes" ),		LDAP_BACK_F_SUPPORT_T_F },
	{ BER_BVC( "discover" ),	LDAP_BACK_F_SUPPORT_T_F_DISCOVER },
	{ BER_BVC( "no" ),		LDAP_BACK_C_NO },
	{ BER_BVNULL,			0 }
};

static int
ldap_back_cf_gen( ConfigArgs *c )
{
	struct ldapinfo	*li = ( struct ldapinfo * )c->be->be_private;
	int		rc;
	int		i;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		struct berval	bv = BER_BVNULL;
		rc = 0;

		switch( c->type ) {
		case LDAP_BACK_CFG_URI:
			if ( li->url != NULL ) {
				c->value_string = ch_strdup( li->url );

			} else {
				rc = 1;
			}
			break;

		case LDAP_BACK_CFG_TLS:
			enum_to_verb( tls_mode, ( li->flags & LDAP_BACK_F_TLS_MASK ), &bv );
			if ( BER_BVISNULL( &bv ) ) {
				/* there's something wrong... */
				assert( 0 );
				rc = 1;

			} else {
				ber_dupbv( &c->value_bv, &bv );
			}
			break;

		case LDAP_BACK_CFG_ACL_AUTHCDN:
		case LDAP_BACK_CFG_ACL_PASSWD:
		case LDAP_BACK_CFG_ACL_METHOD:
			/* handled by LDAP_BACK_CFG_ACL_BIND */
			rc = 1;
			break;

		case LDAP_BACK_CFG_ACL_BIND: {
			int	i;

			bindconf_unparse( &li->acl_sb, &c->value_bv );

			for ( i = 0; isspace( c->value_bv.bv_val[ i ] ); i++ )
				/* count spaces */ ;

			if ( i ) {
				c->value_bv.bv_len -= i;
				AC_MEMCPY( c->value_bv.bv_val, &c->value_bv.bv_val[ i ],
						c->value_bv.bv_len + 1 );
			}
			
			break;
		}

		case LDAP_BACK_CFG_IDASSERT_MODE:
		case LDAP_BACK_CFG_IDASSERT_AUTHCDN:
		case LDAP_BACK_CFG_IDASSERT_PASSWD:
		case LDAP_BACK_CFG_IDASSERT_METHOD:
			/* handled by LDAP_BACK_CFG_IDASSERT_BIND */
			rc = 1;
			break;

		case LDAP_BACK_CFG_IDASSERT_AUTHZFROM: {
			int		i;

			if ( li->idassert_authz == NULL ) {
				rc = 1;
				break;
			}

			for ( i = 0; !BER_BVISNULL( &li->idassert_authz[ i ] ); i++ )
			{
				struct berval	bv;

				ber_dupbv( &bv, &li->idassert_authz[ i ] );
				ber_bvarray_add( &c->rvalue_vals, &bv );
			}
			break;
		}

		case LDAP_BACK_CFG_IDASSERT_BIND: {
			int		i;
			struct berval	bv = BER_BVNULL,
					bc = BER_BVNULL;
			char		*ptr;

			if ( li->idassert_authmethod != LDAP_AUTH_NONE ) {
				switch ( li->idassert_mode ) {
				case LDAP_BACK_IDASSERT_OTHERID:
				case LDAP_BACK_IDASSERT_OTHERDN:
					break;

				default: {
					struct berval	mode = BER_BVNULL;

					enum_to_verb( idassert_mode, li->idassert_mode, &mode );
					if ( BER_BVISNULL( &mode ) ) {
						/* there's something wrong... */
						assert( 0 );
						rc = 1;
	
					} else {
						bv.bv_len = STRLENOF( "mode=" ) + mode.bv_len;
						bv.bv_val = ch_malloc( bv.bv_len + 1 );

						ptr = lutil_strcopy( bv.bv_val, "mode=" );
						ptr = lutil_strcopy( ptr, mode.bv_val );
					}
					break;
				}
				}

				if ( li->idassert_flags & LDAP_BACK_AUTH_NATIVE_AUTHZ ) {
					ber_len_t	len = bv.bv_len + STRLENOF( "authz=native" );

					if ( !BER_BVISEMPTY( &bv ) ) {
						len += STRLENOF( " " );
					}

					bv.bv_val = ch_realloc( bv.bv_val, len + 1 );

					ptr = bv.bv_val + bv.bv_len;

					if ( !BER_BVISEMPTY( &bv ) ) {
						ptr = lutil_strcopy( ptr, " " );
					}

					(void)lutil_strcopy( ptr, "authz=native" );
				}

				if ( li->idassert_flags & LDAP_BACK_AUTH_OVERRIDE ) {
					ber_len_t	len = bv.bv_len + STRLENOF( "flags=override" );

					if ( !BER_BVISEMPTY( &bv ) ) {
						len += STRLENOF( " " );
					}

					bv.bv_val = ch_realloc( bv.bv_val, len + 1 );

					ptr = bv.bv_val + bv.bv_len;

					if ( !BER_BVISEMPTY( &bv ) ) {
						ptr = lutil_strcopy( ptr, " " );
					}

					(void)lutil_strcopy( ptr, "flags=override" );
				}
			}



			bindconf_unparse( &li->idassert_sb, &bc );

			if ( !BER_BVISNULL( &bv ) ) {
				char	*ptr;

				c->value_bv.bv_len = bv.bv_len + bc.bv_len;
				c->value_bv.bv_val = ch_realloc( bv.bv_val, c->value_bv.bv_len + 1 );

				assert( bc.bv_val[ 0 ] == ' ' );

				ptr = lutil_strcopy( c->value_bv.bv_val, bv.bv_val );
				(void)lutil_strcopy( ptr, bc.bv_val );

				free( bc.bv_val );

			} else {
				for ( i = 0; isspace( bc.bv_val[ i ] ); i++ )
					/* count spaces */ ;

				if ( i ) {
					bc.bv_len -= i;
					AC_MEMCPY( bc.bv_val, &bc.bv_val[ i ], bc.bv_len + 1 );
				}

				c->value_bv = bv;
			}
			
			break;
		}

		case LDAP_BACK_CFG_REBIND:
			enum_to_verb( yn_mode, ( ( li->flags & LDAP_BACK_F_SAVECRED ) == LDAP_BACK_F_SAVECRED ), &bv );
			if ( BER_BVISNULL( &bv ) ) {
				/* there's something wrong... */
				assert( 0 );
				rc = 1;

			} else {
				ber_dupbv( &c->value_bv, &bv );
			}
			break;

		case LDAP_BACK_CFG_CHASE:
			enum_to_verb( yn_mode, ( ( li->flags & LDAP_BACK_F_CHASE_REFERRALS ) == LDAP_BACK_F_CHASE_REFERRALS ), &bv );
			if ( BER_BVISNULL( &bv ) ) {
				/* there's something wrong... */
				assert( 0 );
				rc = 1;

			} else {
				ber_dupbv( &c->value_bv, &bv );
			}
			break;

		case LDAP_BACK_CFG_T_F:
			enum_to_verb( t_f_mode, ( ( li->flags & LDAP_BACK_F_SUPPORT_T_F_MASK ) == LDAP_BACK_F_SUPPORT_T_F_MASK ), &bv );
			if ( BER_BVISNULL( &bv ) ) {
				/* there's something wrong... */
				assert( 0 );
				rc = 1;

			} else {
				ber_dupbv( &c->value_bv, &bv );
			}
			break;

		case LDAP_BACK_CFG_WHOAMI:
			enum_to_verb( yn_mode, ( ( li->flags & LDAP_BACK_F_PROXY_WHOAMI ) == LDAP_BACK_F_PROXY_WHOAMI ), &bv );
			if ( BER_BVISNULL( &bv ) ) {
				/* there's something wrong... */
				assert( 0 );
				rc = 1;

			} else {
				ber_dupbv( &c->value_bv, &bv );
			}
			break;

		default:
			/* we need to handle all... */
			assert( 0 );
			break;
		}
		return rc;

	} else if ( c->op == LDAP_MOD_DELETE ) {
		rc = 0;
		switch( c->type ) {
		case LDAP_BACK_CFG_URI:
			if ( li->url != NULL ) {
				ch_free( li->url );
				li->url = NULL;
			}

			if ( li->lud != NULL ) {
				ldap_free_urllist( li->lud );
				li->lud = NULL;
			}
			
			/* better cleanup the cached connections... */
			/* NOTE: don't worry about locking: if we got here,
			 * other threads are suspended. */
			avl_free( li->conntree, ldap_back_conn_free );
			li->conntree = NULL;
			
			break;

		case LDAP_BACK_CFG_TLS:
		case LDAP_BACK_CFG_ACL_AUTHCDN:
		case LDAP_BACK_CFG_ACL_PASSWD:
		case LDAP_BACK_CFG_ACL_METHOD:
			/* handled by LDAP_BACK_CFG_ACL_BIND */
			rc = 1;
			break;

		case LDAP_BACK_CFG_ACL_BIND:
			bindconf_free( &li->acl_sb );
			break;

		case LDAP_BACK_CFG_IDASSERT_MODE:
		case LDAP_BACK_CFG_IDASSERT_AUTHCDN:
		case LDAP_BACK_CFG_IDASSERT_PASSWD:
		case LDAP_BACK_CFG_IDASSERT_METHOD:
			/* handled by LDAP_BACK_CFG_IDASSERT_BIND */
			rc = 1;
			break;

		case LDAP_BACK_CFG_IDASSERT_AUTHZFROM:
			if ( li->idassert_authz != NULL ) {
				ber_bvarray_free( li->idassert_authz );
				li->idassert_authz = NULL;
			}
			break;

		case LDAP_BACK_CFG_IDASSERT_BIND:
			bindconf_free( &li->idassert_sb );
			break;

		case LDAP_BACK_CFG_REBIND:
		case LDAP_BACK_CFG_CHASE:
		case LDAP_BACK_CFG_T_F:
		case LDAP_BACK_CFG_WHOAMI:
			rc = 1;
			break;

		default:
			/* we need to handle all... */
			assert( 0 );
			break;
		}
		return rc;

	}

	switch( c->type ) {
	case LDAP_BACK_CFG_URI: {
		LDAPURLDesc	*tmpludp;
		char		**urllist;
		int		urlrc, i;

		if ( c->argc != 2 ) {
			fprintf( stderr, "%s: line %d: "
					"missing uri "
					"in \"uri <uri>\" line\n",
					c->fname, c->lineno );
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
		urlrc = ldap_url_parselist_ext( &li->lud, c->value_string, "\t" );
#else
		urlrc = ldap_url_parselist( &li->lud, c->value_string );
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
					c->fname, c->lineno, c->value_string, why );
			return 1;
		}

		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
		{
			if ( ( tmpludp->lud_dn != NULL
						&& tmpludp->lud_dn[0] != '\0' )
					|| tmpludp->lud_attrs != NULL
					/* || tmpludp->lud_scope != LDAP_SCOPE_DEFAULT */
					|| tmpludp->lud_filter != NULL
					|| tmpludp->lud_exts != NULL )
			{
				fprintf( stderr, "%s: line %d: "
						"warning, only protocol, "
						"host and port allowed "
						"in \"uri <uri>\" statement "
						"for uri #%d of \"%s\"\n",
						c->fname, c->lineno, i, c->value_string );
			}
		}

#if 0
		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
			/* just count */
		
		urllist = ch_calloc( sizeof( char * ), i + 1 );

		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
		{
			LDAPURLDesc	tmplud;
			ber_len_t	oldlen = 0, len;

			tmplud = *tmpludp;
			tmplud.lud_dn = "";
			tmplud.lud_attrs = NULL;
			tmplud.lud_filter = NULL;
			if ( !ldap_is_ldapi_url( tmplud.lud_scheme ) ) {
				tmplud.lud_exts = NULL;
				tmplud.lud_crit_exts = 0;
			}

			urllist[ i ]  = ldap_url_desc2str( &tmplud );

			if ( urllist[ i ] == NULL ) {
				fprintf( stderr, "%s: line %d: "
					"unable to rebuild uri "
					"in \"uri <uri>\" statement "
					"for \"%s\"\n",
					c->fname, c->lineno, argv[ 1 ] );
				return 1;
			}
		}

		li->url = ldap_charray2str( urllist, " " );
		ldap_charray_free( urllist );
#else
		li->url = ch_strdup( c->value_string );
#endif
		break;
	}

	case LDAP_BACK_CFG_TLS:
		i = verb_to_mask( c->argv[1], tls_mode );
		if ( BER_BVISNULL( &tls_mode[i].word ) ) {
			return 1;
		}
		li->flags &= ~LDAP_BACK_F_TLS_MASK;
		li->flags |= tls_mode[i].mask;
		break;

	case LDAP_BACK_CFG_ACL_AUTHCDN:
		switch ( li->acl_authmethod ) {
		case LDAP_AUTH_NONE:
			li->acl_authmethod = LDAP_AUTH_SIMPLE;
			break;

		case LDAP_AUTH_SIMPLE:
			break;

		default:
			fprintf( stderr, "%s: line %d: "
				"\"acl-authcDN <DN>\" incompatible "
				"with auth method %d.",
				c->fname, c->lineno, li->acl_authmethod );
			return 1;
		}
		if ( !BER_BVISNULL( &li->acl_authcDN ) ) {
			free( li->acl_authcDN.bv_val );
		}
		li->acl_authcDN = c->value_ndn;
		break;

	case LDAP_BACK_CFG_ACL_PASSWD:
		switch ( li->acl_authmethod ) {
		case LDAP_AUTH_NONE:
			li->acl_authmethod = LDAP_AUTH_SIMPLE;
			break;

		case LDAP_AUTH_SIMPLE:
			break;

		default:
			fprintf( stderr, "%s: line %d: "
				"\"acl-passwd <cred>\" incompatible "
				"with auth method %d.",
				c->fname, c->lineno, li->acl_authmethod );
			return 1;
		}
		if ( !BER_BVISNULL( &li->acl_passwd ) ) {
			free( li->acl_passwd.bv_val );
		}
		li->acl_passwd = c->value_bv;
		break;

	case LDAP_BACK_CFG_ACL_METHOD:
	case LDAP_BACK_CFG_ACL_BIND:
		for ( i = 1; i < c->argc; i++ ) {
			if ( bindconf_parse( c->argv[ i ], &li->acl_sb ) ) {
				return 1;
			}
		}
		break;

	case LDAP_BACK_CFG_IDASSERT_MODE:
		i = verb_to_mask( c->argv[1], idassert_mode );
		if ( BER_BVISNULL( &idassert_mode[i].word ) ) {
			if ( strncasecmp( c->argv[1], "u:", STRLENOF( "u:" ) ) == 0 ) {
				li->idassert_mode = LDAP_BACK_IDASSERT_OTHERID;
				ber_str2bv( c->argv[1], 0, 1, &li->idassert_authzID );
				li->idassert_authzID.bv_val[ 0 ] = 'u';
				
			} else {
				struct berval	id, ndn;

				ber_str2bv( c->argv[1], 0, 0, &id );

				if ( strncasecmp( c->argv[1], "dn:", STRLENOF( "dn:" ) ) == 0 ) {
					id.bv_val += STRLENOF( "dn:" );
					id.bv_len -= STRLENOF( "dn:" );
				}

				rc = dnNormalize( 0, NULL, NULL, &id, &ndn, NULL );
                                if ( rc != LDAP_SUCCESS ) {
                                        Debug( LDAP_DEBUG_ANY,
                                                "%s: line %d: idassert ID \"%s\" is not a valid DN\n",
                                                c->fname, c->lineno, c->argv[1] );
                                        return 1;
                                }

                                li->idassert_authzID.bv_len = STRLENOF( "dn:" ) + ndn.bv_len;
                                li->idassert_authzID.bv_val = ch_malloc( li->idassert_authzID.bv_len + 1 );
                                AC_MEMCPY( li->idassert_authzID.bv_val, "dn:", STRLENOF( "dn:" ) );
                                AC_MEMCPY( &li->idassert_authzID.bv_val[ STRLENOF( "dn:" ) ], ndn.bv_val, ndn.bv_len + 1 );
                                ch_free( ndn.bv_val );

                                li->idassert_mode = LDAP_BACK_IDASSERT_OTHERDN;
			}

		} else {
			li->idassert_mode = idassert_mode[i].mask;
		}

		if ( c->argc > 2 ) {
			int	i;

			for ( i = 2; i < c->argc; i++ ) {
				if ( strcasecmp( c->argv[ i ], "override" ) == 0 ) {
					li->idassert_flags |= LDAP_BACK_AUTH_OVERRIDE;

				} else {
					Debug( LDAP_DEBUG_ANY,
                                        	"%s: line %d: unknown flag #%d "
                                        	"in \"idassert-mode <args> "
                                        	"[<flags>]\" line.\n",
                                        	c->fname, c->lineno, i - 2 );
                                	return 1;
				}
                        }
                }
		break;

	case LDAP_BACK_CFG_IDASSERT_AUTHCDN:
		switch ( li->idassert_authmethod ) {
		case LDAP_AUTH_NONE:
			li->idassert_authmethod = LDAP_AUTH_SIMPLE;
			break;

		case LDAP_AUTH_SIMPLE:
			break;

		default:
			fprintf( stderr, "%s: line %d: "
				"\"idassert-authcDN <DN>\" incompatible "
				"with auth method %d.",
				c->fname, c->lineno, li->idassert_authmethod );
			return 1;
		}
		if ( !BER_BVISNULL( &li->idassert_authcDN ) ) {
			free( li->idassert_authcDN.bv_val );
		}
		li->idassert_authcDN = c->value_ndn;
		break;

	case LDAP_BACK_CFG_IDASSERT_PASSWD:
		switch ( li->idassert_authmethod ) {
		case LDAP_AUTH_NONE:
			li->idassert_authmethod = LDAP_AUTH_SIMPLE;
			break;

		case LDAP_AUTH_SIMPLE:
			break;

		default:
			fprintf( stderr, "%s: line %d: "
				"\"idassert-passwd <cred>\" incompatible "
				"with auth method %d.",
				c->fname, c->lineno, li->idassert_authmethod );
			return 1;
		}
		if ( !BER_BVISNULL( &li->idassert_passwd ) ) {
			free( li->idassert_passwd.bv_val );
		}
		li->idassert_passwd = c->value_bv;
		break;

	case LDAP_BACK_CFG_IDASSERT_AUTHZFROM:
		ber_bvarray_add( &li->idassert_authz, &c->value_bv );
		break;

	case LDAP_BACK_CFG_IDASSERT_METHOD:
		/* no longer supported */
		fprintf( stderr, "%s: %d: "
			"\"idassert-method <args>\": "
			"no longer supported; use \"idassert-bind\".\n",
			c->fname, c->lineno );
		return 1;

	case LDAP_BACK_CFG_IDASSERT_BIND:
		for ( i = 1; i < c->argc; i++ ) {
			if ( strncasecmp( c->argv[ i ], "mode=", STRLENOF( "mode=" ) ) == 0 ) {
				char	*argvi = c->argv[ i ] + STRLENOF( "mode=" );
				int	j;

				j = verb_to_mask( argvi, idassert_mode );
				if ( BER_BVISNULL( &idassert_mode[ j ].word ) ) {
					fprintf( stderr, "%s: %d: "
						"\"idassert-bind <args>\": "
						"unknown mode \"%s\".\n",
						c->fname, c->lineno, argvi );
					return 1;
				}

				li->idassert_mode = idassert_mode[ j ].mask;

			} else if ( strncasecmp( c->argv[ i ], "authz=", STRLENOF( "authz=" ) ) == 0 ) {
				char	*argvi = c->argv[ i ] + STRLENOF( "authz=" );

				if ( strcasecmp( argvi, "native" ) == 0 ) {
					if ( li->idassert_authmethod != LDAP_AUTH_SASL ) {
						fprintf( stderr, "%s: %d: "
							"\"idassert-bind <args>\": "
							"authz=\"native\" incompatible "
							"with auth method.\n",
							c->fname, c->lineno );
						return 1;
					}
					li->idassert_flags |= LDAP_BACK_AUTH_NATIVE_AUTHZ;

				} else if ( strcasecmp( argvi, "proxyAuthz" ) == 0 ) {
					li->idassert_flags &= ~LDAP_BACK_AUTH_NATIVE_AUTHZ;

				} else {
					fprintf( stderr, "%s: %d: "
						"\"idassert-bind <args>\": "
						"unknown authz \"%s\".\n",
						c->fname, c->lineno, argvi );
					return 1;
				}

			} else if ( strncasecmp( c->argv[ i ], "flags=", STRLENOF( "flags=" ) ) == 0 ) {
				char	*argvi = c->argv[ i ] + STRLENOF( "flags=" );
				char	**flags = ldap_str2charray( argvi, "," );
				int	j;

				if ( flags == NULL ) {
					fprintf( stderr, "%s: %d: "
						"\"idassert-bind <args>\": "
						"unable to parse flags \"%s\".\n",
						c->fname, c->lineno, argvi );
					return 1;
				}

				for ( j = 0; flags[ j ] != NULL; j++ ) {
					if ( strcasecmp( flags[ j ], "override" ) == 0 ) {
						li->idassert_flags |= LDAP_BACK_AUTH_OVERRIDE;

					} else {
						fprintf( stderr, "%s: %d: "
							"\"idassert-bind <args>\": "
							"unknown flag \"%s\".\n",
							c->fname, c->lineno, flags[ j ] );
						return 1;
					}
				}

				ldap_charray_free( flags );

			} else if ( bindconf_parse( c->argv[ i ], &li->idassert_sb ) ) {
				return 1;
			}
		}
		break;

	case LDAP_BACK_CFG_REBIND: {
		int	dorebind = 0;

		if ( c->argc == 1 ) {
			/* legacy */
			dorebind = 1;

		} else {
			i = verb_to_mask( c->argv[1], yn_mode );
			if ( BER_BVISNULL( &yn_mode[i].word ) ) {
				return 1;
			}
			if ( yn_mode[i].mask & LDAP_BACK_C_YES ) {
				dorebind = 1;
			}
		}

		if ( dorebind ) {
			li->flags |= LDAP_BACK_F_SAVECRED;

		} else {
			li->flags &= ~LDAP_BACK_F_SAVECRED;
		}
		break;
	}

	case LDAP_BACK_CFG_CHASE: {
		int	dochase = 0;

		if ( c->argc == 1 ) {
			/* legacy */
			dochase = 1;

		} else {
			i = verb_to_mask( c->argv[1], yn_mode );
			if ( BER_BVISNULL( &yn_mode[i].word ) ) {
				return 1;
			}
			if ( yn_mode[i].mask & LDAP_BACK_C_YES ) {
				dochase = 1;
			}
		}

		if ( dochase ) {
			li->flags |= LDAP_BACK_F_CHASE_REFERRALS;

		} else {
			li->flags &= ~LDAP_BACK_F_CHASE_REFERRALS;
		}
		break;
	}

	case LDAP_BACK_CFG_T_F:
		i = verb_to_mask( c->argv[1], t_f_mode );
		if ( BER_BVISNULL( &t_f_mode[i].word ) ) {
			return 1;
		}
		li->flags &= ~LDAP_BACK_F_SUPPORT_T_F_MASK;
		li->flags |= t_f_mode[i].mask;
		break;

	case LDAP_BACK_CFG_WHOAMI: {
		int	dowhoami = 0;

		if ( c->argc == 1 ) {
			/* legacy */
			dowhoami = 1;

		} else {
			i = verb_to_mask( c->argv[1], yn_mode );
			if ( BER_BVISNULL( &yn_mode[i].word ) ) {
				return 1;
			}
			if ( yn_mode[i].mask & LDAP_BACK_C_YES ) {
				dowhoami = 1;
			}
		}

		if ( dowhoami ) {
			li->flags |= LDAP_BACK_F_PROXY_WHOAMI;

			load_extop( (struct berval *)&slap_EXOP_WHOAMI,
					0, ldap_back_exop_whoami );

		} else {
			li->flags &= ~LDAP_BACK_F_PROXY_WHOAMI;
		}
		break;
	}

	case LDAP_BACK_CFG_REWRITE:
		fprintf( stderr, "%s: line %d: "
			"rewrite/remap capabilities have been moved "
			"to the \"rwm\" overlay; see slapo-rwm(5) "
			"for details (hint: add \"overlay rwm\" "
			"and prefix all directives with \"rwm-\").\n",
			c->fname, c->lineno );
		return 1;
		
	default:
		assert( 0 );
	}

	return 0;
}

int
ldap_back_init_cf( BackendInfo *bi )
{
	int			rc;
	AttributeDescription	*ad = NULL;
	const char		*text;

	bi->bi_cf_ocs = ldapocs;

	rc = config_register_schema( ldapcfg, ldapocs );
	if ( rc ) {
		return rc;
	}

	/* setup olcDbAclPasswd and olcDbIDAssertPasswd 
	 * to be base64-encoded when written in LDIF form;
	 * basically, we don't care if it fails */
	rc = slap_str2ad( "olcDbACLPasswd", &ad, &text );
	if ( rc ) {
		Debug( LDAP_DEBUG_ANY, "config_back_initialize: "
			"warning, unable to get \"olcDbACLPasswd\" "
			"attribute description: %d: %s\n",
			rc, text, 0 );
	} else {
		(void)ldif_must_b64_encode_register( ad->ad_cname.bv_val,
			ad->ad_type->sat_oid );
	}

	ad = NULL;
	rc = slap_str2ad( "olcDbIDAssertPasswd", &ad, &text );
	if ( rc ) {
		Debug( LDAP_DEBUG_ANY, "config_back_initialize: "
			"warning, unable to get \"olcDbIDAssertPasswd\" "
			"attribute description: %d: %s\n",
			rc, text, 0 );
	} else {
		(void)ldif_must_b64_encode_register( ad->ad_cname.bv_val,
			ad->ad_type->sat_oid );
	}

	return 0;
}


static int
parse_idassert( BackendDB *be, const char *fname, int lineno,
		int argc, char **argv );

static int
parse_acl_auth( BackendDB *be, const char *fname, int lineno,
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

	/* server address to query (no longer supported, use "uri" directive) */
	if ( strcasecmp( argv[0], "server" ) == 0 ) {
		fprintf( stderr,
	"%s: line %d: \"server <address>\" directive is no longer supported.\n",
					fname, lineno );
		return 1;

	/* URI of server to query (obsoletes "server" directive) */
	} else if ( strcasecmp( argv[0], "uri" ) == 0 ) {
		LDAPURLDesc	*tmpludp;
		char		**urllist;
		int		urlrc, i;

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
		urlrc = ldap_url_parselist( &li->lud, argv[ 1 ] );
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

		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
		{
			if ( ( tmpludp->lud_dn != NULL
						&& tmpludp->lud_dn[0] != '\0' )
					|| tmpludp->lud_attrs != NULL
					/* || tmpludp->lud_scope != LDAP_SCOPE_DEFAULT */
					|| tmpludp->lud_filter != NULL
					|| tmpludp->lud_exts != NULL )
			{
				fprintf( stderr, "%s: line %d: "
						"warning, only protocol, "
						"host and port allowed "
						"in \"uri <uri>\" statement "
						"for uri #%d of \"%s\"\n",
						fname, lineno, i, argv[1] );
			}
		}

#if 0
		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
			/* just count */
		
		urllist = ch_calloc( sizeof( char * ), i + 1 );

		for ( i = 0, tmpludp = li->lud;
				tmpludp;
				i++, tmpludp = tmpludp->lud_next )
		{
			LDAPURLDesc	tmplud;
			ber_len_t	oldlen = 0, len;

			tmplud = *tmpludp;
			tmplud.lud_dn = "";
			tmplud.lud_attrs = NULL;
			tmplud.lud_filter = NULL;
			if ( !ldap_is_ldapi_url( tmplud.lud_scheme ) ) {
				tmplud.lud_exts = NULL;
				tmplud.lud_crit_exts = 0;
			}

			urllist[ i ]  = ldap_url_desc2str( &tmplud );

			if ( urllist[ i ] == NULL ) {
				fprintf( stderr, "%s: line %d: "
					"unable to rebuild uri "
					"in \"uri <uri>\" statement "
					"for \"%s\"\n",
					fname, lineno, argv[ 1 ] );
				return 1;
			}
		}

		li->url = ldap_charray2str( urllist, " " );
		ldap_charray_free( urllist );
#else
		li->url = ch_strdup( argv[ 1 ] );
#endif

	} else if ( strcasecmp( argv[0], "tls" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
		"%s: line %d: \"tls <what>\" needs 1 argument.\n",
					fname, lineno );
			return( 1 );
		}

		/* none */
		if ( strcasecmp( argv[1], "none" ) == 0 ) {
			li->flags &= ~LDAP_BACK_F_TLS_MASK;
	
		/* try start tls */
		} else if ( strcasecmp( argv[1], "start" ) == 0 ) {
			li->flags |= LDAP_BACK_F_TLS_USE_MASK;
	
		/* try start tls */
		} else if ( strcasecmp( argv[1], "try-start" ) == 0 ) {
			li->flags &= ~LDAP_BACK_F_TLS_CRITICAL;
			li->flags |= LDAP_BACK_F_USE_TLS;
	
		/* propagate start tls */
		} else if ( strcasecmp( argv[1], "propagate" ) == 0 ) {
			li->flags |= LDAP_BACK_F_TLS_PROPAGATE_MASK;
		
		/* try start tls */
		} else if ( strcasecmp( argv[1], "try-propagate" ) == 0 ) {
			li->flags &= ~LDAP_BACK_F_TLS_CRITICAL;
			li->flags |= LDAP_BACK_F_PROPAGATE_TLS;

		} else {
			fprintf( stderr,
		"%s: line %d: \"tls <what>\": unknown argument \"%s\".\n",
					fname, lineno, argv[1] );
			return( 1 );
		}
	
	/* remote ACL stuff... */
	} else if ( strncasecmp( argv[0], "acl-", STRLENOF( "acl-" ) ) == 0
			|| strncasecmp( argv[0], "bind", STRLENOF( "bind" ) ) == 0 )
	{
		/* NOTE: "bind{DN,pw}" was initially used; it's now
		 * deprected and undocumented, it can be dropped at some
		 * point, since nobody should be really using it */
		return parse_acl_auth( be, fname, lineno, argc, argv );

	/* identity assertion stuff... */
	} else if ( strncasecmp( argv[0], "idassert-", STRLENOF( "idassert-" ) ) == 0
			|| strncasecmp( argv[0], "proxyauthz", STRLENOF( "proxyauthz" ) ) == 0 )
	{
		/* NOTE: "proxyauthz{DN,pw}" was initially used; it's now
		 * deprected and undocumented, it can be dropped at some
		 * point, since nobody should be really using it */
		return parse_idassert( be, fname, lineno, argc, argv );

	/* save bind creds for referral rebinds? */
	} else if ( strcasecmp( argv[0], "rebind-as-user" ) == 0 ) {
		switch ( argc ) {
		case 1:
			fprintf( stderr,
	"%s: line %d: \"rebind-as-user {NO|yes}\": use without args is deprecated.\n",
				fname, lineno );
	
			li->flags |= LDAP_BACK_F_SAVECRED;
			break;

		case 2:
			if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
				li->flags |= LDAP_BACK_F_SAVECRED;

			} else if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
				li->flags &= ~LDAP_BACK_F_SAVECRED;

			} else {
				fprintf( stderr,
	"%s: line %d: \"rebind-as-user {NO|yes}\": unknown argument \"%s\".\n",
					fname, lineno, argv[ 1 ] );
				return( 1 );
			}
			break;

		default:
			fprintf( stderr,
	"%s: line %d: \"rebind-as-user {NO|yes}\" needs 1 argument.\n",
					fname, lineno );
			return( 1 );
		}

	} else if ( strcasecmp( argv[0], "chase-referrals" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: \"chase-referrals {YES|no}\" needs 1 argument.\n",
					fname, lineno );
			return( 1 );
		}

		/* this is the default; we add it because the default might change... */
		if ( strcasecmp( argv[1], "yes" ) == 0 ) {
			li->flags |= LDAP_BACK_F_CHASE_REFERRALS;

		} else if ( strcasecmp( argv[1], "no" ) == 0 ) {
			li->flags &= ~LDAP_BACK_F_CHASE_REFERRALS;

		} else {
			fprintf( stderr,
		"%s: line %d: \"chase-referrals {YES|no}\": unknown argument \"%s\".\n",
					fname, lineno, argv[1] );
			return( 1 );
		}
	
	} else if ( strcasecmp( argv[ 0 ], "t-f-support" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
		"%s: line %d: \"t-f-support {NO|yes|discover}\" needs 1 argument.\n",
					fname, lineno );
			return( 1 );
		}

		if ( strcasecmp( argv[ 1 ], "no" ) == 0 ) {
			li->flags &= ~(LDAP_BACK_F_SUPPORT_T_F|LDAP_BACK_F_SUPPORT_T_F_DISCOVER);

		} else if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
			li->flags |= LDAP_BACK_F_SUPPORT_T_F;

		} else if ( strcasecmp( argv[ 1 ], "discover" ) == 0 ) {
			li->flags |= LDAP_BACK_F_SUPPORT_T_F_DISCOVER;

		} else {
			fprintf( stderr,
	"%s: line %d: \"t-f-support {NO|yes|discover}\": unknown argument \"%s\".\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

	/* intercept exop_who_am_i? */
	} else if ( strcasecmp( argv[0], "proxy-whoami" ) == 0 ) {
		int	doload_extop = 0;

		switch ( argc ) {
		case 1:
			fprintf( stderr,
	"%s: line %d: \"proxy-whoami {NO|yes}\": use without args is deprecated.\n",
				fname, lineno );
	
			doload_extop = 1;
			break;

		case 2:
			if ( strcasecmp( argv[ 1 ], "yes" ) == 0 ) {
				doload_extop = 1;

			} else if ( strcasecmp( argv[ 1 ], "no" ) != 0 ) {
				fprintf( stderr,
	"%s: line %d: \"proxy-whoami {NO|yes}\": unknown argument \"%s\".\n",
					fname, lineno, argv[ 1 ] );
				return( 1 );
			}
			break;

		default:
			fprintf( stderr,
	"%s: line %d: \"proxy-whoami {NO|yes}\" needs 1 argument.\n",
					fname, lineno );
			return( 1 );
		}

		if ( doload_extop ) {
			li->flags |= LDAP_BACK_F_PROXY_WHOAMI;

			load_extop( (struct berval *)&slap_EXOP_WHOAMI,
					0, ldap_back_exop_whoami );
		}

	/* FIXME: legacy: intercept old rewrite/remap directives
	 * and try to start the rwm overlay */
	} else if ( strcasecmp( argv[0], "suffixmassage" ) == 0
			|| strcasecmp( argv[0], "map" ) == 0
			|| strncasecmp( argv[0], "rewrite", STRLENOF( "rewrite" ) ) == 0 )
	{
#if 0
		fprintf( stderr, "%s: line %d: "
			"rewrite/remap capabilities have been moved "
			"to the \"rwm\" overlay; see slapo-rwm(5) "
			"for details.  I'm trying to do my best "
			"to preserve backwards compatibility...\n",
			fname, lineno );

		if ( li->rwm_started == 0 ) {
			if ( overlay_config( be, "rwm" ) ) {
				fprintf( stderr, "%s: line %d: "
					"unable to configure the \"rwm\" "
					"overlay, required by directive "
					"\"%s\".\n",
					fname, lineno, argv[0] );
#if SLAPD_OVER_RWM == SLAPD_MOD_DYNAMIC
				fprintf( stderr, "\thint: try loading the \"rwm.la\" dynamic module.\n" );
#endif /* SLAPD_OVER_RWM == SLAPD_MOD_DYNAMIC */
				return( 1 );
			}

			fprintf( stderr, "%s: line %d: back-ldap: "
				"automatically starting \"rwm\" overlay, "
				"triggered by \"%s\" directive.\n",
				fname, lineno, argv[ 0 ] );

		/* this is the default; we add it because the default might change... */
			li->rwm_started = 1;

			return ( *be->bd_info->bi_db_config )( be, fname, lineno, argc, argv );
		}
#else
		fprintf( stderr, "%s: line %d: "
			"rewrite/remap capabilities have been moved "
			"to the \"rwm\" overlay; see slapo-rwm(5) "
			"for details (hint: add \"overlay rwm\" "
			"and prefix all directives with \"rwm-\").\n",
			fname, lineno );
#endif

		return 1;
	
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
		int doretry = 1;

		ctrls[0] = &c;
		op2.o_ndn = op->o_conn->c_ndn;
		lc = ldap_back_getconn(&op2, rs, LDAP_BACK_SENDERR);
		if (!lc || !ldap_back_dobind( lc, op, rs, LDAP_BACK_SENDERR )) {
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
				if ( rs->sr_err == LDAP_SERVER_DOWN && doretry ) {
					doretry = 0;
					if ( ldap_back_retry( lc, op, rs, LDAP_BACK_SENDERR ) )
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
		char	*argv1;

		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing method in \"%s <method>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		argv1 = argv[1];
		if ( strncasecmp( argv1, "bindmethod=", STRLENOF( "bindmethod=" ) ) == 0 ) {
			argv1 += STRLENOF( "bindmethod=" );
		}

		if ( strcasecmp( argv1, "none" ) == 0 ) {
			/* FIXME: is this at all useful? */
			li->idassert_authmethod = LDAP_AUTH_NONE;

			if ( argc != 2 ) {
				fprintf( stderr,
	"%s: line %d: trailing args in \"%s %s ...\" line ignored\"\n",
					fname, lineno, argv[0], argv[1] );
			}

		} else if ( strcasecmp( argv1, "simple" ) == 0 ) {
			int	arg;

			for ( arg = 2; arg < argc; arg++ ) {
				if ( strncasecmp( argv[arg], "authcdn=", STRLENOF( "authcdn=" ) ) == 0 ) {
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

				} else if ( strncasecmp( argv[arg], "cred=", STRLENOF( "cred=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "cred=" );

					if ( !BER_BVISNULL( &li->idassert_passwd ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL cred already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->idassert_passwd.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->idassert_passwd );

				} else {
					fprintf( stderr, "%s: line %d: "
							"unknown parameter %s\n",
		    					fname, lineno, argv[arg] );
					return 1;
				}
			}

			li->idassert_authmethod = LDAP_AUTH_SIMPLE;

		} else if ( strcasecmp( argv1, "sasl" ) == 0 ) {
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
						fprintf( stderr, "%s: line %d: "
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

static int
parse_acl_auth(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;

	/* name to use for remote ACL access */
	if ( strcasecmp( argv[0], "acl-authcdn" ) == 0
			|| strcasecmp( argv[0], "binddn" ) == 0 )
	{
		struct berval	dn;
		int		rc;

		/* FIXME: "binddn" is no longer documented, and
		 * temporarily supported for backwards compatibility */

		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing name in \"%s <name>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		if ( !BER_BVISNULL( &li->acl_authcDN ) ) {
			fprintf( stderr, "%s: line %d: "
					"authcDN already defined; replacing...\n",
					fname, lineno );
			ch_free( li->acl_authcDN.bv_val );
		}
		
		ber_str2bv( argv[1], 0, 0, &dn );
		rc = dnNormalize( 0, NULL, NULL, &dn, &li->acl_authcDN, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: acl ID \"%s\" is not a valid DN\n",
				fname, lineno, argv[1] );
			return 1;
		}

	/* password to use for remote ACL access */
	} else if ( strcasecmp( argv[0], "acl-passwd" ) == 0
			|| strcasecmp( argv[0], "bindpw" ) == 0 )
	{
		/* FIXME: "bindpw" is no longer documented, and
		 * temporarily supported for backwards compatibility */

		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: missing password in \"%s <password>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		if ( !BER_BVISNULL( &li->acl_passwd ) ) {
			fprintf( stderr, "%s: line %d: "
					"passwd already defined; replacing...\n",
					fname, lineno );
			ch_free( li->acl_passwd.bv_val );
		}
		
		ber_str2bv( argv[1], 0, 1, &li->acl_passwd );

	} else if ( strcasecmp( argv[0], "acl-method" ) == 0 ) {
		char	*argv1;

		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing method in \"%s <method>\" line\n",
			    fname, lineno, argv[0] );
			return( 1 );
		}

		argv1 = argv[1];
		if ( strncasecmp( argv1, "bindmethod=", STRLENOF( "bindmethod=" ) ) == 0 ) {
			argv1 += STRLENOF( "bindmethod=" );
		}

		if ( strcasecmp( argv1, "none" ) == 0 ) {
			/* FIXME: is this at all useful? */
			li->acl_authmethod = LDAP_AUTH_NONE;

			if ( argc != 2 ) {
				fprintf( stderr,
	"%s: line %d: trailing args in \"%s %s ...\" line ignored\"\n",
					fname, lineno, argv[0], argv[1] );
			}

		} else if ( strcasecmp( argv1, "simple" ) == 0 ) {
			li->acl_authmethod = LDAP_AUTH_SIMPLE;

			if ( argc != 2 ) {
				fprintf( stderr,
	"%s: line %d: trailing args in \"%s %s ...\" line ignored\"\n",
					fname, lineno, argv[0], argv[1] );
			}

		} else if ( strcasecmp( argv1, "sasl" ) == 0 ) {
#ifdef HAVE_CYRUS_SASL
			int	arg;

			for ( arg = 2; arg < argc; arg++ ) {
				if ( strncasecmp( argv[arg], "mech=", STRLENOF( "mech=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "mech=" );

					if ( !BER_BVISNULL( &li->acl_sasl_mech ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL mech already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->acl_sasl_mech.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->acl_sasl_mech );

				} else if ( strncasecmp( argv[arg], "realm=", STRLENOF( "realm=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "realm=" );

					if ( !BER_BVISNULL( &li->acl_sasl_realm ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL realm already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->acl_sasl_realm.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->acl_sasl_realm );

				} else if ( strncasecmp( argv[arg], "authcdn=", STRLENOF( "authcdn=" ) ) == 0 ) {
					char		*val = argv[arg] + STRLENOF( "authcdn=" );
					struct berval	dn;
					int		rc;

					if ( !BER_BVISNULL( &li->acl_authcDN ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL authcDN already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->acl_authcDN.bv_val );
					}
					if ( strncasecmp( argv[arg], "dn:", STRLENOF( "dn:" ) ) == 0 ) {
						val += STRLENOF( "dn:" );
					}

					ber_str2bv( val, 0, 0, &dn );
					rc = dnNormalize( 0, NULL, NULL, &dn, &li->acl_authcDN, NULL );
					if ( rc != LDAP_SUCCESS ) {
						Debug( LDAP_DEBUG_ANY,
							"%s: line %d: SASL authcdn \"%s\" is not a valid DN\n",
							fname, lineno, val );
						return 1;
					}

				} else if ( strncasecmp( argv[arg], "authcid=", STRLENOF( "authcid=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "authcid=" );

					if ( !BER_BVISNULL( &li->acl_authcID ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL authcID already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->acl_authcID.bv_val );
					}
					if ( strncasecmp( argv[arg], "u:", STRLENOF( "u:" ) ) == 0 ) {
						val += STRLENOF( "u:" );
					}
					ber_str2bv( val, 0, 1, &li->acl_authcID );

				} else if ( strncasecmp( argv[arg], "cred=", STRLENOF( "cred=" ) ) == 0 ) {
					char	*val = argv[arg] + STRLENOF( "cred=" );

					if ( !BER_BVISNULL( &li->acl_passwd ) ) {
						fprintf( stderr, "%s: line %d: "
								"SASL cred already defined; replacing...\n",
			    					fname, lineno );
						ch_free( li->acl_passwd.bv_val );
					}
					ber_str2bv( val, 0, 1, &li->acl_passwd );

				} else {
					fprintf( stderr, "%s: line %d: "
							"unknown SASL parameter %s\n",
		    					fname, lineno, argv[arg] );
					return 1;
				}
			}

			li->acl_authmethod = LDAP_AUTH_SASL;

#else /* !HAVE_CYRUS_SASL */
			fprintf( stderr, "%s: line %d: "
					"compile --with-cyrus-sasl to enable SASL auth\n",
					fname, lineno );
			return 1;
#endif /* !HAVE_CYRUS_SASL */

		} else {
			fprintf( stderr, "%s: line %d: "
					"unhandled acl-method method %s\n",
					fname, lineno, argv[1] );
			return 1;
		}

	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}

