/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2012 The OpenLDAP Foundation.
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
#include "config.h"
#include "lutil.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

static ConfigDriver meta_back_cf_gen;

static int ldap_back_map_config(
	ConfigArgs *c,
	struct ldapmap	*oc_map,
	struct ldapmap	*at_map );

enum {
	LDAP_BACK_CFG_URI = 1,
	LDAP_BACK_CFG_TLS,
	LDAP_BACK_CFG_ACL_AUTHCDN,
	LDAP_BACK_CFG_ACL_PASSWD,
	LDAP_BACK_CFG_IDASSERT_AUTHZFROM,
	LDAP_BACK_CFG_IDASSERT_BIND,
	LDAP_BACK_CFG_REBIND,
	LDAP_BACK_CFG_CHASE,
	LDAP_BACK_CFG_T_F,
	LDAP_BACK_CFG_TIMEOUT,
	LDAP_BACK_CFG_IDLE_TIMEOUT,
	LDAP_BACK_CFG_CONN_TTL,
	LDAP_BACK_CFG_NETWORK_TIMEOUT,
	LDAP_BACK_CFG_VERSION,
	LDAP_BACK_CFG_SINGLECONN,
	LDAP_BACK_CFG_USETEMP,
	LDAP_BACK_CFG_CONNPOOLMAX,
	LDAP_BACK_CFG_CANCEL,
	LDAP_BACK_CFG_QUARANTINE,
	LDAP_BACK_CFG_ST_REQUEST,
	LDAP_BACK_CFG_NOREFS,
	LDAP_BACK_CFG_NOUNDEFFILTER,

	LDAP_BACK_CFG_REWRITE,

	LDAP_BACK_CFG_SUFFIXM,
	LDAP_BACK_CFG_MAP,
	LDAP_BACK_CFG_SUBTREE_EX,
	LDAP_BACK_CFG_SUBTREE_IN,
	LDAP_BACK_CFG_DEFAULT_T,
	LDAP_BACK_CFG_DNCACHE_TTL,
	LDAP_BACK_CFG_BIND_TIMEOUT,
	LDAP_BACK_CFG_ONERR,
	LDAP_BACK_CFG_PSEUDOROOT_BIND_DEFER,
	LDAP_BACK_CFG_PSEUDOROOTDN,
	LDAP_BACK_CFG_PSEUDOROOTPW,
	LDAP_BACK_CFG_NRETRIES,
	LDAP_BACK_CFG_CLIENT_PR,

	LDAP_BACK_CFG_LAST
};

static ConfigTable metacfg[] = {
	{ "uri", "uri", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_URI,
		meta_back_cf_gen, "( OLcfgDbAt:0.14 "
			"NAME 'olcDbURI' "
			"DESC 'URI (list) for remote DSA' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "tls", "what", 2, 0, 0,
		ARG_MAGIC|LDAP_BACK_CFG_TLS,
		meta_back_cf_gen, "( OLcfgDbAt:3.1 "
			"NAME 'olcDbStartTLS' "
			"DESC 'StartTLS' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "acl-authcDN", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_ACL_AUTHCDN,
		meta_back_cf_gen, "( OLcfgDbAt:3.2 "
			"NAME 'olcDbACLAuthcDn' "
			"DESC 'Remote ACL administrative identity' "
			"OBSOLETE "
			"SYNTAX OMsDN "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated, will be removed; aliases "acl-authcDN" */
	{ "binddn", "DN", 2, 2, 0,
		ARG_DN|ARG_MAGIC|LDAP_BACK_CFG_ACL_AUTHCDN,
		meta_back_cf_gen, NULL, NULL, NULL },
	{ "acl-passwd", "cred", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_ACL_PASSWD,
		meta_back_cf_gen, "( OLcfgDbAt:3.3 "
			"NAME 'olcDbACLPasswd' "
			"DESC 'Remote ACL administrative identity credentials' "
			"OBSOLETE "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	/* deprecated, will be removed; aliases "acl-passwd" */
	{ "bindpw", "cred", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_ACL_PASSWD,
		meta_back_cf_gen, NULL, NULL, NULL },
	{ "idassert-bind", "args", 2, 0, 0,
		ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_BIND,
		meta_back_cf_gen, "( OLcfgDbAt:3.7 "
			"NAME 'olcDbIDAssertBind' "
			"DESC 'Remote Identity Assertion administrative identity auth bind configuration' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "idassert-authzFrom", "authzRule", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_IDASSERT_AUTHZFROM,
		meta_back_cf_gen, "( OLcfgDbAt:3.9 "
			"NAME 'olcDbIDAssertAuthzFrom' "
			"DESC 'Remote Identity Assertion authz rules' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString "
			"X-ORDERED 'VALUES' )",
		NULL, NULL },
	{ "rebind-as-user", "true|FALSE", 1, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_REBIND,
		meta_back_cf_gen, "( OLcfgDbAt:3.10 "
			"NAME 'olcDbRebindAsUser' "
			"DESC 'Rebind as user' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "chase-referrals", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_CHASE,
		meta_back_cf_gen, "( OLcfgDbAt:3.11 "
			"NAME 'olcDbChaseReferrals' "
			"DESC 'Chase referrals' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "t-f-support", "true|FALSE|discover", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_T_F,
		meta_back_cf_gen, "( OLcfgDbAt:3.12 "
			"NAME 'olcDbTFSupport' "
			"DESC 'Absolute filters support' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "timeout", "timeout(list)", 2, 0, 0,
		ARG_MAGIC|LDAP_BACK_CFG_TIMEOUT,
		meta_back_cf_gen, "( OLcfgDbAt:3.14 "
			"NAME 'olcDbTimeout' "
			"DESC 'Per-operation timeouts' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "idle-timeout", "timeout", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_IDLE_TIMEOUT,
		meta_back_cf_gen, "( OLcfgDbAt:3.15 "
			"NAME 'olcDbIdleTimeout' "
			"DESC 'connection idle timeout' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "conn-ttl", "ttl", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_CONN_TTL,
		meta_back_cf_gen, "( OLcfgDbAt:3.16 "
			"NAME 'olcDbConnTtl' "
			"DESC 'connection ttl' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "network-timeout", "timeout", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_NETWORK_TIMEOUT,
		meta_back_cf_gen, "( OLcfgDbAt:3.17 "
			"NAME 'olcDbNetworkTimeout' "
			"DESC 'connection network timeout' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "protocol-version", "version", 2, 2, 0,
		ARG_MAGIC|ARG_INT|LDAP_BACK_CFG_VERSION,
		meta_back_cf_gen, "( OLcfgDbAt:3.18 "
			"NAME 'olcDbProtocolVersion' "
			"DESC 'protocol version' "
			"SYNTAX OMsInteger "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "single-conn", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_SINGLECONN,
		meta_back_cf_gen, "( OLcfgDbAt:3.19 "
			"NAME 'olcDbSingleConn' "
			"DESC 'cache a single connection per identity' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "cancel", "ABANDON|ignore|exop", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_CANCEL,
		meta_back_cf_gen, "( OLcfgDbAt:3.20 "
			"NAME 'olcDbCancel' "
			"DESC 'abandon/ignore/exop operations when appropriate' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "quarantine", "retrylist", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_QUARANTINE,
		meta_back_cf_gen, "( OLcfgDbAt:3.21 "
			"NAME 'olcDbQuarantine' "
			"DESC 'Quarantine database if connection fails and retry according to rule' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "use-temporary-conn", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_USETEMP,
		meta_back_cf_gen, "( OLcfgDbAt:3.22 "
			"NAME 'olcDbUseTemporaryConn' "
			"DESC 'Use temporary connections if the cached one is busy' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "conn-pool-max", "<n>", 2, 2, 0,
		ARG_MAGIC|ARG_INT|LDAP_BACK_CFG_CONNPOOLMAX,
		meta_back_cf_gen, "( OLcfgDbAt:3.23 "
			"NAME 'olcDbConnectionPoolMax' "
			"DESC 'Max size of privileged connections pool' "
			"SYNTAX OMsInteger "
			"SINGLE-VALUE )",
		NULL, NULL },
#ifdef SLAP_CONTROL_X_SESSION_TRACKING
	{ "session-tracking-request", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_ST_REQUEST,
		meta_back_cf_gen, "( OLcfgDbAt:3.24 "
			"NAME 'olcDbSessionTrackingRequest' "
			"DESC 'Add session tracking control to proxied requests' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
#endif /* SLAP_CONTROL_X_SESSION_TRACKING */
	{ "norefs", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_NOREFS,
		meta_back_cf_gen, "( OLcfgDbAt:3.25 "
			"NAME 'olcDbNoRefs' "
			"DESC 'Do not return search reference responses' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "noundeffilter", "true|FALSE", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_NOUNDEFFILTER,
		meta_back_cf_gen, "( OLcfgDbAt:3.26 "
			"NAME 'olcDbNoUndefFilter' "
			"DESC 'Do not propagate undefined search filters' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },

	{ "rewrite", "arglist", 2, 4, STRLENOF( "rewrite" ),
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_REWRITE,
		meta_back_cf_gen, "( OLcfgDbAt:3.100 "
			"NAME 'olcDbRewrite' "
			"DESC 'DN rewriting rules' "
			"SYNTAX OMsDirectoryString )",
		NULL, NULL },
	{ "suffixmassage", "virtual> <real", 3, 3, 0,
		ARG_MAGIC|LDAP_BACK_CFG_SUFFIXM,
		meta_back_cf_gen, "( OLcfgDbAt:3.101 "
			"NAME 'olcDbSuffixMassage' "
			"DESC 'Suffix rewriting rule' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "map", "attribute|objectClass> [*|<local>] *|<remote", 3, 4, 0,
		ARG_MAGIC|LDAP_BACK_CFG_MAP,
		meta_back_cf_gen, "( OLcfgDbAt:3.102 "
			"NAME 'olcDbMap' "
			"DESC 'Map attribute and objectclass names' "
			"SYNTAX OMsDirectoryString )",
		NULL, NULL },

	{ "subtree-exclude", "pattern", 2, 2, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_SUBTREE_EX,
		meta_back_cf_gen, "( OLcfgDbAt:3.103 "
			"NAME 'olcDbSubtreeExclude' "
			"DESC 'DN of subtree to exclude from target' "
			"SYNTAX OMsDirectoryString )",
		NULL, NULL },
	{ "subtree-include", "pattern", 2, 2, 0,
		ARG_STRING|ARG_MAGIC|LDAP_BACK_CFG_SUBTREE_IN,
		meta_back_cf_gen, "( OLcfgDbAt:3.104 "
			"NAME 'olcDbSubtreeInclude' "
			"DESC 'DN of subtree to include in target' "
			"SYNTAX OMsDirectoryString )",
		NULL, NULL },
	{ "default-target", "[none|<target ID>]", 1, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_DEFAULT_T,
		meta_back_cf_gen, "( OLcfgDbAt:3.105 "
			"NAME 'olcDbDefaultTarget' "
			"DESC 'Specify the default target' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "dncache-ttl", "ttl", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_DNCACHE_TTL,
		meta_back_cf_gen, "( OLcfgDbAt:3.106 "
			"NAME 'olcDbDnCacheTtl' "
			"DESC 'dncache ttl' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "bind-timeout", "microseconds", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_BIND_TIMEOUT,
		meta_back_cf_gen, "( OLcfgDbAt:3.107 "
			"NAME 'olcDbBindTimeout' "
			"DESC 'bind timeout' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "onerr", "CONTINUE|report|stop", 2, 2, 0,
		ARG_MAGIC|LDAP_BACK_CFG_ONERR,
		meta_back_cf_gen, "( OLcfgDbAt:3.108 "
			"NAME 'olcDbOnErr' "
			"DESC 'error handling' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "pseudoroot-bind-defer", "TRUE|false", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_PSEUDOROOT_BIND_DEFER,
		meta_back_cf_gen, "( OLcfgDbAt:3.109 "
			"NAME 'olcDbPseudoRootBindDefer' "
			"DESC 'error handling' "
			"SYNTAX OMsBoolean "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "root-bind-defer", "TRUE|false", 2, 2, 0,
		ARG_MAGIC|ARG_ON_OFF|LDAP_BACK_CFG_PSEUDOROOT_BIND_DEFER,
		meta_back_cf_gen, NULL, NULL, NULL },
	{ "pseudorootdn", "dn", 2, 2, 0,
		ARG_MAGIC|ARG_DN|LDAP_BACK_CFG_PSEUDOROOTDN,
		meta_back_cf_gen, NULL, NULL, NULL },
	{ "pseudorootpw", "password", 2, 2, 0,
		ARG_MAGIC|ARG_STRING|LDAP_BACK_CFG_PSEUDOROOTDN,
		meta_back_cf_gen, NULL, NULL, NULL },
	{ "nretries", "NEVER|forever|<number>", 2, 2, 0,
		ARG_MAGIC|ARG_STRING|LDAP_BACK_CFG_NRETRIES,
		meta_back_cf_gen, "( OLcfgDbAt:3.110 "
			"NAME 'olcDbNretries' "
			"DESC 'retry handling' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	{ "client-pr", "accept-unsolicited|disable|<size>", 2, 2, 0,
		ARG_MAGIC|ARG_STRING|LDAP_BACK_CFG_CLIENT_PR,
		meta_back_cf_gen, "( OLcfgDbAt:3.111 "
			"NAME 'olcDbClientPr' "
			"DESC 'PagedResults handling' "
			"SYNTAX OMsDirectoryString "
			"SINGLE-VALUE )",
		NULL, NULL },
	
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};

#ifdef SLAP_CONTROL_X_SESSION_TRACKING
#define	ST_ATTR "$ olcDbSessionTrackingRequest "
#else
#define	ST_ATTR ""
#endif /* SLAP_CONTROL_X_SESSION_TRACKING */

#define TARGET_ATTRS	\
			"$ olcDbCancel " \
			"$ olcDbChaseReferrals " \
			"$ olcDbClientPr " \
			"$ olcDbDefaultTarget " \
			"$ olcDbIdleTimeout " \
			"$ olcDbNetworkTimeout " \
			"$ olcDbNoRefs " \
			"$ olcDbNoUndefFilter " \
			"$ olcDbNretries " \
			"$ olcDbProtocolVersion " \
			ST_ATTR \
			"$ olcDbTFSupport "

static ConfigOCs metaocs[] = {
	{ "( OLcfgDbOc:3.2 "
		"NAME 'olcMetaConfig' "
		"DESC 'Meta backend configuration' "
		"SUP olcDatabaseConfig "
		"MAY ( olcDbConnTtl "
			"$ olcDbDnCacheTtl "
			"$ olcDbOnErr "
			"$ olcDbPseudoRootBindDefer "
			"$ olcDbQuarantine "
			"$ olcDbRebindAsUser "
			"$ olcDbSingleConn "
			"$ olcDbUseTemporaryConn "
			"$ olcDbConnectionPoolMax "

			/* defaults, may be overridden per-target */
			TARGET_ATTRS
		") )",
		 	Cft_Database, metacfg},
	{ "( OLcfgDbOc:3.3 "
		"NAME 'olcMetaTarget' "
		"DESC 'Meta target configuration' "
		"MUST olcDbURI "
		"MAY ( olcDbACLAuthcDn "
			"$ olcDbACLPasswd "
			"$ olcDbBindTimeout "
			"$ olcDbIDAssertAuthzFrom "
			"$ olcDbIDAssertBind "
			"$ olcDbMap "
			"$ olcDbRewrite "
			"$ olcDbSubtreeExclude "
			"$ olcDbSubtreeInclude "
			"$ olcDbSuffixMassage "
			"$ olcDbTimeout "
			"$ olcDbStartTLS "

			/* defaults may be inherited */
			TARGET_ATTRS
		") )",
		 	Cft_Misc, metacfg, NULL /* meta_ldadd */},
	{ NULL, 0, NULL }
};

static int
meta_back_new_target(
	metatarget_t	**mtp )
{
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

	ldap_pvt_thread_mutex_init( &mt->mt_uri_mutex );

	mt->mt_idassert_mode = LDAP_BACK_IDASSERT_LEGACY;
	mt->mt_idassert_authmethod = LDAP_AUTH_NONE;
	mt->mt_idassert_tls = SB_TLS_DEFAULT;

	/* by default, use proxyAuthz control on each operation */
	mt->mt_idassert_flags = LDAP_BACK_AUTH_PRESCRIPTIVE;

	*mtp = mt;

	return 0;
}

int
meta_subtree_destroy( metasubtree_t *ms )
{
	if ( ms->ms_next ) {
		meta_subtree_destroy( ms->ms_next );
	}

	switch ( ms->ms_type ) {
	case META_ST_SUBTREE:
	case META_ST_SUBORDINATE:
		ber_memfree( ms->ms_dn.bv_val );
		break;

	case META_ST_REGEX:
		regfree( &ms->ms_regex );
		ch_free( ms->ms_regex_pattern );
		break;

	default:
		return -1;
	}

	ch_free( ms );

	return 0;
}

static int
meta_subtree_config(
	metatarget_t *mt,
	ConfigArgs *c )
{
	meta_st_t	type = META_ST_SUBTREE;
	char		*pattern;
	struct berval	ndn = BER_BVNULL;
	metasubtree_t	*ms = NULL;

	if ( c->type == LDAP_BACK_CFG_SUBTREE_EX ) {
		if ( mt->mt_subtree && !mt->mt_subtree_exclude ) {
			snprintf( c->cr_msg, sizeof(c->cr_msg),
				"\"subtree-exclude\" incompatible with previous \"subtree-include\" directives" );
			return 1;
		}

		mt->mt_subtree_exclude = 1;

	} else {
		if ( mt->mt_subtree && mt->mt_subtree_exclude ) {
			snprintf( c->cr_msg, sizeof(c->cr_msg),
				"\"subtree-include\" incompatible with previous \"subtree-exclude\" directives" );
			return 1;
		}
	}

	pattern = c->argv[1];
	if ( strncasecmp( pattern, "dn", STRLENOF( "dn" ) ) == 0 ) {
		char *style;

		pattern = &pattern[STRLENOF( "dn")];

		if ( pattern[0] == '.' ) {
			style = &pattern[1];

			if ( strncasecmp( style, "subtree", STRLENOF( "subtree" ) ) == 0 ) {
				type = META_ST_SUBTREE;
				pattern = &style[STRLENOF( "subtree" )];

			} else if ( strncasecmp( style, "children", STRLENOF( "children" ) ) == 0 ) {
				type = META_ST_SUBORDINATE;
				pattern = &style[STRLENOF( "children" )];

			} else if ( strncasecmp( style, "sub", STRLENOF( "sub" ) ) == 0 ) {
				type = META_ST_SUBTREE;
				pattern = &style[STRLENOF( "sub" )];

			} else if ( strncasecmp( style, "regex", STRLENOF( "regex" ) ) == 0 ) {
				type = META_ST_REGEX;
				pattern = &style[STRLENOF( "regex" )];

			} else {
				snprintf( c->cr_msg, sizeof(c->cr_msg), "unknown style in \"dn.<style>\"" );
				return 1;
			}
		}

		if ( pattern[0] != ':' ) {
			snprintf( c->cr_msg, sizeof(c->cr_msg), "missing colon after \"dn.<style>\"" );
			return 1;
		}
		pattern++;
	}

	switch ( type ) {
	case META_ST_SUBTREE:
	case META_ST_SUBORDINATE: {
		struct berval dn;

		ber_str2bv( pattern, 0, 0, &dn );
		if ( dnNormalize( 0, NULL, NULL, &dn, &ndn, NULL )
			!= LDAP_SUCCESS )
		{
			snprintf( c->cr_msg, sizeof(c->cr_msg), "DN=\"%s\" is invalid", pattern );
			return 1;
		}

		if ( !dnIsSuffix( &ndn, &mt->mt_nsuffix ) ) {
			snprintf( c->cr_msg, sizeof(c->cr_msg),
				"DN=\"%s\" is not a subtree of target \"%s\"",
				pattern, mt->mt_nsuffix.bv_val );
			ber_memfree( ndn.bv_val );
			return( 1 );
		}
		} break;

	default:
		/* silence warnings */
		break;
	}

	ms = ch_calloc( sizeof( metasubtree_t ), 1 );
	ms->ms_type = type;

	switch ( ms->ms_type ) {
	case META_ST_SUBTREE:
	case META_ST_SUBORDINATE:
		ms->ms_dn = ndn;
		break;

	case META_ST_REGEX: {
		int rc;

		rc = regcomp( &ms->ms_regex, pattern, REG_EXTENDED|REG_ICASE );
		if ( rc != 0 ) {
			char regerr[ SLAP_TEXT_BUFLEN ];

			regerror( rc, &ms->ms_regex, regerr, sizeof(regerr) );

			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"regular expression \"%s\" bad because of %s",
				pattern, regerr );
			ch_free( ms );
			return 1;
		}
		ms->ms_regex_pattern = ch_strdup( pattern );
		} break;
	}

	if ( mt->mt_subtree == NULL ) {
		 mt->mt_subtree = ms;

	} else {
		metasubtree_t **msp;

		for ( msp = &mt->mt_subtree; *msp; ) {
			switch ( ms->ms_type ) {
			case META_ST_SUBTREE:
				switch ( (*msp)->ms_type ) {
				case META_ST_SUBTREE:
					if ( dnIsSuffix( &(*msp)->ms_dn, &ms->ms_dn ) ) {
						metasubtree_t *tmp = *msp;
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.subtree:%s\" is contained in rule \"dn.subtree:%s\" (replaced)\n",
							c->log, pattern, (*msp)->ms_dn.bv_val );
						*msp = (*msp)->ms_next;
						tmp->ms_next = NULL;
						meta_subtree_destroy( tmp );
						continue;

					} else if ( dnIsSuffix( &ms->ms_dn, &(*msp)->ms_dn ) ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.subtree:%s\" contains rule \"dn.subtree:%s\" (ignored)\n",
							c->log, (*msp)->ms_dn.bv_val, pattern );
						meta_subtree_destroy( ms );
						ms = NULL;
						return( 0 );
					}
					break;

				case META_ST_SUBORDINATE:
					if ( dnIsSuffix( &(*msp)->ms_dn, &ms->ms_dn ) ) {
						metasubtree_t *tmp = *msp;
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" is contained in rule \"dn.subtree:%s\" (replaced)\n",
							c->log, pattern, (*msp)->ms_dn.bv_val );
						*msp = (*msp)->ms_next;
						tmp->ms_next = NULL;
						meta_subtree_destroy( tmp );
						continue;

					} else if ( dnIsSuffix( &ms->ms_dn, &(*msp)->ms_dn ) && ms->ms_dn.bv_len > (*msp)->ms_dn.bv_len ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" contains rule \"dn.subtree:%s\" (ignored)\n",
							c->log, (*msp)->ms_dn.bv_val, pattern );
						meta_subtree_destroy( ms );
						ms = NULL;
						return( 0 );
					}
					break;

				case META_ST_REGEX:
					if ( regexec( &(*msp)->ms_regex, ms->ms_dn.bv_val, 0, NULL, 0 ) == 0 ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.regex:%s\" may contain rule \"dn.subtree:%s\"\n",
							c->log, (*msp)->ms_regex_pattern, ms->ms_dn.bv_val );
					}
					break;
				}
				break;

			case META_ST_SUBORDINATE:
				switch ( (*msp)->ms_type ) {
				case META_ST_SUBTREE:
					if ( dnIsSuffix( &(*msp)->ms_dn, &ms->ms_dn ) ) {
						metasubtree_t *tmp = *msp;
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" is contained in rule \"dn.subtree:%s\" (replaced)\n",
							c->log, pattern, (*msp)->ms_dn.bv_val );
						*msp = (*msp)->ms_next;
						tmp->ms_next = NULL;
						meta_subtree_destroy( tmp );
						continue;

					} else if ( dnIsSuffix( &ms->ms_dn, &(*msp)->ms_dn ) && ms->ms_dn.bv_len > (*msp)->ms_dn.bv_len ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" contains rule \"dn.subtree:%s\" (ignored)\n",
							c->log, (*msp)->ms_dn.bv_val, pattern );
						meta_subtree_destroy( ms );
						ms = NULL;
						return( 0 );
					}
					break;

				case META_ST_SUBORDINATE:
					if ( dnIsSuffix( &(*msp)->ms_dn, &ms->ms_dn ) ) {
						metasubtree_t *tmp = *msp;
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" is contained in rule \"dn.children:%s\" (replaced)\n",
							c->log, pattern, (*msp)->ms_dn.bv_val );
						*msp = (*msp)->ms_next;
						tmp->ms_next = NULL;
						meta_subtree_destroy( tmp );
						continue;

					} else if ( dnIsSuffix( &ms->ms_dn, &(*msp)->ms_dn ) ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.children:%s\" contains rule \"dn.children:%s\" (ignored)\n",
							c->log, (*msp)->ms_dn.bv_val, pattern );
						meta_subtree_destroy( ms );
						ms = NULL;
						return( 0 );
					}
					break;

				case META_ST_REGEX:
					if ( regexec( &(*msp)->ms_regex, ms->ms_dn.bv_val, 0, NULL, 0 ) == 0 ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.regex:%s\" may contain rule \"dn.subtree:%s\"\n",
							c->log, (*msp)->ms_regex_pattern, ms->ms_dn.bv_val );
					}
					break;
				}
				break;

			case META_ST_REGEX:
				switch ( (*msp)->ms_type ) {
				case META_ST_SUBTREE:
				case META_ST_SUBORDINATE:
					if ( regexec( &ms->ms_regex, (*msp)->ms_dn.bv_val, 0, NULL, 0 ) == 0 ) {
						Debug( LDAP_DEBUG_CONFIG,
							"%s: previous rule \"dn.subtree:%s\" may be contained in rule \"dn.regex:%s\"\n",
							c->log, (*msp)->ms_dn.bv_val, ms->ms_regex_pattern );
					}
					break;

				case META_ST_REGEX:
					/* no check possible */
					break;
				}
				break;
			}

			msp = &(*msp)->ms_next;
		}

		*msp = ms;
	}

	return 0;
}

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
	{ BER_BVC( "ldaps" ),		LDAP_BACK_F_TLS_LDAPS },
	{ BER_BVC( "none" ),		LDAP_BACK_F_NONE },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks t_f_mode[] = {
	{ BER_BVC( "yes" ),		LDAP_BACK_F_T_F },
	{ BER_BVC( "discover" ),	LDAP_BACK_F_T_F_DISCOVER },
	{ BER_BVC( "no" ),		LDAP_BACK_F_NONE },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks cancel_mode[] = {
	{ BER_BVC( "ignore" ),		LDAP_BACK_F_CANCEL_IGNORE },
	{ BER_BVC( "exop" ),		LDAP_BACK_F_CANCEL_EXOP },
	{ BER_BVC( "exop-discover" ),	LDAP_BACK_F_CANCEL_EXOP_DISCOVER },
	{ BER_BVC( "abandon" ),		LDAP_BACK_F_CANCEL_ABANDON },
	{ BER_BVNULL,			0 }
};

static slap_verbmasks onerr_mode[] = {
	{ BER_BVC( "stop" ),		META_BACK_F_ONERR_STOP },
	{ BER_BVC( "report" ),	META_BACK_F_ONERR_REPORT },
	{ BER_BVC( "continue" ),		LDAP_BACK_F_NONE },
	{ BER_BVNULL,			0 }
};

/* see enum in slap.h */
static slap_cf_aux_table timeout_table[] = {
	{ BER_BVC("bind="),	SLAP_OP_BIND * sizeof( time_t ),	'u', 0, NULL },
	/* unbind makes no sense */
	{ BER_BVC("add="),	SLAP_OP_ADD * sizeof( time_t ),		'u', 0, NULL },
	{ BER_BVC("delete="),	SLAP_OP_DELETE * sizeof( time_t ),	'u', 0, NULL },
	{ BER_BVC("modrdn="),	SLAP_OP_MODRDN * sizeof( time_t ),	'u', 0, NULL },
	{ BER_BVC("modify="),	SLAP_OP_MODIFY * sizeof( time_t ),	'u', 0, NULL },
	{ BER_BVC("compare="),	SLAP_OP_COMPARE * sizeof( time_t ),	'u', 0, NULL },
	{ BER_BVC("search="),	SLAP_OP_SEARCH * sizeof( time_t ),	'u', 0, NULL },
	/* abandon makes little sense */
#if 0	/* not implemented yet */
	{ BER_BVC("extended="),	SLAP_OP_EXTENDED * sizeof( time_t ),	'u', 0, NULL },
#endif
	{ BER_BVNULL, 0, 0, 0, NULL }
};

static int
meta_back_cf_gen( ConfigArgs *c )
{
	metainfo_t	*mi = ( metainfo_t * )c->be->be_private;
	int i, rc = 0;

	assert( mi != NULL );

	if ( c->op == SLAP_CONFIG_EMIT ) {
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		return 1;
	}

	switch( c->type ) {
	case LDAP_BACK_CFG_URI: {
		LDAPURLDesc 	*ludp;
		struct berval	dn;
		int		j;

		metatarget_t	*mt;

		char		**uris = NULL;

		if ( c->be->be_nsuffix == NULL ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"the suffix must be defined before any target" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		i = mi->mi_ntargets++;

		mi->mi_targets = ( metatarget_t ** )ch_realloc( mi->mi_targets,
			sizeof( metatarget_t * ) * mi->mi_ntargets );
		if ( mi->mi_targets == NULL ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"out of memory while storing server name"
				" in \"%s <protocol>://<server>[:port]/<naming context>\"",
				c->argv[0] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( meta_back_new_target( &mi->mi_targets[ i ] ) != 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to init server"
				" in \"%s <protocol>://<server>[:port]/<naming context>\"",
				c->argv[0] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		mt = mi->mi_targets[ i ];

		mt->mt_rebind_f = mi->mi_rebind_f;
		mt->mt_urllist_f = mi->mi_urllist_f;
		mt->mt_urllist_p = mt;

		mt->mt_nretries = mi->mi_nretries;
		mt->mt_quarantine = mi->mi_quarantine;
		if ( META_BACK_QUARANTINE( mi ) ) {
			ldap_pvt_thread_mutex_init( &mt->mt_quarantine_mutex );
		}
		mt->mt_flags = mi->mi_flags;
		mt->mt_version = mi->mi_version;
#ifdef SLAPD_META_CLIENT_PR
		mt->mt_ps = mi->mi_ps;
#endif /* SLAPD_META_CLIENT_PR */
		mt->mt_network_timeout = mi->mi_network_timeout;
		mt->mt_bind_timeout = mi->mi_bind_timeout;
		for ( j = 0; j < SLAP_OP_LAST; j++ ) {
			mt->mt_timeout[ j ] = mi->mi_timeout[ j ];
		}

		for ( j = 1; j < c->argc; j++ ) {
			char	**tmpuris = ldap_str2charray( c->argv[ j ], "\t" );

			if ( tmpuris == NULL ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"unable to parse URIs #%d"
					" in \"%s <protocol>://<server>[:port]/<naming context>\"",
					j-1, c->argv[0] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}

			if ( j == 0 ) {
				uris = tmpuris;

			} else {
				ldap_charray_merge( &uris, tmpuris );
				ldap_charray_free( tmpuris );
			}
		}

		for ( j = 0; uris[ j ] != NULL; j++ ) {
			char *tmpuri = NULL;

			/*
			 * uri MUST be legal!
			 */
			if ( ldap_url_parselist_ext( &ludp, uris[ j ], "\t",
					LDAP_PVT_URL_PARSE_NONE ) != LDAP_SUCCESS
				|| ludp->lud_next != NULL )
			{
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"unable to parse URI #%d"
					" in \"%s <protocol>://<server>[:port]/<naming context>\"",
					j-1, c->argv[0] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				ldap_charray_free( uris );
				return 1;
			}

			if ( j == 0 ) {

				/*
				 * uri MUST have the <dn> part!
				 */
				if ( ludp->lud_dn == NULL ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"missing <naming context> "
						" in \"%s <protocol>://<server>[:port]/<naming context>\"",
						c->argv[0] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					ldap_free_urllist( ludp );
					ldap_charray_free( uris );
					return 1;
				}

				/*
				 * copies and stores uri and suffix
				 */
				ber_str2bv( ludp->lud_dn, 0, 0, &dn );
				rc = dnPrettyNormal( NULL, &dn, &mt->mt_psuffix,
					&mt->mt_nsuffix, NULL );
				if ( rc != LDAP_SUCCESS ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"target DN is invalid \"%s\"",
						c->argv[1] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					ldap_free_urllist( ludp );
					ldap_charray_free( uris );
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
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"invalid scope for target \"%s\"",
						c->argv[1] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					ldap_free_urllist( ludp );
					ldap_charray_free( uris );
					return( 1 );
				}

			} else {
				/* check all, to apply the scope check on the first one */
				if ( ludp->lud_dn != NULL && ludp->lud_dn[ 0 ] != '\0' ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"multiple URIs must have no DN part" );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					ldap_free_urllist( ludp );
					ldap_charray_free( uris );
					return( 1 );

				}
			}

			tmpuri = ldap_url_list2urls( ludp );
			ldap_free_urllist( ludp );
			if ( tmpuri == NULL ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ), "no memory?" );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				ldap_charray_free( uris );
				return( 1 );
			}
			ldap_memfree( uris[ j ] );
			uris[ j ] = tmpuri;
		}

		mt->mt_uri = ldap_charray2str( uris, " " );
		ldap_charray_free( uris );
		if ( mt->mt_uri == NULL) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ), "no memory?" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return( 1 );
		}

		/*
		 * uri MUST be a branch of suffix!
		 */
		for ( j = 0; !BER_BVISNULL( &c->be->be_nsuffix[ j ] ); j++ ) {
			if ( dnIsSuffix( &mt->mt_nsuffix, &c->be->be_nsuffix[ j ] ) ) {
				break;
			}
		}

		if ( BER_BVISNULL( &c->be->be_nsuffix[ j ] ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"<naming context> of URI must be within the naming context of this database." );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
	} break;
	case LDAP_BACK_CFG_SUBTREE_EX:
	case LDAP_BACK_CFG_SUBTREE_IN:
	/* subtree-exclude */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( meta_subtree_config( mi->mi_targets[ i ], c )) {
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		break;

	case LDAP_BACK_CFG_DEFAULT_T:
	/* default target directive */
		i = mi->mi_ntargets - 1;

		if ( c->argc == 1 ) {
 			if ( i < 0 ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"\"%s\" alone must be inside a \"uri\" directive",
					c->argv[0] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}
			mi->mi_defaulttarget = i;

		} else {
			if ( strcasecmp( c->argv[ 1 ], "none" ) == 0 ) {
				if ( i >= 0 ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"\"%s none\" should go before uri definitions",
						c->argv[0] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				}
				mi->mi_defaulttarget = META_DEFAULT_TARGET_NONE;

			} else {

				if ( lutil_atoi( &mi->mi_defaulttarget, c->argv[ 1 ] ) != 0
					|| mi->mi_defaulttarget < 0
					|| mi->mi_defaulttarget >= i - 1 )
				{
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"illegal target number %d",
						mi->mi_defaulttarget );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					return 1;
				}
			}
		}
		break;

	case LDAP_BACK_CFG_DNCACHE_TTL:
	/* ttl of dn cache */
		if ( strcasecmp( c->argv[ 1 ], "forever" ) == 0 ) {
			mi->mi_cache.ttl = META_DNCACHE_FOREVER;

		} else if ( strcasecmp( c->argv[ 1 ], "disabled" ) == 0 ) {
			mi->mi_cache.ttl = META_DNCACHE_DISABLED;

		} else {
			unsigned long	t;

			if ( lutil_parse_time( c->argv[ 1 ], &t ) != 0 ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"unable to parse dncache ttl \"%s\"",
					c->argv[ 1 ] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}
			mi->mi_cache.ttl = (time_t)t;
		}
		break;

	case LDAP_BACK_CFG_NETWORK_TIMEOUT: {
	/* network timeout when connecting to ldap servers */
		unsigned long	t;
		time_t		*tp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_network_timeout
				: &mi->mi_network_timeout;

		if ( lutil_parse_time( c->argv[ 1 ], &t ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to parse network timeout \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		*tp = (time_t)t;
		} break;

	case LDAP_BACK_CFG_IDLE_TIMEOUT: {
	/* idle timeout when connecting to ldap servers */
		unsigned long	t;

		if ( lutil_parse_time( c->argv[ 1 ], &t ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to parse idle timeout \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;

		}
		mi->mi_idle_timeout = (time_t)t;
		} break;

	case LDAP_BACK_CFG_CONN_TTL: {
	/* conn ttl */
		unsigned long	t;

		if ( lutil_parse_time( c->argv[ 1 ], &t ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to parse conn ttl \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;

		}
		mi->mi_conn_ttl = (time_t)t;
		} break;

	case LDAP_BACK_CFG_BIND_TIMEOUT: {
	/* bind timeout when connecting to ldap servers */
		unsigned long	t;
		struct timeval	*tp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_bind_timeout
				: &mi->mi_bind_timeout;

		if ( lutil_atoul( &t, c->argv[ 1 ] ) != 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to parse bind timeout \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;

		}

		tp->tv_sec = t/1000000;
		tp->tv_usec = t%1000000;
		} break;

	case LDAP_BACK_CFG_ACL_AUTHCDN:
	/* name to use for meta_back_group */

		i = mi->mi_ntargets - 1;
		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( strcasecmp( c->argv[ 0 ], "binddn" ) == 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s: "
				"\"binddn\" statement is deprecated; "
				"use \"acl-authcDN\" instead\n",
				c->log, 0, 0 );
			/* FIXME: some day we'll need to throw an error */
		}

		ber_memfree_x( c->value_dn.bv_val, NULL );
		mi->mi_targets[ i ]->mt_binddn = c->value_ndn;
		BER_BVZERO( &c->value_dn );
		BER_BVZERO( &c->value_ndn );
		break;

	case LDAP_BACK_CFG_ACL_PASSWD:
	/* password to use for meta_back_group */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( strcasecmp( c->argv[ 0 ], "bindpw" ) == 0 ) {
			Debug( LDAP_DEBUG_ANY, "%s "
				"\"bindpw\" statement is deprecated; "
				"use \"acl-passwd\" instead\n",
				c->log, 0, 0 );
			/* FIXME: some day we'll need to throw an error */
		}

		ber_str2bv( c->argv[ 1 ], 0L, 1, &mi->mi_targets[ i ]->mt_bindpw );
		break;

	case LDAP_BACK_CFG_REBIND: {
	/* save bind creds for referral rebinds? */
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( c->argc == 1 || c->value_int ) {
			*flagsp |= LDAP_BACK_F_SAVECRED;
		} else {
			*flagsp &= ~LDAP_BACK_F_SAVECRED;
		}
		} break;

	case LDAP_BACK_CFG_CHASE: {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( c->argc == 1 || c->value_int ) {
			*flagsp |= LDAP_BACK_F_CHASE_REFERRALS;
		} else {
			*flagsp &= ~LDAP_BACK_F_CHASE_REFERRALS;
		}
		} break;

	case LDAP_BACK_CFG_TLS: {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		i = verb_to_mask( c->argv[1], tls_mode );
		if ( BER_BVISNULL( &tls_mode[i].word ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"%s unknown argument \"%s\"",
				c->argv[0], c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( c->argc > 2 ) {
			metatarget_t	*mt = NULL;

			if ( mi->mi_ntargets - 1 < 0 ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"need \"uri\" directive first" );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}

			mt = mi->mi_targets[ mi->mi_ntargets - 1 ];

			for ( i = 2; i < c->argc; i++ ) {
				if ( bindconf_tls_parse( c->argv[i], &mt->mt_tls ))
					return 1;
			}
			bindconf_tls_defaults( &mt->mt_tls );
		}
		} break;

	case LDAP_BACK_CFG_T_F: {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;
		slap_mask_t mask;

		i = verb_to_mask( c->argv[1], t_f_mode );
		if ( BER_BVISNULL( &t_f_mode[i].word ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"%s unknown argument \"%s\"",
				c->argv[0], c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		mask = t_f_mode[i].mask;

		*flagsp &= ~LDAP_BACK_F_T_F_MASK2;
		*flagsp |= mask;
		} break;

	case LDAP_BACK_CFG_ONERR: {
	/* onerr? */
		slap_mask_t mask;

		i = verb_to_mask( c->argv[1], onerr_mode );
		if ( BER_BVISNULL( &onerr_mode[i].word ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"%s unknown argument \"%s\"",
				c->argv[0], c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		mask = onerr_mode[i].mask;

		mi->mi_flags &= ~META_BACK_F_ONERR_MASK;
		mi->mi_flags |= mask;
		} break;

	case LDAP_BACK_CFG_PSEUDOROOT_BIND_DEFER:
	/* bind-defer? */
		if ( c->argc == 1 || c->value_int ) {
			mi->mi_flags |= META_BACK_F_DEFER_ROOTDN_BIND;
		} else {
			mi->mi_flags &= ~META_BACK_F_DEFER_ROOTDN_BIND;
		}
		break;

	case LDAP_BACK_CFG_SINGLECONN:
	/* single-conn? */
		if ( mi->mi_ntargets > 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"%s\" must appear before target definitions",
				c->argv[0] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return( 1 );
		}
		if ( c->value_int ) {
			mi->mi_flags |= LDAP_BACK_F_SINGLECONN;
		} else {
			mi->mi_flags &= ~LDAP_BACK_F_SINGLECONN;
		}
		break;

	case LDAP_BACK_CFG_USETEMP:
	/* use-temporaries? */
		if ( mi->mi_ntargets > 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"%s\" must appear before target definitions",
				c->argv[0] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return( 1 );
		}
		if ( c->value_int ) {
			mi->mi_flags |= LDAP_BACK_F_USE_TEMPORARIES;
		} else {
			mi->mi_flags &= ~LDAP_BACK_F_USE_TEMPORARIES;
		}
		break;

	case LDAP_BACK_CFG_CONNPOOLMAX:
	/* privileged connections pool max size ? */
		if ( mi->mi_ntargets > 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"\"%s\" must appear before target definitions",
				c->argv[0] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return( 1 );
		}

		if ( c->value_int < LDAP_BACK_CONN_PRIV_MIN
			|| c->value_int > LDAP_BACK_CONN_PRIV_MAX )
		{
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"invalid max size " "of privileged "
				"connections pool \"%s\" "
				"in \"conn-pool-max <n> "
				"(must be between %d and %d)\"",
				c->argv[ 1 ],
				LDAP_BACK_CONN_PRIV_MIN,
				LDAP_BACK_CONN_PRIV_MAX );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		mi->mi_conn_priv_max = c->value_int;
		break;

	case LDAP_BACK_CFG_CANCEL: {
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;
		slap_mask_t mask;

		i = verb_to_mask( c->argv[1], cancel_mode );
		if ( BER_BVISNULL( &cancel_mode[i].word ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"%s unknown argument \"%s\"",
				c->argv[0], c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		mask = t_f_mode[i].mask;

		*flagsp &= ~LDAP_BACK_F_CANCEL_MASK2;
		*flagsp |= mask;
		} break;;

	case LDAP_BACK_CFG_TIMEOUT: {
		time_t	*tv = mi->mi_ntargets ?
				mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_timeout
				: mi->mi_timeout;

		for ( i = 1; i < c->argc; i++ ) {
			if ( isdigit( (unsigned char) c->argv[ i ][ 0 ] ) ) {
				int		j;
				unsigned	u;

				if ( lutil_atoux( &u, c->argv[ i ], 0 ) != 0 ) {
					snprintf( c->cr_msg, sizeof( c->cr_msg),
						"unable to parse timeout \"%s\"",
						c->argv[ i ] );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					return 1;
				}

				for ( j = 0; j < SLAP_OP_LAST; j++ ) {
					tv[ j ] = u;
				}

				continue;
			}

			if ( slap_cf_aux_table_parse( c->argv[ i ], tv, timeout_table, "slapd-meta timeout" ) ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg),
					"unable to parse timeout \"%s\"",
					c->argv[ i ] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}
		}
		} break;

	case LDAP_BACK_CFG_PSEUDOROOTDN:
	/* name to use as pseudo-root dn */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		/*
		 * exact replacement:
		 *

idassert-bind	bindmethod=simple
		binddn=<pseudorootdn>
		credentials=<pseudorootpw>
		mode=none
		flags=non-prescriptive
idassert-authzFrom	"dn:<rootdn>"

		 * so that only when authc'd as <rootdn> the proxying occurs
		 * rebinding as the <pseudorootdn> without proxyAuthz.
		 */

		Debug( LDAP_DEBUG_ANY,
			"%s: \"pseudorootdn\", \"pseudorootpw\" are no longer supported; "
			"use \"idassert-bind\" and \"idassert-authzFrom\" instead.\n",
			c->log, 0, 0 );

		{
			char	binddn[ SLAP_TEXT_BUFLEN ];
			char	*cargv[] = {
				"idassert-bind",
				"bindmethod=simple",
				NULL,
				"mode=none",
				"flags=non-prescriptive",
				NULL
			};
			char **oargv;
			int oargc;
			int	cargc = 5;
			int	rc;


			if ( BER_BVISNULL( &c->be->be_rootndn ) ) {
				Debug( LDAP_DEBUG_ANY, "%s: \"pseudorootpw\": \"rootdn\" must be defined first.\n",
					c->log, 0, 0 );
				return 1;
			}

			if ( sizeof( binddn ) <= (unsigned) snprintf( binddn,
					sizeof( binddn ), "binddn=%s", c->argv[ 1 ] ))
			{
				Debug( LDAP_DEBUG_ANY, "%s: \"pseudorootdn\" too long.\n",
					c->log, 0, 0 );
				return 1;
			}
			cargv[ 2 ] = binddn;

			oargv = c->argv;
			oargc = c->argc;
			c->argv = cargv;
			c->argc = cargc;
			rc = mi->mi_ldap_extra->idassert_parse( c, &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert );
			c->argv = oargv;
			c->argc = oargc;
			if ( rc == 0 ) {
				struct berval	bv;

				if ( mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert_authz != NULL ) {
					Debug( LDAP_DEBUG_ANY, "%s: \"idassert-authzFrom\" already defined (discarded).\n",
						c->log, 0, 0 );
					ber_bvarray_free( mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert_authz );
					mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert_authz = NULL;
				}

				assert( !BER_BVISNULL( &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert_authcDN ) );

				bv.bv_len = STRLENOF( "dn:" ) + c->be->be_rootndn.bv_len;
				bv.bv_val = ber_memalloc( bv.bv_len + 1 );
				AC_MEMCPY( bv.bv_val, "dn:", STRLENOF( "dn:" ) );
				AC_MEMCPY( &bv.bv_val[ STRLENOF( "dn:" ) ], c->be->be_rootndn.bv_val, c->be->be_rootndn.bv_len + 1 );

				ber_bvarray_add( &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert_authz, &bv );
			}

			return rc;
		}
		break;

	case LDAP_BACK_CFG_PSEUDOROOTPW:
	/* password to use as pseudo-root */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		Debug( LDAP_DEBUG_ANY,
			"%s: \"pseudorootdn\", \"pseudorootpw\" are no longer supported; "
			"use \"idassert-bind\" and \"idassert-authzFrom\" instead.\n",
			c->log, 0, 0 );

		if ( BER_BVISNULL( &mi->mi_targets[ i ]->mt_idassert_authcDN ) ) {
			Debug( LDAP_DEBUG_ANY, "%s: \"pseudorootpw\": \"pseudorootdn\" must be defined first.\n",
				c->log, 0, 0 );
			return 1;
		}

		if ( !BER_BVISNULL( &mi->mi_targets[ i ]->mt_idassert_passwd ) ) {
			memset( mi->mi_targets[ i ]->mt_idassert_passwd.bv_val, 0,
				mi->mi_targets[ i ]->mt_idassert_passwd.bv_len );
			ber_memfree( mi->mi_targets[ i ]->mt_idassert_passwd.bv_val );
		}
		ber_str2bv( c->argv[ 1 ], 0, 1, &mi->mi_targets[ i ]->mt_idassert_passwd );

	case LDAP_BACK_CFG_IDASSERT_BIND:
	/* idassert-bind */
		if ( mi->mi_ntargets == 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		rc = mi->mi_ldap_extra->idassert_parse( c, &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert );
		break;

	case LDAP_BACK_CFG_IDASSERT_AUTHZFROM:
	/* idassert-authzFrom */
		if ( mi->mi_ntargets == 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		rc = mi->mi_ldap_extra->idassert_authzfrom_parse( c, &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_idassert );
		break;

	case LDAP_BACK_CFG_QUARANTINE: {
	/* quarantine */
		slap_retry_info_t	*ri = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_quarantine
				: &mi->mi_quarantine;

		if ( ( mi->mi_ntargets == 0 && META_BACK_QUARANTINE( mi ) )
			|| ( mi->mi_ntargets > 0 && META_BACK_TGT_QUARANTINE( mi->mi_targets[ mi->mi_ntargets - 1 ] ) ) )
		{
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"quarantine already defined" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( ri != &mi->mi_quarantine ) {
			ri->ri_interval = NULL;
			ri->ri_num = NULL;
		}

		if ( mi->mi_ntargets > 0 && !META_BACK_QUARANTINE( mi ) ) {
			ldap_pvt_thread_mutex_init( &mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_quarantine_mutex );
		}

		if ( mi->mi_ldap_extra->retry_info_parse( c->argv[ 1 ], ri, c->cr_msg, sizeof( c->cr_msg ) ) ) {
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		if ( mi->mi_ntargets == 0 ) {
			mi->mi_flags |= LDAP_BACK_F_QUARANTINE;

		} else {
			mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags |= LDAP_BACK_F_QUARANTINE;
		}
		} break;

#ifdef SLAP_CONTROL_X_SESSION_TRACKING
	case LDAP_BACK_CFG_ST_REQUEST: {
	/* session tracking request */
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( c->value_int ) {
			*flagsp |= LDAP_BACK_F_ST_REQUEST;
		} else {
			*flagsp &= ~LDAP_BACK_F_ST_REQUEST;
		}
		} break;
#endif /* SLAP_CONTROL_X_SESSION_TRACKING */

	case LDAP_BACK_CFG_SUFFIXM: {
	/* dn massaging */
		BackendDB 	*tmp_bd;
		struct berval	dn, nvnc, pvnc, nrnc, prnc;
		int j;

		i = mi->mi_ntargets - 1;
		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
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

		ber_str2bv( c->argv[ 1 ], 0, 0, &dn );
		if ( dnPrettyNormal( NULL, &dn, &pvnc, &nvnc, NULL ) != LDAP_SUCCESS ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"suffix \"%s\" is invalid",
				c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		for ( j = 0; !BER_BVISNULL( &c->be->be_nsuffix[ j ] ); j++ ) {
			if ( dnIsSuffix( &nvnc, &c->be->be_nsuffix[ 0 ] ) ) {
				break;
			}
		}

		if ( BER_BVISNULL( &c->be->be_nsuffix[ j ] ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"suffix \"%s\" must be within the database naming context",
				c->argv[1] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;
		}

		ber_str2bv( c->argv[ 2 ], 0, 0, &dn );
		if ( dnPrettyNormal( NULL, &dn, &prnc, &nrnc, NULL ) != LDAP_SUCCESS ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"massaged suffix \"%s\" is invalid",
				c->argv[2] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			free( pvnc.bv_val );
			free( nvnc.bv_val );
			return 1;
		}

		tmp_bd = select_backend( &nrnc, 0 );
		if ( tmp_bd != NULL && tmp_bd->be_private == c->be->be_private ) {
			Debug( LDAP_DEBUG_ANY,
	"%s: warning: <massaged suffix> \"%s\" resolves to this database, in "
	"\"suffixMassage <suffix> <massaged suffix>\"\n",
				c->log, prnc.bv_val, 0 );
		}

		/*
		 * The suffix massaging is emulated by means of the
		 * rewrite capabilities
		 */
	 	rc = suffix_massage_config( mi->mi_targets[ i ]->mt_rwmap.rwm_rw,
				&pvnc, &nvnc, &prnc, &nrnc );

		free( pvnc.bv_val );
		free( nvnc.bv_val );
		free( prnc.bv_val );
		free( nrnc.bv_val );

		return rc;
		}

	case LDAP_BACK_CFG_REWRITE:
	/* rewrite stuff ... */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

 		return rewrite_parse( mi->mi_targets[ i ]->mt_rwmap.rwm_rw,
				c->fname, c->lineno, c->argc, c->argv );

	case LDAP_BACK_CFG_MAP:
	/* objectclass/attribute mapping */
		i = mi->mi_ntargets - 1;

		if ( i < 0 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"need \"uri\" directive first" );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}

		return ldap_back_map_config( c, &mi->mi_targets[ i ]->mt_rwmap.rwm_oc,
				&mi->mi_targets[ i ]->mt_rwmap.rwm_at );

	case LDAP_BACK_CFG_NRETRIES: {
		int		nretries = META_RETRY_UNDEFINED;

		i = mi->mi_ntargets - 1;

		if ( strcasecmp( c->argv[ 1 ], "forever" ) == 0 ) {
			nretries = META_RETRY_FOREVER;

		} else if ( strcasecmp( c->argv[ 1 ], "never" ) == 0 ) {
			nretries = META_RETRY_NEVER;

		} else {
			if ( lutil_atoi( &nretries, c->argv[ 1 ] ) != 0 ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"unable to parse nretries {never|forever|<retries>}: \"%s\"",
					c->argv[ 1 ] );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}
		}

		if ( i < 0 ) {
			mi->mi_nretries = nretries;

		} else {
			mi->mi_targets[ i ]->mt_nretries = nretries;
		}
		} break;

	case LDAP_BACK_CFG_VERSION: {
		int	*version = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_version
				: &mi->mi_version;

		if ( *version != 0 && ( *version < LDAP_VERSION_MIN || *version > LDAP_VERSION_MAX ) ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unsupported protocol version \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return 1;
		}
		} break;

	case LDAP_BACK_CFG_NOREFS: {
	/* do not return search references */
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( c->value_int ) {
			*flagsp |= LDAP_BACK_F_NOREFS;
		} else {
			*flagsp &= ~LDAP_BACK_F_NOREFS;
		}
		} break;

	case LDAP_BACK_CFG_NOUNDEFFILTER: {
	/* do not propagate undefined search filters */
		unsigned	*flagsp = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_flags
				: &mi->mi_flags;

		if ( c->value_int ) {
			*flagsp |= LDAP_BACK_F_NOUNDEFFILTER;
		} else {
			*flagsp &= ~LDAP_BACK_F_NOUNDEFFILTER;
		}
		} break;

#ifdef SLAPD_META_CLIENT_PR
	case LDAP_BACK_CFG_CLIENT_PR: {
		int *ps = mi->mi_ntargets ?
				&mi->mi_targets[ mi->mi_ntargets - 1 ]->mt_ps
				: &mi->mi_ps;

		if ( strcasecmp( c->argv[ 1 ], "accept-unsolicited" ) == 0 ) {
			*ps = META_CLIENT_PR_ACCEPT_UNSOLICITED;

		} else if ( strcasecmp( c->argv[ 1 ], "disable" ) == 0 ) {
			*ps = META_CLIENT_PR_DISABLE;

		} else if ( lutil_atoi( ps, c->argv[ 1 ] ) || *ps < -1 ) {
			snprintf( c->cr_msg, sizeof( c->cr_msg ),
				"unable to parse client-pr {accept-unsolicited|disable|<size>}: \"%s\"",
				c->argv[ 1 ] );
			Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
			return( 1 );
		}
		} break;
#endif /* SLAPD_META_CLIENT_PR */

	/* anything else */
	default:
		return SLAP_CONF_UNKNOWN;
	}

	return rc;
}

int
meta_back_init_cf( BackendInfo *bi )
{
	int			rc;
	AttributeDescription	*ad = NULL;
	const char		*text;

	/* Make sure we don't exceed the bits reserved for userland */
	config_check_userland( LDAP_BACK_CFG_LAST );

	bi->bi_cf_ocs = metaocs;

	rc = config_register_schema( metacfg, metaocs );
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
ldap_back_map_config(
		ConfigArgs *c,
		struct ldapmap	*oc_map,
		struct ldapmap	*at_map )
{
	struct ldapmap		*map;
	struct ldapmapping	*mapping;
	char			*src, *dst;
	int			is_oc = 0;

	if ( strcasecmp( c->argv[ 1 ], "objectclass" ) == 0 ) {
		map = oc_map;
		is_oc = 1;

	} else if ( strcasecmp( c->argv[ 1 ], "attribute" ) == 0 ) {
		map = at_map;

	} else {
		snprintf( c->cr_msg, sizeof(c->cr_msg),
			"%s unknown argument \"%s\"",
			c->argv[0], c->argv[1] );
		Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
		return 1;
	}

	if ( !is_oc && map->map == NULL ) {
		/* only init if required */
		ldap_back_map_init( map, &mapping );
	}

	if ( strcmp( c->argv[ 2 ], "*" ) == 0 ) {
		if ( c->argc < 4 || strcmp( c->argv[ 3 ], "*" ) == 0 ) {
			map->drop_missing = ( c->argc < 4 );
			goto success_return;
		}
		src = dst = c->argv[ 3 ];

	} else if ( c->argc < 4 ) {
		src = "";
		dst = c->argv[ 2 ];

	} else {
		src = c->argv[ 2 ];
		dst = ( strcmp( c->argv[ 3 ], "*" ) == 0 ? src : c->argv[ 3 ] );
	}

	if ( ( map == at_map )
		&& ( strcasecmp( src, "objectclass" ) == 0
			|| strcasecmp( dst, "objectclass" ) == 0 ) )
	{
		snprintf( c->cr_msg, sizeof(c->cr_msg),
			"objectclass attribute cannot be mapped" );
		Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
		return 1;
	}

	mapping = (struct ldapmapping *)ch_calloc( 2,
		sizeof(struct ldapmapping) );
	if ( mapping == NULL ) {
		snprintf( c->cr_msg, sizeof(c->cr_msg),
			"out of memory" );
		Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
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
	"warning, source objectClass '%s' should be defined in schema\n",
					c->log, src, 0 );

				/*
				 * FIXME: this should become an err
				 */
				goto error_return;
			}
		}

		if ( oc_bvfind( &mapping[ 0 ].dst ) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
	"warning, destination objectClass '%s' is not defined in schema\n",
				c->log, dst, 0 );
		}
	} else {
		int			rc;
		const char		*text = NULL;
		AttributeDescription	*ad = NULL;

		if ( src[ 0 ] != '\0' ) {
			rc = slap_bv2ad( &mapping[ 0 ].src, &ad, &text );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
	"warning, source attributeType '%s' should be defined in schema\n",
					c->log, src, 0 );

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
					snprintf( c->cr_msg, sizeof( c->cr_msg ),
						"source attributeType \"%s\": %d (%s)",
						src, rc, text ? text : "" );
					Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
					goto error_return;
				}
			}

			ad = NULL;
		}

		rc = slap_bv2ad( &mapping[ 0 ].dst, &ad, &text );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
	"warning, destination attributeType '%s' is not defined in schema\n",
				c->log, dst, 0 );

			/*
			 * we create a fake "proxied" ad
			 * and add it here.
			 */

			rc = slap_bv2undef_ad( &mapping[ 0 ].dst,
					&ad, &text, SLAP_AD_PROXIED );
			if ( rc != LDAP_SUCCESS ) {
				snprintf( c->cr_msg, sizeof( c->cr_msg ),
					"destination attributeType \"%s\": %d (%s)\n",
					dst, rc, text ? text : "" );
				Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
				return 1;
			}
		}
	}

	if ( (src[ 0 ] != '\0' && avl_find( map->map, (caddr_t)&mapping[ 0 ], mapping_cmp ) != NULL)
			|| avl_find( map->remap, (caddr_t)&mapping[ 1 ], mapping_cmp ) != NULL)
	{
		snprintf( c->cr_msg, sizeof( c->cr_msg ),
			"duplicate mapping found." );
		Debug( LDAP_DEBUG_ANY, "%s: %s.\n", c->log, c->cr_msg, 0 );
		goto error_return;
	}

	if ( src[ 0 ] != '\0' ) {
		avl_insert( &map->map, (caddr_t)&mapping[ 0 ],
					mapping_cmp, mapping_dup );
	}
	avl_insert( &map->remap, (caddr_t)&mapping[ 1 ],
				mapping_cmp, mapping_dup );

success_return:;
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

