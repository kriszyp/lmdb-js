/* bconfig.c - the config backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005 The OpenLDAP Foundation.
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
 * This work was originally developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/errno.h>

#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

#include <lutil.h>

#include "config.h"

static struct berval config_rdn = BER_BVC("cn=config");

#ifdef SLAPD_MODULES
typedef struct modpath_s {
	struct modpath_s *mp_next;
	struct berval mp_path;
	BerVarray mp_loads;
} ModPaths;
#endif

typedef struct ConfigFile {
	struct ConfigFile *c_sibs;
	struct ConfigFile *c_kids;
	struct berval c_file;
#ifdef SLAPD_MODULES
	ModPaths c_modpaths;
	ModPaths *c_modlast;
#endif
	BerVarray c_dseFiles;
} ConfigFile;

typedef struct CfOcInfo {
	struct berval *co_name;
	ConfigTable *co_table;
	ConfigType co_type;
} CfOcInfo;

typedef struct CfEntryInfo {
	struct CfEntryInfo *ce_sibs;
	struct CfEntryInfo *ce_kids;
	Entry *ce_entry;
	ConfigType ce_type;
	BackendInfo *ce_bi;
	BackendDB *ce_be;
} CfEntryInfo;

typedef struct {
	ConfigFile *cb_config;
	CfEntryInfo *cb_root;
	BackendDB	*cb_be;	/* config backend */
	BackendDB	cb_db;	/* underlying database */
	int		cb_got_ldif;
} CfBackInfo;

/* These do nothing in slapd, they're kept only to make them
 * editable here.
 */
static char *replica_pidFile, *replica_argsFile;
static int replicationInterval;

static char	*passwd_salt;
static char	*logfileName;
static BerVarray authz_rewrites;

static struct berval cfdir;

/* Private state */
static AttributeDescription *cfAd_backend, *cfAd_database, *cfAd_overlay,
	*cfAd_include;

static ObjectClass *cfOc_schema, *cfOc_global, *cfOc_backend, *cfOc_database,
	*cfOc_include, *cfOc_overlay;

static ConfigFile cf_prv, *cfn = &cf_prv;

static Avlnode *CfOcTree;

static int add_syncrepl LDAP_P(( Backend *, char **, int ));
static int parse_syncrepl_line LDAP_P(( char **, int, syncinfo_t *));
static void syncrepl_unparse LDAP_P (( syncinfo_t *, struct berval *));
static int config_add_internal( CfBackInfo *cfb, Entry *e, SlapReply *rs );

static ConfigDriver config_fname;
static ConfigDriver config_cfdir;
static ConfigDriver config_generic;
static ConfigDriver config_search_base;
static ConfigDriver config_passwd_hash;
static ConfigDriver config_schema_dn;
static ConfigDriver config_sizelimit;
static ConfigDriver config_timelimit;
static ConfigDriver config_limits; 
static ConfigDriver config_overlay;
static ConfigDriver config_suffix; 
static ConfigDriver config_deref_depth;
static ConfigDriver config_rootdn;
static ConfigDriver config_rootpw;
static ConfigDriver config_restrict;
static ConfigDriver config_allows;
static ConfigDriver config_disallows;
static ConfigDriver config_requires;
static ConfigDriver config_security;
static ConfigDriver config_referral;
static ConfigDriver config_loglevel;
static ConfigDriver config_syncrepl;
static ConfigDriver config_replica;
static ConfigDriver config_updatedn;
static ConfigDriver config_updateref;
static ConfigDriver config_include;
#ifdef HAVE_TLS
static ConfigDriver config_tls_option;
static ConfigDriver config_tls_config;
#endif

enum {
	CFG_ACL = 1,
	CFG_BACKEND,
	CFG_DATABASE,
	CFG_TLS_RAND,
	CFG_TLS_CIPHER,
	CFG_TLS_CERT_FILE,
	CFG_TLS_CERT_KEY,
	CFG_TLS_CA_PATH,
	CFG_TLS_CA_FILE,
	CFG_TLS_VERIFY,
	CFG_TLS_CRLCHECK,
	CFG_SIZE,
	CFG_TIME,
	CFG_CONCUR,
	CFG_THREADS,
	CFG_SALT,
	CFG_LIMITS,
	CFG_RO,
	CFG_REWRITE,
	CFG_DEPTH,
	CFG_OID,
	CFG_OC,
	CFG_DIT,
	CFG_ATTR,
	CFG_ATOPT,
	CFG_CHECK,
	CFG_AUDITLOG,
	CFG_REPLOG,
	CFG_ROOTDSE,
	CFG_LOGFILE,
	CFG_PLUGIN,
	CFG_MODLOAD,
	CFG_MODPATH,
	CFG_LASTMOD,
	CFG_AZPOLICY,
	CFG_AZREGEXP,
	CFG_SASLSECP,
	CFG_SSTR_IF_MAX,
	CFG_SSTR_IF_MIN,
};

typedef struct {
	char *name, *oid;
} OidRec;

static OidRec OidMacros[] = {
	/* OpenLDAProot:666.11.1 */
	{ "OLcfg", "1.3.6.1.4.1.4203.666.11.1" },
	{ "OLcfgAt", "OLcfg:3" },
	{ "OLcfgOc", "OLcfg:4" },
	{ "OMsyn", "1.3.6.1.4.1.1466.115.121.1" },
	{ "OMsInteger", "OMsyn:2" },
	{ "OMsBoolean", "OMsyn:7" },
	{ "OMsDN", "OMsyn:12" },
	{ "OMsDirectoryString", "OMsyn:15" },
	{ "OMsOctetString", "OMsyn:40" },
	{ NULL, NULL }
};

/* alphabetical ordering */

ConfigTable config_back_cf_table[] = {
	/* This attr is read-only */
	{ "", "", 0, 0, 0, ARG_MAGIC,
		&config_fname, "( OLcfgAt:78 NAME 'olcConfigFile' "
			"DESC 'File for slapd configuration directives' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "", "", 0, 0, 0, ARG_MAGIC,
		&config_cfdir, "( OLcfgAt:79 NAME 'olcConfigDir' "
			"DESC 'Directory for slapd configuration backend' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "access",	NULL, 0, 0, 0, ARG_MAY_DB|ARG_MAGIC|CFG_ACL,
		&config_generic, "( OLcfgAt:1 NAME 'olcAccess' "
			"DESC 'Access Control List' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "allows",	"features", 2, 0, 5, ARG_PRE_DB|ARG_MAGIC,
		&config_allows, "( OLcfgAt:2 NAME 'olcAllows' "
			"DESC 'Allowed set of deprecated features' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "argsfile", "file", 2, 2, 0, ARG_STRING,
		&slapd_args_file, "( OLcfgAt:3 NAME 'olcArgsFile' "
			"DESC 'File for slapd command line options' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	/* Use standard 'attributeTypes' attr */
	{ "attribute",	"attribute", 2, 0, 9, ARG_PAREN|ARG_MAGIC|CFG_ATTR,
		&config_generic, NULL, NULL, NULL },
	{ "attributeoptions", NULL, 0, 0, 0, ARG_MAGIC|CFG_ATOPT,
		&config_generic, "( OLcfgAt:5 NAME 'olcAttributeOptions' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "authid-rewrite", NULL, 2, 0, 0,
#ifdef SLAP_AUTH_REWRITE
		ARG_MAGIC|CFG_REWRITE, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		 "( OLcfgAt:6 NAME 'olcAuthIDRewrite' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "authz-policy", "policy", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, "( OLcfgAt:7 NAME 'olcAuthzPolicy' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "authz-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, "( OLcfgAt:8 NAME 'olcAuthzRegexp' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "backend", "type", 2, 2, 0, ARG_PRE_DB|ARG_MAGIC|CFG_BACKEND,
		&config_generic, "( OLcfgAt:9 NAME 'olcBackend' "
			"DESC 'A type of backend' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "concurrency", "level", 2, 2, 0, ARG_INT|ARG_MAGIC|CFG_CONCUR,
		&config_generic, "( OLcfgAt:10 NAME 'olcConcurrency' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "conn_max_pending", "max", 2, 2, 0, ARG_INT,
		&slap_conn_max_pending, "( OLcfgAt:11 NAME 'olcConnMaxPending' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "conn_max_pending_auth", "max", 2, 2, 0, ARG_INT,
		&slap_conn_max_pending_auth, "( OLcfgAt:12 NAME 'olcConnMaxPendingAuth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "database", "type", 2, 2, 0, ARG_MAGIC|CFG_DATABASE,
		&config_generic, "( OLcfgAt:13 NAME 'olcDatabase' "
			"DESC 'The backend type for a database instance' "
			"SUP olcBackend X-ORDERED 'VALUES' )", NULL, NULL },
	{ "defaultSearchBase", "dn", 2, 2, 0, ARG_PRE_BI|ARG_PRE_DB|ARG_DN|ARG_MAGIC,
		&config_search_base, "( OLcfgAt:14 NAME 'olcDefaultSearchBase' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "disallows", "features", 2, 0, 8, ARG_PRE_DB|ARG_MAGIC,
		&config_disallows, "( OLcfgAt:15 NAME 'olcDisallows' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	/* use standard schema */
	{ "ditcontentrule",	NULL, 0, 0, 0, ARG_MAGIC|CFG_DIT,
		&config_generic, NULL, NULL, NULL },
	{ "gentlehup", "on|off", 2, 2, 0,
#ifdef SIGHUP
		ARG_ON_OFF, &global_gentlehup,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:17 NAME 'olcGentleHUP' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "idletimeout", "timeout", 2, 2, 0, ARG_INT,
		&global_idletimeout, "( OLcfgAt:18 NAME 'olcIdleTimeout' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
/* XXX -- special case? */
	{ "include", "file", 2, 2, 0, ARG_MAGIC,
		&config_include, "( OLcfgAt:19 NAME 'olcInclude' "
			"SUP labeledURI )", NULL, NULL },
	{ "index_substr_if_minlen", "min", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MIN,
		&config_generic, "( OLcfgAt:20 NAME 'olcIndexSubstrIfMinLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_if_maxlen", "max", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MAX,
		&config_generic, "( OLcfgAt:21 NAME 'olcIndexSubstrIfMaxLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_any_len", "len", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_len, "( OLcfgAt:22 NAME 'olcIndexSubstrAnyLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_step", "step", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_step, "( OLcfgAt:23 NAME 'olcIndexSubstrAnyStep' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "lastmod", "on|off", 2, 2, 0, ARG_DB|ARG_ON_OFF|ARG_MAGIC|CFG_LASTMOD,
		&config_generic, "( OLcfgAt:24 NAME 'olcLastMod' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "limits", "limits", 2, 0, 0, ARG_DB|ARG_MAGIC|CFG_LIMITS,
		&config_generic, "( OLcfgAt:25 NAME 'olcLimits' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "localSSF", "ssf", 2, 2, 0, ARG_INT,
		&local_ssf, "( OLcfgAt:26 NAME 'olcLocalSSF' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "logfile", "file", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_LOGFILE,
		&config_generic, "( OLcfgAt:27 NAME 'olcLogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "loglevel", "level", 2, 0, 0, ARG_MAGIC,
		&config_loglevel, "( OLcfgAt:28 NAME 'olcLogLevel' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "maxDerefDepth", "depth", 2, 2, 0, ARG_DB|ARG_INT|ARG_MAGIC|CFG_DEPTH,
		&config_generic, "( OLcfgAt:29 NAME 'olcMaxDerefDepth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "moduleload",	"file", 2, 0, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODLOAD, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:30 NAME 'olcModuleLoad' "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "modulepath", "path", 2, 2, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODPATH, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:31 NAME 'olcModulePath' "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	/* use standard schema */
	{ "objectclass", "objectclass", 2, 0, 0, ARG_PAREN|ARG_MAGIC|CFG_OC,
		&config_generic, NULL, NULL, NULL },
	{ "objectidentifier", NULL,	0, 0, 0, ARG_MAGIC|CFG_OID,
		&config_generic, "( OLcfgAt:33 NAME 'olcObjectIdentifier' "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "overlay", "overlay", 2, 2, 0, ARG_MAGIC,
		&config_overlay, "( OLcfgAt:34 NAME 'olcOverlay' "
			"SUP olcDatabase X-ORDERED 'VALUES' )", NULL, NULL },
	{ "password-crypt-salt-format", "salt", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_SALT,
		&config_generic, "( OLcfgAt:35 NAME 'olcPasswordCryptSaltFormat' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "password-hash", "hash", 2, 2, 0, ARG_MAGIC,
		&config_passwd_hash, "( OLcfgAt:36 NAME 'olcPasswordHash' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "pidfile", "file", 2, 2, 0, ARG_STRING,
		&slapd_pid_file, "( OLcfgAt:37 NAME 'olcPidFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "plugin", NULL, 0, 0, 0,
#ifdef LDAP_SLAPI
		ARG_MAGIC|CFG_PLUGIN, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:38 NAME 'olcPlugin' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "pluginlog", "filename", 2, 2, 0,
#ifdef LDAP_SLAPI
		ARG_STRING, &slapi_log_file,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:39 NAME 'olcPluginLogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "readonly", "on|off", 2, 2, 0, ARG_MAY_DB|ARG_ON_OFF|ARG_MAGIC|CFG_RO,
		&config_generic, "( OLcfgAt:40 NAME 'olcReadOnly' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "referral", "url", 2, 2, 0, ARG_MAGIC,
		&config_referral, "( OLcfgAt:41 NAME 'olcReferral' "
			"SUP labeledURI SINGLE-VALUE )", NULL, NULL },
	{ "replica", "host or uri", 2, 0, 0, ARG_DB|ARG_MAGIC,
		&config_replica, "( OLcfgAt:42 NAME 'olcReplica' "
			"SUP labeledURI )", NULL, NULL },
	{ "replica-argsfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_argsFile, "( OLcfgAt:43 NAME 'olcReplicaArgsFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "replica-pidfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_pidFile, "( OLcfgAt:44 NAME 'olcReplicaPidFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "replicationInterval", NULL, 0, 0, 0, ARG_INT,
		&replicationInterval, "( OLcfgAt:45 NAME 'olcReplicationInterval' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "replogfile", "filename", 2, 2, 0, ARG_MAY_DB|ARG_MAGIC|ARG_STRING|CFG_REPLOG,
		&config_generic, "( OLcfgAt:46 NAME 'olcReplogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "require", "features", 2, 0, 7, ARG_MAY_DB|ARG_MAGIC,
		&config_requires, "( OLcfgAt:47 NAME 'olcRequires' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "restrict", "op_list", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_restrict, "( OLcfgAt:48 NAME 'olcRestrict' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "reverse-lookup", "on|off", 2, 2, 0,
#ifdef SLAPD_RLOOKUPS
		ARG_ON_OFF, &use_reverse_lookup,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:49 NAME 'olcReverseLookup' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "rootdn", "dn", 2, 2, 0, ARG_DB|ARG_DN|ARG_MAGIC,
		&config_rootdn, "( OLcfgAt:50 NAME 'olcRootDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "rootDSE", "file", 2, 2, 0, ARG_MAGIC|CFG_ROOTDSE,
		&config_generic, "( OLcfgAt:51 NAME 'olcRootDSE' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "rootpw", "password", 2, 2, 0, ARG_STRING|ARG_DB|ARG_MAGIC,
		&config_rootpw, "( OLcfgAt:52 NAME 'olcRootPW' "
			"SYNTAX OMsOctetString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-authz-policy", NULL, 2, 2, 0, ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-host", "host", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_host,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:53 NAME 'olcSaslHost' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-realm", "realm", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_realm,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:54 NAME 'olcSaslRealm' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-secprops", "properties", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_MAGIC|CFG_SASLSECP, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:56 NAME 'olcSaslSecProps' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "saslRegexp",	NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "schemacheck", "on|off", 2, 2, 0, ARG_ON_OFF|ARG_MAGIC|CFG_CHECK,
		&config_generic, "( OLcfgAt:57 NAME 'olcSchemaCheck' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "schemadn", "dn", 2, 2, 0, ARG_MAY_DB|ARG_DN|ARG_MAGIC,
		&config_schema_dn, "( OLcfgAt:58 NAME 'olcSchemaDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "security", "factors", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_security, "( OLcfgAt:59 NAME 'olcSecurity' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "sizelimit", "limit",	2, 0, 0, ARG_MAY_DB|ARG_MAGIC|CFG_SIZE,
		&config_sizelimit, "( OLcfgAt:60 NAME 'olcSizeLimit' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "sockbuf_max_incoming", "max", 2, 2, 0, ARG_BER_LEN_T,
		&sockbuf_max_incoming, "( OLcfgAt:61 NAME 'olcSockbufMaxIncoming' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "sockbuf_max_incoming_auth", "max", 2, 2, 0, ARG_BER_LEN_T,
		&sockbuf_max_incoming_auth, "( OLcfgAt:62 NAME 'olcSockbufMaxIncomingAuth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "srvtab", "file", 2, 2, 0,
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		ARG_STRING, &ldap_srvtab,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:63 NAME 'olcSrvtab' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "suffix",	"suffix", 2, 2, 0, ARG_DB|ARG_DN|ARG_MAGIC,
		&config_suffix, "( OLcfgAt:64 NAME 'olcSuffix' "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "syncrepl", NULL, 0, 0, 0, ARG_DB|ARG_MAGIC,
		&config_syncrepl, "( OLcfgAt:65 NAME 'olcSyncrepl' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "threads", "count", 2, 2, 0, ARG_INT|ARG_MAGIC|CFG_THREADS,
		&config_generic, "( OLcfgAt:66 NAME 'olcThreads' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "timelimit", "limit", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC|CFG_TIME,
		&config_timelimit, "( OLcfgAt:67 NAME 'olcTimeLimit' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "TLSCACertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:68 NAME 'olcTLSCACertificateFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCACertificatePath", NULL,	0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_PATH|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:69 NAME 'olcTLSCACertificatePath' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:70 NAME 'olcTLSCertificateFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCertificateKeyFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_KEY|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:71 NAME 'olcTLSCertificateKeyFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCipherSuite",	NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CIPHER|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:72 NAME 'olcTLSCipherSuite' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCRLCheck", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CRLCHECK|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:73 NAME 'olcTLSCRLCheck' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSRandFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_RAND|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:74 NAME 'olcTLSRandFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSVerifyClient", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_VERIFY|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:75 NAME 'olcTLSVerifyClient' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "ucdata-path", "path", 2, 2, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL },
	{ "updatedn", "dn", 2, 2, 0, ARG_DB|ARG_MAGIC,
		&config_updatedn, "( OLcfgAt:76 NAME 'olcUpdateDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "updateref", "url", 2, 2, 0, ARG_DB|ARG_MAGIC,
		&config_updateref, "( OLcfgAt:77 NAME 'olcUpdateRef' "
			"SUP labeledURI )", NULL, NULL },
	{ NULL,	NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};

static ConfigOCs cf_ocs[] = {
	{ "( OLcfgOc:1 "
		"NAME 'olcConfig' "
		"DESC 'OpenLDAP configuration object' "
		"ABSTRACT SUP top "
		"MAY ( cn $ olcConfigFile ) )", Cft_Abstract, NULL },
	{ "( OLcfgOc:2 "
		"NAME 'olcGlobal' "
		"DESC 'OpenLDAP Global configuration options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcConfigDir $ olcAllows $ olcArgsFile $ olcAttributeOptions $ "
		 "olcAuthIDRewrite $ olcAuthzPolicy $ olcAuthzRegexp $ "
		 "olcConcurrency $ olcConnMaxPending $ olcConnMaxPendingAuth $ "
		 "olcDefaultSearchBase $ olcDisallows $ olcGentleHUP $ "
		 "olcIdleTimeout $ olcIndexSubstrIfMaxLen $ olcIndexSubstrIfMinLen $ "
		 "olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcLocalSSF $ "
		 "olcLogLevel $ olcModuleLoad $ olcModulePath $ olcObjectIdentifier $ "
		 "olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ "
		 "olcPlugin $ olcPluginLogFile $ olcReadOnly $ olcReferral $ "
		 "olcReplicaPidFile $ olcReplicaArgsFile $ olcReplicationInterval $ "
		 "olcReplogFile $ olcRequires $ olcRestrict $ olcReverseLookup $ "
		 "olcRootDSE $ olcRootPW $ olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ "
		 "olcSchemaCheck $ olcSchemaDN $ olcSecurity $ olcSizeLimit $ "
		 "olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcSrvtab $ "
		 "olcThreads $ olcTimeLimit $ olcTLSCACertificateFile $ "
		 "olcTLSCACertificatePath $ olcTLSCertificateFile $ "
		 "olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ "
		 "olcTLSRandFile $ olcTLSVerifyClient ) )", Cft_Global, &cfOc_global },
	{ "( OLcfgOc:3 "
		"NAME 'olcSchemaConfig' "
		"DESC 'OpenLDAP schema object' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcObjectIdentifier $ attributeTypes $ objectClasses $ "
		 "ditContentRules ) )", Cft_Schema, &cfOc_schema },
	{ "( OLcfgOc:4 "
		"NAME 'olcBackendConfig' "
		"DESC 'OpenLDAP Backend-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcBackend ) )", Cft_Backend, &cfOc_backend },
	{ "( OLcfgOc:5 "
		"NAME 'olcDatabaseConfig' "
		"DESC 'OpenLDAP Database-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcDatabase $ olcAccess $ olcLastMod $ olcLimits $ "
		 "olcMaxDerefDepth $ olcPlugin $ olcReadOnly $ olcReplica $ "
		 "olcReplogFile $ olcRequires $ olcRestrict $ olcRootDN $ olcRootPW $ "
		 "olcSchemaDN $ olcSecurity $ olcSizeLimit $ olcSuffix $ olcSyncrepl $ "
		 "olcTimeLimit $ olcUpdateDN $ olcUpdateRef ) )",
		 	Cft_Database, &cfOc_database },
	{ "( OLcfgOc:6 "
		"NAME 'olcOverlayConfig' "
		"DESC 'OpenLDAP Overlay-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcOverlay ) )", Cft_Overlay, &cfOc_overlay },
	{ "( OLcfgOc:7 "
		"NAME 'olcIncludeFile' "
		"DESC 'OpenLDAP configuration include file' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( olcInclude $ olcModuleLoad $ olcModulePath $ olcRootDSE ) )",
		Cft_Include, &cfOc_include },
	{ NULL, 0, NULL }
};

static int
config_generic(ConfigArgs *c) {
	char *p;
	int i;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		int rc = 0;
		switch(c->type) {
		case CFG_CONCUR:
			c->value_int = ldap_pvt_thread_get_concurrency();
			break;
		case CFG_THREADS:
			c->value_int = connection_pool_max;
			break;
		case CFG_SALT:
			if ( passwd_salt )
				c->value_string = ch_strdup( passwd_salt );
			else
				rc = 1;
			break;
		case CFG_LIMITS:
			if ( c->be->be_limits ) {
				char buf[4096*3];
				struct berval bv;
				int i;

				for ( i=0; c->be->be_limits[i]; i++ ) {
					bv.bv_len = sprintf( buf, "{%d}", i );
					bv.bv_val = buf+bv.bv_len;
					limits_unparse( c->be->be_limits[i], &bv );
					bv.bv_len += bv.bv_val - buf;
					bv.bv_val = buf;
					value_add_one( &c->rvalue_vals, &bv );
				}
			}
			if ( !c->rvalue_vals ) rc = 1;
			break;
		case CFG_RO:
			c->value_int = (c->be->be_restrictops & SLAP_RESTRICT_OP_WRITES) != 0;
			break;
		case CFG_AZPOLICY:
			c->value_string = ch_strdup( slap_sasl_getpolicy());
			break;
		case CFG_AZREGEXP:
			slap_sasl_regexp_unparse( &c->rvalue_vals );
			if ( !c->rvalue_vals ) rc = 1;
			break;
#ifdef HAVE_CYRUS_SASL
		case CFG_SASLSECP: {
			struct berval bv = BER_BVNULL;
			slap_sasl_secprops_unparse( &bv );
			if ( !BER_BVISNULL( &bv )) {
				ber_bvarray_add( &c->rvalue_vals, &bv );
			} else {
				rc = 1;
			}
			}
			break;
#endif
		case CFG_DEPTH:
			c->value_int = c->be->be_max_deref_depth;
			break;
		case CFG_OID:
			oidm_unparse( &c->rvalue_vals );
			if ( !c->rvalue_vals )
				rc = 1;
			break;
		case CFG_CHECK:
			c->value_int = global_schemacheck;
			break;
		case CFG_ACL: {
			AccessControl *a;
			char *src, *dst, ibuf[11];
			struct berval bv, abv;
			for (i=0, a=c->be->be_acl; a; i++,a=a->acl_next) {
				abv.bv_len = sprintf( ibuf, "{%x}", i );
				acl_unparse( a, &bv );
				abv.bv_val = ch_malloc( abv.bv_len + bv.bv_len + 1 );
				AC_MEMCPY( abv.bv_val, ibuf, abv.bv_len );
				/* Turn TAB / EOL into plain space */
				for (src=bv.bv_val,dst=abv.bv_val+abv.bv_len; *src; src++) {
					if (isspace(*src)) *dst++ = ' ';
					else *dst++ = *src;
				}
				*dst = '\0';
				if (dst[-1] == ' ') {
					dst--;
					*dst = '\0';
				}
				abv.bv_len = dst - abv.bv_val;
				ber_bvarray_add( &c->rvalue_vals, &abv );
			}
			rc = (!i);
			break;
		}
		case CFG_REPLOG:
			if ( c->be->be_replogfile )
				c->value_string = ch_strdup( c->be->be_replogfile );
			break;
		case CFG_ROOTDSE: {
			ConfigFile *cf = (ConfigFile *)c->line;
			if ( cf->c_dseFiles ) {
				value_add( &c->rvalue_vals, cf->c_dseFiles );
			} else {
				rc = 1;
			}
			}
			break;
		case CFG_LOGFILE:
			if ( logfileName )
				c->value_string = ch_strdup( logfileName );
			else
				rc = 1;
			break;
		case CFG_LASTMOD:
			c->value_int = (SLAP_NOLASTMOD(c->be) == 0);
			break;
		case CFG_SSTR_IF_MAX:
			c->value_int = index_substr_if_maxlen;
			break;
		case CFG_SSTR_IF_MIN:
			c->value_int = index_substr_if_minlen;
			break;
#ifdef SLAPD_MODULES
		case CFG_MODLOAD: {
			ConfigFile *cf = (ConfigFile *)c->line;
			ModPaths *mp;
			for (i=0, mp=&cf->c_modpaths; mp; mp=mp->mp_next, i++) {
				int j;
				if (!mp->mp_loads) continue;
				for (j=0; !BER_BVISNULL(&mp->mp_loads[j]); j++) {
					struct berval bv;
					bv.bv_val = c->log;
					bv.bv_len = sprintf( bv.bv_val, "{%d}{%d}%s", i, j,
						mp->mp_loads[j].bv_val );
					value_add_one( &c->rvalue_vals, &bv );
				}
			}
			rc = c->rvalue_vals ? 0 : 1;
			}
			break;
		case CFG_MODPATH: {
			ConfigFile *cf = (ConfigFile *)c->line;
			ModPaths *mp;
			for (i=0, mp=&cf->c_modpaths; mp; mp=mp->mp_next, i++) {
				struct berval bv;
				if ( BER_BVISNULL( &mp->mp_path ) && !mp->mp_loads )
					continue;
				bv.bv_val = c->log;
				bv.bv_len = sprintf( bv.bv_val, "{%d}%s", i,
					mp->mp_path.bv_val );
				value_add_one( &c->rvalue_vals, &bv );
			}
			rc = c->rvalue_vals ? 0 : 1;
			}
			break;
#endif
#ifdef LDAP_SLAPI
		case CFG_PLUGIN:
			slapi_int_plugin_unparse( c->be, &c->rvalue_vals );
			if ( !c->rvalue_vals ) rc = 1;
			break;
#endif
#ifdef SLAP_AUTH_REWRITE
		case CFG_REWRITE:
			if ( authz_rewrites ) {
				struct berval bv, idx;
				char ibuf[32];
				int i;

				idx.bv_val = ibuf;
				for ( i=0; !BER_BVISNULL( &authz_rewrites[i] ); i++ ) {
					idx.bv_len = sprintf( idx.bv_val, "{%d}", i );
					bv.bv_len = idx.bv_len + authz_rewrites[i].bv_len;
					bv.bv_val = ch_malloc( bv.bv_len + 1 );
					strcpy( bv.bv_val, idx.bv_val );
					strcpy( bv.bv_val+idx.bv_len, authz_rewrites[i].bv_val );
					ber_bvarray_add( &c->rvalue_vals, &bv );
				}
			}
			if ( !c->rvalue_vals ) rc = 1;
			break;
#endif
		default:
			rc = 1;
		}
		return rc;
	}

 	p = strchr(c->line,'(' /*')'*/);
	switch(c->type) {
		case CFG_BACKEND:
			if(!(c->bi = backend_info(c->argv[1]))) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"backend %s failed init!\n", c->log, c->argv[1], 0);
				return(1);
			}
			break;

		case CFG_DATABASE:
			c->bi = NULL;
			/* NOTE: config is always the first backend!
			 */
			if ( !strcasecmp( c->argv[1], "config" )) {
				c->be = backendDB;
			} else if ( !strcasecmp( c->argv[1], "frontend" )) {
				c->be = frontendDB;
			} else if(!(c->be = backend_db_init(c->argv[1]))) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"database %s failed init!\n", c->log, c->argv[1], 0);
				return(1);
			}
			break;

		case CFG_CONCUR:
			ldap_pvt_thread_set_concurrency(c->value_int);
			break;

		case CFG_THREADS:
			ldap_pvt_thread_pool_maxthreads(&connection_pool, c->value_int);
			connection_pool_max = c->value_int;	/* save for reference */
			break;

		case CFG_SALT:
			if ( passwd_salt ) ch_free( passwd_salt );
			passwd_salt = c->value_string;
			lutil_salt_format(passwd_salt);
			break;

		case CFG_LIMITS:
			if(limits_parse(c->be, c->fname, c->lineno, c->argc, c->argv))
				return(1);
			break;

		case CFG_RO:
			if(c->value_int)
				c->be->be_restrictops |= SLAP_RESTRICT_OP_WRITES;
			else
				c->be->be_restrictops &= ~SLAP_RESTRICT_OP_WRITES;
			break;

		case CFG_AZPOLICY:
			ch_free(c->value_string);
			if (slap_sasl_setpolicy( c->argv[1] )) {
				Debug(LDAP_DEBUG_ANY, "%s: unable to parse value \"%s\" in"
					" \"authz-policy <policy>\"\n",
					c->log, c->argv[1], 0 );
				return(1);
			}
			break;
		
		case CFG_AZREGEXP:
			if (slap_sasl_regexp_config( c->argv[1], c->argv[2] ))
				return(1);
			break;
				
#ifdef HAVE_CYRUS_SASL
		case CFG_SASLSECP:
			{
			char *txt = slap_sasl_secprops( c->argv[1] );
			if ( txt ) {
				Debug(LDAP_DEBUG_ANY, "%s: sasl-secprops: %s\n",
					c->log, txt, 0 );
				return(1);
			}
			break;
			}
#endif

		case CFG_DEPTH:
			c->be->be_max_deref_depth = c->value_int;
			break;

		case CFG_OID:
			if(parse_oidm(c->fname, c->lineno, c->argc, c->argv)) return(0);
			break;

		case CFG_OC:
			if(parse_oc(c->fname, c->lineno, p, c->argv)) return(1);
			break;

		case CFG_DIT:
			if(parse_cr(c->fname, c->lineno, p, c->argv)) return(1);
			break;

		case CFG_ATTR:
			if(parse_at(c->fname, c->lineno, p, c->argv)) return(1);
			break;

		case CFG_ATOPT:
			ad_define_option(NULL, NULL, 0);
			for(i = 1; i < c->argc; i++)
				if(ad_define_option(c->argv[i], c->fname, c->lineno))
					return(1);
			break;

		case CFG_CHECK:
			global_schemacheck = c->value_int;
			if(!global_schemacheck) Debug(LDAP_DEBUG_ANY, "%s: "
				"schema checking disabled! your mileage may vary!\n",
				c->log, 0, 0);
			break;

		case CFG_ACL:
			parse_acl(c->be, c->fname, c->lineno, c->argc, c->argv);
			break;

		case CFG_REPLOG:
			if(SLAP_MONITOR(c->be)) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"\"replogfile\" should not be used "
					"inside monitor database\n",
					c->log, 0, 0);
				return(0);	/* FIXME: should this be an error? */
			}

			c->be->be_replogfile = c->value_string;
			break;

		case CFG_ROOTDSE:
			if(read_root_dse_file(c->argv[1])) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"could not read \"rootDSE <filename>\" line\n",
					c->log, 0, 0);
				return(1);
			}
			{
				struct berval bv;
				ber_str2bv( c->argv[1], 0, 1, &bv );
				ber_bvarray_add( &cfn->c_dseFiles, &bv );
			}
			break;

		case CFG_LOGFILE: {
				FILE *logfile;
				if ( logfileName ) ch_free( logfileName );
				logfileName = c->value_string;
				logfile = fopen(logfileName, "w");
				if(logfile) lutil_debug_file(logfile);
			} break;

		case CFG_LASTMOD:
			if(SLAP_NOLASTMODCMD(c->be)) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"lastmod not available for %s databases\n",
					c->log, c->be->bd_info->bi_type, 0);
				return(1);
			}
			if(c->value_int)
				SLAP_DBFLAGS(c->be) &= ~SLAP_DBFLAG_NOLASTMOD;
			else
				SLAP_DBFLAGS(c->be) |= SLAP_DBFLAG_NOLASTMOD;
			break;

		case CFG_SSTR_IF_MAX:
			if (c->value_int < index_substr_if_minlen) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"invalid max value (%d)\n",
					c->log, c->value_int, 0 );
				return(1);
			}
			index_substr_if_maxlen = c->value_int;
			break;

		case CFG_SSTR_IF_MIN:
			if (c->value_int > index_substr_if_maxlen) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"invalid min value (%d)\n",
					c->log, c->value_int, 0 );
				return(1);
			}
			index_substr_if_minlen = c->value_int;
			break;

#ifdef SLAPD_MODULES
		case CFG_MODLOAD:
			if(module_load(c->argv[1], c->argc - 2, (c->argc > 2) ? c->argv + 2 : NULL))
				return(1);
			/* Record this load on the current path */
			{
				struct berval bv;
				ber_str2bv(c->line, 0, 1, &bv);
				ber_bvarray_add( &cfn->c_modlast->mp_loads, &bv );
			}
			break;

		case CFG_MODPATH:
			if(module_path(c->argv[1])) return(1);
			/* Record which path was used with each module */
			{
				ModPaths *mp;

				if (!cfn->c_modpaths.mp_loads) {
					mp = &cfn->c_modpaths;
				} else {
					mp = ch_malloc( sizeof( ModPaths ));
					cfn->c_modlast->mp_next = mp;
				}
				ber_str2bv(c->argv[1], 0, 1, &mp->mp_path);
				mp->mp_next = NULL;
				mp->mp_loads = NULL;
				cfn->c_modlast = mp;
			}
			
			break;
#endif

#ifdef LDAP_SLAPI
		case CFG_PLUGIN:
			if(slapi_int_read_config(c->be, c->fname, c->lineno, c->argc, c->argv) != LDAP_SUCCESS)
				return(1);
			slapi_plugins_used++;
			break;
#endif

#ifdef SLAP_AUTH_REWRITE
		case CFG_REWRITE: {
			struct berval bv;
			if(slap_sasl_rewrite_config(c->fname, c->lineno, c->argc, c->argv))
				return(1);
			ber_str2bv( c->line, 0, 1, &bv );
			ber_bvarray_add( &authz_rewrites, &bv );
			}
			break;
#endif


		default:
			Debug(LDAP_DEBUG_ANY, "%s: unknown CFG_TYPE %d"
				"(ignored)\n", c->log, c->type, 0);

	}
	return(0);
}


static int
config_fname(ConfigArgs *c) {
	if(c->op == SLAP_CONFIG_EMIT && c->line) {
		ConfigFile *cf = (ConfigFile *)c->line;
		value_add_one( &c->rvalue_vals, &cf->c_file );
		return 0;
	}
	return(0);
}

static int
config_cfdir(ConfigArgs *c) {
	if(c->op == SLAP_CONFIG_EMIT) {
		value_add_one( &c->rvalue_vals, &cfdir );
		return 0;
	}
	return(0);
}

static int
config_search_base(ConfigArgs *c) {
	struct berval dn;

	if(c->op == SLAP_CONFIG_EMIT) {
		int rc = 1;
		if (!BER_BVISEMPTY(&default_search_base)) {
			value_add_one(&c->rvalue_vals, &default_search_base);
			value_add_one(&c->rvalue_nvals, &default_search_nbase);
			rc = 0;
		}
		return rc;
	}

	if(c->bi || c->be != frontendDB) {
		Debug(LDAP_DEBUG_ANY, "%s: defaultSearchBase line must appear "
			"prior to any backend or database definition\n",
			c->log, 0, 0);
		return(1);
	}

	if(default_search_nbase.bv_len) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"default search base \"%s\" already defined "
			"(discarding old)\n",
			c->log, default_search_base.bv_val, 0);
		free(default_search_base.bv_val);
		free(default_search_nbase.bv_val);
	}

	default_search_base = c->value_dn;
	default_search_nbase = c->value_ndn;
	return(0);
}

static int
config_passwd_hash(ConfigArgs *c) {
	int i;
	if (c->op == SLAP_CONFIG_EMIT) {
		struct berval bv;
		for (i=0; default_passwd_hash && default_passwd_hash[i]; i++) {
			ber_str2bv(default_passwd_hash[i], 0, 0, &bv);
			value_add_one(&c->rvalue_vals, &bv);
		}
		return i ? 0 : 1;
	}
	if(default_passwd_hash) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"already set default password_hash\n",
			c->log, 0, 0);
		return(1);
	}
	for(i = 1; i < c->argc; i++) {
		if(!lutil_passwd_scheme(c->argv[i])) {
			Debug(LDAP_DEBUG_ANY, "%s: "
				"password scheme \"%s\" not available\n",
				c->log, c->argv[i], 0);
		} else {
			ldap_charray_add(&default_passwd_hash, c->argv[i]);
		}
		if(!default_passwd_hash) {
			Debug(LDAP_DEBUG_ANY, "%s: no valid hashes found\n",
				c->log, 0, 0 );
			return(1);
		}
	}
	return(0);
}

static int
config_schema_dn(ConfigArgs *c) {
	if ( c->op == SLAP_CONFIG_EMIT ) {
		int rc = 1;
		if ( !BER_BVISEMPTY( &c->be->be_schemadn )) {
			value_add_one(&c->rvalue_vals, &c->be->be_schemadn);
			value_add_one(&c->rvalue_nvals, &c->be->be_schemandn);
			rc = 0;
		}
		return rc;
	}
	c->be->be_schemadn = c->value_dn;
	c->be->be_schemandn = c->value_ndn;
	return(0);
}

static int
config_sizelimit(ConfigArgs *c) {
	int i, rc = 0;
	char *next;
	struct slap_limits_set *lim = &c->be->be_def_limit;
	if (c->op == SLAP_CONFIG_EMIT) {
		char buf[8192];
		struct berval bv;
		bv.bv_val = buf;
		bv.bv_len = 0;
		limits_unparse_one( lim, SLAP_LIMIT_SIZE, &bv );
		if ( !BER_BVISEMPTY( &bv ))
			value_add_one( &c->rvalue_vals, &bv );
		else
			rc = 1;
		return rc;
	}
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "size", 4)) {
			rc = limits_parse_one(c->argv[i], lim);
			if ( rc ) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"unable to parse value \"%s\" in \"sizelimit <limit>\" line\n",
					c->log, c->argv[i], 0);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_s_soft = -1;
			} else {
				lim->lms_s_soft = strtol(c->argv[i], &next, 0);
				if(next == c->argv[i]) {
					Debug(LDAP_DEBUG_ANY, "%s: "
						"unable to parse limit \"%s\" in \"sizelimit <limit>\" line\n",
						c->log, c->argv[i], 0);
					return(1);
				} else if(next[0] != '\0') {
					Debug(LDAP_DEBUG_ANY, "%s: "
						"trailing chars \"%s\" in \"sizelimit <limit>\" line (ignored)\n",
						c->log, next, 0);
				}
			}
			lim->lms_s_hard = 0;
		}
	}
	return(0);
}

static int
config_timelimit(ConfigArgs *c) {
	int i, rc = 0;
	char *next;
	struct slap_limits_set *lim = &c->be->be_def_limit;
	if (c->op == SLAP_CONFIG_EMIT) {
		char buf[8192];
		struct berval bv;
		bv.bv_val = buf;
		bv.bv_len = 0;
		limits_unparse_one( lim, SLAP_LIMIT_TIME, &bv );
		if ( !BER_BVISEMPTY( &bv ))
			value_add_one( &c->rvalue_vals, &bv );
		else
			rc = 1;
		return rc;
	}
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "time", 4)) {
			rc = limits_parse_one(c->argv[i], lim);
			if ( rc ) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"unable to parse value \"%s\" in \"timelimit <limit>\" line\n",
					c->log, c->argv[i], 0);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_t_soft = -1;
			} else {
				lim->lms_t_soft = strtol(c->argv[i], &next, 0);
				if(next == c->argv[i]) {
					Debug(LDAP_DEBUG_ANY, "%s: "
						"unable to parse limit \"%s\" in \"timelimit <limit>\" line\n",
						c->log, c->argv[i], 0);
					return(1);
				} else if(next[0] != '\0') {
					Debug(LDAP_DEBUG_ANY, "%s: "
						"trailing chars \"%s\" in \"timelimit <limit>\" line (ignored)\n",
						c->log, next, 0);
				}
			}
			lim->lms_t_hard = 0;
		}
	}
	return(0);
}

static int
config_overlay(ConfigArgs *c) {
	if (c->op == SLAP_CONFIG_EMIT) {
		return 1;
	}
	if(c->argv[1][0] == '-' && overlay_config(c->be, &c->argv[1][1])) {
		/* log error */
		Debug(LDAP_DEBUG_ANY, "%s: (optional) %s overlay \"%s\" configuration failed (ignored)\n",
			c->log, c->be == frontendDB ? "global " : "", c->argv[1][1]);
	} else if(overlay_config(c->be, c->argv[1])) {
		return(1);
	}
	return(0);
}

static int
config_suffix(ConfigArgs *c) {
	Backend *tbe;
	struct berval pdn, ndn;
	int rc;

	if (c->be == frontendDB) return 1;

	if (c->op == SLAP_CONFIG_EMIT) {
		if (!BER_BVISNULL( &c->be->be_suffix[0] )) {
			value_add( &c->rvalue_vals, c->be->be_suffix );
			value_add( &c->rvalue_nvals, c->be->be_nsuffix );
			return 0;
		} else {
			return 1;
		}
	}
#ifdef SLAPD_MONITOR_DN
	if(!strcasecmp(c->argv[1], SLAPD_MONITOR_DN)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"\"%s\" is reserved for monitoring slapd\n",
			c->log, SLAPD_MONITOR_DN, 0);
		return(1);
	}
#endif

	pdn = c->value_dn;
	ndn = c->value_ndn;
	tbe = select_backend(&ndn, 0, 0);
	if(tbe == c->be) {
		Debug(LDAP_DEBUG_ANY, "%s: suffix already served by this backend! (ignored)\n",
			c->log, 0, 0);
		free(pdn.bv_val);
		free(ndn.bv_val);
	} else if(tbe) {
		Debug(LDAP_DEBUG_ANY, "%s: suffix already served by a preceding backend \"%s\"\n",
			c->log, tbe->be_suffix[0].bv_val, 0);
		free(pdn.bv_val);
		free(ndn.bv_val);
		return(1);
	} else if(pdn.bv_len == 0 && default_search_nbase.bv_len) {
		Debug(LDAP_DEBUG_ANY, "%s: suffix DN empty and default search "
			"base provided \"%s\" (assuming okay)\n",
			c->log, default_search_base.bv_val, 0);
	}
	ber_bvarray_add(&c->be->be_suffix, &pdn);
	ber_bvarray_add(&c->be->be_nsuffix, &ndn);
	return(0);
}

static int
config_rootdn(ConfigArgs *c) {
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( !BER_BVISNULL( &c->be->be_rootdn )) {
			value_add_one(&c->rvalue_vals, &c->be->be_rootdn);
			value_add_one(&c->rvalue_nvals, &c->be->be_rootndn);
			return 0;
		} else {
			return 1;
		}
	}
	c->be->be_rootdn = c->value_dn;
	c->be->be_rootndn = c->value_ndn;
	return(0);
}

static int
config_rootpw(ConfigArgs *c) {
	Backend *tbe;
	if (c->op == SLAP_CONFIG_EMIT) {
		if (!BER_BVISEMPTY(&c->be->be_rootpw)) {
			c->value_string=c->be->be_rootpw.bv_val;
			return 0;
		}
		return 1;
	}

	tbe = select_backend(&c->be->be_rootndn, 0, 0);
	if(tbe != c->be) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"rootpw can only be set when rootdn is under suffix\n",
			c->log, 0, 0);
		return(1);
	}
	ber_str2bv(c->value_string, 0, 0, &c->be->be_rootpw);
	return(0);
}

static int
config_restrict(ConfigArgs *c) {
	slap_mask_t restrictops = 0;
	int i;
	slap_verbmasks restrictable_ops[] = {
		{ BER_BVC("bind"),		SLAP_RESTRICT_OP_BIND },
		{ BER_BVC("add"),		SLAP_RESTRICT_OP_ADD },
		{ BER_BVC("modify"),		SLAP_RESTRICT_OP_MODIFY },
		{ BER_BVC("rename"),		SLAP_RESTRICT_OP_RENAME },
		{ BER_BVC("modrdn"),		0 },
		{ BER_BVC("delete"),		SLAP_RESTRICT_OP_DELETE },
		{ BER_BVC("search"),		SLAP_RESTRICT_OP_SEARCH },
		{ BER_BVC("compare"),	SLAP_RESTRICT_OP_COMPARE },
		{ BER_BVC("read"),		SLAP_RESTRICT_OP_READS },
		{ BER_BVC("write"),		SLAP_RESTRICT_OP_WRITES },
		{ BER_BVC("extended"),	SLAP_RESTRICT_OP_EXTENDED },
		{ BER_BVC("extended=" LDAP_EXOP_START_TLS ),		SLAP_RESTRICT_EXOP_START_TLS },
		{ BER_BVC("extended=" LDAP_EXOP_MODIFY_PASSWD ),	SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
		{ BER_BVC("extended=" LDAP_EXOP_X_WHO_AM_I ),		SLAP_RESTRICT_EXOP_WHOAMI },
		{ BER_BVC("extended=" LDAP_EXOP_X_CANCEL ),		SLAP_RESTRICT_EXOP_CANCEL },
		{ BER_BVNULL,	0 }
	};

	if (c->op == SLAP_CONFIG_EMIT) {
		return mask_to_verbs( restrictable_ops, c->be->be_restrictops,
			&c->rvalue_vals );
	}
	i = verbs_to_mask( c->argc, c->argv, restrictable_ops, &restrictops );
	if ( i ) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"unknown operation %s in \"restrict <features>\" line\n",
			c->log, c->argv[i], 0);
		return(1);
	}
	if ( restrictops & SLAP_RESTRICT_OP_EXTENDED )
		restrictops &= ~SLAP_RESTRICT_EXOP_MASK;
	c->be->be_restrictops |= restrictops;
	return(0);
}

static int
config_allows(ConfigArgs *c) {
	slap_mask_t allows = 0;
	int i;
	slap_verbmasks allowable_ops[] = {
		{ BER_BVC("bind_v2"),		SLAP_ALLOW_BIND_V2 },
		{ BER_BVC("bind_anon_cred"),	SLAP_ALLOW_BIND_ANON_CRED },
		{ BER_BVC("bind_anon_dn"),	SLAP_ALLOW_BIND_ANON_DN },
		{ BER_BVC("update_anon"),	SLAP_ALLOW_UPDATE_ANON },
		{ BER_BVNULL,	0 }
	};
	if (c->op == SLAP_CONFIG_EMIT) {
		return mask_to_verbs( allowable_ops, global_allows, &c->rvalue_vals );
	}
	i = verbs_to_mask(c->argc, c->argv, allowable_ops, &allows);
	if ( i ) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"unknown feature %s in \"allow <features>\" line\n",
			c->log, c->argv[i], 0);
		return(1);
	}
	global_allows |= allows;
	return(0);
}

static int
config_disallows(ConfigArgs *c) {
	slap_mask_t disallows = 0;
	int i;
	slap_verbmasks disallowable_ops[] = {
		{ BER_BVC("bind_anon"),		SLAP_DISALLOW_BIND_ANON },
		{ BER_BVC("bind_simple"),	SLAP_DISALLOW_BIND_SIMPLE },
		{ BER_BVC("bind_krb4"),		SLAP_DISALLOW_BIND_KRBV4 },
		{ BER_BVC("tls_2_anon"),		SLAP_DISALLOW_TLS_2_ANON },
		{ BER_BVC("tls_authc"),		SLAP_DISALLOW_TLS_AUTHC },
		{ BER_BVNULL, 0 }
	};
	if (c->op == SLAP_CONFIG_EMIT) {
		return mask_to_verbs( disallowable_ops, global_disallows, &c->rvalue_vals );
	}
	i = verbs_to_mask(c->argc, c->argv, disallowable_ops, &disallows);
	if ( i ) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"unknown feature %s in \"disallow <features>\" line\n",
			c->log, c->argv[i], 0);
		return(1);
	}
	global_disallows |= disallows;
	return(0);
}

static int
config_requires(ConfigArgs *c) {
	slap_mask_t requires = 0;
	int i;
	slap_verbmasks requires_ops[] = {
		{ BER_BVC("bind"),		SLAP_REQUIRE_BIND },
		{ BER_BVC("LDAPv3"),		SLAP_REQUIRE_LDAP_V3 },
		{ BER_BVC("authc"),		SLAP_REQUIRE_AUTHC },
		{ BER_BVC("sasl"),		SLAP_REQUIRE_SASL },
		{ BER_BVC("strong"),		SLAP_REQUIRE_STRONG },
		{ BER_BVNULL, 0 }
	};
	if (c->op == SLAP_CONFIG_EMIT) {
		return mask_to_verbs( requires_ops, c->be->be_requires, &c->rvalue_vals );
	}
	i = verbs_to_mask(c->argc, c->argv, requires_ops, &requires);
	if ( i ) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"unknown feature %s in \"require <features>\" line\n",
			c->log, c->argv[i], 0);
		return(1);
	}
	c->be->be_requires = requires;
	return(0);
}

static int
config_loglevel(ConfigArgs *c) {
	int i;
	char *next;
	slap_verbmasks loglevel_ops[] = {
		{ BER_BVC("Trace"),	LDAP_DEBUG_TRACE },
		{ BER_BVC("Packets"),	LDAP_DEBUG_PACKETS },
		{ BER_BVC("Args"),	LDAP_DEBUG_ARGS },
		{ BER_BVC("Conns"),	LDAP_DEBUG_CONNS },
		{ BER_BVC("BER"),	LDAP_DEBUG_BER },
		{ BER_BVC("Filter"),	LDAP_DEBUG_FILTER },
		{ BER_BVC("Config"),	LDAP_DEBUG_CONFIG },
		{ BER_BVC("ACL"),	LDAP_DEBUG_ACL },
		{ BER_BVC("Stats"),	LDAP_DEBUG_STATS },
		{ BER_BVC("Stats2"),	LDAP_DEBUG_STATS2 },
		{ BER_BVC("Shell"),	LDAP_DEBUG_SHELL },
		{ BER_BVC("Parse"),	LDAP_DEBUG_PARSE },
		{ BER_BVC("Cache"),	LDAP_DEBUG_CACHE },
		{ BER_BVC("Index"),	LDAP_DEBUG_INDEX },
		{ BER_BVC("Any"),	-1 },
		{ BER_BVNULL,	0 }
	};

	if (c->op == SLAP_CONFIG_EMIT) {
		return mask_to_verbs( loglevel_ops, ldap_syslog, &c->rvalue_vals );
	}

	ldap_syslog = 0;

	for( i=1; i < c->argc; i++ ) {
		int	level;

		if ( isdigit( c->argv[i][0] ) ) {
			level = strtol( c->argv[i], &next, 10 );
			if ( next == NULL || next[0] != '\0' ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: unable to parse level \"%s\" "
					"in \"loglevel <level> [...]\" line.\n",
					c->log, c->argv[i], 0);
				return( 1 );
			}
		} else {
			int j = verb_to_mask(c->argv[i], loglevel_ops);
			if(BER_BVISNULL(&loglevel_ops[j].word)) {
				Debug( LDAP_DEBUG_ANY,
					"%s: unknown level \"%s\" "
					"in \"loglevel <level> [...]\" line.\n",
					c->log, c->argv[i], 0);
				return( 1 );
			}
			level = loglevel_ops[j].mask;
		}
		ldap_syslog |= level;
	}
	return(0);
}

static int
config_syncrepl(ConfigArgs *c) {
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( c->be->be_syncinfo ) {
			struct berval bv;
			syncrepl_unparse( c->be->be_syncinfo, &bv ); 
			ber_bvarray_add( &c->rvalue_vals, &bv );
			return 0;
		}
		return 1;
	}
	if(SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"syncrepl: database already shadowed.\n",
			c->log, 0, 0);
		return(1);
	} else if(add_syncrepl(c->be, c->argv, c->argc)) {
		return(1);
	}
	SLAP_DBFLAGS(c->be) |= (SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SYNC_SHADOW);
	return(0);
}

static int
config_referral(ConfigArgs *c) {
	struct berval vals[2];
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( default_referral ) {
			value_add( &c->rvalue_vals, default_referral );
			return 0;
		} else {
			return 1;
		}
	}
	if(validate_global_referral(c->argv[1])) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"invalid URL (%s) in \"referral\" line.\n",
			c->log, c->argv[1], 0);
		return(1);
	}

	ber_str2bv(c->argv[1], 0, 0, &vals[0]);
	vals[1].bv_val = NULL; vals[1].bv_len = 0;
	if(value_add(&default_referral, vals)) return(LDAP_OTHER);
	return(0);
}

static struct {
	struct berval key;
	int off;
} sec_keys[] = {
	{ BER_BVC("ssf="), offsetof(slap_ssf_set_t, sss_ssf) },
	{ BER_BVC("transport="), offsetof(slap_ssf_set_t, sss_transport) },
	{ BER_BVC("tls="), offsetof(slap_ssf_set_t, sss_tls) },
	{ BER_BVC("sasl="), offsetof(slap_ssf_set_t, sss_sasl) },
	{ BER_BVC("update_ssf="), offsetof(slap_ssf_set_t, sss_update_ssf) },
	{ BER_BVC("update_transport="), offsetof(slap_ssf_set_t, sss_update_transport) },
	{ BER_BVC("update_tls="), offsetof(slap_ssf_set_t, sss_update_tls) },
	{ BER_BVC("update_sasl="), offsetof(slap_ssf_set_t, sss_update_sasl) },
	{ BER_BVC("simple_bind="), offsetof(slap_ssf_set_t, sss_simple_bind) },
	{ BER_BVNULL, 0 }
};

static int
config_security(ConfigArgs *c) {
	slap_ssf_set_t *set = &c->be->be_ssf_set;
	char *next;
	int i, j;
	if (c->op == SLAP_CONFIG_EMIT) {
		char numbuf[32];
		struct berval bv;
		slap_ssf_t *tgt;
		int rc = 1;

		for (i=0; !BER_BVISNULL( &sec_keys[i].key ); i++) {
			tgt = (slap_ssf_t *)((char *)set + sec_keys[i].off);
			if ( *tgt ) {
				rc = 0;
				bv.bv_len = sprintf( numbuf, "%u", *tgt );
				bv.bv_len += sec_keys[i].key.bv_len;
				bv.bv_val = ch_malloc( bv.bv_len + 1);
				next = lutil_strcopy( bv.bv_val, sec_keys[i].key.bv_val );
				strcpy( next, numbuf );
				ber_bvarray_add( &c->rvalue_vals, &bv );
			}
		}
		return rc;
	}
	for(i = 1; i < c->argc; i++) {
		slap_ssf_t *tgt = NULL;
		char *src;
		for ( j=0; !BER_BVISNULL( &sec_keys[j].key ); j++ ) {
			if(!strncasecmp(c->argv[i], sec_keys[j].key.bv_val,
				sec_keys[j].key.bv_len)) {
				src = c->argv[i] + sec_keys[j].key.bv_len;
				tgt = (slap_ssf_t *)((char *)set + sec_keys[j].off);
				break;
			}
		}
		if ( !tgt ) {
			Debug(LDAP_DEBUG_ANY, "%s: "
				"unknown factor %s in \"security <factors>\" line\n",
				c->log, c->argv[i], 0);
			return(1);
		}

		*tgt = strtol(src, &next, 10);
		if(next == NULL || next[0] != '\0' ) {
			Debug(LDAP_DEBUG_ANY, "%s: "
				"unable to parse factor \"%s\" in \"security <factors>\" line\n",
				c->log, c->argv[i], 0);
			return(1);
		}
	}
	return(0);
}

static char *
anlist_unparse( AttributeName *an, char *ptr ) {
	int comma = 0;

	for (; !BER_BVISNULL( &an->an_name ); an++) {
		if ( comma ) *ptr++ = ',';
		ptr = lutil_strcopy( ptr, an->an_name.bv_val );
		comma = 1;
	}
	return ptr;
}

static void
replica_unparse( struct slap_replica_info *ri, int i, struct berval *bv )
{
	int len;
	char *ptr;
	struct berval bc = {0};
	char numbuf[32];

	len = sprintf(numbuf, "{%d}", i );

	len += strlen( ri->ri_uri ) + STRLENOF("uri=");
	if ( ri->ri_nsuffix ) {
		for (i=0; !BER_BVISNULL( &ri->ri_nsuffix[i] ); i++) {
			len += ri->ri_nsuffix[i].bv_len + STRLENOF(" suffix=\"\"");
		}
	}
	if ( ri->ri_attrs ) {
		len += STRLENOF("attr");
		if ( ri->ri_exclude ) len++;
		for (i=0; !BER_BVISNULL( &ri->ri_attrs[i].an_name ); i++) {
			len += 1 + ri->ri_attrs[i].an_name.bv_len;
		}
	}
	bindconf_unparse( &ri->ri_bindconf, &bc );
	len += bc.bv_len;

	bv->bv_val = ch_malloc(len + 1);
	bv->bv_len = len;

	ptr = lutil_strcopy( bv->bv_val, numbuf );
	ptr = lutil_strcopy( ptr, "uri=" );
	ptr = lutil_strcopy( ptr, ri->ri_uri );

	if ( ri->ri_nsuffix ) {
		for (i=0; !BER_BVISNULL( &ri->ri_nsuffix[i] ); i++) {
			ptr = lutil_strcopy( ptr, " suffix=\"" );
			ptr = lutil_strcopy( ptr, ri->ri_nsuffix[i].bv_val );
			*ptr++ = '"';
		}
	}
	if ( ri->ri_attrs ) {
		ptr = lutil_strcopy( ptr, "attr" );
		if ( ri->ri_exclude ) *ptr++ = '!';
		*ptr++ = '=';
		ptr = anlist_unparse( ri->ri_attrs, ptr );
	}
	if ( bc.bv_val ) {
		strcpy( ptr, bc.bv_val );
		ch_free( bc.bv_val );
	}
}

static int
config_replica(ConfigArgs *c) {
	int i, nr = -1, len;
	char *replicahost, *replicauri;
	LDAPURLDesc *ludp;

	if (c->op == SLAP_CONFIG_EMIT) {
		if (c->be->be_replica) {
			struct berval bv;
			for (i=0;c->be->be_replica[i]; i++) {
				replica_unparse( c->be->be_replica[i], i, &bv );
				ber_bvarray_add( &c->rvalue_vals, &bv );
			}
			return 0;
		}
		return 1;
	}
	if(SLAP_MONITOR(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"\"replica\" should not be used inside monitor database\n",
			c->log, 0, 0);
		return(0);	/* FIXME: should this be an error? */
	}

	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "host=", STRLENOF("host="))) {
			replicahost = c->argv[i] + STRLENOF("host=");
			len = strlen( replicahost );
			replicauri = ch_malloc( len + STRLENOF("ldap://") + 1 );
			sprintf( replicauri, "ldap://%s", replicahost );
			replicahost = replicauri + STRLENOF( "ldap://");
			nr = add_replica_info(c->be, replicauri, replicahost);
			break;
		} else if(!strncasecmp(c->argv[i], "uri=", STRLENOF("uri="))) {
			if(ldap_url_parse(c->argv[i] + STRLENOF("uri="), &ludp) != LDAP_SUCCESS) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"replica line contains invalid "
					"uri definition.\n", c->log, 0, 0);
				return(1);
			}
			if(!ludp->lud_host) {
				Debug(LDAP_DEBUG_ANY, "%s: "
					"replica line contains invalid "
					"uri definition - missing hostname.\n",
					c->log, 0, 0);
				return(1);
			}
			ldap_free_urldesc(ludp);
			replicauri = c->argv[i] + STRLENOF("uri=");
			replicauri = ch_strdup( replicauri );
			replicahost = strchr( replicauri, '/' );
			replicahost += 2;
			nr = add_replica_info(c->be, replicauri, replicahost);
			break;
		}
	}
	if(i == c->argc) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"missing host or uri in \"replica\" line\n",
			c->log, 0, 0);
		return(1);
	} else if(nr == -1) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"unable to add replica \"%s\"\n",
			c->log, replicauri, 0);
		return(1);
	} else {
		for(i = 1; i < c->argc; i++) {
			if(!strncasecmp(c->argv[i], "suffix=", STRLENOF( "suffix="))) {
				switch(add_replica_suffix(c->be, nr, c->argv[i] + STRLENOF("suffix="))) {
					case 1:
						Debug(LDAP_DEBUG_ANY, "%s: "
						"suffix \"%s\" in \"replica\" line is not valid for backend (ignored)\n",
						c->log, c->argv[i] + STRLENOF("suffix="), 0);
						break;
					case 2:
						Debug(LDAP_DEBUG_ANY, "%s: "
						"unable to normalize suffix in \"replica\" line (ignored)\n",
						c->log, 0, 0);
						break;
				}

			} else if(!strncasecmp(c->argv[i], "attr", STRLENOF("attr"))) {
				int exclude = 0;
				char *arg = c->argv[i] + STRLENOF("attr");
				if(arg[0] == '!') {
					arg++;
					exclude = 1;
				}
				if(arg[0] != '=') {
					continue;
				}
				if(add_replica_attrs(c->be, nr, arg + 1, exclude)) {
					Debug(LDAP_DEBUG_ANY, "%s: "
						"attribute \"%s\" in \"replica\" line is unknown\n",
						c->log, arg + 1, 0);
					return(1);
				}
			} else if ( bindconf_parse( c->argv[i],
					&c->be->be_replica[nr]->ri_bindconf ) ) {
				return(1);
			}
		}
	}
	return(0);
}

static int
config_updatedn(ConfigArgs *c) {
	struct berval dn;
	int rc;
	if (c->op == SLAP_CONFIG_EMIT) {
		if (!BER_BVISEMPTY(&c->be->be_update_ndn)) {
			value_add_one(&c->rvalue_vals, &c->be->be_update_ndn);
			value_add_one(&c->rvalue_nvals, &c->be->be_update_ndn);
			return 0;
		}
		return 1;
	}
	if(SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"updatedn: database already shadowed.\n",
			c->log, 0, 0);
		return(1);
	}

	ber_str2bv(c->argv[1], 0, 0, &dn);

	rc = dnNormalize(0, NULL, NULL, &dn, &c->be->be_update_ndn, NULL);

	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"updatedn DN is invalid: %d (%s)\n",
			c->log, rc, ldap_err2string( rc ));
		return(1);
	}

	SLAP_DBFLAGS(c->be) |= (SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SLURP_SHADOW);
	return(0);
}

static int
config_updateref(ConfigArgs *c) {
	struct berval vals[2];
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( c->be->be_update_refs ) {
			value_add( &c->rvalue_vals, c->be->be_update_refs );
			return 0;
		} else {
			return 1;
		}
	}
	if(!SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"updateref line must come after syncrepl or updatedn.\n",
			c->log, 0, 0);
		return(1);
	}

	if(validate_global_referral(c->argv[1])) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"invalid URL (%s) in \"updateref\" line.\n",
			c->log, c->argv[1], 0);
		return(1);
	}
	ber_str2bv(c->argv[1], 0, 0, &vals[0]);
	vals[1].bv_val = NULL;
	if(value_add(&c->be->be_update_refs, vals)) return(LDAP_OTHER);
	return(0);
}

static int
config_include(ConfigArgs *c) {
	unsigned long savelineno = c->lineno;
	int rc;
	ConfigFile *cf;
	ConfigFile *cfsave = cfn;
	ConfigFile *cf2 = NULL;
	if (c->op == SLAP_CONFIG_EMIT) {
		return 1;
	}
	cf = ch_calloc( 1, sizeof(ConfigFile));
#ifdef SLAPD_MODULES
	cf->c_modlast = &cf->c_modpaths;
#endif
	if ( cfn->c_kids ) {
		for (cf2=cfn->c_kids; cf2 && cf2->c_sibs; cf2=cf2->c_sibs) ;
		cf2->c_sibs = cf;
	} else {
		cfn->c_kids = cf;
	}
	cfn = cf;
	ber_str2bv( c->argv[1], 0, 1, &cf->c_file );
	rc = read_config_file(c->argv[1], c->depth + 1, c);
	c->lineno = savelineno - 1;
	cfn = cfsave;
	if ( rc ) {
		if ( cf2 ) cf2->c_sibs = NULL;
		else cfn->c_kids = NULL;
		ch_free( cf->c_file.bv_val );
		ch_free( cf );
	}
	return(rc);
}

#ifdef HAVE_TLS
static int
config_tls_option(ConfigArgs *c) {
	int flag;
	switch(c->type) {
	case CFG_TLS_RAND:		flag = LDAP_OPT_X_TLS_RANDOM_FILE;	break;
	case CFG_TLS_CIPHER:	flag = LDAP_OPT_X_TLS_CIPHER_SUITE;	break;
	case CFG_TLS_CERT_FILE:	flag = LDAP_OPT_X_TLS_CERTFILE;		break;	
	case CFG_TLS_CERT_KEY:	flag = LDAP_OPT_X_TLS_KEYFILE;		break;
	case CFG_TLS_CA_PATH:	flag = LDAP_OPT_X_TLS_CACERTDIR;	break;
	case CFG_TLS_CA_FILE:	flag = LDAP_OPT_X_TLS_CACERTFILE;	break;
	default:		Debug(LDAP_DEBUG_ANY, "%s: "
					"unknown tls_option <%x>\n",
					c->log, c->type, 0);
	}
	if (c->op == SLAP_CONFIG_EMIT) {
		return ldap_pvt_tls_get_option( NULL, flag, &c->value_string );
	}
	ch_free(c->value_string);
	return(ldap_pvt_tls_set_option(NULL, flag, c->argv[1]));
}

/* FIXME: this ought to be provided by libldap */
static int
config_tls_config(ConfigArgs *c) {
	int i, flag;
	slap_verbmasks crlkeys[] = {
		{ BER_BVC("none"),	LDAP_OPT_X_TLS_CRL_NONE },
		{ BER_BVC("peer"),	LDAP_OPT_X_TLS_CRL_PEER },
		{ BER_BVC("all"),	LDAP_OPT_X_TLS_CRL_ALL },
		{ BER_BVNULL, 0 }
	};
	slap_verbmasks vfykeys[] = {
		{ BER_BVC("never"),	LDAP_OPT_X_TLS_NEVER },
		{ BER_BVC("demand"),	LDAP_OPT_X_TLS_DEMAND },
		{ BER_BVC("try"),	LDAP_OPT_X_TLS_TRY },
		{ BER_BVC("hard"),	LDAP_OPT_X_TLS_HARD },
		{ BER_BVNULL, 0 }
	}, *keys;
	switch(c->type) {
#ifdef HAVE_OPENSSL_CRL
	case CFG_TLS_CRLCHECK:	flag = LDAP_OPT_X_TLS_CRLCHECK; keys = crlkeys;
		break;
#endif
	case CFG_TLS_VERIFY:	flag = LDAP_OPT_X_TLS_REQUIRE_CERT; keys = vfykeys;
		break;
	default:		Debug(LDAP_DEBUG_ANY, "%s: "
					"unknown tls_option <%x>\n",
					c->log, c->type, 0);
	}
	if (c->op == SLAP_CONFIG_EMIT) {
		ldap_pvt_tls_get_option( NULL, flag, &c->value_int );
		for (i=0; !BER_BVISNULL(&keys[i].word); i++) {
			if (keys[i].mask == c->value_int) {
				c->value_string = ch_strdup( keys[i].word.bv_val );
				return 0;
			}
		}
		return 1;
	}
	ch_free( c->value_string );
	if(isdigit((unsigned char)c->argv[1][0])) {
		i = atoi(c->argv[1]);
		return(ldap_pvt_tls_set_option(NULL, flag, &i));
	} else {
		return(ldap_int_tls_config(NULL, flag, c->argv[1]));
	}
}
#endif

static int
add_syncrepl(
	Backend *be,
	char    **cargv,
	int     cargc
)
{
	syncinfo_t *si;
	int	rc = 0;

	si = (syncinfo_t *) ch_calloc( 1, sizeof( syncinfo_t ) );

	if ( si == NULL ) {
		Debug( LDAP_DEBUG_ANY, "out of memory in add_syncrepl\n", 0, 0, 0 );
		return 1;
	}

	si->si_bindconf.sb_tls = SB_TLS_OFF;
	si->si_bindconf.sb_method = LDAP_AUTH_SIMPLE;
	si->si_schemachecking = 0;
	ber_str2bv( "(objectclass=*)", STRLENOF("(objectclass=*)"), 1,
		&si->si_filterstr );
	si->si_base.bv_val = NULL;
	si->si_scope = LDAP_SCOPE_SUBTREE;
	si->si_attrsonly = 0;
	si->si_anlist = (AttributeName *) ch_calloc( 1, sizeof( AttributeName ));
	si->si_exanlist = (AttributeName *) ch_calloc( 1, sizeof( AttributeName ));
	si->si_attrs = NULL;
	si->si_allattrs = 0;
	si->si_allopattrs = 0;
	si->si_exattrs = NULL;
	si->si_type = LDAP_SYNC_REFRESH_ONLY;
	si->si_interval = 86400;
	si->si_retryinterval = NULL;
	si->si_retrynum_init = NULL;
	si->si_retrynum = NULL;
	si->si_manageDSAit = 0;
	si->si_tlimit = 0;
	si->si_slimit = 0;

	si->si_presentlist = NULL;
	LDAP_LIST_INIT( &si->si_nonpresentlist );
	ldap_pvt_thread_mutex_init( &si->si_mutex );

	rc = parse_syncrepl_line( cargv, cargc, si );

	if ( rc < 0 ) {
		Debug( LDAP_DEBUG_ANY, "failed to add syncinfo\n", 0, 0, 0 );
		syncinfo_free( si );	
		return 1;
	} else {
		Debug( LDAP_DEBUG_CONFIG,
			"Config: ** successfully added syncrepl \"%s\"\n",
			BER_BVISNULL( &si->si_provideruri ) ?
			"(null)" : si->si_provideruri.bv_val, 0, 0 );
		if ( !si->si_schemachecking ) {
			SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NO_SCHEMA_CHECK;
		}
		si->si_be = be;
		be->be_syncinfo = si;
		return 0;
	}
}

/* NOTE: used & documented in slapd.conf(5) */
#define IDSTR			"rid"
#define PROVIDERSTR		"provider"
#define TYPESTR			"type"
#define INTERVALSTR		"interval"
#define SEARCHBASESTR		"searchbase"
#define FILTERSTR		"filter"
#define SCOPESTR		"scope"
#define ATTRSSTR		"attrs"
#define ATTRSONLYSTR		"attrsonly"
#define SLIMITSTR		"sizelimit"
#define TLIMITSTR		"timelimit"
#define SCHEMASTR		"schemachecking"

/* FIXME: undocumented */
#define OLDAUTHCSTR		"bindprincipal"
#define EXATTRSSTR		"exattrs"
#define RETRYSTR		"retry"

/* FIXME: unused */
#define LASTMODSTR		"lastmod"
#define LMGENSTR		"gen"
#define LMNOSTR			"no"
#define LMREQSTR		"req"
#define SRVTABSTR		"srvtab"
#define SUFFIXSTR		"suffix"
#define MANAGEDSAITSTR		"manageDSAit"

/* mandatory */
#define GOT_ID			0x0001
#define GOT_PROVIDER		0x0002

/* check */
#define GOT_ALL			(GOT_ID|GOT_PROVIDER)

static struct {
	struct berval key;
	int val;
} scopes[] = {
	{ BER_BVC("base"), LDAP_SCOPE_BASE },
	{ BER_BVC("one"), LDAP_SCOPE_ONELEVEL },
#ifdef LDAP_SCOPE_SUBORDINATE
	{ BER_BVC("children"), LDAP_SCOPE_SUBORDINATE },
	{ BER_BVC("subordinate"), 0 },
#endif
	{ BER_BVC("sub"), LDAP_SCOPE_SUBTREE },
	{ BER_BVNULL, 0 }
};

static int
parse_syncrepl_line(
	char		**cargv,
	int		cargc,
	syncinfo_t	*si
)
{
	int	gots = 0;
	int	i;
	char	*val;

	for ( i = 1; i < cargc; i++ ) {
		if ( !strncasecmp( cargv[ i ], IDSTR "=",
					STRLENOF( IDSTR "=" ) ) )
		{
			int tmp;
			/* '\0' string terminator accounts for '=' */
			val = cargv[ i ] + STRLENOF( IDSTR "=" );
			tmp= atoi( val );
			if ( tmp >= 1000 || tmp < 0 ) {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					 "syncrepl id %d is out of range [0..999]\n", tmp );
				return -1;
			}
			si->si_rid = tmp;
			gots |= GOT_ID;
		} else if ( !strncasecmp( cargv[ i ], PROVIDERSTR "=",
					STRLENOF( PROVIDERSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( PROVIDERSTR "=" );
			ber_str2bv( val, 0, 1, &si->si_provideruri );
			gots |= GOT_PROVIDER;
		} else if ( !strncasecmp( cargv[ i ], SCHEMASTR "=",
					STRLENOF( SCHEMASTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( SCHEMASTR "=" );
			if ( !strncasecmp( val, "on", STRLENOF( "on" ) )) {
				si->si_schemachecking = 1;
			} else if ( !strncasecmp( val, "off", STRLENOF( "off" ) ) ) {
				si->si_schemachecking = 0;
			} else {
				si->si_schemachecking = 1;
			}
		} else if ( !strncasecmp( cargv[ i ], FILTERSTR "=",
					STRLENOF( FILTERSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( FILTERSTR "=" );
			ber_str2bv( val, 0, 1, &si->si_filterstr );
		} else if ( !strncasecmp( cargv[ i ], SEARCHBASESTR "=",
					STRLENOF( SEARCHBASESTR "=" ) ) )
		{
			struct berval	bv;
			int		rc;

			val = cargv[ i ] + STRLENOF( SEARCHBASESTR "=" );
			if ( si->si_base.bv_val ) {
				ch_free( si->si_base.bv_val );
			}
			ber_str2bv( val, 0, 0, &bv );
			rc = dnNormalize( 0, NULL, NULL, &bv, &si->si_base, NULL );
			if ( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "Invalid base DN \"%s\": %d (%s)\n",
					val, rc, ldap_err2string( rc ) );
				return -1;
			}
		} else if ( !strncasecmp( cargv[ i ], SCOPESTR "=",
					STRLENOF( SCOPESTR "=" ) ) )
		{
			int j;
			val = cargv[ i ] + STRLENOF( SCOPESTR "=" );
			for ( j=0; !BER_BVISNULL(&scopes[j].key); j++ ) {
				if (!strncasecmp( val, scopes[j].key.bv_val,
					scopes[j].key.bv_len )) {
					while (!scopes[j].val) j--;
					si->si_scope = scopes[j].val;
					break;
				}
			}
			if ( BER_BVISNULL(&scopes[j].key) ) {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"unknown scope \"%s\"\n", val);
				return -1;
			}
		} else if ( !strncasecmp( cargv[ i ], ATTRSONLYSTR "=",
					STRLENOF( ATTRSONLYSTR "=" ) ) )
		{
			si->si_attrsonly = 1;
		} else if ( !strncasecmp( cargv[ i ], ATTRSSTR "=",
					STRLENOF( ATTRSSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( ATTRSSTR "=" );
			if ( !strncasecmp( val, ":include:", STRLENOF(":include:") ) ) {
				char *attr_fname;
				attr_fname = ch_strdup( val + STRLENOF(":include:") );
				si->si_anlist = file2anlist( si->si_anlist, attr_fname, " ,\t" );
				if ( si->si_anlist == NULL ) {
					ch_free( attr_fname );
					return -1;
				}
				si->si_anfile = attr_fname;
			} else {
				char *str, *s, *next;
				char delimstr[] = " ,\t";
				str = ch_strdup( val );
				for ( s = ldap_pvt_strtok( str, delimstr, &next );
						s != NULL;
						s = ldap_pvt_strtok( NULL, delimstr, &next ) )
				{
					if ( strlen(s) == 1 && *s == '*' ) {
						si->si_allattrs = 1;
						*(val + ( s - str )) = delimstr[0];
					}
					if ( strlen(s) == 1 && *s == '+' ) {
						si->si_allopattrs = 1;
						*(val + ( s - str )) = delimstr[0];
					}
				}
				ch_free( str );
				si->si_anlist = str2anlist( si->si_anlist, val, " ,\t" );
				if ( si->si_anlist == NULL ) {
					return -1;
				}
			}
		} else if ( !strncasecmp( cargv[ i ], EXATTRSSTR "=",
					STRLENOF( EXATTRSSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( EXATTRSSTR "=" );
			if ( !strncasecmp( val, ":include:", STRLENOF(":include:") )) {
				char *attr_fname;
				attr_fname = ch_strdup( val + STRLENOF(":include:") );
				si->si_exanlist = file2anlist(
									si->si_exanlist, attr_fname, " ,\t" );
				if ( si->si_exanlist == NULL ) {
					ch_free( attr_fname );
					return -1;
				}
				ch_free( attr_fname );
			} else {
				si->si_exanlist = str2anlist( si->si_exanlist, val, " ,\t" );
				if ( si->si_exanlist == NULL ) {
					return -1;
				}
			}
		} else if ( !strncasecmp( cargv[ i ], TYPESTR "=",
					STRLENOF( TYPESTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( TYPESTR "=" );
			if ( !strncasecmp( val, "refreshOnly",
						STRLENOF("refreshOnly") ))
			{
				si->si_type = LDAP_SYNC_REFRESH_ONLY;
			} else if ( !strncasecmp( val, "refreshAndPersist",
						STRLENOF("refreshAndPersist") ))
			{
				si->si_type = LDAP_SYNC_REFRESH_AND_PERSIST;
				si->si_interval = 60;
			} else {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"unknown sync type \"%s\"\n", val);
				return -1;
			}
		} else if ( !strncasecmp( cargv[ i ], INTERVALSTR "=",
					STRLENOF( INTERVALSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( INTERVALSTR "=" );
			if ( si->si_type == LDAP_SYNC_REFRESH_AND_PERSIST ) {
				si->si_interval = 0;
			} else {
				char *hstr;
				char *mstr;
				char *dstr;
				char *sstr;
				int dd, hh, mm, ss;
				dstr = val;
				hstr = strchr( dstr, ':' );
				if ( hstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return -1;
				}
				*hstr++ = '\0';
				mstr = strchr( hstr, ':' );
				if ( mstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return -1;
				}
				*mstr++ = '\0';
				sstr = strchr( mstr, ':' );
				if ( sstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return -1;
				}
				*sstr++ = '\0';

				dd = atoi( dstr );
				hh = atoi( hstr );
				mm = atoi( mstr );
				ss = atoi( sstr );
				if (( hh > 24 ) || ( hh < 0 ) ||
					( mm > 60 ) || ( mm < 0 ) ||
					( ss > 60 ) || ( ss < 0 ) || ( dd < 0 )) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return -1;
				}
				si->si_interval = (( dd * 24 + hh ) * 60 + mm ) * 60 + ss;
			}
			if ( si->si_interval < 0 ) {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"invalid interval \"%ld\"\n",
					(long) si->si_interval);
				return -1;
			}
		} else if ( !strncasecmp( cargv[ i ], RETRYSTR "=",
					STRLENOF( RETRYSTR "=" ) ) )
		{
			char **retry_list;
			int j, k, n;

			val = cargv[ i ] + STRLENOF( RETRYSTR "=" );
			retry_list = (char **) ch_calloc( 1, sizeof( char * ));
			retry_list[0] = NULL;

			slap_str2clist( &retry_list, val, " ,\t" );

			for ( k = 0; retry_list && retry_list[k]; k++ ) ;
			n = k / 2;
			if ( k % 2 ) {
				fprintf( stderr,
						"Error: incomplete syncrepl retry list\n" );
				for ( k = 0; retry_list && retry_list[k]; k++ ) {
					ch_free( retry_list[k] );
				}
				ch_free( retry_list );
				exit( EXIT_FAILURE );
			}
			si->si_retryinterval = (time_t *) ch_calloc( n + 1, sizeof( time_t ));
			si->si_retrynum = (int *) ch_calloc( n + 1, sizeof( int ));
			si->si_retrynum_init = (int *) ch_calloc( n + 1, sizeof( int ));
			for ( j = 0; j < n; j++ ) {
				si->si_retryinterval[j] = atoi( retry_list[j*2] );
				if ( *retry_list[j*2+1] == '+' ) {
					si->si_retrynum_init[j] = -1;
					si->si_retrynum[j] = -1;
					j++;
					break;
				} else {
					si->si_retrynum_init[j] = atoi( retry_list[j*2+1] );
					si->si_retrynum[j] = atoi( retry_list[j*2+1] );
				}
			}
			si->si_retrynum_init[j] = -2;
			si->si_retrynum[j] = -2;
			si->si_retryinterval[j] = 0;
			
			for ( k = 0; retry_list && retry_list[k]; k++ ) {
				ch_free( retry_list[k] );
			}
			ch_free( retry_list );
		} else if ( !strncasecmp( cargv[ i ], MANAGEDSAITSTR "=",
					STRLENOF( MANAGEDSAITSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( MANAGEDSAITSTR "=" );
			si->si_manageDSAit = atoi( val );
		} else if ( !strncasecmp( cargv[ i ], SLIMITSTR "=",
					STRLENOF( SLIMITSTR "=") ) )
		{
			val = cargv[ i ] + STRLENOF( SLIMITSTR "=" );
			si->si_slimit = atoi( val );
		} else if ( !strncasecmp( cargv[ i ], TLIMITSTR "=",
					STRLENOF( TLIMITSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( TLIMITSTR "=" );
			si->si_tlimit = atoi( val );
		} else if ( bindconf_parse( cargv[i], &si->si_bindconf )) {
			fprintf( stderr, "Error: parse_syncrepl_line: "
				"unknown keyword \"%s\"\n", cargv[ i ] );
			return -1;
		}
	}

	if ( gots != GOT_ALL ) {
		fprintf( stderr,
			"Error: Malformed \"syncrepl\" line in slapd config file" );
		return -1;
	}

	return 0;
}

static void
syncrepl_unparse( syncinfo_t *si, struct berval *bv )
{
	struct berval bc;
	char buf[BUFSIZ*2], *ptr;
	int i, len;

	bindconf_unparse( &si->si_bindconf, &bc );
	ptr = buf;
	ptr += sprintf( ptr, IDSTR "=%03d " PROVIDERSTR "=%s",
		si->si_rid, si->si_provideruri.bv_val );
	if ( !BER_BVISNULL( &bc )) {
		ptr = lutil_strcopy( ptr, bc.bv_val );
		free( bc.bv_val );
	}
	if ( !BER_BVISEMPTY( &si->si_filterstr )) {
		ptr = lutil_strcopy( ptr, " " FILTERSTR "=\"" );
		ptr = lutil_strcopy( ptr, si->si_filterstr.bv_val );
		*ptr++ = '"';
	}
	if ( !BER_BVISNULL( &si->si_base )) {
		ptr = lutil_strcopy( ptr, " " SEARCHBASESTR "=\"" );
		ptr = lutil_strcopy( ptr, si->si_base.bv_val );
		*ptr++ = '"';
	}
	for (i=0; !BER_BVISNULL(&scopes[i].key);i++) {
		if ( si->si_scope == scopes[i].val ) {
			ptr = lutil_strcopy( ptr, " " SCOPESTR "=" );
			ptr = lutil_strcopy( ptr, scopes[i].key.bv_val );
			break;
		}
	}
	if ( si->si_attrsonly ) {
		ptr = lutil_strcopy( ptr, " " ATTRSONLYSTR "=yes" );
	}
	if ( si->si_anfile ) {
		ptr = lutil_strcopy( ptr, " " ATTRSSTR "=:include:" );
		ptr = lutil_strcopy( ptr, si->si_anfile );
	} else if ( si->si_allattrs || si->si_allopattrs ||
		( si->si_anlist && !BER_BVISNULL(&si->si_anlist[0].an_name) )) {
		char *old;
		ptr = lutil_strcopy( ptr, " " ATTRSSTR "=\"" );
		old = ptr;
		ptr = anlist_unparse( si->si_anlist, ptr );
		if ( si->si_allattrs ) {
			if ( old != ptr ) *ptr++ = ',';
			*ptr++ = '*';
		}
		if ( si->si_allopattrs ) {
			if ( old != ptr ) *ptr++ = ',';
			*ptr++ = '+';
		}
		*ptr++ = '"';
	}
	if ( si->si_exanlist && !BER_BVISNULL(&si->si_exanlist[0].an_name) ) {
		ptr = lutil_strcopy( ptr, " " EXATTRSSTR "=" );
		ptr = anlist_unparse( si->si_exanlist, ptr );
	}
	ptr = lutil_strcopy( ptr, " " SCHEMASTR "=" );
	ptr = lutil_strcopy( ptr, si->si_schemachecking ? "on" : "off" );
	
	ptr = lutil_strcopy( ptr, " " TYPESTR "=" );
	ptr = lutil_strcopy( ptr, si->si_type == LDAP_SYNC_REFRESH_AND_PERSIST ?
		"refreshAndPersist" : "refreshOnly" );

	if ( si->si_type == LDAP_SYNC_REFRESH_ONLY ) {
		int dd, hh, mm, ss;

		dd = si->si_interval;
		ss = dd % 60;
		dd /= 60;
		mm = dd % 60;
		dd /= 60;
		hh = dd % 24;
		dd /= 24;
		ptr = lutil_strcopy( ptr, " " INTERVALSTR "=" );
		ptr += sprintf( ptr, "%02d:%02d:%02d:%02d", dd, hh, mm, ss );
	} else if ( si->si_retryinterval ) {
		int space=0;
		ptr = lutil_strcopy( ptr, " " RETRYSTR "=\"" );
		for (i=0; si->si_retryinterval[i]; i++) {
			if ( space ) *ptr++ = ' ';
			space = 1;
			ptr += sprintf( ptr, "%d", si->si_retryinterval[i] );
			if ( si->si_retrynum_init[i] == -1 )
				*ptr++ = '+';
			else
				ptr += sprintf( ptr, "%d", si->si_retrynum_init );
		}
		*ptr++ = '"';
	}

#if 0 /* FIXME: unused in syncrepl.c, should remove it */
	ptr = lutil_strcopy( ptr, " " MANAGEDSAITSTR "=" );
	ptr += sprintf( ptr, "%d", si->si_manageDSAit );
#endif

	if ( si->si_slimit ) {
		ptr = lutil_strcopy( ptr, " " SLIMITSTR "=" );
		ptr += sprintf( ptr, "%d", si->si_slimit );
	}

	if ( si->si_tlimit ) {
		ptr = lutil_strcopy( ptr, " " TLIMITSTR "=" );
		ptr += sprintf( ptr, "%d", si->si_tlimit );
	}
	bc.bv_len = ptr - buf;
	bc.bv_val = buf;
	ber_dupbv( bv, &bc );
}

static CfEntryInfo *
config_find_base( CfEntryInfo *root, struct berval *dn, CfEntryInfo **last )
{
	struct berval cdn;
	char *c;

	if ( !root ) {
		*last = NULL;
		return NULL;
	}

	if ( dn_match( &root->ce_entry->e_nname, dn ))
		return root;

	c = dn->bv_val+dn->bv_len;
	for (;*c != ',';c--);

	while(root) {
		*last = root;
		for (--c;c>dn->bv_val && *c != ',';c--);
		if ( *c == ',' )
			c++;
		cdn.bv_val = c;
		cdn.bv_len = dn->bv_len - (c-dn->bv_val);

		root = root->ce_kids;

		for (;root;root=root->ce_sibs) {
			if ( dn_match( &root->ce_entry->e_nname, &cdn )) {
				if ( cdn.bv_val == dn->bv_val ) {
					return root;
				}
				break;
			}
		}
	}
	return root;
}

static int
config_ldif_resp( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		CfBackInfo *cfb = op->o_callback->sc_private;

		cfb->cb_got_ldif = 1;
		rs->sr_err = config_add_internal( cfb, rs->sr_entry, NULL );
	}
	return rs->sr_err;
}

/* Configure and read the underlying back-ldif store */
static int
config_setup_ldif( BackendDB *be, const char *dir ) {
	CfBackInfo *cfb = be->be_private;
	ConfigArgs c = {0};
	ConfigTable *ct;
	char *argv[3];
	int rc;
	slap_callback cb = { NULL, config_ldif_resp, NULL, NULL };
	Connection conn = {0};
	char opbuf[OPERATION_BUFFER_SIZE];
	Operation *op;
	SlapReply rs = {REP_RESULT};
	Filter filter = { LDAP_FILTER_PRESENT };
	struct berval filterstr = BER_BVC("(objectclass=*)");

	cfb->cb_db.bd_info = backend_info( "ldif" );
	if ( !cfb->cb_db.bd_info )
		return 0;	/* FIXME: eventually this will be a fatal error */

	if ( cfb->cb_db.bd_info->bi_db_init( &cfb->cb_db )) return 1;

	/* Mark that back-ldif type is in use */
	cfb->cb_db.bd_info->bi_nDB++;

	cfb->cb_db.be_suffix = be->be_suffix;
	cfb->cb_db.be_nsuffix = be->be_nsuffix;
	cfb->cb_db.be_rootdn = be->be_rootdn;
	cfb->cb_db.be_rootndn = be->be_rootndn;

	ber_str2bv( dir, 0, 1, &cfdir );

	c.be = &cfb->cb_db;
	c.fname = "slapd";
	c.argc = 2;
	argv[0] = "directory";
	argv[1] = (char *)dir;
	argv[2] = NULL;
	c.argv = argv;

	ct = config_find_keyword( c.be->be_cf_table, &c );
	if ( !ct )
		return 1;

	if ( config_add_vals( ct, &c ))
		return 1;

	if ( backend_startup_one( &cfb->cb_db ))
		return 1;

	op = (Operation *)opbuf;
	connection_fake_init( &conn, op, cfb );

	filter.f_desc = slap_schema.si_ad_objectClass;
	
	op->o_tag = LDAP_REQ_SEARCH;

	op->ors_filter = &filter;
	op->ors_filterstr = filterstr;
	op->ors_scope = LDAP_SCOPE_SUBTREE;

	op->o_dn = be->be_rootdn;
	op->o_ndn = be->be_rootndn;

	op->o_req_dn = be->be_suffix[0];
	op->o_req_ndn = be->be_nsuffix[0];

	op->ors_tlimit = SLAP_NO_LIMIT;
	op->ors_slimit = SLAP_NO_LIMIT;

	op->ors_attrs = slap_anlist_all_attributes;
	op->ors_attrsonly = 0;

	op->o_callback = &cb;
	cb.sc_private = cfb;

	op->o_bd = &cfb->cb_db;
	op->o_bd->be_search( op, &rs );
	
	return 0;
}

static int
CfOcInfo_cmp( const void *c1, const void *c2 ) {
	const CfOcInfo *co1 = c1;
	const CfOcInfo *co2 = c2;

	return ber_bvcmp( co1->co_name, co2->co_name );
}

int
config_register_schema(ConfigTable *ct, ConfigOCs *ocs) {
	int i;
	CfOcInfo *co;

	i = init_config_attrs( ct );
	if ( i ) return i;

	/* set up the objectclasses */
	i = init_config_ocs( ocs );
	if ( i ) return i;

	for (i=0; ocs[i].def; i++) {
		if ( ocs[i].oc ) {
			co = ch_malloc( sizeof(CfOcInfo) );
			co->co_name = &(*ocs[i].oc)->soc_cname;
			co->co_table = ct;
			co->co_type = ocs[i].cft;
			avl_insert( &CfOcTree, co, CfOcInfo_cmp, avl_dup_error );
		}
	}
	return 0;
}

int
read_config(const char *fname, const char *dir) {
	BackendDB *be;
	CfBackInfo *cfb;

	/* Setup the config backend */
	be = backend_db_init( "config" );
	if ( !be )
		return 1;

	/* Setup the underlying back-ldif backend */
	if ( config_setup_ldif( be, dir ))
		return 1;

#if 0	/* not yet
	/* If we read the config from back-ldif, nothing to do here */
	cfb = be->be_private;
	if ( cfb->cb_got_ldif )
		return 0;
#endif
	ber_str2bv( fname, 0, 1, &cf_prv.c_file );

	return read_config_file(fname, 0, NULL);
}

static int
config_back_bind( Operation *op, SlapReply *rs )
{
	if ( op->orb_method == LDAP_AUTH_SIMPLE && be_isroot_pw( op )) {
		ber_dupbv( &op->orb_edn, be_root_dn( op->o_bd ));
		/* frontend sends result */
		return LDAP_SUCCESS;
	}

	rs->sr_err = LDAP_INVALID_CREDENTIALS;
	send_ldap_result( op, rs );

	return rs->sr_err;
}

static int
config_send( Operation *op, SlapReply *rs, CfEntryInfo *ce, int depth )
{
	int rc = 0;

	if ( test_filter( op, ce->ce_entry, op->ors_filter ) == LDAP_COMPARE_TRUE )
	{
		rs->sr_attrs = op->ors_attrs;
		rs->sr_entry = ce->ce_entry;
		rc = send_search_entry( op, rs );
	}
	if ( op->ors_scope == LDAP_SCOPE_SUBTREE ) {
		if ( ce->ce_kids ) {
			rc = config_send( op, rs, ce->ce_kids, 1 );
			if ( rc ) return rc;
		}
		if ( depth ) {
			for (ce=ce->ce_sibs; ce; ce=ce->ce_sibs) {
				rc = config_send( op, rs, ce, 0 );
				if ( rc ) break;
			}
		}
	}
	return rc;
}

static ConfigTable *
config_find_table( CfOcInfo *co, AttributeDescription *ad )
{
	int i;

	for (i=0; co->co_table[i].name; i++)
		if ( co->co_table[i].ad == ad )
			return &co->co_table[i];
	return NULL;
}

/* Sort the values in an X-ORDERED attribute.
 * If the values have no index, leave them in their given order.
 * If the values have indexes, sort them and then strip the index.
 * If some are indexed and some are not, return Error.
 *
 * FIXME: This function probably belongs in the frontend somewhere,
 * like slap_mods_check.
 */
static int
sort_vals( Attribute *a )
{
	int i;
	int index = 0, noindex = 0;

	/* count attrs, look for index */
	for (i=0; a->a_vals[i].bv_val; i++) {
		if ( a->a_vals[i].bv_val[0] == '{' ) {
			char *ptr;
			index = 1;
			ptr = strchr( a->a_vals[i].bv_val, '}' );
			if ( !ptr || !ptr[1] )
				return LDAP_INVALID_SYNTAX;
			if ( noindex )
				return LDAP_INVALID_SYNTAX;
		} else {
			noindex = 1;
			if ( index )
				return LDAP_INVALID_SYNTAX;
		}
	}

	if ( index ) {
		int vals = i, *indexes, j, idx;
		struct berval tmp, ntmp;
		char *ptr;

		/* Strip index from normalized values */
		if ( !a->a_nvals || a->a_vals == a->a_nvals ) {
			a->a_nvals = ch_malloc( (vals+1)*sizeof(struct berval));
			for ( i=0; i<vals; i++ ) {
				ptr = strchr(a->a_vals[i].bv_val, '}') + 1;
				a->a_nvals[i].bv_len = a->a_vals[i].bv_len -
					(ptr - a->a_vals[i].bv_val);
				a->a_nvals[i].bv_val = ch_malloc( a->a_nvals[i].bv_len + 1);
				strcpy(a->a_nvals[i].bv_val, ptr );
			}
		} else {
			for ( i=0; i<vals; i++ ) {
				ptr = strchr(a->a_nvals[i].bv_val, '}') + 1;
				a->a_nvals[i].bv_len -= ptr - a->a_nvals[i].bv_val;
				strcpy(a->a_nvals[i].bv_val, ptr);
			}
		}
				
		indexes = ch_malloc( vals * sizeof(int) );
		for ( i=0; i<vals; i++)
			indexes[i] = atoi(a->a_vals[i].bv_val+1);

		/* Insertion sort */
		for ( i=1; i<vals; i++ ) {
			idx = indexes[i];
			tmp = a->a_vals[i];
			ntmp = a->a_nvals[i];
			j = i;
			while ((j > 0) && (indexes[j-1] > idx)) {
				indexes[j] = indexes[j-1];
				a->a_vals[j] = a->a_vals[j-1];
				a->a_nvals[j] = a->a_nvals[j-1];
				j--;
			}
			indexes[j] = idx;
			a->a_vals[j] = tmp;
			a->a_nvals[j] = ntmp;
		}
	}
	return 0;
}

static int
check_attr( ConfigTable *ct, ConfigArgs *ca, Attribute *a )
{
	int i, rc = 0;

	if ( a->a_desc->ad_type->sat_flags & SLAP_AT_ORDERED ) {
		rc = sort_vals( a );
		if ( rc )
			return rc;
	}
	for ( i=0; a->a_nvals[i].bv_val; i++ ) {
		ca->line = a->a_nvals[i].bv_val;
		rc = config_parse_vals( ct, ca, i );
		if ( rc )
			break;
	}
	return rc;
}

/* Parse an LDAP entry into config directives */
static int
config_add_internal( CfBackInfo *cfb, Entry *e, SlapReply *rs )
{
	CfEntryInfo *ce, *last;
	CfOcInfo co, *coptr, **colst = NULL;
	Attribute *a, *oc_at, *type_attr;
	AttributeDescription *type_ad = NULL;
	int i, j, nocs, rc;
	ConfigArgs ca = {0};
	struct berval pdn;
	Entry *xe = NULL;
	ConfigTable *ct, *type_ct = NULL;

	/* Make sure parent exists and entry does not */
	ce = config_find_base( cfb->cb_root, &e->e_nname, &last );
	if ( ce )
		return LDAP_ALREADY_EXISTS;

	dnParent( &e->e_nname, &pdn );

	/* If last is NULL, the new entry is the root/suffix entry, 
	 * otherwise last should be the parent.
	 */
	if ( last && !dn_match( &last->ce_entry->e_nname, &pdn )) {
		if ( rs )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		return LDAP_NO_SUCH_OBJECT;
	}

	oc_at = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	if ( !oc_at ) return LDAP_OBJECT_CLASS_VIOLATION;

	/* count the objectclasses */
	for ( i=0; oc_at->a_nvals[i].bv_val; i++ );
	nocs = i;
	colst = (CfOcInfo **)ch_malloc( nocs * sizeof(CfOcInfo *));

	for ( i=0, j=0; i<nocs; i++) {
		co.co_name = &oc_at->a_nvals[i];
		coptr = avl_find( CfOcTree, &co, CfOcInfo_cmp );
		
		/* ignore non-config objectclasses. probably should be
		 * an error, general data doesn't belong here.
		 */
		if ( !coptr ) continue;

		/* Ignore the root objectclass, it has no implementation.
		 */
		if ( coptr->co_type == Cft_Abstract ) continue;
		colst[j++] = coptr;
	}
	nocs = j;

	/* Only the root can be Cft_Global, everything else must
	 * have a parent. Only limited nesting arrangements are allowed.
	 */
	switch( colst[0]->co_type ) {
	case Cft_Global:
		if ( last )  {
			rc = LDAP_CONSTRAINT_VIOLATION;
			goto leave;
		}
		break;
	case Cft_Schema:
	case Cft_Backend:
	case Cft_Database:
	case Cft_Include:
		if ( !last || ( last->ce_type != Cft_Global &&
			last->ce_type != colst[0]->co_type )) {
			rc = LDAP_CONSTRAINT_VIOLATION;
			goto leave;
		}
		break;
	case Cft_Overlay:
		if ( !last || ( last->ce_type != Cft_Global &&
			last->ce_type != Cft_Database &&
			last->ce_type != colst[0]->co_type )) {
			rc = LDAP_CONSTRAINT_VIOLATION;
			goto leave;
		}
		break;
	}

	/* Parse all the values and check for simple syntax errors before
	 * performing any set actions.
	 */
	switch (colst[0]->co_type) {
	case Cft_Global:	/* */
	case Cft_Schema:
		ca.be = cfb->cb_be;
		break;
	case Cft_Backend:
		if ( last->ce_type == Cft_Backend )
			ca.bi = last->ce_bi;
		else
			type_ad = cfAd_backend;
		break;
	case Cft_Database:
		if ( last->ce_type == Cft_Database ) {
			ca.be = last->ce_be;
		} else {
			type_ad = cfAd_database;
			/* dummy, just to get past check_attr */
			ca.be = frontendDB;
		}
		break;

	case Cft_Overlay:
		ca.be = last->ce_be;
		type_ad = cfAd_overlay;

	case Cft_Include:
		if ( !rs )	/* ignored */
			break;
		type_ad = cfAd_include;
	}
	init_config_argv( &ca );
	if ( type_ad ) {
		type_attr = attr_find( e->e_attrs, type_ad );
		if ( !type_attr ) {
			rc = LDAP_OBJECT_CLASS_VIOLATION;
			goto leave;
		}
		for ( i=0; i<nocs; i++ ) {
			type_ct = config_find_table( colst[i], type_ad );
			if ( type_ct ) break;
		}
		if ( !type_ct ) {
			rc = LDAP_OBJECT_CLASS_VIOLATION;
			goto leave;
		}
		rc = check_attr( type_ct, &ca, type_attr );
		if ( rc ) goto leave;
	}
	for ( a=e->e_attrs; a; a=a->a_next ) {
		if ( a == type_attr || a == oc_at ) continue;
		ct = NULL;
		for ( i=0; i<nocs; i++ ) {
			ct = config_find_table( colst[i], a->a_desc );
			if ( ct ) break;
		}
		if ( !ct ) continue;	/* user data? */
		rc = check_attr( ct, &ca, a );
		if ( rc ) goto leave;
	}

	/* Basic syntax checks are OK. Do the actual settings. */
	if ( type_ct ) {
		ca.line = type_attr->a_nvals[0].bv_val;
		rc = config_parse_add( type_ct, &ca, 0 );
		if ( rc ) goto leave;
	}
	for ( a=e->e_attrs; a; a=a->a_next ) {
		if ( a == type_attr || a == oc_at ) continue;
		ct = NULL;
		for ( i=0; i<nocs; i++ ) {
			ct = config_find_table( colst[i], a->a_desc );
			if ( ct ) break;
		}
		if ( !ct ) continue;	/* user data? */
		for (i=0; a->a_nvals[i].bv_val; i++) {
			ca.line = a->a_nvals[i].bv_val;
			rc = config_parse_add( ct, &ca, i );
			if ( rc ) goto leave;
		}
	}
	ce = ch_calloc( 1, sizeof(CfEntryInfo) );
	ce->ce_entry = entry_dup( e );
	ce->ce_entry->e_private = ce;
	ce->ce_type = colst[0]->co_type;
	if ( !last ) {
		cfb->cb_root = ce;
	} else if ( last->ce_kids ) {
		CfEntryInfo *c2;

		for (c2=last->ce_kids; c2 && c2->ce_sibs; c2 = c2->ce_sibs);
		c2->ce_sibs = ce;
	} else {
		last->ce_kids = ce;
	}

leave:
	ch_free( ca.argv );
	if ( colst ) ch_free( colst );
	return rc;
}

/* Parse an LDAP entry into config directives, then store in underlying
 * database.
 */
static int
config_back_add( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ldap_pvt_thread_pool_pause( &connection_pool );

	/* Strategy:
	 * 1) check for existence of entry
	 * 2) perform internal add
	 * 3) store entry in underlying database
	 */

	ldap_pvt_thread_pool_resume( &connection_pool );

out:
	send_ldap_result( op, rs );
	return rs->sr_err;
}

static int
config_back_modify( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ce = config_find_base( cfb->cb_root, &op->o_req_ndn, &last );
	if ( !ce ) {
		if ( last )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto out;
	}
	ldap_pvt_thread_pool_pause( &connection_pool );

	/* Strategy:
	 * 1) perform the Modify on the cached Entry.
	 * 2) verify that the Entry still satisfies the schema.
	 * 3) perform the individual config operations.
	 * 4) store Modified entry in underlying LDIF backend.
	 */
	ldap_pvt_thread_pool_resume( &connection_pool );
out:
	send_ldap_result( op, rs );
	return rs->sr_err;
}

static int
config_back_search( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;
	int rc;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ce = config_find_base( cfb->cb_root, &op->o_req_ndn, &last );
	if ( !ce ) {
		if ( last )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto out;
	}
	switch ( op->ors_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_SCOPE_SUBTREE:
		config_send( op, rs, ce, 0 );
		break;
		
	case LDAP_SCOPE_ONELEVEL:
		for (ce = ce->ce_kids; ce; ce=ce->ce_sibs) {
			config_send( op, rs, ce, 1 );
		}
		break;
	}
		
	rs->sr_err = LDAP_SUCCESS;
out:
	send_ldap_result( op, rs );
	return 0;
}

static Entry *
config_alloc_entry( struct berval *pdn, struct berval *rdn )
{
	Entry *e = ch_calloc( 1, sizeof(Entry) );
	CfEntryInfo *ce = ch_calloc( 1, sizeof(CfEntryInfo) );
	e->e_private = ce;
	ce->ce_entry = e;
	build_new_dn( &e->e_name, pdn, rdn, NULL );
	ber_dupbv( &e->e_nname, &e->e_name );
	return e;
}

#define	NO_TABLE	0
#define	BI_TABLE	1
#define	BE_TABLE	2

static int
config_build_entry( ConfigArgs *c, Entry *e, ObjectClass *oc,
	 struct berval *rdn, ConfigTable *ct, int table )
{
	struct berval vals[2];
	struct berval ad_name;
	AttributeDescription *ad = NULL;
	int rc, i;
	char *ptr;
	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof(textbuf);
	AttributeType **at;
	Attribute *oc_at;

	BER_BVZERO( &vals[1] );

	vals[0] = oc->soc_cname;
	attr_merge(e, slap_schema.si_ad_objectClass, vals, NULL );
	ptr = strchr(rdn->bv_val, '=');
	ad_name.bv_val = rdn->bv_val;
	ad_name.bv_len = ptr - rdn->bv_val;
	rc = slap_bv2ad( &ad_name, &ad, &text );
	if ( rc ) {
		return rc;
	}
	vals[0].bv_val = ptr+1;
	vals[0].bv_len = rdn->bv_len - (vals[0].bv_val - rdn->bv_val);
	attr_merge(e, ad, vals, NULL );

	for (at=oc->soc_required; at && *at; at++) {
		/* Skip the naming attr */
		if ((*at)->sat_ad == ad || (*at)->sat_ad == slap_schema.si_ad_cn )
			continue;
		for (i=0;ct[i].name;i++) {
			if (ct[i].ad == (*at)->sat_ad) {
				rc = config_get_vals(&ct[i], c);
				if (rc == LDAP_SUCCESS) {
					attr_merge(e, ct[i].ad, c->rvalue_vals, c->rvalue_nvals);
					ber_bvarray_free( c->rvalue_nvals );
					ber_bvarray_free( c->rvalue_vals );
				}
				break;
			}
		}
	}

	for (at=oc->soc_allowed; at && *at; at++) {
		/* Skip the naming attr */
		if ((*at)->sat_ad == ad || (*at)->sat_ad == slap_schema.si_ad_cn )
			continue;
		for (i=0;ct[i].name;i++) {
			if (ct[i].ad == (*at)->sat_ad) {
				rc = config_get_vals(&ct[i], c);
				if (rc == LDAP_SUCCESS) {
					attr_merge(e, ct[i].ad, c->rvalue_vals, c->rvalue_nvals);
					ber_bvarray_free( c->rvalue_nvals );
					ber_bvarray_free( c->rvalue_vals );
				}
				break;
			}
		}
	}

	if ( table ) {
		if ( table == BI_TABLE )
			ct = c->bi->bi_cf_table;
		else
			ct = c->be->be_cf_table;
		for (;ct && ct->name;ct++) {
			if (!ct->ad) continue;
			rc = config_get_vals(ct, c);
			if (rc == LDAP_SUCCESS) {
				attr_merge(e, ct->ad, c->rvalue_vals, c->rvalue_nvals);
			}
		}
	}
	oc_at = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	rc = structural_class(oc_at->a_vals, vals, NULL, &text, textbuf, textlen);
	BER_BVZERO( &vals[1] );
	attr_merge(e, slap_schema.si_ad_structuralObjectClass, vals, NULL );

	return 0;
}

static CfEntryInfo *
config_build_includes( ConfigArgs *c, Entry *parent,
	Operation *op, SlapReply *rs )
{
	Entry *e;
	int i;
	ConfigFile *cf = (ConfigFile *)c->line;
	CfEntryInfo *ce, *ceparent, *ceprev;

	ceparent = parent->e_private;

	for (i=0; cf; cf=cf->c_sibs, i++) {
		c->value_dn.bv_val = c->log;
		c->value_dn.bv_len = sprintf(c->value_dn.bv_val, "cn=include{%d}", i);
		e = config_alloc_entry( &parent->e_nname, &c->value_dn );
		c->line = (char *)cf;
		config_build_entry( c, e, cfOc_include, &c->value_dn,
			c->bi->bi_cf_table, NO_TABLE );
		op->ora_e = e;
		op->o_bd->be_add( op, rs );
		ce = e->e_private;
		ce->ce_type = Cft_Include;
		ce->ce_bi = c->bi;
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
		if ( cf->c_kids ) {
			c->line = (char *)cf->c_kids;
			config_build_includes( c, e, op, rs );
		}
	}
	return ce;
}

static int
config_back_db_open( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	struct berval rdn;
	Entry *e, *parent;
	CfEntryInfo *ce, *ceparent, *ceprev;
	int i, rc;
	BackendInfo *bi;
	BackendDB *bptr;
	ConfigArgs c;
	ConfigTable *ct;
	Connection conn = {0};
	char opbuf[OPERATION_BUFFER_SIZE];
	Operation *op;
	slap_callback cb = { NULL, slap_null_cb, NULL, NULL };
	SlapReply rs = {REP_RESULT};

	/* If we read the config from back-ldif, nothing to do here */
	if ( cfb->cb_got_ldif )
		return 0;

	op = (Operation *)opbuf;
	connection_fake_init( &conn, op, cfb );

	op->o_dn = be->be_rootdn;
	op->o_ndn = be->be_rootndn;

	op->o_tag = LDAP_REQ_ADD;
	op->o_callback = &cb;
	op->o_bd = &cfb->cb_db;

	/* create root of tree */
	rdn = config_rdn;
	e = config_alloc_entry( NULL, &rdn );
	ce = e->e_private;
	cfb->cb_root = ce;
	c.be = be;
	c.bi = be->bd_info;
	c.line = (char *)cfb->cb_config;
	ct = c.bi->bi_cf_table;
	config_build_entry( &c, e, cfOc_global, &rdn, ct, NO_TABLE );
	op->ora_e = e;
	op->o_bd->be_add( op, &rs );
	ce->ce_type = Cft_Global;
	ce->ce_bi = c.bi;

	parent = e;
	ceparent = ce;

	/* Create schema nodes... cn=schema will contain the hardcoded core
	 * schema, read-only. Child objects will contain runtime loaded schema
	 * files.  FIXME
	 */

	/* Create includeFile nodes... */
	if ( cfb->cb_config->c_kids ) {
		c.line = (char *)cfb->cb_config->c_kids;
		ceprev = config_build_includes( &c, parent, op, &rs );
	}

	/* Create backend nodes. Skip if they don't provide a cf_table.
	 * There usually aren't any of these.
	 */
	
	c.line = 0;
	bi = backendInfo;
	for (i=0; i<nBackendInfo; i++, bi++) {
		if (!bi->bi_cf_table) continue;
		if (!bi->bi_private) continue;

		rdn.bv_val = c.log;
		rdn.bv_len = sprintf(rdn.bv_val, "%s=%s", cfAd_backend->ad_cname.bv_val, bi->bi_type);
		e = config_alloc_entry( &parent->e_nname, &rdn );
		ce = e->e_private;
		ce->ce_type = Cft_Backend;
		ce->ce_bi = bi;
		c.bi = bi;
		config_build_entry( &c, e, cfOc_backend, &rdn, ct, BI_TABLE );
		op->ora_e = e;
		op->o_bd->be_add( op, &rs );
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
	}

	/* Create database nodes... */
	for (i=0; i<nBackendDB; i++) {
		slap_overinfo *oi = NULL;
		if ( i == 0 ) {
			bptr = frontendDB;
		} else {
			bptr = &backendDB[i];
		}
		if ( overlay_is_over( bptr )) {
			oi = bptr->bd_info->bi_private;
			bi = oi->oi_orig;
		} else {
			bi = bptr->bd_info;
		}
		rdn.bv_val = c.log;
		rdn.bv_len = sprintf(rdn.bv_val, "%s={%0x}%s", cfAd_database->ad_cname.bv_val,
			i, bi->bi_type);
		e = config_alloc_entry( &parent->e_nname, &rdn );
		ce = e->e_private;
		c.be = bptr;
		c.bi = bi;
		ce->ce_type = Cft_Database;
		ce->ce_be = c.be;
		ce->ce_bi = c.bi;
		config_build_entry( &c, e, cfOc_database, &rdn, ct, BE_TABLE );
		op->ora_e = e;
		op->o_bd->be_add( op, &rs );
		if ( !ceparent->ce_kids ) {
			ceparent->ce_kids = ce;
		} else {
			ceprev->ce_sibs = ce;
		}
		ceprev = ce;
		/* Iterate through overlays */
		if ( oi ) {
			slap_overinst *on;
			Entry *oe;
			CfEntryInfo *opar = ce, *oprev = NULL;
			int j;

			for (j=0,on=oi->oi_list; on; j++,on=on->on_next) {
				rdn.bv_val = c.log;
				rdn.bv_len = sprintf(rdn.bv_val, "%s={%0x}%s",
					cfAd_overlay->ad_cname.bv_val, j, on->on_bi.bi_type );
				oe = config_alloc_entry( &e->e_nname, &rdn );
				ce = oe->e_private;
				c.be = bptr;
				c.bi = &on->on_bi;
				ce->ce_type = Cft_Overlay;
				ce->ce_be = c.be;
				ce->ce_bi = c.bi;
				config_build_entry( &c, oe, cfOc_overlay, &rdn, ct, BI_TABLE );
				op->ora_e = oe;
				op->o_bd->be_add( op, &rs );
				if ( !opar->ce_kids ) {
					opar->ce_kids = ce;
				} else {
					oprev->ce_sibs = ce;
				}
				oprev = ce;
			}
		}
	}

	return 0;
}

static int
config_back_db_destroy( Backend *be )
{
	free( be->be_private );
	return 0;
}

static int
config_back_db_init( Backend *be )
{
	struct berval dn;
	CfBackInfo *cfb;

	cfb = ch_calloc( 1, sizeof(CfBackInfo));
	cfb->cb_config = &cf_prv;
	cfb->cb_be = be;
	be->be_private = cfb;

	ber_dupbv( &be->be_rootdn, &config_rdn );
	ber_dupbv( &be->be_rootndn, &be->be_rootdn );
	ber_dupbv( &dn, &be->be_rootdn );
	ber_bvarray_add( &be->be_suffix, &dn );
	ber_dupbv( &dn, &be->be_rootdn );
	ber_bvarray_add( &be->be_nsuffix, &dn );

	/* Hide from namingContexts */
	SLAP_BFLAGS(be) |= SLAP_BFLAG_CONFIG;

	return 0;
}

static struct {
	char *name;
	AttributeDescription **desc;
	AttributeDescription *sub;
} ads[] = {
	{ "attribute", NULL, NULL },
	{ "backend", &cfAd_backend, NULL },
	{ "database", &cfAd_database, NULL },
	{ "ditcontentrule", NULL, NULL },
	{ "include", &cfAd_include, NULL },
	{ "objectclass", NULL, NULL },
	{ "overlay", &cfAd_overlay, NULL },
	{ NULL, NULL, NULL }
};

/* Notes:
 *   add / delete: all types that may be added or deleted must use an
 * X-ORDERED attributeType for their RDN. Adding and deleting entries
 * should automatically renumber the index of any siblings as needed,
 * so that no gaps in the numbering sequence exist after the add/delete
 * is completed.
 *   What can be added:
 *     schema objects
 *     backend objects for backend-specific config directives
 *     database objects
 *     overlay objects
 *
 *   delete: probably no support this time around.
 *
 *   modrdn: generally not done. Will be invoked automatically by add/
 * delete to update numbering sequence. Perform as an explicit operation
 * so that the renumbering effect may be replicated. Subtree rename must
 * be supported, since renumbering a database will affect all its child
 * overlays.
 *
 *  modify: must be fully supported. 
 */

int
config_back_initialize( BackendInfo *bi )
{
	ConfigTable *ct = config_back_cf_table;
	char *argv[4];
	int i;

	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = config_back_db_init;
	bi->bi_db_config = 0;
	bi->bi_db_open = config_back_db_open;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = config_back_db_destroy;

	bi->bi_op_bind = config_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = config_back_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = config_back_modify;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = 0;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	argv[3] = NULL;
	for (i=0; OidMacros[i].name; i++ ) {
		argv[1] = OidMacros[i].name;
		argv[2] = OidMacros[i].oid;
		parse_oidm( "slapd", i, 3, argv );
	}

	bi->bi_cf_table = ct;

	i = config_register_schema( ct, cf_ocs );
	if ( i ) return i;

	/* set up the notable AttributeDescriptions */
	ads[0].sub = slap_schema.si_ad_attributeTypes;
	ads[3].sub = slap_schema.si_ad_ditContentRules;
	ads[5].sub = slap_schema.si_ad_objectClasses;

	i = 0;
	for (;ct->name;ct++) {
		if (strcmp(ct->name, ads[i].name)) continue;
		if (ads[i].sub) {
			ct->ad = ads[i].sub;
		} else {
			*ads[i].desc = ct->ad;
		}
		i++;
		if (!ads[i].name) break;
	}

	return 0;
}

