/* bconfig.c - the config backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2008 The OpenLDAP Foundation.
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
#include <sys/stat.h>

#include "slap.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

#include <ldif.h>
#include <lutil.h>

#include "config.h"

static struct berval config_rdn = BER_BVC("cn=config");
static struct berval schema_rdn = BER_BVC("cn=schema");

#ifdef SLAPD_MODULES
typedef struct modpath_s {
	struct modpath_s *mp_next;
	struct berval mp_path;
	BerVarray mp_loads;
} ModPaths;

static ModPaths modpaths, *modlast = &modpaths, *modcur = &modpaths;
#endif

typedef struct ConfigFile {
	struct ConfigFile *c_sibs;
	struct ConfigFile *c_kids;
	struct berval c_file;
	AttributeType *c_at_head, *c_at_tail;
	ContentRule *c_cr_head, *c_cr_tail;
	ObjectClass *c_oc_head, *c_oc_tail;
	OidMacro *c_om_head, *c_om_tail;
	BerVarray c_dseFiles;
} ConfigFile;

typedef struct {
	ConfigFile *cb_config;
	CfEntryInfo *cb_root;
	BackendDB	cb_db;	/* underlying database */
	int		cb_got_ldif;
	int		cb_use_ldif;
} CfBackInfo;

/* These do nothing in slapd, they're kept only to make them
 * editable here.
 */
static char *replica_pidFile, *replica_argsFile;
static int replicationInterval;

static char	*passwd_salt;
static char	*logfileName;
#ifdef SLAP_AUTH_REWRITE
static BerVarray authz_rewrites;
#endif

static struct berval cfdir;

/* Private state */
static AttributeDescription *cfAd_backend, *cfAd_database, *cfAd_overlay,
	*cfAd_include;

static ConfigFile *cfn;

static Avlnode *CfOcTree;

static int config_add_internal( CfBackInfo *cfb, Entry *e, ConfigArgs *ca,
	SlapReply *rs, int *renumber );

static ConfigDriver config_fname;
static ConfigDriver config_cfdir;
static ConfigDriver config_generic;
static ConfigDriver config_search_base;
static ConfigDriver config_passwd_hash;
static ConfigDriver config_schema_dn;
static ConfigDriver config_sizelimit;
static ConfigDriver config_timelimit;
static ConfigDriver config_overlay;
static ConfigDriver config_subordinate; 
static ConfigDriver config_suffix; 
static ConfigDriver config_rootdn;
static ConfigDriver config_rootpw;
static ConfigDriver config_restrict;
static ConfigDriver config_allows;
static ConfigDriver config_disallows;
static ConfigDriver config_requires;
static ConfigDriver config_security;
static ConfigDriver config_referral;
static ConfigDriver config_loglevel;
static ConfigDriver config_replica;
static ConfigDriver config_updatedn;
static ConfigDriver config_updateref;
static ConfigDriver config_include;
#ifdef HAVE_TLS
static ConfigDriver config_tls_option;
static ConfigDriver config_tls_config;
#endif
extern ConfigDriver syncrepl_config;

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
	CFG_TLS_DH_FILE,
	CFG_TLS_VERIFY,
	CFG_TLS_CRLCHECK,
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
	CFG_TTHREADS,

	CFG_LAST
};

typedef struct {
	char *name, *oid;
} OidRec;

static OidRec OidMacros[] = {
	/* OpenLDAProot:666.11.1 */
	{ "OLcfg", "1.3.6.1.4.1.4203.666.11.1" },
	{ "OLcfgAt", "OLcfg:3" },
	{ "OLcfgGlAt", "OLcfgAt:0" },
	{ "OLcfgBkAt", "OLcfgAt:1" },
	{ "OLcfgDbAt", "OLcfgAt:2" },
	{ "OLcfgOvAt", "OLcfgAt:3" },
	{ "OLcfgOc", "OLcfg:4" },
	{ "OLcfgGlOc", "OLcfgOc:0" },
	{ "OLcfgBkOc", "OLcfgOc:1" },
	{ "OLcfgDbOc", "OLcfgOc:2" },
	{ "OLcfgOvOc", "OLcfgOc:3" },
	{ "OMsyn", "1.3.6.1.4.1.1466.115.121.1" },
	{ "OMsInteger", "OMsyn:27" },
	{ "OMsBoolean", "OMsyn:7" },
	{ "OMsDN", "OMsyn:12" },
	{ "OMsDirectoryString", "OMsyn:15" },
	{ "OMsOctetString", "OMsyn:40" },
	{ NULL, NULL }
};

/*
 * Backend/Database registry
 *
 * OLcfg{Bk|Db}{Oc|At}:0		-> common
 * OLcfg{Bk|Db}{Oc|At}:1		-> bdb
 * OLcfg{Bk|Db}{Oc|At}:2		-> ldif
 * OLcfg{Bk|Db}{Oc|At}:3		-> ldap?
 */

/*
 * Overlay registry
 *
 * OLcfgOv{Oc|At}:1			-> syncprov
 * OLcfgOv{Oc|At}:2			-> pcache
 * OLcfgOv{Oc|At}:3			-> chain
 * OLcfgOv{Oc|At}:4			-> accesslog
 * OLcfgOv{Oc|At}:5			-> valsort
 * OLcfgOv{Oc|At}:6			-> smbk5pwd (use a separate arc for contrib?)
 */

/* alphabetical ordering */

static ConfigTable config_back_cf_table[] = {
	/* This attr is read-only */
	{ "", "", 0, 0, 0, ARG_MAGIC,
		&config_fname, "( OLcfgGlAt:78 NAME 'olcConfigFile' "
			"DESC 'File for slapd configuration directives' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "", "", 0, 0, 0, ARG_MAGIC,
		&config_cfdir, "( OLcfgGlAt:79 NAME 'olcConfigDir' "
			"DESC 'Directory for slapd configuration backend' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "access",	NULL, 0, 0, 0, ARG_MAY_DB|ARG_MAGIC|CFG_ACL,
		&config_generic, "( OLcfgGlAt:1 NAME 'olcAccess' "
			"DESC 'Access Control List' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "allows",	"features", 2, 0, 5, ARG_PRE_DB|ARG_MAGIC,
		&config_allows, "( OLcfgGlAt:2 NAME 'olcAllows' "
			"DESC 'Allowed set of deprecated features' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "argsfile", "file", 2, 2, 0, ARG_STRING,
		&slapd_args_file, "( OLcfgGlAt:3 NAME 'olcArgsFile' "
			"DESC 'File for slapd command line options' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "attributeoptions", NULL, 0, 0, 0, ARG_MAGIC|CFG_ATOPT,
		&config_generic, "( OLcfgGlAt:5 NAME 'olcAttributeOptions' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "attribute",	"attribute", 2, 0, 9,
		ARG_PAREN|ARG_MAGIC|CFG_ATTR|ARG_NO_DELETE|ARG_NO_INSERT,
		&config_generic, "( OLcfgGlAt:4 NAME 'olcAttributeTypes' "
			"DESC 'OpenLDAP attributeTypes' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )",
				NULL, NULL },
	{ "authid-rewrite", NULL, 2, 0, STRLENOF( "authid-rewrite" ),
#ifdef SLAP_AUTH_REWRITE
		ARG_MAGIC|CFG_REWRITE|ARG_NO_INSERT, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		 "( OLcfgGlAt:6 NAME 'olcAuthIDRewrite' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "authz-policy", "policy", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, "( OLcfgGlAt:7 NAME 'olcAuthzPolicy' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "authz-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP|ARG_NO_INSERT,
		&config_generic, "( OLcfgGlAt:8 NAME 'olcAuthzRegexp' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "backend", "type", 2, 2, 0, ARG_PRE_DB|ARG_MAGIC|CFG_BACKEND,
		&config_generic, "( OLcfgGlAt:9 NAME 'olcBackend' "
			"DESC 'A type of backend' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE X-ORDERED 'SIBLINGS' )",
				NULL, NULL },
	{ "concurrency", "level", 2, 2, 0, ARG_INT|ARG_MAGIC|CFG_CONCUR,
		&config_generic, "( OLcfgGlAt:10 NAME 'olcConcurrency' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "conn_max_pending", "max", 2, 2, 0, ARG_INT,
		&slap_conn_max_pending, "( OLcfgGlAt:11 NAME 'olcConnMaxPending' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "conn_max_pending_auth", "max", 2, 2, 0, ARG_INT,
		&slap_conn_max_pending_auth, "( OLcfgGlAt:12 NAME 'olcConnMaxPendingAuth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "database", "type", 2, 2, 0, ARG_MAGIC|CFG_DATABASE,
		&config_generic, "( OLcfgGlAt:13 NAME 'olcDatabase' "
			"DESC 'The backend type for a database instance' "
			"SUP olcBackend SINGLE-VALUE X-ORDERED 'SIBLINGS' )", NULL, NULL },
	{ "defaultSearchBase", "dn", 2, 2, 0, ARG_PRE_BI|ARG_PRE_DB|ARG_DN|ARG_QUOTE|ARG_MAGIC,
		&config_search_base, "( OLcfgGlAt:14 NAME 'olcDefaultSearchBase' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "disallows", "features", 2, 0, 8, ARG_PRE_DB|ARG_MAGIC,
		&config_disallows, "( OLcfgGlAt:15 NAME 'olcDisallows' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "ditcontentrule",	NULL, 0, 0, 0, ARG_MAGIC|CFG_DIT|ARG_NO_DELETE|ARG_NO_INSERT,
		&config_generic, "( OLcfgGlAt:16 NAME 'olcDitContentRules' "
			"DESC 'OpenLDAP DIT content rules' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )",
			NULL, NULL },
	{ "gentlehup", "on|off", 2, 2, 0,
#ifdef SIGHUP
		ARG_ON_OFF, &global_gentlehup,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:17 NAME 'olcGentleHUP' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "idletimeout", "timeout", 2, 2, 0, ARG_INT,
		&global_idletimeout, "( OLcfgGlAt:18 NAME 'olcIdleTimeout' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "include", "file", 2, 2, 0, ARG_MAGIC,
		&config_include, "( OLcfgGlAt:19 NAME 'olcInclude' "
			"SUP labeledURI )", NULL, NULL },
	{ "index_substr_if_minlen", "min", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MIN,
		&config_generic, "( OLcfgGlAt:20 NAME 'olcIndexSubstrIfMinLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_if_maxlen", "max", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MAX,
		&config_generic, "( OLcfgGlAt:21 NAME 'olcIndexSubstrIfMaxLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_any_len", "len", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_len, "( OLcfgGlAt:22 NAME 'olcIndexSubstrAnyLen' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "index_substr_any_step", "step", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_step, "( OLcfgGlAt:23 NAME 'olcIndexSubstrAnyStep' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "lastmod", "on|off", 2, 2, 0, ARG_DB|ARG_ON_OFF|ARG_MAGIC|CFG_LASTMOD,
		&config_generic, "( OLcfgDbAt:0.4 NAME 'olcLastMod' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "limits", "limits", 2, 0, 0, ARG_DB|ARG_MAGIC|CFG_LIMITS,
		&config_generic, "( OLcfgDbAt:0.5 NAME 'olcLimits' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "localSSF", "ssf", 2, 2, 0, ARG_INT,
		&local_ssf, "( OLcfgGlAt:26 NAME 'olcLocalSSF' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "logfile", "file", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_LOGFILE,
		&config_generic, "( OLcfgGlAt:27 NAME 'olcLogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "loglevel", "level", 2, 0, 0, ARG_MAGIC,
		&config_loglevel, "( OLcfgGlAt:28 NAME 'olcLogLevel' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "maxDerefDepth", "depth", 2, 2, 0, ARG_DB|ARG_INT|ARG_MAGIC|CFG_DEPTH,
		&config_generic, "( OLcfgDbAt:0.6 NAME 'olcMaxDerefDepth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "moduleload",	"file", 2, 0, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODLOAD|ARG_NO_DELETE, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:30 NAME 'olcModuleLoad' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "modulepath", "path", 2, 2, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODPATH|ARG_NO_DELETE|ARG_NO_INSERT, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:31 NAME 'olcModulePath' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "objectclass", "objectclass", 2, 0, 0, ARG_PAREN|ARG_MAGIC|CFG_OC|ARG_NO_DELETE|ARG_NO_INSERT,
		&config_generic, "( OLcfgGlAt:32 NAME 'olcObjectClasses' "
		"DESC 'OpenLDAP object classes' "
		"EQUALITY caseIgnoreMatch "
		"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )",
			NULL, NULL },
	{ "objectidentifier", NULL,	0, 0, 0, ARG_MAGIC|CFG_OID,
		&config_generic, "( OLcfgGlAt:33 NAME 'olcObjectIdentifier' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "overlay", "overlay", 2, 2, 0, ARG_MAGIC,
		&config_overlay, "( OLcfgGlAt:34 NAME 'olcOverlay' "
			"SUP olcDatabase SINGLE-VALUE X-ORDERED 'SIBLINGS' )", NULL, NULL },
	{ "password-crypt-salt-format", "salt", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_SALT,
		&config_generic, "( OLcfgGlAt:35 NAME 'olcPasswordCryptSaltFormat' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "password-hash", "hash", 2, 2, 0, ARG_MAGIC,
		&config_passwd_hash, "( OLcfgGlAt:36 NAME 'olcPasswordHash' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "pidfile", "file", 2, 2, 0, ARG_STRING,
		&slapd_pid_file, "( OLcfgGlAt:37 NAME 'olcPidFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "plugin", NULL, 0, 0, 0,
#ifdef LDAP_SLAPI
		ARG_MAGIC|CFG_PLUGIN, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:38 NAME 'olcPlugin' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "pluginlog", "filename", 2, 2, 0,
#ifdef LDAP_SLAPI
		ARG_STRING, &slapi_log_file,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:39 NAME 'olcPluginLogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "readonly", "on|off", 2, 2, 0, ARG_MAY_DB|ARG_ON_OFF|ARG_MAGIC|CFG_RO,
		&config_generic, "( OLcfgGlAt:40 NAME 'olcReadOnly' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "referral", "url", 2, 2, 0, ARG_MAGIC,
		&config_referral, "( OLcfgGlAt:41 NAME 'olcReferral' "
			"SUP labeledURI SINGLE-VALUE )", NULL, NULL },
	{ "replica", "host or uri", 2, 0, 0, ARG_DB|ARG_MAGIC,
		&config_replica, "( OLcfgDbAt:0.7 NAME 'olcReplica' "
			"EQUALITY caseIgnoreMatch "
			"SUP labeledURI X-ORDERED 'VALUES' )", NULL, NULL },
	{ "replica-argsfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_argsFile, "( OLcfgGlAt:43 NAME 'olcReplicaArgsFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "replica-pidfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_pidFile, "( OLcfgGlAt:44 NAME 'olcReplicaPidFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "replicationInterval", NULL, 0, 0, 0, ARG_INT,
		&replicationInterval, "( OLcfgGlAt:45 NAME 'olcReplicationInterval' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "replogfile", "filename", 2, 2, 0, ARG_MAY_DB|ARG_MAGIC|ARG_STRING|CFG_REPLOG,
		&config_generic, "( OLcfgGlAt:46 NAME 'olcReplogFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "require", "features", 2, 0, 7, ARG_MAY_DB|ARG_MAGIC,
		&config_requires, "( OLcfgGlAt:47 NAME 'olcRequires' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "restrict", "op_list", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_restrict, "( OLcfgGlAt:48 NAME 'olcRestrict' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "reverse-lookup", "on|off", 2, 2, 0,
#ifdef SLAPD_RLOOKUPS
		ARG_ON_OFF, &use_reverse_lookup,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:49 NAME 'olcReverseLookup' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "rootdn", "dn", 2, 2, 0, ARG_DB|ARG_DN|ARG_QUOTE|ARG_MAGIC,
		&config_rootdn, "( OLcfgDbAt:0.8 NAME 'olcRootDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "rootDSE", "file", 2, 2, 0, ARG_MAGIC|CFG_ROOTDSE,
		&config_generic, "( OLcfgGlAt:51 NAME 'olcRootDSE' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "rootpw", "password", 2, 2, 0, ARG_BERVAL|ARG_DB|ARG_MAGIC,
		&config_rootpw, "( OLcfgDbAt:0.9 NAME 'olcRootPW' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-authz-policy", NULL, 2, 2, 0, ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-host", "host", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_host,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:53 NAME 'olcSaslHost' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-realm", "realm", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_realm,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:54 NAME 'olcSaslRealm' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sasl-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-secprops", "properties", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_MAGIC|CFG_SASLSECP, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:56 NAME 'olcSaslSecProps' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "saslRegexp",	NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "schemadn", "dn", 2, 2, 0, ARG_MAY_DB|ARG_DN|ARG_QUOTE|ARG_MAGIC,
		&config_schema_dn, "( OLcfgGlAt:58 NAME 'olcSchemaDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "security", "factors", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_security, "( OLcfgGlAt:59 NAME 'olcSecurity' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "sizelimit", "limit",	2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_sizelimit, "( OLcfgGlAt:60 NAME 'olcSizeLimit' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "sockbuf_max_incoming", "max", 2, 2, 0, ARG_BER_LEN_T,
		&sockbuf_max_incoming, "( OLcfgGlAt:61 NAME 'olcSockbufMaxIncoming' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "sockbuf_max_incoming_auth", "max", 2, 2, 0, ARG_BER_LEN_T,
		&sockbuf_max_incoming_auth, "( OLcfgGlAt:62 NAME 'olcSockbufMaxIncomingAuth' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "srvtab", "file", 2, 2, 0,
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		ARG_STRING, &ldap_srvtab,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:63 NAME 'olcSrvtab' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "subordinate", "[advertise]", 1, 2, 0, ARG_DB|ARG_MAGIC,
		&config_subordinate, "( OLcfgDbAt:0.15 NAME 'olcSubordinate' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "suffix",	"suffix", 2, 2, 0, ARG_DB|ARG_DN|ARG_QUOTE|ARG_MAGIC,
		&config_suffix, "( OLcfgDbAt:0.10 NAME 'olcSuffix' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "syncrepl", NULL, 0, 0, 0, ARG_DB|ARG_MAGIC,
		&syncrepl_config, "( OLcfgDbAt:0.11 NAME 'olcSyncrepl' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "threads", "count", 2, 2, 0,
#ifdef NO_THREADS
		ARG_IGNORED, NULL,
#else
		ARG_INT|ARG_MAGIC|CFG_THREADS, &config_generic,
#endif
		"( OLcfgGlAt:66 NAME 'olcThreads' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "timelimit", "limit", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_timelimit, "( OLcfgGlAt:67 NAME 'olcTimeLimit' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCACertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:68 NAME 'olcTLSCACertificateFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCACertificatePath", NULL,	0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_PATH|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:69 NAME 'olcTLSCACertificatePath' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:70 NAME 'olcTLSCertificateFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCertificateKeyFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_KEY|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:71 NAME 'olcTLSCertificateKeyFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCipherSuite",	NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CIPHER|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:72 NAME 'olcTLSCipherSuite' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSCRLCheck", NULL, 0, 0, 0,
#if defined(HAVE_TLS) && defined(HAVE_OPENSSL_CRL)
		CFG_TLS_CRLCHECK|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:73 NAME 'olcTLSCRLCheck' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSRandFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_RAND|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:74 NAME 'olcTLSRandFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSVerifyClient", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_VERIFY|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:75 NAME 'olcTLSVerifyClient' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "TLSDHParamFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_DH_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgGlAt:77 NAME 'olcTLSDHParamFile' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "tool-threads", "count", 2, 2, 0, ARG_INT|ARG_MAGIC|CFG_TTHREADS,
		&config_generic, "( OLcfgGlAt:80 NAME 'olcToolThreads' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "ucdata-path", "path", 2, 2, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL },
	{ "updatedn", "dn", 2, 2, 0, ARG_DB|ARG_DN|ARG_QUOTE|ARG_MAGIC,
		&config_updatedn, "( OLcfgDbAt:0.12 NAME 'olcUpdateDN' "
			"SYNTAX OMsDN SINGLE-VALUE )", NULL, NULL },
	{ "updateref", "url", 2, 2, 0, ARG_DB|ARG_MAGIC,
		&config_updateref, "( OLcfgDbAt:0.13 NAME 'olcUpdateRef' "
			"EQUALITY caseIgnoreMatch "
			"SUP labeledURI )", NULL, NULL },
	{ NULL,	NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};

/* Routines to check if a child can be added to this type */
static ConfigLDAPadd cfAddSchema, cfAddInclude, cfAddDatabase,
	cfAddBackend, cfAddModule, cfAddOverlay;

/* NOTE: be careful when defining array members
 * that can be conditionally compiled */
#define CFOC_GLOBAL	cf_ocs[1]
#define CFOC_SCHEMA	cf_ocs[2]
#define CFOC_BACKEND	cf_ocs[3]
#define CFOC_DATABASE	cf_ocs[4]
#define CFOC_OVERLAY	cf_ocs[5]
#define CFOC_INCLUDE	cf_ocs[6]
#define CFOC_FRONTEND	cf_ocs[7]
#ifdef SLAPD_MODULES
#define CFOC_MODULE	cf_ocs[8]
#endif /* SLAPD_MODULES */

static ConfigOCs cf_ocs[] = {
	{ "( OLcfgGlOc:0 "
		"NAME 'olcConfig' "
		"DESC 'OpenLDAP configuration object' "
		"ABSTRACT SUP top )", Cft_Abstract, NULL },
	{ "( OLcfgGlOc:1 "
		"NAME 'olcGlobal' "
		"DESC 'OpenLDAP Global configuration options' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( cn $ olcConfigFile $ olcConfigDir $ olcAllows $ olcArgsFile $ "
		 "olcAttributeOptions $ olcAuthIDRewrite $ "
		 "olcAuthzPolicy $ olcAuthzRegexp $ olcConcurrency $ "
		 "olcConnMaxPending $ olcConnMaxPendingAuth $ "
		 "olcDisallows $ olcGentleHUP $ olcIdleTimeout $ "
		 "olcIndexSubstrIfMaxLen $ olcIndexSubstrIfMinLen $ "
		 "olcIndexSubstrAnyLen $ olcIndexSubstrAnyStep $ olcLocalSSF $ "
		 "olcLogLevel $ "
		 "olcPasswordCryptSaltFormat $ olcPasswordHash $ olcPidFile $ "
		 "olcPluginLogFile $ olcReadOnly $ olcReferral $ "
		 "olcReplicaPidFile $ olcReplicaArgsFile $ olcReplicationInterval $ "
		 "olcReplogFile $ olcRequires $ olcRestrict $ olcReverseLookup $ "
		 "olcRootDSE $ "
		 "olcSaslHost $ olcSaslRealm $ olcSaslSecProps $ "
		 "olcSecurity $ olcSizeLimit $ "
		 "olcSockbufMaxIncoming $ olcSockbufMaxIncomingAuth $ olcSrvtab $ "
		 "olcThreads $ olcTimeLimit $ olcTLSCACertificateFile $ "
		 "olcTLSCACertificatePath $ olcTLSCertificateFile $ "
		 "olcTLSCertificateKeyFile $ olcTLSCipherSuite $ olcTLSCRLCheck $ "
		 "olcTLSRandFile $ olcTLSVerifyClient $ olcTLSDHParamFile $ "
		 "olcToolThreads $ "
		 "olcObjectIdentifier $ olcAttributeTypes $ olcObjectClasses $ "
		 "olcDitContentRules ) )", Cft_Global },
	{ "( OLcfgGlOc:2 "
		"NAME 'olcSchemaConfig' "
		"DESC 'OpenLDAP schema object' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( cn $ olcObjectIdentifier $ olcAttributeTypes $ "
		 "olcObjectClasses $ olcDitContentRules ) )",
		 	Cft_Schema, NULL, cfAddSchema },
	{ "( OLcfgGlOc:3 "
		"NAME 'olcBackendConfig' "
		"DESC 'OpenLDAP Backend-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MUST olcBackend )", Cft_Backend, NULL, cfAddBackend },
	{ "( OLcfgGlOc:4 "
		"NAME 'olcDatabaseConfig' "
		"DESC 'OpenLDAP Database-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MUST olcDatabase "
		"MAY ( olcSuffix $ olcSubordinate $ olcAccess $ olcLastMod $ olcLimits $ "
		 "olcMaxDerefDepth $ olcPlugin $ olcReadOnly $ olcReplica $ "
		 "olcReplogFile $ olcRequires $ olcRestrict $ olcRootDN $ olcRootPW $ "
		 "olcSchemaDN $ olcSecurity $ olcSizeLimit $ olcSyncrepl $ "
		 "olcTimeLimit $ olcUpdateDN $ olcUpdateRef ) )",
		 	Cft_Database, NULL, cfAddDatabase },
	{ "( OLcfgGlOc:5 "
		"NAME 'olcOverlayConfig' "
		"DESC 'OpenLDAP Overlay-specific options' "
		"SUP olcConfig STRUCTURAL "
		"MUST olcOverlay )", Cft_Overlay, NULL, cfAddOverlay },
	{ "( OLcfgGlOc:6 "
		"NAME 'olcIncludeFile' "
		"DESC 'OpenLDAP configuration include file' "
		"SUP olcConfig STRUCTURAL "
		"MUST olcInclude "
		"MAY ( cn $ olcRootDSE ) )",
		Cft_Include, NULL, cfAddInclude },
	/* This should be STRUCTURAL like all the other database classes, but
	 * that would mean inheriting all of the olcDatabaseConfig attributes,
	 * which causes them to be merged twice in config_build_entry.
	 */
	{ "( OLcfgGlOc:7 "
		"NAME 'olcFrontendConfig' "
		"DESC 'OpenLDAP frontend configuration' "
		"AUXILIARY "
		"MAY ( olcDefaultSearchBase $ olcPasswordHash ) )",
		Cft_Database, NULL, NULL },
#ifdef SLAPD_MODULES
	{ "( OLcfgGlOc:8 "
		"NAME 'olcModuleList' "
		"DESC 'OpenLDAP dynamic module info' "
		"SUP olcConfig STRUCTURAL "
		"MAY ( cn $ olcModulePath $ olcModuleLoad ) )",
		Cft_Module, NULL, cfAddModule },
#endif
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
		case CFG_TTHREADS:
			c->value_int = slap_tool_thread_max;
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
					bv.bv_len = snprintf( buf, sizeof( buf ), SLAP_X_ORDERED_FMT, i );
					if ( bv.bv_len >= sizeof( buf ) ) {
						ber_bvarray_free_x( c->rvalue_vals, NULL );
						c->rvalue_vals = NULL;
						rc = 1;
						break;
					}
					bv.bv_val = buf + bv.bv_len;
					limits_unparse( c->be->be_limits[i], &bv );
					bv.bv_len += bv.bv_val - buf;
					bv.bv_val = buf;
					value_add_one( &c->rvalue_vals, &bv );
				}
			}
			if ( !c->rvalue_vals ) rc = 1;
			break;
		case CFG_RO:
			c->value_int = (c->be->be_restrictops & SLAP_RESTRICT_OP_WRITES) ==
				SLAP_RESTRICT_OP_WRITES;
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
		case CFG_OID: {
			ConfigFile *cf = c->private;
			if ( !cf )
				oidm_unparse( &c->rvalue_vals, NULL, NULL, 1 );
			else if ( cf->c_om_head )
				oidm_unparse( &c->rvalue_vals, cf->c_om_head,
					cf->c_om_tail, 0 );
			if ( !c->rvalue_vals )
				rc = 1;
			}
			break;
		case CFG_ATOPT:
			ad_unparse_options( &c->rvalue_vals );
			break;
		case CFG_OC: {
			ConfigFile *cf = c->private;
			if ( !cf )
				oc_unparse( &c->rvalue_vals, NULL, NULL, 1 );
			else if ( cf->c_oc_head )
				oc_unparse( &c->rvalue_vals, cf->c_oc_head,
					cf->c_oc_tail, 0 );
			if ( !c->rvalue_vals )
				rc = 1;
			}
			break;
		case CFG_ATTR: {
			ConfigFile *cf = c->private;
			if ( !cf )
				at_unparse( &c->rvalue_vals, NULL, NULL, 1 );
			else if ( cf->c_at_head )
				at_unparse( &c->rvalue_vals, cf->c_at_head,
					cf->c_at_tail, 0 );
			if ( !c->rvalue_vals )
				rc = 1;
			}
			break;
		case CFG_DIT: {
			ConfigFile *cf = c->private;
			if ( !cf )
				cr_unparse( &c->rvalue_vals, NULL, NULL, 1 );
			else if ( cf->c_cr_head )
				cr_unparse( &c->rvalue_vals, cf->c_cr_head,
					cf->c_cr_tail, 0 );
			if ( !c->rvalue_vals )
				rc = 1;
			}
			break;
			
		case CFG_ACL: {
			AccessControl *a;
			char *src, *dst, ibuf[11];
			struct berval bv, abv;
			for (i=0, a=c->be->be_acl; a; i++,a=a->acl_next) {
				abv.bv_len = snprintf( ibuf, sizeof( ibuf ), SLAP_X_ORDERED_FMT, i );
				if ( abv.bv_len >= sizeof( ibuf ) ) {
					ber_bvarray_free_x( c->rvalue_vals, NULL );
					c->rvalue_vals = NULL;
					i = 0;
					break;
				}
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
			ConfigFile *cf = c->private;
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
			ModPaths *mp = c->private;
			if (mp->mp_loads) {
				int i;
				for (i=0; !BER_BVISNULL(&mp->mp_loads[i]); i++) {
					struct berval bv;
					bv.bv_val = c->log;
					bv.bv_len = snprintf( bv.bv_val, sizeof( c->log ),
						SLAP_X_ORDERED_FMT "%s", i,
						mp->mp_loads[i].bv_val );
					if ( bv.bv_len >= sizeof( c->log ) ) {
						ber_bvarray_free_x( c->rvalue_vals, NULL );
						c->rvalue_vals = NULL;
						break;
					}
					value_add_one( &c->rvalue_vals, &bv );
				}
			}

			rc = c->rvalue_vals ? 0 : 1;
			}
			break;
		case CFG_MODPATH: {
			ModPaths *mp = c->private;
			if ( !BER_BVISNULL( &mp->mp_path ))
				value_add_one( &c->rvalue_vals, &mp->mp_path );

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
					idx.bv_len = snprintf( idx.bv_val, sizeof( ibuf ), SLAP_X_ORDERED_FMT, i );
					if ( idx.bv_len >= sizeof( ibuf ) ) {
						ber_bvarray_free_x( c->rvalue_vals, NULL );
						c->rvalue_vals = NULL;
						break;
					}
					bv.bv_len = idx.bv_len + authz_rewrites[i].bv_len;
					bv.bv_val = ch_malloc( bv.bv_len + 1 );
					AC_MEMCPY( bv.bv_val, idx.bv_val, idx.bv_len );
					AC_MEMCPY( &bv.bv_val[ idx.bv_len ],
						authz_rewrites[i].bv_val,
						authz_rewrites[i].bv_len + 1 );
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		int rc = 0;
		switch(c->type) {
		/* single-valued attrs, no-ops */
		case CFG_CONCUR:
		case CFG_THREADS:
		case CFG_TTHREADS:
		case CFG_RO:
		case CFG_AZPOLICY:
		case CFG_DEPTH:
		case CFG_LASTMOD:
		case CFG_SASLSECP:
		case CFG_SSTR_IF_MAX:
		case CFG_SSTR_IF_MIN:
			break;

		/* no-ops, requires slapd restart */
		case CFG_PLUGIN:
		case CFG_MODLOAD:
		case CFG_AZREGEXP:
		case CFG_REWRITE:
			snprintf(c->log, sizeof( c->log ), "change requires slapd restart");
			break;

		case CFG_SALT:
			ch_free( passwd_salt );
			passwd_salt = NULL;
			break;

		case CFG_REPLOG:
			ch_free( c->be->be_replogfile );
			c->be->be_replogfile = NULL;
			break;

		case CFG_LOGFILE:
			ch_free( logfileName );
			logfileName = NULL;
			break;

		case CFG_ACL:
			if ( c->valx < 0 ) {
				AccessControl *end;
				if ( c->be == frontendDB )
					end = NULL;
				else
					end = frontendDB->be_acl;
				acl_destroy( c->be->be_acl, end );
				c->be->be_acl = end;

			} else {
				AccessControl **prev, *a;
				int i;
				for (i=0, prev = &c->be->be_acl; i < c->valx;
					i++ ) {
					a = *prev;
					prev = &a->acl_next;
				}
				a = *prev;
				*prev = a->acl_next;
				acl_free( a );
			}
			break;

		case CFG_LIMITS:
			/* FIXME: there is no limits_free function */
		case CFG_ATOPT:
			/* FIXME: there is no ad_option_free function */
		case CFG_ROOTDSE:
			/* FIXME: there is no way to remove attributes added by
				a DSE file */
		case CFG_OID:
		case CFG_OC:
		case CFG_DIT:
		case CFG_ATTR:
		case CFG_MODPATH:
		default:
			rc = 1;
			break;
		}
		return rc;
	}

 	p = strchr(c->line,'(' /*')'*/);

	switch(c->type) {
		case CFG_BACKEND:
			if(!(c->bi = backend_info(c->argv[1]))) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> failed init", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s (%s)!\n",
					c->log, c->msg, c->argv[1] );
				return(1);
			}
			break;

		case CFG_DATABASE:
			c->bi = NULL;
			/* NOTE: config is always the first backend!
			 */
			if ( !strcasecmp( c->argv[1], "config" )) {
				c->be = LDAP_STAILQ_FIRST(&backendDB);
			} else if ( !strcasecmp( c->argv[1], "frontend" )) {
				c->be = frontendDB;
			} else {
				c->be = backend_db_init(c->argv[1], NULL);
				if ( !c->be ) {
					snprintf( c->msg, sizeof( c->msg ), "<%s> failed init", c->argv[0] );
					Debug(LDAP_DEBUG_ANY, "%s: %s (%s)!\n",
						c->log, c->msg, c->argv[1] );
					return(1);
				}
			}
			break;

		case CFG_CONCUR:
			ldap_pvt_thread_set_concurrency(c->value_int);
			break;

		case CFG_THREADS:
			if ( c->value_int < 2 ) {
				snprintf( c->msg, sizeof( c->msg ),
					"threads=%d smaller than minimum value 2",
					c->value_int );
				Debug(LDAP_DEBUG_ANY, "%s: %s.\n",
					c->log, c->msg, 0 );
				return 1;

			} else if ( c->value_int > 2 * SLAP_MAX_WORKER_THREADS ) {
				snprintf( c->msg, sizeof( c->msg ),
					"warning, threads=%d larger than twice the default (2*%d=%d); YMMV",
					c->value_int, SLAP_MAX_WORKER_THREADS, 2 * SLAP_MAX_WORKER_THREADS );
				Debug(LDAP_DEBUG_ANY, "%s: %s.\n",
					c->log, c->msg, 0 );
			}
			if ( slapMode & SLAP_SERVER_MODE )
				ldap_pvt_thread_pool_maxthreads(&connection_pool, c->value_int);
			connection_pool_max = c->value_int;	/* save for reference */
			break;

		case CFG_TTHREADS:
			if ( slapMode & SLAP_TOOL_MODE )
				ldap_pvt_thread_pool_maxthreads(&connection_pool, c->value_int);
			slap_tool_thread_max = c->value_int;	/* save for reference */
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
				snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse value", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					c->log, c->msg, c->argv[1] );
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
				snprintf( c->msg, sizeof(c->msg), "<%s> %s",
					c->argv[0], txt );
				Debug(LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->msg, 0 );
				return(1);
			}
			break;
			}
#endif

		case CFG_DEPTH:
			c->be->be_max_deref_depth = c->value_int;
			break;

		case CFG_OID: {
			OidMacro *om;

			if(parse_oidm(c->fname, c->lineno, c->argc, c->argv, 1, &om))
				return(1);
			if (!cfn->c_om_head) cfn->c_om_head = om;
			cfn->c_om_tail = om;
			}
			break;

		case CFG_OC: {
			ObjectClass *oc;

			if(parse_oc(c->fname, c->lineno, p, c->argv, &oc)) return(1);
			if (!cfn->c_oc_head) cfn->c_oc_head = oc;
			cfn->c_oc_tail = oc;
			}
			break;

		case CFG_DIT: {
			ContentRule *cr;

			if(parse_cr(c->fname, c->lineno, p, c->argv, &cr)) return(1);
			if (!cfn->c_cr_head) cfn->c_cr_head = cr;
			cfn->c_cr_tail = cr;
			}
			break;

		case CFG_ATTR: {
			AttributeType *at;

			if(parse_at(c->fname, c->lineno, p, c->argv, &at)) return(1);
			if (!cfn->c_at_head) cfn->c_at_head = at;
			cfn->c_at_tail = at;
			}
			break;

		case CFG_ATOPT:
			ad_define_option(NULL, NULL, 0);
			for(i = 1; i < c->argc; i++)
				if(ad_define_option(c->argv[i], c->fname, c->lineno))
					return(1);
			break;

		case CFG_ACL:
			/* Don't append to the global ACL if we're on a specific DB */
			i = c->valx;
			if ( c->be != frontendDB && frontendDB->be_acl && c->valx == -1 ) {
				AccessControl *a;
				i = 0;
				for ( a=c->be->be_acl; a && a != frontendDB->be_acl;
					a = a->acl_next )
					i++;
			}
			if ( parse_acl(c->be, c->fname, c->lineno, c->argc, c->argv, i ) ) {
				return 1;
			}
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
				snprintf( c->msg, sizeof( c->msg ), "<%s> could not read file", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s %s\n",
					c->log, c->msg, c->argv[1] );
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
				snprintf( c->msg, sizeof( c->msg ), "<%s> not available for %s database",
					c->argv[0], c->be->bd_info->bi_type );
				Debug(LDAP_DEBUG_ANY, "%s: %s\n",
					c->log, c->msg, 0 );
				return(1);
			}
			if(c->value_int)
				SLAP_DBFLAGS(c->be) &= ~SLAP_DBFLAG_NOLASTMOD;
			else
				SLAP_DBFLAGS(c->be) |= SLAP_DBFLAG_NOLASTMOD;
			break;

		case CFG_SSTR_IF_MAX:
			if (c->value_int < index_substr_if_minlen) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> invalid value", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s (%d)\n",
					c->log, c->msg, c->value_int );
				return(1);
			}
			index_substr_if_maxlen = c->value_int;
			break;

		case CFG_SSTR_IF_MIN:
			if (c->value_int > index_substr_if_maxlen) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> invalid value", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s (%d)\n",
					c->log, c->msg, c->value_int );
				return(1);
			}
			index_substr_if_minlen = c->value_int;
			break;

#ifdef SLAPD_MODULES
		case CFG_MODLOAD:
			/* If we're just adding a module on an existing modpath,
			 * make sure we've selected the current path.
			 */
			if ( c->op == LDAP_MOD_ADD && c->private && modcur != c->private ) {
				modcur = c->private;
				/* This should never fail */
				if ( module_path( modcur->mp_path.bv_val )) {
					snprintf( c->msg, sizeof( c->msg ), "<%s> module path no longer valid",
						c->argv[0] );
					Debug(LDAP_DEBUG_ANY, "%s: %s (%s)\n",
						c->log, c->msg, modcur->mp_path.bv_val );
					return(1);
				}
			}
			if(module_load(c->argv[1], c->argc - 2, (c->argc > 2) ? c->argv + 2 : NULL))
				return(1);
			/* Record this load on the current path */
			{
				struct berval bv;
				char *ptr;
				if ( c->op == SLAP_CONFIG_ADD ) {
					ptr = c->line + STRLENOF("moduleload");
					while (!isspace(*ptr)) ptr++;
					while (isspace(*ptr)) ptr++;
				} else {
					ptr = c->line;
				}
				ber_str2bv(ptr, 0, 1, &bv);
				ber_bvarray_add( &modcur->mp_loads, &bv );
			}
			break;

		case CFG_MODPATH:
			if(module_path(c->argv[1])) return(1);
			/* Record which path was used with each module */
			{
				ModPaths *mp;

				if (!modpaths.mp_loads) {
					mp = &modpaths;
				} else {
					mp = ch_malloc( sizeof( ModPaths ));
					modlast->mp_next = mp;
				}
				ber_str2bv(c->argv[1], 0, 1, &mp->mp_path);
				mp->mp_next = NULL;
				mp->mp_loads = NULL;
				modlast = mp;
				c->private = mp;
				modcur = mp;
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
			char *line;
			
			if(slap_sasl_rewrite_config(c->fname, c->lineno, c->argc, c->argv))
				return(1);

			if ( c->argc > 1 ) {
				char	*s;

				/* quote all args but the first */
				line = ldap_charray2str( c->argv, "\" \"" );
				ber_str2bv( line, 0, 0, &bv );
				s = ber_bvchr( &bv, '"' );
				assert( s != NULL );
				/* move the trailing quote of argv[0] to the end */
				AC_MEMCPY( s, s + 1, bv.bv_len - ( s - bv.bv_val ) );
				bv.bv_val[ bv.bv_len - 1 ] = '"';

			} else {
				ber_str2bv( c->argv[ 0 ], 0, 1, &bv );
			}
			
			ber_bvarray_add( &authz_rewrites, &bv );
			}
			break;
#endif


		default:
			Debug( SLAPD_DEBUG_CONFIG_ERROR,
				"%s: unknown CFG_TYPE %d"
				SLAPD_CONF_UNKNOWN_IGNORED ".\n",
				c->log, c->type, 0 );
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
			return 1;
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */

	}
	return(0);
}


static int
config_fname(ConfigArgs *c) {
	if(c->op == SLAP_CONFIG_EMIT) {
		if (c->private) {
			ConfigFile *cf = c->private;
			value_add_one( &c->rvalue_vals, &cf->c_file );
			return 0;
		}
		return 1;
	}
	return(0);
}

static int
config_cfdir(ConfigArgs *c) {
	if(c->op == SLAP_CONFIG_EMIT) {
		if ( !BER_BVISEMPTY( &cfdir )) {
			value_add_one( &c->rvalue_vals, &cfdir );
			return 0;
		}
		return 1;
	}
	return(0);
}

static int
config_search_base(ConfigArgs *c) {
	if(c->op == SLAP_CONFIG_EMIT) {
		int rc = 1;
		if (!BER_BVISEMPTY(&default_search_base)) {
			value_add_one(&c->rvalue_vals, &default_search_base);
			value_add_one(&c->rvalue_nvals, &default_search_nbase);
			rc = 0;
		}
		return rc;
	} else if( c->op == LDAP_MOD_DELETE ) {
		ch_free( default_search_base.bv_val );
		ch_free( default_search_nbase.bv_val );
		BER_BVZERO( &default_search_base );
		BER_BVZERO( &default_search_nbase );
		return 0;
	}

	if(c->bi || c->be != frontendDB) {
		Debug(LDAP_DEBUG_ANY, "%s: defaultSearchBase line must appear "
			"prior to any backend or database definition\n",
			c->log, 0, 0);
		return(1);
	}

	if(default_search_nbase.bv_len) {
		free(default_search_base.bv_val);
		free(default_search_nbase.bv_val);
	}

	default_search_base = c->value_dn;
	default_search_nbase = c->value_ndn;
	return(0);
}

/* For backward compatibility we allow this in the global entry
 * but we now defer it to the frontend entry to allow modules
 * to load new hash types.
 */
static int
config_passwd_hash(ConfigArgs *c) {
	int i;
	if (c->op == SLAP_CONFIG_EMIT) {
		struct berval bv;
		/* Don't generate it in the global entry */
		if ( c->table == Cft_Global )
			return 1;
		for (i=0; default_passwd_hash && default_passwd_hash[i]; i++) {
			ber_str2bv(default_passwd_hash[i], 0, 0, &bv);
			value_add_one(&c->rvalue_vals, &bv);
		}
		return i ? 0 : 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		/* Deleting from global is a no-op, only the frontendDB entry matters */
		if ( c->table == Cft_Global )
			return 0;
		if ( c->valx < 0 ) {
			ldap_charray_free( default_passwd_hash );
			default_passwd_hash = NULL;
		} else {
			i = c->valx;
			ch_free( default_passwd_hash[i] );
			for (; default_passwd_hash[i]; i++ )
				default_passwd_hash[i] = default_passwd_hash[i+1];
		}
		return 0;
	}
	for(i = 1; i < c->argc; i++) {
		if(!lutil_passwd_scheme(c->argv[i])) {
			snprintf( c->msg, sizeof( c->msg ), "<%s> scheme not available", c->argv[0] );
			Debug(LDAP_DEBUG_ANY, "%s: %s (%s)\n",
				c->log, c->msg, c->argv[i]);
		} else {
			ldap_charray_add(&default_passwd_hash, c->argv[i]);
		}
	}
	if(!default_passwd_hash) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> no valid hashes found", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s\n",
			c->log, c->msg, 0 );
		return(1);
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		ch_free( c->be->be_schemadn.bv_val );
		ch_free( c->be->be_schemandn.bv_val );
		BER_BVZERO( &c->be->be_schemadn );
		BER_BVZERO( &c->be->be_schemandn );
		return 0;
	}
	ch_free( c->be->be_schemadn.bv_val );
	ch_free( c->be->be_schemandn.bv_val );
	c->be->be_schemadn = c->value_dn;
	c->be->be_schemandn = c->value_ndn;
	return(0);
}

static int
config_sizelimit(ConfigArgs *c) {
	int i, rc = 0;
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		/* Reset to defaults */
		lim->lms_s_soft = SLAPD_DEFAULT_SIZELIMIT;
		lim->lms_s_hard = 0;
		lim->lms_s_unchecked = -1;
		lim->lms_s_pr = 0;
		lim->lms_s_pr_hide = 0;
		lim->lms_s_pr_total = 0;
		return 0;
	}
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "size", 4)) {
			rc = limits_parse_one(c->argv[i], lim);
			if ( rc ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse value", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					c->log, c->msg, c->argv[i]);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_s_soft = -1;
			} else {
				if ( lutil_atoix( &lim->lms_s_soft, c->argv[i], 0 ) != 0 ) {
					snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse limit", c->argv[0]);
					Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
						c->log, c->msg, c->argv[i]);
					return(1);
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		/* Reset to defaults */
		lim->lms_t_soft = SLAPD_DEFAULT_TIMELIMIT;
		lim->lms_t_hard = 0;
		return 0;
	}
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "time", 4)) {
			rc = limits_parse_one(c->argv[i], lim);
			if ( rc ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse value", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					c->log, c->msg, c->argv[i]);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_t_soft = -1;
			} else {
				if ( lutil_atoix( &lim->lms_t_soft, c->argv[i], 0 ) != 0 ) {
					snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse limit", c->argv[0]);
					Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
						c->log, c->msg, c->argv[i]);
					return(1);
				}
			}
			lim->lms_t_hard = 0;
		}
	}
	return(0);
}

static int
config_overlay(ConfigArgs *c) {
	slap_overinfo *oi;
	if (c->op == SLAP_CONFIG_EMIT) {
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		assert(0);
	}
	if(c->argv[1][0] == '-' && overlay_config(c->be, &c->argv[1][1])) {
		/* log error */
		Debug( SLAPD_DEBUG_CONFIG_ERROR, "%s: (optional) %s overlay \"%s\" configuration failed"
			SLAPD_CONF_UNKNOWN_IGNORED ".\n",
			c->log, c->be == frontendDB ? "global " : "", &c->argv[1][1]);
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
		return 1;
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */
	} else if(overlay_config(c->be, c->argv[1])) {
		return(1);
	}
	/* Setup context for subsequent config directives.
	 * The newly added overlay is at the head of the list.
	 */
	oi = (slap_overinfo *)c->be->bd_info;
	c->bi = &oi->oi_list->on_bi;
	return(0);
}

static int
config_subordinate(ConfigArgs *c)
{
	int rc = 1;
	int advertise;

	switch( c->op ) {
	case SLAP_CONFIG_EMIT:
		if ( SLAP_GLUE_SUBORDINATE( c->be )) {
			struct berval bv;

			bv.bv_val = SLAP_GLUE_ADVERTISE( c->be ) ? "advertise" : "TRUE";
			bv.bv_len = SLAP_GLUE_ADVERTISE( c->be ) ? STRLENOF("advertise") :
				STRLENOF("TRUE");

			value_add_one( &c->rvalue_vals, &bv );
			rc = 0;
		}
		break;
	case LDAP_MOD_DELETE:
		if ( !c->line  || strcasecmp( c->line, "advertise" )) {
			glue_sub_del( c->be );
		} else {
			SLAP_DBFLAGS( c->be ) &= ~SLAP_DBFLAG_GLUE_ADVERTISE;
		}
		rc = 0;
		break;
	case LDAP_MOD_ADD:
	case SLAP_CONFIG_ADD:
		advertise = ( c->argc == 2 && !strcasecmp( c->argv[1], "advertise" ));
		rc = glue_sub_add( c->be, advertise, CONFIG_ONLINE_ADD( c ));
		break;
	}
	return rc;
}

static int
config_suffix(ConfigArgs *c)
{
	Backend *tbe;
	struct berval pdn, ndn;
	char	*notallowed = NULL;

	if ( c->be == frontendDB ) {
		notallowed = "frontend";

	} else if ( SLAP_MONITOR(c->be) ) {
		notallowed = "monitor";

	} else if ( SLAP_CONFIG(c->be) ) {
		notallowed = "config";
	}

	if ( notallowed != NULL ) {
		char	buf[ SLAP_TEXT_BUFLEN ] = { '\0' };

		switch ( c->op ) {
		case LDAP_MOD_ADD:
		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_INCREMENT:
		case SLAP_CONFIG_ADD:
			if ( !BER_BVISNULL( &c->value_dn ) ) {
				snprintf( buf, sizeof( buf ), "<%s> ",
						c->value_dn.bv_val );
			}

			Debug(LDAP_DEBUG_ANY,
				"%s: suffix %snot allowed in %s database.\n",
				c->log, buf, notallowed );
			break;

		case SLAP_CONFIG_EMIT:
			/* don't complain when emitting... */
			break;

		default:
			/* FIXME: don't know what values may be valid;
			 * please remove assertion, or add legal values
			 * to either block */
			assert( 0 );
			break;
		}

		return 1;
	}

	if (c->op == SLAP_CONFIG_EMIT) {
		if ( c->be->be_suffix == NULL
				|| BER_BVISNULL( &c->be->be_suffix[0] ) )
		{
			return 1;
		} else {
			value_add( &c->rvalue_vals, c->be->be_suffix );
			value_add( &c->rvalue_nvals, c->be->be_nsuffix );
			return 0;
		}
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( c->valx < 0 ) {
			ber_bvarray_free( c->be->be_suffix );
			ber_bvarray_free( c->be->be_nsuffix );
			c->be->be_suffix = NULL;
			c->be->be_nsuffix = NULL;
		} else {
			int i = c->valx;
			ch_free( c->be->be_suffix[i].bv_val );
			ch_free( c->be->be_nsuffix[i].bv_val );
			for (; c->be->be_suffix[i].bv_val; i++) {
				c->be->be_suffix[i] = c->be->be_suffix[i+1];
				c->be->be_nsuffix[i] = c->be->be_nsuffix[i+1];
			}
		}
		return 0;
	}

#ifdef SLAPD_MONITOR_DN
	if(!strcasecmp(c->argv[1], SLAPD_MONITOR_DN)) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> DN is reserved for monitoring slapd",
			c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s (%s)\n",
			c->log, c->msg, SLAPD_MONITOR_DN);
		return(1);
	}
#endif

	pdn = c->value_dn;
	ndn = c->value_ndn;
	tbe = select_backend(&ndn, 0, 0);
	if(tbe == c->be) {
		Debug( SLAPD_DEBUG_CONFIG_ERROR,
			"%s: suffix already served by this backend!"
			SLAPD_CONF_UNKNOWN_IGNORED ".\n",
			c->log, 0, 0);
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
		return 1;
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */
		free(pdn.bv_val);
		free(ndn.bv_val);
	} else if(tbe) {
		char	*type = tbe->bd_info->bi_type;

		if ( overlay_is_over( tbe ) ) {
			slap_overinfo	*oi = (slap_overinfo *)tbe->bd_info->bi_private;
			type = oi->oi_orig->bi_type;
		}

		snprintf( c->msg, sizeof( c->msg ), "<%s> namingContext \"%s\" already served by "
			"a preceding %s database serving namingContext",
			c->argv[0], pdn.bv_val, type );
		Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
			c->log, c->msg, tbe->be_suffix[0].bv_val);
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		ch_free( c->be->be_rootdn.bv_val );
		ch_free( c->be->be_rootndn.bv_val );
		BER_BVZERO( &c->be->be_rootdn );
		BER_BVZERO( &c->be->be_rootndn );
		return 0;
	}
	if ( !BER_BVISNULL( &c->be->be_rootdn )) {
		ch_free( c->be->be_rootdn.bv_val );
		ch_free( c->be->be_rootndn.bv_val );
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
			/* don't copy, because "rootpw" is marked
			 * as CFG_BERVAL */
			c->value_bv = c->be->be_rootpw;
			return 0;
		}
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		ch_free( c->be->be_rootpw.bv_val );
		BER_BVZERO( &c->be->be_rootpw );
		return 0;
	}

	tbe = select_backend(&c->be->be_rootndn, 0, 0);
	if(tbe != c->be) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> can only be set when rootdn is under suffix",
			c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s\n",
			c->log, c->msg, 0);
		return(1);
	}
	if ( !BER_BVISNULL( &c->be->be_rootpw ))
		ch_free( c->be->be_rootpw.bv_val );
	c->be->be_rootpw = c->value_bv;
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( !c->line ) {
			c->be->be_restrictops = 0;
		} else {
			restrictops = verb_to_mask( c->line, restrictable_ops );
			c->be->be_restrictops ^= restrictops;
		}
		return 0;
	}
	i = verbs_to_mask( c->argc, c->argv, restrictable_ops, &restrictops );
	if ( i ) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> unknown operation", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s %s\n",
			c->log, c->msg, c->argv[i]);
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( !c->line ) {
			global_allows = 0;
		} else {
			allows = verb_to_mask( c->line, allowable_ops );
			global_allows ^= allows;
		}
		return 0;
	}
	i = verbs_to_mask(c->argc, c->argv, allowable_ops, &allows);
	if ( i ) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> unknown feature", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s %s\n",
			c->log, c->msg, c->argv[i]);
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( !c->line ) {
			global_disallows = 0;
		} else {
			disallows = verb_to_mask( c->line, disallowable_ops );
			global_disallows ^= disallows;
		}
		return 0;
	}
	i = verbs_to_mask(c->argc, c->argv, disallowable_ops, &disallows);
	if ( i ) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> unknown feature", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s %s\n",
			c->log, c->msg, c->argv[i]);
		return(1);
	}
	global_disallows |= disallows;
	return(0);
}

static int
config_requires(ConfigArgs *c) {
	slap_mask_t requires = frontendDB->be_requires;
	int i, argc = c->argc;
	char **argv = c->argv;

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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( !c->line ) {
			c->be->be_requires = 0;
		} else {
			requires = verb_to_mask( c->line, requires_ops );
			c->be->be_requires ^= requires;
		}
		return 0;
	}
	/* "none" can only be first, to wipe out default/global values */
	if ( strcasecmp( c->argv[ 1 ], "none" ) == 0 ) {
		argv++;
		argc--;
		requires = 0;
	}
	i = verbs_to_mask(argc, argv, requires_ops, &requires);
	if ( i ) {
		if (strcasecmp( c->argv[ i ], "none" ) == 0 ) {
			snprintf( c->msg, sizeof( c->msg ), "<%s> \"none\" (#%d) must be listed first", c->argv[0], i - 1 );
			Debug(LDAP_DEBUG_ANY, "%s: %s\n",
				c->log, c->msg, 0);
		} else {
			snprintf( c->msg, sizeof( c->msg ), "<%s> unknown feature #%d", c->argv[0], i - 1 );
			Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
				c->log, c->msg, c->argv[i]);
		}
		return(1);
	}
	c->be->be_requires = requires;
	return(0);
}

static slap_verbmasks	*loglevel_ops;

static int
loglevel_init( void )
{
	slap_verbmasks	lo[] = {
		{ BER_BVC("Any"),	-1 },
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
		{ BER_BVC("Sync"),	LDAP_DEBUG_SYNC },
		{ BER_BVC("None"),	LDAP_DEBUG_NONE },
		{ BER_BVNULL,		0 }
	};

	return slap_verbmasks_init( &loglevel_ops, lo );
}

static void
loglevel_destroy( void )
{
	if ( loglevel_ops ) {
		(void)slap_verbmasks_destroy( loglevel_ops );
	}
	loglevel_ops = NULL;
}

static slap_mask_t	loglevel_ignore[] = { -1, 0 };

int
slap_loglevel_register( slap_mask_t m, struct berval *s )
{
	int	rc;

	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	rc = slap_verbmasks_append( &loglevel_ops, m, s, loglevel_ignore );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "slap_loglevel_register(%lu, \"%s\") failed\n",
			m, s->bv_val, 0 );
	}

	return rc;
}

int
slap_loglevel_get( struct berval *s, int *l )
{
	int		rc;
	slap_mask_t	m, i;

	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	for ( m = 0, i = 1; !BER_BVISNULL( &loglevel_ops[ i ].word ); i++ ) {
		m |= loglevel_ops[ i ].mask;
	}

	for ( i = 1; m & i; i <<= 1 )
		;

	if ( i == 0 ) {
		return -1;
	}

	rc = slap_verbmasks_append( &loglevel_ops, i, s, loglevel_ignore );

	if ( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "slap_loglevel_get(%lu, \"%s\") failed\n",
			i, s->bv_val, 0 );

	} else {
		*l = i;
	}

	return rc;
}

int
str2loglevel( const char *s, int *l )
{
	int	i;

	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	i = verb_to_mask( s, loglevel_ops );

	if ( BER_BVISNULL( &loglevel_ops[ i ].word ) ) {
		return -1;
	}

	*l = loglevel_ops[ i ].mask;

	return 0;
}

const char *
loglevel2str( int l )
{
	struct berval	bv = BER_BVNULL;

	loglevel2bv( l, &bv );

	return bv.bv_val;
}

int
loglevel2bv( int l, struct berval *bv )
{
	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	BER_BVZERO( bv );

	return enum_to_verb( loglevel_ops, l, bv ) == -1;
}

int
loglevel2bvarray( int l, BerVarray *bva )
{
	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	return mask_to_verbs( loglevel_ops, l, bva );
}

static int config_syslog;

static int
config_loglevel(ConfigArgs *c) {
	int i;

	if ( loglevel_ops == NULL ) {
		loglevel_init();
	}

	if (c->op == SLAP_CONFIG_EMIT) {
		/* Get default or commandline slapd setting */
		if ( ldap_syslog && !config_syslog )
			config_syslog = ldap_syslog;
		return loglevel2bvarray( config_syslog, &c->rvalue_vals );

	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( !c->line ) {
			config_syslog = 0;
		} else {
			int level = verb_to_mask( c->line, loglevel_ops );
			config_syslog ^= level;
		}
		if ( slapMode & SLAP_SERVER_MODE ) {
			ldap_syslog = config_syslog;
		}
		return 0;
	}

	for( i=1; i < c->argc; i++ ) {
		int	level;

		if ( isdigit( c->argv[i][0] ) || c->argv[i][0] == '-' ) {
			if( lutil_atoi( &level, c->argv[i] ) != 0 ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse level", c->argv[0] );
				Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					c->log, c->msg, c->argv[i]);
				return( 1 );
			}
		} else {
			if ( str2loglevel( c->argv[i], &level ) ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> unknown level", c->argv[0] );
				Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					c->log, c->msg, c->argv[i]);
				return( 1 );
			}
		}
		/* Explicitly setting a zero clears all the levels */
		if ( level )
			config_syslog |= level;
		else
			config_syslog = 0;
	}
	if ( slapMode & SLAP_SERVER_MODE ) {
		ldap_syslog = config_syslog;
	}
	return(0);
}

static int
config_referral(ConfigArgs *c) {
	struct berval val;
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( default_referral ) {
			value_add( &c->rvalue_vals, default_referral );
			return 0;
		} else {
			return 1;
		}
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( c->valx < 0 ) {
			ber_bvarray_free( default_referral );
			default_referral = NULL;
		} else {
			int i = c->valx;
			ch_free( default_referral[i].bv_val );
			for (; default_referral[i].bv_val; i++ )
				default_referral[i] = default_referral[i+1];
		}
		return 0;
	}
	if(validate_global_referral(c->argv[1])) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> invalid URL", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s (%s)\n",
			c->log, c->msg, c->argv[1]);
		return(1);
	}

	ber_str2bv(c->argv[1], 0, 0, &val);
	if(value_add_one(&default_referral, &val)) return(LDAP_OTHER);
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
				bv.bv_len = snprintf( numbuf, sizeof( numbuf ), "%u", *tgt );
				if ( bv.bv_len >= sizeof( numbuf ) ) {
					ber_bvarray_free_x( c->rvalue_vals, NULL );
					c->rvalue_vals = NULL;
					rc = 1;
					break;
				}
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
			snprintf( c->msg, sizeof( c->msg ), "<%s> unknown factor", c->argv[0] );
			Debug(LDAP_DEBUG_ANY, "%s: %s %s\n",
				c->log, c->msg, c->argv[i]);
			return(1);
		}

		if ( lutil_atou( tgt, src ) != 0 ) {
			snprintf( c->msg, sizeof( c->msg ), "<%s> unable to parse factor", c->argv[0] );
			Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
				c->log, c->msg, c->argv[i]);
			return(1);
		}
	}
	return(0);
}

char *
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
	struct berval bc = BER_BVNULL;
	char numbuf[32];

	assert( !BER_BVISNULL( &ri->ri_bindconf.sb_uri ) );
	
	BER_BVZERO( bv );

	len = snprintf(numbuf, sizeof( numbuf ), SLAP_X_ORDERED_FMT, i );
	if ( len >= sizeof( numbuf ) ) {
		/* FIXME: how can indicate error? */
		return;
	}

	if ( ri->ri_nsuffix ) {
		for (i=0; !BER_BVISNULL( &ri->ri_nsuffix[i] ); i++) {
			len += ri->ri_nsuffix[i].bv_len + STRLENOF(" suffix=\"\"");
		}
	}
	if ( ri->ri_attrs ) {
		len += STRLENOF(" attrs");
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

	/* start with URI from bindconf */
	assert( !BER_BVISNULL( &bc ) );
	if ( bc.bv_val ) {
		strcpy( ptr, bc.bv_val );
		ch_free( bc.bv_val );
	}

	if ( ri->ri_nsuffix ) {
		for (i=0; !BER_BVISNULL( &ri->ri_nsuffix[i] ); i++) {
			ptr = lutil_strcopy( ptr, " suffix=\"" );
			ptr = lutil_strcopy( ptr, ri->ri_nsuffix[i].bv_val );
			*ptr++ = '"';
		}
	}
	if ( ri->ri_attrs ) {
		ptr = lutil_strcopy( ptr, " attrs" );
		if ( ri->ri_exclude ) *ptr++ = '!';
		*ptr++ = '=';
		ptr = anlist_unparse( ri->ri_attrs, ptr );
	}
}

static int
config_replica(ConfigArgs *c) {
	int i, nr = -1;
	char *replicahost = NULL, *replicauri = NULL;
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		/* FIXME: there is no replica_free function */
		if ( c->valx < 0 ) {
		} else {
		}
	}
	if(SLAP_MONITOR(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: "
			"\"replica\" should not be used inside monitor database\n",
			c->log, 0, 0);
		return(0);	/* FIXME: should this be an error? */
	}

	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "host=", STRLENOF("host="))) {
			ber_len_t	len;

			if ( replicauri ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> replica host/URI already specified", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n", c->log, c->msg, replicauri );
				return(1);
			}

			replicahost = c->argv[i] + STRLENOF("host=");
			len = strlen( replicahost ) + STRLENOF("ldap://");
			replicauri = ch_malloc( len + 1 );
			snprintf( replicauri, len + 1, "ldap://%s", replicahost );
			replicahost = replicauri + STRLENOF( "ldap://");
			nr = add_replica_info(c->be, replicauri, replicahost);
			break;
		} else if(!strncasecmp(c->argv[i], "uri=", STRLENOF("uri="))) {
			ber_len_t	len;

			if ( replicauri ) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> replica host/URI already specified", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n", c->log, c->msg, replicauri );
				return(1);
			}

			if(ldap_url_parse(c->argv[i] + STRLENOF("uri="), &ludp) != LDAP_SUCCESS) {
				snprintf( c->msg, sizeof( c->msg ), "<%s> invalid uri", c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->msg, 0 );
				return(1);
			}
			if(!ludp->lud_host) {
				ldap_free_urldesc(ludp);
				snprintf( c->msg, sizeof( c->msg ), "<%s> invalid uri - missing hostname",
					c->argv[0] );
				Debug(LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->msg, 0 );
				return(1);
			}

			len = strlen(ludp->lud_scheme) + strlen(ludp->lud_host) +
				STRLENOF("://") + 1;
			if (ludp->lud_port != LDAP_PORT) {
				if (ludp->lud_port < 1 || ludp->lud_port > 65535) {
					ldap_free_urldesc(ludp);
					snprintf( c->msg, sizeof( c->msg ), "<%s> invalid port",
						c->argv[0] );
					Debug(LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->msg, 0 );
					return(1);
				}
				len += STRLENOF(":65535");
			}
			replicauri = ch_malloc( len );
			replicahost = lutil_strcopy( replicauri, ludp->lud_scheme );
			replicahost = lutil_strcopy( replicahost, "://" );
			if (ludp->lud_port == LDAP_PORT) {
				strcpy( replicahost, ludp->lud_host );
			} else {
				sprintf( replicahost, "%s:%d",ludp->lud_host,ludp->lud_port );
			}
			ldap_free_urldesc(ludp);
			nr = add_replica_info(c->be, replicauri, replicahost);
			break;
		}
	}
	if(i == c->argc) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> missing host or uri", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s\n", c->log, c->msg, 0 );
		return(1);
	} else if(nr == -1) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> unable to add replica", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n", c->log, c->msg,
			replicauri ? replicauri : "" );
		return(1);
	} else {
		for(i = 1; i < c->argc; i++) {
			if(!strncasecmp(c->argv[i], "uri=", STRLENOF("uri="))) {
				/* dealt with separately; don't let it get to bindconf */
				;

			} else if(!strncasecmp(c->argv[i], "host=", STRLENOF("host="))) {
				/* dealt with separately; don't let it get to bindconf */
				;


			} else if(!strncasecmp(c->argv[i], "suffix=", STRLENOF( "suffix="))) {
				switch(add_replica_suffix(c->be, nr, c->argv[i] + STRLENOF("suffix="))) {
					case 1:
						Debug( SLAPD_DEBUG_CONFIG_ERROR, "%s: "
						"suffix \"%s\" in \"replica\" line is not valid for backend"
						SLAPD_CONF_UNKNOWN_IGNORED ".\n",
						c->log, c->argv[i] + STRLENOF("suffix="), 0);
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
						return 1;
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */
						break;
					case 2:
						Debug( SLAPD_DEBUG_CONFIG_ERROR, "%s: "
						"unable to normalize suffix in \"replica\" line"
						SLAPD_CONF_UNKNOWN_IGNORED ".\n",
						c->log, 0, 0);
#ifdef SLAPD_CONF_UNKNOWN_BAILOUT
						return 1;
#endif /* SLAPD_CONF_UNKNOWN_BAILOUT */
						break;
				}

			} else if (!strncasecmp(c->argv[i], "attr", STRLENOF("attr"))
				|| !strncasecmp(c->argv[i], "attrs", STRLENOF("attrs")))
			{
				int exclude = 0;
				char *arg = c->argv[i] + STRLENOF("attr");
				if (arg[0] == 's') {
					arg++;
				} else {
					Debug( LDAP_DEBUG_ANY,
						"%s: \"attr\" "
						"is deprecated (and undocumented); "
						"use \"attrs\" instead.\n",
						c->log, 0, 0 );
				}
				if(arg[0] == '!') {
					arg++;
					exclude = 1;
				}
				if(arg[0] != '=') {
					continue;
				}
				if(add_replica_attrs(c->be, nr, arg + 1, exclude)) {
					snprintf( c->msg, sizeof( c->msg ), "<%s> unknown attribute", c->argv[0] );
					Debug(LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
						c->log, c->msg, arg + 1);
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
	if (c->op == SLAP_CONFIG_EMIT) {
		if (!BER_BVISEMPTY(&c->be->be_update_ndn)) {
			value_add_one(&c->rvalue_vals, &c->be->be_update_ndn);
			value_add_one(&c->rvalue_nvals, &c->be->be_update_ndn);
			return 0;
		}
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
		ch_free( c->be->be_update_ndn.bv_val );
		BER_BVZERO( &c->be->be_update_ndn );
		SLAP_DBFLAGS(c->be) ^= (SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SLURP_SHADOW);
		return 0;
	}
	if(SLAP_SHADOW(c->be)) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> database already shadowed", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s\n",
			c->log, c->msg, 0);
		return(1);
	}

	ber_memfree_x( c->value_dn.bv_val, NULL );
	if ( !BER_BVISNULL( &c->be->be_update_ndn ) ) {
		ber_memfree_x( c->be->be_update_ndn.bv_val, NULL );
	}
	c->be->be_update_ndn = c->value_ndn;
	BER_BVZERO( &c->value_dn );
	BER_BVZERO( &c->value_ndn );

	return config_slurp_shadow( c );
}

int
config_shadow( ConfigArgs *c, int flag )
{
	char	*notallowed = NULL;

	if ( c->be == frontendDB ) {
		notallowed = "frontend";

	} else if ( SLAP_MONITOR(c->be) ) {
		notallowed = "monitor";

	} else if ( SLAP_CONFIG(c->be) ) {
		notallowed = "config";
	}

	if ( notallowed != NULL ) {
		Debug( LDAP_DEBUG_ANY, "%s: %s database cannot be shadow.\n", c->log, notallowed, 0 );
		return 1;
	}

	SLAP_DBFLAGS(c->be) |= (SLAP_DBFLAG_SHADOW | flag);

	return 0;
}

static int
config_updateref(ConfigArgs *c) {
	struct berval val;
	if (c->op == SLAP_CONFIG_EMIT) {
		if ( c->be->be_update_refs ) {
			value_add( &c->rvalue_vals, c->be->be_update_refs );
			return 0;
		} else {
			return 1;
		}
	} else if ( c->op == LDAP_MOD_DELETE ) {
		if ( c->valx < 0 ) {
			ber_bvarray_free( c->be->be_update_refs );
			c->be->be_update_refs = NULL;
		} else {
			int i = c->valx;
			ch_free( c->be->be_update_refs[i].bv_val );
			for (; c->be->be_update_refs[i].bv_val; i++)
				c->be->be_update_refs[i] = c->be->be_update_refs[i+1];
		}
		return 0;
	}
	if(!SLAP_SHADOW(c->be)) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> must appear after syncrepl or updatedn",
			c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s\n",
			c->log, c->msg, 0);
		return(1);
	}

	if(validate_global_referral(c->argv[1])) {
		snprintf( c->msg, sizeof( c->msg ), "<%s> invalid URL", c->argv[0] );
		Debug(LDAP_DEBUG_ANY, "%s: %s (%s)\n",
			c->log, c->msg, c->argv[1]);
		return(1);
	}
	ber_str2bv(c->argv[1], 0, 0, &val);
	if(value_add_one(&c->be->be_update_refs, &val)) return(LDAP_OTHER);
	return(0);
}

static int
config_include(ConfigArgs *c) {
	int savelineno = c->lineno;
	int rc;
	ConfigFile *cf;
	ConfigFile *cfsave = cfn;
	ConfigFile *cf2 = NULL;
	if (c->op == SLAP_CONFIG_EMIT) {
		if (c->private) {
			ConfigFile *cf = c->private;
			value_add_one( &c->rvalue_vals, &cf->c_file );
			return 0;
		}
		return 1;
	} else if ( c->op == LDAP_MOD_DELETE ) {
	}
	cf = ch_calloc( 1, sizeof(ConfigFile));
	if ( cfn->c_kids ) {
		for (cf2=cfn->c_kids; cf2 && cf2->c_sibs; cf2=cf2->c_sibs) ;
		cf2->c_sibs = cf;
	} else {
		cfn->c_kids = cf;
	}
	cfn = cf;
	ber_str2bv( c->argv[1], 0, 1, &cf->c_file );
	rc = read_config_file(c->argv[1], c->depth + 1, c, config_back_cf_table);
	c->lineno = savelineno - 1;
	cfn = cfsave;
	if ( rc ) {
		if ( cf2 ) cf2->c_sibs = NULL;
		else cfn->c_kids = NULL;
		ch_free( cf->c_file.bv_val );
		ch_free( cf );
	} else {
		c->private = cf;
	}
	return(rc);
}

#ifdef HAVE_TLS
static int
config_tls_option(ConfigArgs *c) {
	int flag;
	switch(c->type) {
	case CFG_TLS_RAND:	flag = LDAP_OPT_X_TLS_RANDOM_FILE;	break;
	case CFG_TLS_CIPHER:	flag = LDAP_OPT_X_TLS_CIPHER_SUITE;	break;
	case CFG_TLS_CERT_FILE:	flag = LDAP_OPT_X_TLS_CERTFILE;		break;	
	case CFG_TLS_CERT_KEY:	flag = LDAP_OPT_X_TLS_KEYFILE;		break;
	case CFG_TLS_CA_PATH:	flag = LDAP_OPT_X_TLS_CACERTDIR;	break;
	case CFG_TLS_CA_FILE:	flag = LDAP_OPT_X_TLS_CACERTFILE;	break;
	case CFG_TLS_DH_FILE:	flag = LDAP_OPT_X_TLS_DHFILE;	break;
	default:		Debug(LDAP_DEBUG_ANY, "%s: "
					"unknown tls_option <0x%x>\n",
					c->log, c->type, 0);
		return 1;
	}
	if (c->op == SLAP_CONFIG_EMIT) {
		return ldap_pvt_tls_get_option( NULL, flag, &c->value_string );
	} else if ( c->op == LDAP_MOD_DELETE ) {
		return ldap_pvt_tls_set_option( NULL, flag, NULL );
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
	case CFG_TLS_CRLCHECK:	flag = LDAP_OPT_X_TLS_CRLCHECK;		keys = crlkeys;	break;
	case CFG_TLS_VERIFY:	flag = LDAP_OPT_X_TLS_REQUIRE_CERT;	keys = vfykeys;	break;
	default:
		Debug(LDAP_DEBUG_ANY, "%s: "
				"unknown tls_option <0x%x>\n",
				c->log, c->type, 0);
		return 1;
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
	} else if ( c->op == LDAP_MOD_DELETE ) {
		int i = 0;
		return ldap_pvt_tls_set_option( NULL, flag, &i );
	}
	ch_free( c->value_string );
	if ( isdigit( (unsigned char)c->argv[1][0] ) ) {
		if ( lutil_atoi( &i, c->argv[1] ) != 0 ) {
			Debug(LDAP_DEBUG_ANY, "%s: "
				"unable to parse %s \"%s\"\n",
				c->log, c->argv[0], c->argv[1] );
			return 1;
		}
		return(ldap_pvt_tls_set_option(NULL, flag, &i));
	} else {
		return(ldap_int_tls_config(NULL, flag, c->argv[1]));
	}
}
#endif

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
		cdn.bv_val = c;
		if ( *c == ',' )
			cdn.bv_val++;
		cdn.bv_len = dn->bv_len - (cdn.bv_val - dn->bv_val);

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

typedef struct setup_cookie {
	CfBackInfo *cfb;
	ConfigArgs *ca;
} setup_cookie;

static int
config_ldif_resp( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		setup_cookie *sc = op->o_callback->sc_private;

		sc->cfb->cb_got_ldif = 1;
		rs->sr_err = config_add_internal( sc->cfb, rs->sr_entry, sc->ca, NULL, NULL );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY, "config error processing %s: %s\n",
				rs->sr_entry->e_name.bv_val, sc->ca->msg, 0 );
		}
	}
	return rs->sr_err;
}

/* Configure and read the underlying back-ldif store */
static int
config_setup_ldif( BackendDB *be, const char *dir, int readit ) {
	CfBackInfo *cfb = be->be_private;
	ConfigArgs c = {0};
	ConfigTable *ct;
	char *argv[3];
	int rc = 0;
	setup_cookie sc;
	slap_callback cb = { NULL, config_ldif_resp, NULL, NULL };
	Connection conn = {0};
	OperationBuffer opbuf;
	Operation *op;
	SlapReply rs = {REP_RESULT};
	Filter filter = { LDAP_FILTER_PRESENT };
	struct berval filterstr = BER_BVC("(objectclass=*)");
	struct stat st;

	/* Is the config directory available? */
	if ( stat( dir, &st ) < 0 ) {
		/* No, so don't bother using the backing store.
		 * All changes will be in-memory only.
		 */
		return 0;
	}
		
	cfb->cb_db.bd_info = backend_info( "ldif" );
	if ( !cfb->cb_db.bd_info )
		return 0;	/* FIXME: eventually this will be a fatal error */

	if ( backend_db_init( "ldif", &cfb->cb_db ) == NULL )
		return 1;

	cfb->cb_db.be_suffix = be->be_suffix;
	cfb->cb_db.be_nsuffix = be->be_nsuffix;

	/* The suffix is always "cn=config". The underlying DB's rootdn
	 * is always the same as the suffix.
	 */
	cfb->cb_db.be_rootdn = be->be_suffix[0];
	cfb->cb_db.be_rootndn = be->be_nsuffix[0];

	ber_str2bv( dir, 0, 1, &cfdir );

	c.be = &cfb->cb_db;
	c.fname = "slapd";
	c.argc = 2;
	argv[0] = "directory";
	argv[1] = (char *)dir;
	argv[2] = NULL;
	c.argv = argv;
	c.table = Cft_Database;

	ct = config_find_keyword( c.be->be_cf_ocs->co_table, &c );
	if ( !ct )
		return 1;

	if ( config_add_vals( ct, &c ))
		return 1;

	if ( backend_startup_one( &cfb->cb_db ))
		return 1;

	if ( readit ) {
		void *thrctx = ldap_pvt_thread_pool_context();

		op = (Operation *) &opbuf;
		connection_fake_init( &conn, op, thrctx );

		filter.f_desc = slap_schema.si_ad_objectClass;

		op->o_tag = LDAP_REQ_SEARCH;

		op->ors_filter = &filter;
		op->ors_filterstr = filterstr;
		op->ors_scope = LDAP_SCOPE_SUBTREE;

		op->o_dn = c.be->be_rootdn;
		op->o_ndn = c.be->be_rootndn;

		op->o_req_dn = be->be_suffix[0];
		op->o_req_ndn = be->be_nsuffix[0];

		op->ors_tlimit = SLAP_NO_LIMIT;
		op->ors_slimit = SLAP_NO_LIMIT;

		op->ors_attrs = slap_anlist_all_attributes;
		op->ors_attrsonly = 0;

		op->o_callback = &cb;
		sc.cfb = cfb;
		sc.ca = &c;
		cb.sc_private = &sc;

		op->o_bd = &cfb->cb_db;
		rc = op->o_bd->be_search( op, &rs );

		ldap_pvt_thread_pool_context_reset( thrctx );
	}

	/* ITS#4194 - only use if it's present, or we're converting. */
	if ( !readit || rc == LDAP_SUCCESS )
		cfb->cb_use_ldif = 1;

	return rc;
}

static int
CfOc_cmp( const void *c1, const void *c2 ) {
	const ConfigOCs *co1 = c1;
	const ConfigOCs *co2 = c2;

	return ber_bvcmp( co1->co_name, co2->co_name );
}

int
config_register_schema(ConfigTable *ct, ConfigOCs *ocs) {
	int i;

	i = init_config_attrs( ct );
	if ( i ) return i;

	/* set up the objectclasses */
	i = init_config_ocs( ocs );
	if ( i ) return i;

	for (i=0; ocs[i].co_def; i++) {
		if ( ocs[i].co_oc ) {
			ocs[i].co_name = &ocs[i].co_oc->soc_cname;
			if ( !ocs[i].co_table )
				ocs[i].co_table = ct;
			avl_insert( &CfOcTree, &ocs[i], CfOc_cmp, avl_dup_error );
		}
	}
	return 0;
}

int
read_config(const char *fname, const char *dir) {
	BackendDB *be;
	CfBackInfo *cfb;
	const char *cfdir, *cfname;
	int rc;

	/* Setup the config backend */
	be = backend_db_init( "config", NULL );
	if ( !be )
		return 1;

	cfb = be->be_private;

	/* If no .conf, or a dir was specified, setup the dir */
	if ( !fname || dir ) {
		if ( dir ) {
			/* If explicitly given, check for existence */
			struct stat st;

			if ( stat( dir, &st ) < 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"invalid config directory %s, error %d\n",
						dir, errno, 0 );
				return 1;
			}
			cfdir = dir;
		} else {
			cfdir = SLAPD_DEFAULT_CONFIGDIR;
		}
		/* if fname is defaulted, try reading .d */
		rc = config_setup_ldif( be, cfdir, !fname );

		if ( rc ) {
			/* It may be OK if the base object doesn't exist yet. */
			if ( rc != LDAP_NO_SUCH_OBJECT )
				return 1;
			/* ITS#4194: But if dir was specified and no fname,
			 * then we were supposed to read the dir. Unless we're
			 * trying to slapadd the dir...
			 */
			if ( dir && !fname ) {
				if ( slapMode & (SLAP_SERVER_MODE|SLAP_TOOL_READMAIN|SLAP_TOOL_READONLY))
					return 1;
				/* Assume it's slapadd with a config dir, let it continue */
				rc = 0;
				cfb->cb_got_ldif = 1;
				cfb->cb_use_ldif = 1;
				goto done;
			}
		}

		/* If we read the config from back-ldif, nothing to do here */
		if ( cfb->cb_got_ldif ) {
			rc = 0;
			goto done;
		}
	}

	if ( fname )
		cfname = fname;
	else
		cfname = SLAPD_DEFAULT_CONFIGFILE;

	rc = read_config_file(cfname, 0, NULL, config_back_cf_table);

	if ( rc == 0 )
		ber_str2bv( cfname, 0, 1, &cfb->cb_config->c_file );

done:
	if ( rc == 0 && BER_BVISNULL( &frontendDB->be_schemadn ) ) {
		ber_str2bv( SLAPD_SCHEMA_DN, STRLENOF( SLAPD_SCHEMA_DN ), 1,
			&frontendDB->be_schemadn );
		rc = dnNormalize( 0, NULL, NULL, &frontendDB->be_schemadn, &frontendDB->be_schemandn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug(LDAP_DEBUG_ANY, "read_config: "
				"unable to normalize default schema DN \"%s\"\n",
				frontendDB->be_schemadn.bv_val, 0, 0 );
			/* must not happen */
			assert( 0 );
		}
	}
	return rc;
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
		rs->sr_flags = 0;
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
config_find_table( ConfigOCs **colst, int nocs, AttributeDescription *ad,
	ConfigArgs *ca )
{
	int i, j;

	for (j=0; j<nocs; j++) {
		for (i=0; colst[j]->co_table[i].name; i++)
			if ( colst[j]->co_table[i].ad == ad ) {
				ca->table = colst[j]->co_type;
				return &colst[j]->co_table[i];
			}
	}
	return NULL;
}

/* Sort the attributes of the entry according to the order defined
 * in the objectclass, with required attributes occurring before
 * allowed attributes. For any attributes with sequencing dependencies
 * (e.g., rootDN must be defined after suffix) the objectclass must
 * list the attributes in the desired sequence.
 */
static void
sort_attrs( Entry *e, ConfigOCs **colst, int nocs )
{
	Attribute *a, *head = NULL, *tail = NULL, **prev;
	int i, j;

	for (i=0; i<nocs; i++) {
		if ( colst[i]->co_oc->soc_required ) {
			AttributeType **at = colst[i]->co_oc->soc_required;
			for (j=0; at[j]; j++) {
				for (a=e->e_attrs, prev=&e->e_attrs; a;
					prev = &(*prev)->a_next, a=a->a_next) {
					if ( a->a_desc == at[j]->sat_ad ) {
						*prev = a->a_next;
						if (!head) {
							head = a;
							tail = a;
						} else {
							tail->a_next = a;
							tail = a;
						}
						break;
					}
				}
			}
		}
		if ( colst[i]->co_oc->soc_allowed ) {
			AttributeType **at = colst[i]->co_oc->soc_allowed;
			for (j=0; at[j]; j++) {
				for (a=e->e_attrs, prev=&e->e_attrs; a;
					prev = &(*prev)->a_next, a=a->a_next) {
					if ( a->a_desc == at[j]->sat_ad ) {
						*prev = a->a_next;
						if (!head) {
							head = a;
							tail = a;
						} else {
							tail->a_next = a;
							tail = a;
						}
						break;
					}
				}
			}
		}
	}
	if ( tail ) {
		tail->a_next = e->e_attrs;
		e->e_attrs = head;
	}
}

static int
check_vals( ConfigTable *ct, ConfigArgs *ca, void *ptr, int isAttr )
{
	Attribute *a = NULL;
	AttributeDescription *ad;
	BerVarray vals;

	int i, rc = 0, sort = 0;

	if ( isAttr ) {
		a = ptr;
		ad = a->a_desc;
		vals = a->a_vals;
	} else {
		Modifications *ml = ptr;
		ad = ml->sml_desc;
		vals = ml->sml_values;
	}

	if ( a && ( ad->ad_type->sat_flags & SLAP_AT_ORDERED_VAL )) {
		sort = 1;
		rc = ordered_value_sort( a, 1 );
		if ( rc ) {
			snprintf(ca->msg, sizeof( ca->msg ), "ordered_value_sort failed on attr %s\n",
				ad->ad_cname.bv_val );
			return rc;
		}
	}
	for ( i=0; vals[i].bv_val; i++ ) {
		ca->line = vals[i].bv_val;
		if ( sort ) {
			char *idx = strchr( ca->line, '}' );
			if ( idx ) ca->line = idx+1;
		}
		rc = config_parse_vals( ct, ca, i );
		if ( rc ) {
			break;
		}
	}
	return rc;
}

static int
check_name_index( CfEntryInfo *parent, ConfigType ce_type, Entry *e,
	SlapReply *rs, int *renum )
{
	CfEntryInfo *ce;
	int index = -1, gotindex = 0, nsibs;
	int renumber = 0, tailindex = 0;
	char *ptr1, *ptr2 = NULL;
	struct berval rdn;

	if ( renum ) *renum = 0;

	/* These entries don't get indexed/renumbered */
	if ( ce_type == Cft_Global ) return 0;
	if ( ce_type == Cft_Schema && parent->ce_type == Cft_Global ) return 0;

	if ( ce_type == Cft_Include || ce_type == Cft_Module )
		tailindex = 1;

	/* See if the rdn has an index already */
	dnRdn( &e->e_name, &rdn );
	ptr1 = ber_bvchr( &e->e_name, '{' );
	if ( ptr1 && ptr1 - e->e_name.bv_val < rdn.bv_len ) {
		char	*next;
		ptr2 = strchr( ptr1, '}' );
		if (!ptr2 || ptr2 - e->e_name.bv_val > rdn.bv_len)
			return LDAP_NAMING_VIOLATION;
		if ( ptr2-ptr1 == 1)
			return LDAP_NAMING_VIOLATION;
		gotindex = 1;
		index = strtol( ptr1 + 1, &next, 10 );
		if ( next == ptr1 + 1 || next[ 0 ] != '}' ) {
			return LDAP_NAMING_VIOLATION;
		}
		if ( index < 0 ) {
			/* Special case, we allow -1 for the frontendDB */
			if ( index != -1 || ce_type != Cft_Database ||
				strncmp( ptr2+1, "frontend,", STRLENOF("frontend,") ))

				return LDAP_NAMING_VIOLATION;
		}
	}

	/* count related kids */
	for (nsibs=0, ce=parent->ce_kids; ce; ce=ce->ce_sibs) {
		if ( ce->ce_type == ce_type ) nsibs++;
	}

	if ( index != nsibs ) {
		if ( gotindex ) {
			if ( index < nsibs ) {
				if ( tailindex ) return LDAP_NAMING_VIOLATION;
				/* Siblings need to be renumbered */
				renumber = 1;
			}
		}
		if ( !renumber ) {
			struct berval ival, newrdn, nnewrdn;
			struct berval rtype, rval;
			Attribute *a;
			AttributeDescription *ad = NULL;
			char ibuf[32];
			const char *text;

			rval.bv_val = strchr(rdn.bv_val, '=' ) + 1;
			rval.bv_len = rdn.bv_len - (rval.bv_val - rdn.bv_val);
			rtype.bv_val = rdn.bv_val;
			rtype.bv_len = rval.bv_val - rtype.bv_val - 1;

			/* Find attr */
			slap_bv2ad( &rtype, &ad, &text );
			a = attr_find( e->e_attrs, ad );
			if (!a ) return LDAP_NAMING_VIOLATION;

			ival.bv_val = ibuf;
			ival.bv_len = snprintf( ibuf, sizeof( ibuf ), SLAP_X_ORDERED_FMT, nsibs );
			if ( ival.bv_len >= sizeof( ibuf ) ) {
				return LDAP_NAMING_VIOLATION;
			}
			
			newrdn.bv_len = rdn.bv_len + ival.bv_len;
			newrdn.bv_val = ch_malloc( newrdn.bv_len+1 );

			if ( tailindex ) {
				ptr1 = lutil_strncopy( newrdn.bv_val, rdn.bv_val, rdn.bv_len );
				ptr1 = lutil_strcopy( ptr1, ival.bv_val );
			} else {
				int xlen;
				if ( !gotindex ) {
					ptr2 = rval.bv_val;
					xlen = rval.bv_len;
				} else {
					xlen = rdn.bv_len - (ptr2 - rdn.bv_val);
				}
				ptr1 = lutil_strncopy( newrdn.bv_val, rtype.bv_val,
					rtype.bv_len );
				*ptr1++ = '=';
				ptr1 = lutil_strcopy( ptr1, ival.bv_val );
				ptr1 = lutil_strncopy( ptr1, ptr2, xlen );
				*ptr1 = '\0';
			}

			/* Do the equivalent of ModRDN */
			/* Replace DN / NDN */
			newrdn.bv_len = ptr1 - newrdn.bv_val;
			rdnNormalize( 0, NULL, NULL, &newrdn, &nnewrdn, NULL );
			free( e->e_name.bv_val );
			build_new_dn( &e->e_name, &parent->ce_entry->e_name,
				&newrdn, NULL );
			free( e->e_nname.bv_val );
			build_new_dn( &e->e_nname, &parent->ce_entry->e_nname,
				&nnewrdn, NULL );

			/* Replace attr */
			free( a->a_vals[0].bv_val );
			ptr1 = strchr( newrdn.bv_val, '=' ) + 1;
			a->a_vals[0].bv_len = newrdn.bv_len - (ptr1 - newrdn.bv_val);
			a->a_vals[0].bv_val = ch_malloc( a->a_vals[0].bv_len + 1 );
			strcpy( a->a_vals[0].bv_val, ptr1 );

			if ( a->a_nvals != a->a_vals ) {
				free( a->a_nvals[0].bv_val );
				ptr1 = strchr( nnewrdn.bv_val, '=' ) + 1;
				a->a_nvals[0].bv_len = nnewrdn.bv_len - (ptr1 - nnewrdn.bv_val);
				a->a_nvals[0].bv_val = ch_malloc( a->a_nvals[0].bv_len + 1 );
				strcpy( a->a_nvals[0].bv_val, ptr1 );
			}
			free( nnewrdn.bv_val );
			free( newrdn.bv_val );
		}
	}
	if ( renum ) *renum = renumber;
	return 0;
}

static ConfigOCs **
count_ocs( Attribute *oc_at, int *nocs )
{
	int i, j, n;
	ConfigOCs co, *coptr, **colst;

	/* count the objectclasses */
	for ( i=0; oc_at->a_nvals[i].bv_val; i++ );
	n = i;
	colst = (ConfigOCs **)ch_malloc( n * sizeof(ConfigOCs *));

	for ( i=0, j=0; i<n; i++) {
		co.co_name = &oc_at->a_nvals[i];
		coptr = avl_find( CfOcTree, &co, CfOc_cmp );
		
		/* ignore non-config objectclasses. probably should be
		 * an error, general data doesn't belong here.
		 */
		if ( !coptr ) continue;

		/* Ignore the root objectclass, it has no implementation.
		 */
		if ( coptr->co_type == Cft_Abstract ) continue;
		colst[j++] = coptr;
	}
	*nocs = j;
	return colst;
}

static int
cfAddInclude( CfEntryInfo *p, Entry *e, ConfigArgs *ca )
{
	if ( p->ce_type != Cft_Global && p->ce_type != Cft_Include )
		return LDAP_CONSTRAINT_VIOLATION;

	/* If we're reading from a configdir, don't parse this entry */
	if ( ca->lineno )
		return LDAP_COMPARE_TRUE;

	cfn = p->ce_private;
	ca->private = cfn;
	return LDAP_SUCCESS;
}

static int
cfAddSchema( CfEntryInfo *p, Entry *e, ConfigArgs *ca )
{
	ConfigFile *cfo;

	/* This entry is hardcoded, don't re-parse it */
	if ( p->ce_type == Cft_Global ) {
		cfn = p->ce_private;
		ca->private = cfn;
		return LDAP_COMPARE_TRUE;
	}
	if ( p->ce_type != Cft_Schema )
		return LDAP_CONSTRAINT_VIOLATION;

	cfn = ch_calloc( 1, sizeof(ConfigFile) );
	ca->private = cfn;
	cfo = p->ce_private;
	cfn->c_sibs = cfo->c_kids;
	cfo->c_kids = cfn;
	return LDAP_SUCCESS;
}

static int
cfAddDatabase( CfEntryInfo *p, Entry *e, struct config_args_s *ca )
{
	if ( p->ce_type != Cft_Global )
		return LDAP_CONSTRAINT_VIOLATION;
	ca->be = frontendDB;	/* just to get past check_vals */
	return LDAP_SUCCESS;
}

static int
cfAddBackend( CfEntryInfo *p, Entry *e, struct config_args_s *ca )
{
	if ( p->ce_type != Cft_Global )
		return LDAP_CONSTRAINT_VIOLATION;
	return LDAP_SUCCESS;
}

static int
cfAddModule( CfEntryInfo *p, Entry *e, struct config_args_s *ca )
{
	if ( p->ce_type != Cft_Global )
		return LDAP_CONSTRAINT_VIOLATION;
	return LDAP_SUCCESS;
}

static int
cfAddOverlay( CfEntryInfo *p, Entry *e, struct config_args_s *ca )
{
	if ( p->ce_type != Cft_Database )
		return LDAP_CONSTRAINT_VIOLATION;
	ca->be = p->ce_be;
	return LDAP_SUCCESS;
}

/* Parse an LDAP entry into config directives */
static int
config_add_internal( CfBackInfo *cfb, Entry *e, ConfigArgs *ca, SlapReply *rs, int *renum )
{
	CfEntryInfo *ce, *last;
	ConfigOCs **colst;
	Attribute *a, *oc_at;
	int i, nocs, rc = 0;
	struct berval pdn;
	ConfigTable *ct;
	char *ptr;

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

	memset( ca, 0, sizeof(ConfigArgs));

	/* Fake the coordinates based on whether we're part of an
	 * LDAP Add or if reading the config dir
	 */
	if ( rs ) {
		ca->fname = "slapd";
		ca->lineno = 0;
	} else {
		ca->fname = cfdir.bv_val;
		ca->lineno = 1;
	}

	colst = count_ocs( oc_at, &nocs );

	/* Only the root can be Cft_Global, everything else must
	 * have a parent. Only limited nesting arrangements are allowed.
	 */
	rc = LDAP_CONSTRAINT_VIOLATION;
	if ( colst[0]->co_type == Cft_Global && !last ) {
		cfn = cfb->cb_config;
		ca->private = cfn;
		ca->be = frontendDB;	/* just to get past check_vals */
		rc = LDAP_SUCCESS;
	}

	/* Check whether the Add is allowed by its parent, and do
	 * any necessary arg setup
	 */
	if ( last ) {
		for ( i=0; i<nocs; i++ ) {
			if ( colst[i]->co_ldadd &&
				( rc = colst[i]->co_ldadd( last, e, ca ))
					!= LDAP_CONSTRAINT_VIOLATION ) {
				break;
			}
		}
	}

	/* Add the entry but don't parse it, we already have its contents */
	if ( rc == LDAP_COMPARE_TRUE ) {
		rc = LDAP_SUCCESS;
		goto ok;
	}

	if ( rc != LDAP_SUCCESS )
		goto done;

	/* Parse all the values and check for simple syntax errors before
	 * performing any set actions.
	 *
	 * If doing an LDAPadd, check for indexed names and any necessary
	 * renaming/renumbering. Entries that don't need indexed names are
	 * ignored. Entries that need an indexed name and arrive without one
	 * are assigned to the end. Entries that arrive with an index may
	 * cause the following entries to be renumbered/bumped down.
	 *
	 * Note that "pseudo-indexed" entries (cn=Include{xx}, cn=Module{xx})
	 * don't allow Adding an entry with an index that's already in use.
	 * This is flagged as an error (LDAP_ALREADY_EXISTS) up above.
	 *
	 * These entries can have auto-assigned indexes (appended to the end)
	 * but only the other types support auto-renumbering of siblings.
	 */
	rc = check_name_index( last, colst[0]->co_type, e, rs, renum );
	if ( rc )
		goto done;

	init_config_argv( ca );

	/* Make sure we process attrs in the required order */
	sort_attrs( e, colst, nocs );

	for ( a=e->e_attrs; a; a=a->a_next ) {
		if ( a == oc_at ) continue;
		ct = config_find_table( colst, nocs, a->a_desc, ca );
		if ( !ct ) continue;	/* user data? */
		rc = check_vals( ct, ca, a, 1 );
		if ( rc ) goto done;
	}

	/* Basic syntax checks are OK. Do the actual settings. */
	for ( a=e->e_attrs; a; a=a->a_next ) {
		if ( a == oc_at ) continue;
		ct = config_find_table( colst, nocs, a->a_desc, ca );
		if ( !ct ) continue;	/* user data? */
		for (i=0; a->a_vals[i].bv_val; i++) {
			ca->line = a->a_vals[i].bv_val;
			if ( a->a_desc->ad_type->sat_flags & SLAP_AT_ORDERED ) {
				ptr = strchr( ca->line, '}' );
				if ( ptr ) ca->line = ptr+1;
			}
			ca->valx = i;
			rc = config_parse_add( ct, ca );
			if ( rc ) {
				rc = LDAP_OTHER;
				goto done;
			}
		}
	}
ok:
	/* Newly added databases and overlays need to be started up */
	if ( CONFIG_ONLINE_ADD( ca )) {
		if ( colst[0]->co_type == Cft_Database ) {
			rc = backend_startup_one( ca->be );

		} else if ( colst[0]->co_type == Cft_Overlay ) {
			if ( ca->bi->bi_db_open ) {
				BackendInfo *bi_orig = ca->be->bd_info;
				ca->be->bd_info = ca->bi;
				rc = ca->bi->bi_db_open( ca->be );
				ca->be->bd_info = bi_orig;
			}
		}
		if ( rc ) {
			snprintf( ca->msg, sizeof( ca->msg ), "<%s> failed startup", ca->argv[0] );
			Debug(LDAP_DEBUG_ANY, "%s: %s (%s)!\n",
				ca->log, ca->msg, ca->argv[1] );
			rc = LDAP_OTHER;
			goto done;
		}
	}

	ce = ch_calloc( 1, sizeof(CfEntryInfo) );
	ce->ce_parent = last;
	ce->ce_entry = entry_dup( e );
	ce->ce_entry->e_private = ce;
	ce->ce_type = colst[0]->co_type;
	ce->ce_be = ca->be;
	ce->ce_bi = ca->bi;
	ce->ce_private = ca->private;
	if ( !last ) {
		cfb->cb_root = ce;
	} else if ( last->ce_kids ) {
		CfEntryInfo *c2;

		for (c2=last->ce_kids; c2 && c2->ce_sibs; c2 = c2->ce_sibs);

		c2->ce_sibs = ce;
	} else {
		last->ce_kids = ce;
	}

done:
	if ( rc ) {
		if ( (colst[0]->co_type == Cft_Database) && ca->be ) {
			if ( ca->be != frontendDB )
				backend_destroy_one( ca->be, 1 );
		} else if ( (colst[0]->co_type == Cft_Overlay) && ca->bi ) {
			overlay_destroy_one( ca->be, (slap_overinst *)ca->bi );
		}
	}

	ch_free( ca->argv );
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
	int renumber;
	ConfigArgs ca;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto out;
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ldap_pvt_thread_pool_pause( &connection_pool );

	/* Strategy:
	 * 1) check for existence of entry
	 * 2) check for sibling renumbering
	 * 3) perform internal add
	 * 4) store entry in underlying database
	 * 5) perform any necessary renumbering
	 */
	rs->sr_err = config_add_internal( cfb, op->ora_e, &ca, rs, &renumber );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		rs->sr_text = ca.msg;
	} else if ( cfb->cb_use_ldif ) {
		BackendDB *be = op->o_bd;
		slap_callback sc = { NULL, slap_null_cb, NULL, NULL };
		struct berval dn, ndn;

		op->o_bd = &cfb->cb_db;

		/* Save current rootdn; use the underlying DB's rootdn */
		dn = op->o_dn;
		ndn = op->o_ndn;
		op->o_dn = op->o_bd->be_rootdn;
		op->o_ndn = op->o_bd->be_rootndn;

		sc.sc_next = op->o_callback;
		op->o_callback = &sc;
		op->o_bd->be_add( op, rs );
		op->o_bd = be;
		op->o_callback = sc.sc_next;
		op->o_dn = dn;
		op->o_ndn = ndn;
	}
	if ( renumber ) {
	}

	ldap_pvt_thread_pool_resume( &connection_pool );

out:
	send_ldap_result( op, rs );
	return rs->sr_err;
}

typedef struct delrec {
	struct delrec *next;
	int nidx;
	int idx[1];
} delrec;

static int
config_modify_internal( CfEntryInfo *ce, Operation *op, SlapReply *rs,
	ConfigArgs *ca )
{
	int rc = LDAP_UNWILLING_TO_PERFORM;
	Modifications *ml;
	Entry *e = ce->ce_entry;
	Attribute *save_attrs = e->e_attrs, *oc_at;
	ConfigTable *ct;
	ConfigOCs **colst;
	int i, nocs;
	char *ptr;
	delrec *dels = NULL, *deltail = NULL;

	oc_at = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	if ( !oc_at ) return LDAP_OBJECT_CLASS_VIOLATION;

	colst = count_ocs( oc_at, &nocs );

	e->e_attrs = attrs_dup( e->e_attrs );

	init_config_argv( ca );
	ca->be = ce->ce_be;
	ca->bi = ce->ce_bi;
	ca->private = ce->ce_private;
	ca->ca_entry = e;
	ca->fname = "slapd";
	strcpy( ca->log, "back-config" );

	for (ml = op->orm_modlist; ml; ml=ml->sml_next) {
		ct = config_find_table( colst, nocs, ml->sml_desc, ca );
		switch (ml->sml_op) {
		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE: {
			BerVarray vals = NULL, nvals = NULL;
			int *idx = NULL;
			if ( ct && ( ct->arg_type & ARG_NO_DELETE )) {
				rc = LDAP_OTHER;
				snprintf(ca->msg, sizeof(ca->msg), "cannot delete %s",
					ml->sml_desc->ad_cname.bv_val );
				goto out;
			}
			if ( ml->sml_op == LDAP_MOD_REPLACE ) {
				vals = ml->sml_values;
				nvals = ml->sml_nvalues;
				ml->sml_values = NULL;
				ml->sml_nvalues = NULL;
			}
			/* If we're deleting by values, remember the indexes of the
			 * values we deleted.
			 */
			if ( ct && ml->sml_values ) {
				delrec *d;
				for (i=0; ml->sml_values[i].bv_val; i++);
				d = ch_malloc( sizeof(delrec) + (i - 1)* sizeof(int));
				d->nidx = i;
				d->next = NULL;
				if ( dels ) {
					deltail->next = d;
				} else {
					dels = d;
				}
				deltail = d;
				idx = d->idx;
			}
			rc = modify_delete_vindex(e, &ml->sml_mod,
				get_permissiveModify(op),
				&rs->sr_text, ca->msg, sizeof(ca->msg), idx );
			if ( ml->sml_op == LDAP_MOD_REPLACE ) {
				ml->sml_values = vals;
				ml->sml_nvalues = nvals;
			}
			if ( !vals )
				break;
			}
			/* FALLTHRU: LDAP_MOD_REPLACE && vals */

		case LDAP_MOD_ADD:
		case SLAP_MOD_SOFTADD: {
			int mop = ml->sml_op;
			int navals = -1;
			ml->sml_op = LDAP_MOD_ADD;
			if ( ct ) {
				if ( ct->arg_type & ARG_NO_INSERT ) {
					Attribute *a = attr_find( e->e_attrs, ml->sml_desc );
					if ( a ) {
						for (i = 0; a->a_vals[i].bv_val; i++ );
						navals = i;
					}
				}
				for ( i=0; !BER_BVISNULL( &ml->sml_values[i] ); i++ ) {
					if ( ml->sml_values[i].bv_val[0] == '{' &&
						navals >= 0 )
					{
						char	*next, *val = ml->sml_values[i].bv_val + 1;
						int	j;

						j = strtol( val, &next, 0 );
						if ( next == val || next[ 0 ] != '}' || j < navals ) {
							rc = LDAP_OTHER;
							snprintf(ca->msg, sizeof(ca->msg), "cannot insert %s",
								ml->sml_desc->ad_cname.bv_val );
							goto out;
						}
					}
					rc = check_vals( ct, ca, ml, 0 );
					if ( rc ) goto out;
				}
			}
			rc = modify_add_values(e, &ml->sml_mod,
				   get_permissiveModify(op),
				   &rs->sr_text, ca->msg, sizeof(ca->msg) );

			/* If value already exists, show success here
			 * and ignore this operation down below.
			 */
			if ( mop == SLAP_MOD_SOFTADD ) {
				if ( rc == LDAP_TYPE_OR_VALUE_EXISTS )
					rc = LDAP_SUCCESS;
				else
					mop = LDAP_MOD_ADD;
			}
			ml->sml_op = mop;
			break;
			}

			break;
		case LDAP_MOD_INCREMENT:	/* FIXME */
			break;
		default:
			break;
		}
		if(rc != LDAP_SUCCESS) break;
	}
	
	if(rc == LDAP_SUCCESS) {
		/* check that the entry still obeys the schema */
		rc = entry_schema_check(op, e, NULL, 0,
			&rs->sr_text, ca->msg, sizeof(ca->msg) );
	}
	if ( rc == LDAP_SUCCESS ) {
		/* Basic syntax checks are OK. Do the actual settings. */
		for ( ml = op->orm_modlist; ml; ml = ml->sml_next ) {
			ct = config_find_table( colst, nocs, ml->sml_desc, ca );
			if ( !ct ) continue;

			switch (ml->sml_op) {
			case LDAP_MOD_DELETE:
			case LDAP_MOD_REPLACE: {
				BerVarray vals = NULL, nvals = NULL;
				Attribute *a;
				delrec *d = NULL;

				a = attr_find( e->e_attrs, ml->sml_desc );

				if ( ml->sml_op == LDAP_MOD_REPLACE ) {
					vals = ml->sml_values;
					nvals = ml->sml_nvalues;
					ml->sml_values = NULL;
					ml->sml_nvalues = NULL;
				}

				if ( ml->sml_values )
					d = dels;

				/* If we didn't delete the whole attribute */
				if ( ml->sml_values && a ) {
					struct berval *mvals;
					int j;

					if ( ml->sml_nvalues )
						mvals = ml->sml_nvalues;
					else
						mvals = ml->sml_values;

					/* use the indexes we saved up above */
					for (i=0; i < d->nidx; i++) {
						struct berval bv = *mvals++;
						if ( a->a_desc->ad_type->sat_flags & SLAP_AT_ORDERED &&
							bv.bv_val[0] == '{' ) {
							ptr = strchr( bv.bv_val, '}' ) + 1;
							bv.bv_len -= ptr - bv.bv_val;
							bv.bv_val = ptr;
						}
						ca->line = bv.bv_val;
						ca->valx = d->idx[i];
						rc = config_del_vals( ct, ca );
						if ( rc != LDAP_SUCCESS ) break;
						for (j=i+1; j < d->nidx; j++)
							if ( d->idx[j] >d->idx[i] )
								d->idx[j]--;
					}
				} else {
					ca->valx = -1;
					ca->line = NULL;
					rc = config_del_vals( ct, ca );
					if ( rc ) rc = LDAP_OTHER;
				}
				if ( ml->sml_values ) {
					ch_free( dels );
					dels = d->next;
				}
				if ( ml->sml_op == LDAP_MOD_REPLACE ) {
					ml->sml_values = vals;
					ml->sml_nvalues = nvals;
				}
				if ( !vals || rc != LDAP_SUCCESS )
					break;
				}
				/* FALLTHRU: LDAP_MOD_REPLACE && vals */

			case LDAP_MOD_ADD:
				for (i=0; ml->sml_values[i].bv_val; i++) {
					ca->line = ml->sml_values[i].bv_val;
					ca->valx = -1;
					if ( ml->sml_desc->ad_type->sat_flags & SLAP_AT_ORDERED &&
						ca->line[0] == '{' )
					{
						ptr = strchr( ca->line + 1, '}' );
						if ( ptr ) {
							char	*next;

							ca->valx = strtol( ca->line + 1, &next, 0 );
							if ( next == ca->line + 1 || next[ 0 ] != '}' ) {
								rc = LDAP_OTHER;
								goto out;
							}
							ca->line = ptr+1;
						}
					}
					rc = config_parse_add( ct, ca );
					if ( rc ) {
						rc = LDAP_OTHER;
						goto out;
					}
				}

				break;
			}
		}
	}

out:
	if ( ca->cleanup )
		ca->cleanup( ca );
	if ( rc == LDAP_SUCCESS ) {
		attrs_free( save_attrs );
	} else {
		attrs_free( e->e_attrs );
		e->e_attrs = save_attrs;
	}
	ch_free( ca->argv );
	if ( colst ) ch_free( colst );

	return rc;
}

static int
config_back_modify( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;
	Modifications *ml;
	ConfigArgs ca = {0};
	struct berval rdn;
	char *ptr;
	AttributeDescription *rad = NULL;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto out;
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ce = config_find_base( cfb->cb_root, &op->o_req_ndn, &last );
	if ( !ce ) {
		if ( last )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto out;
	}

	/* Get type of RDN */
	rdn = ce->ce_entry->e_nname;
	ptr = strchr( rdn.bv_val, '=' );
	rdn.bv_len = ptr - rdn.bv_val;
	slap_bv2ad( &rdn, &rad, &rs->sr_text );

	/* Some basic validation... */
	for ( ml = op->orm_modlist; ml; ml = ml->sml_next ) {
		/* Don't allow Modify of RDN; must use ModRdn for that. */
		if ( ml->sml_desc == rad ) {
			rs->sr_err = LDAP_NOT_ALLOWED_ON_RDN;
			rs->sr_text = "Use modrdn to change the entry name";
			goto out;
		}
	}

	ldap_pvt_thread_pool_pause( &connection_pool );

	/* Strategy:
	 * 1) perform the Modify on the cached Entry.
	 * 2) verify that the Entry still satisfies the schema.
	 * 3) perform the individual config operations.
	 * 4) store Modified entry in underlying LDIF backend.
	 */
	rs->sr_err = config_modify_internal( ce, op, rs, &ca );
	if ( rs->sr_err ) {
		rs->sr_text = ca.msg;
	} else if ( cfb->cb_use_ldif ) {
		BackendDB *be = op->o_bd;
		slap_callback sc = { NULL, slap_null_cb, NULL, NULL };
		struct berval dn, ndn;

		op->o_bd = &cfb->cb_db;

		dn = op->o_dn;
		ndn = op->o_ndn;
		op->o_dn = op->o_bd->be_rootdn;
		op->o_ndn = op->o_bd->be_rootndn;

		sc.sc_next = op->o_callback;
		op->o_callback = &sc;
		op->o_bd->be_modify( op, rs );
		op->o_bd = be;
		op->o_callback = sc.sc_next;
		op->o_dn = dn;
		op->o_ndn = ndn;
	}

	ldap_pvt_thread_pool_resume( &connection_pool );
out:
	send_ldap_result( op, rs );
	return rs->sr_err;
}

static int
config_back_modrdn( Operation *op, SlapReply *rs )
{
	CfBackInfo *cfb;
	CfEntryInfo *ce, *last;

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto out;
	}

	cfb = (CfBackInfo *)op->o_bd->be_private;

	ce = config_find_base( cfb->cb_root, &op->o_req_ndn, &last );
	if ( !ce ) {
		if ( last )
			rs->sr_matched = last->ce_entry->e_name.bv_val;
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto out;
	}

	/* We don't allow moving objects to new parents.
	 * Generally we only allow reordering a set of ordered entries.
	 */
	if ( op->orr_newSup ) {
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		goto out;
	}
	ldap_pvt_thread_pool_pause( &connection_pool );

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

	if ( !be_isroot( op ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto out;
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

static void
config_build_attrs( Entry *e, AttributeType **at, AttributeDescription *ad,
	ConfigTable *ct, ConfigArgs *c )
{
	int i, rc;

	for (; at && *at; at++) {
		/* Skip the naming attr */
		if ((*at)->sat_ad == ad || (*at)->sat_ad == slap_schema.si_ad_cn )
			continue;
		for (i=0;ct[i].name;i++) {
			if (ct[i].ad == (*at)->sat_ad) {
				rc = config_get_vals(&ct[i], c);
				/* NOTE: tolerate that config_get_vals()
				 * returns success with no values */
				if (rc == LDAP_SUCCESS && c->rvalue_vals != NULL ) {
					if ( c->rvalue_nvals )
						attr_merge(e, ct[i].ad, c->rvalue_vals,
							c->rvalue_nvals);
					else
						attr_merge_normalize(e, ct[i].ad,
							c->rvalue_vals, NULL);
					ber_bvarray_free( c->rvalue_nvals );
					ber_bvarray_free( c->rvalue_vals );
				}
				break;
			}
		}
	}
}

Entry *
config_build_entry( Operation *op, SlapReply *rs, CfEntryInfo *parent,
	ConfigArgs *c, struct berval *rdn, ConfigOCs *main, ConfigOCs *extra )
{
	Entry *e = ch_calloc( 1, sizeof(Entry) );
	CfEntryInfo *ce = ch_calloc( 1, sizeof(CfEntryInfo) );
	struct berval val;
	struct berval ad_name;
	AttributeDescription *ad = NULL;
	int rc;
	char *ptr;
	const char *text;
	Attribute *oc_at;
	struct berval pdn;
	ObjectClass *oc;
	CfEntryInfo *ceprev = NULL;

	Debug( LDAP_DEBUG_TRACE, "config_build_entry: \"%s\"\n", rdn->bv_val, 0, 0);
	e->e_private = ce;
	ce->ce_entry = e;
	ce->ce_parent = parent;
	if ( parent ) {
		pdn = parent->ce_entry->e_nname;
		if ( parent->ce_kids )
			for ( ceprev = parent->ce_kids; ceprev->ce_sibs;
				ceprev = ceprev->ce_sibs );
	} else {
		BER_BVZERO( &pdn );
	}

	ce->ce_type = main->co_type;
	ce->ce_private = c->private;
	ce->ce_be = c->be;
	ce->ce_bi = c->bi;

	build_new_dn( &e->e_name, &pdn, rdn, NULL );
	ber_dupbv( &e->e_nname, &e->e_name );

	attr_merge_normalize_one(e, slap_schema.si_ad_objectClass,
		main->co_name, NULL );
	if ( extra )
		attr_merge_normalize_one(e, slap_schema.si_ad_objectClass,
			extra->co_name, NULL );
	ptr = strchr(rdn->bv_val, '=');
	ad_name.bv_val = rdn->bv_val;
	ad_name.bv_len = ptr - rdn->bv_val;
	rc = slap_bv2ad( &ad_name, &ad, &text );
	if ( rc ) {
		return NULL;
	}
	val.bv_val = ptr+1;
	val.bv_len = rdn->bv_len - (val.bv_val - rdn->bv_val);
	attr_merge_normalize_one(e, ad, &val, NULL );

	oc = main->co_oc;
	c->table = main->co_type;
	if ( oc->soc_required )
		config_build_attrs( e, oc->soc_required, ad, main->co_table, c );

	if ( oc->soc_allowed )
		config_build_attrs( e, oc->soc_allowed, ad, main->co_table, c );

	if ( extra ) {
		oc = extra->co_oc;
		c->table = extra->co_type;
		if ( oc->soc_required )
			config_build_attrs( e, oc->soc_required, ad, extra->co_table, c );

		if ( oc->soc_allowed )
			config_build_attrs( e, oc->soc_allowed, ad, extra->co_table, c );
	}

	oc_at = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	rc = structural_class(oc_at->a_vals, &val, NULL, &text, c->msg,
		sizeof(c->msg));
	attr_merge_normalize_one(e, slap_schema.si_ad_structuralObjectClass, &val, NULL );
	if ( op ) {
		op->ora_e = e;
		op->o_bd->be_add( op, rs );
		if ( ( rs->sr_err != LDAP_SUCCESS ) 
				&& (rs->sr_err != LDAP_ALREADY_EXISTS) ) {
			return NULL;
		}
	}
	if ( ceprev ) {
		ceprev->ce_sibs = ce;
	} else if ( parent ) {
		parent->ce_kids = ce;
	}

	return e;
}

static int
config_build_schema_inc( ConfigArgs *c, CfEntryInfo *ceparent,
	Operation *op, SlapReply *rs )
{
	Entry *e;
	ConfigFile *cf = c->private;
	char *ptr;
	struct berval bv;

	for (; cf; cf=cf->c_sibs, c->depth++) {
		if ( !cf->c_at_head && !cf->c_cr_head && !cf->c_oc_head &&
			!cf->c_om_head ) continue;
		c->value_dn.bv_val = c->log;
		LUTIL_SLASHPATH( cf->c_file.bv_val );
		bv.bv_val = strrchr(cf->c_file.bv_val, LDAP_DIRSEP[0]);
		if ( !bv.bv_val ) {
			bv = cf->c_file;
		} else {
			bv.bv_val++;
			bv.bv_len = cf->c_file.bv_len - (bv.bv_val - cf->c_file.bv_val);
		}
		ptr = strchr( bv.bv_val, '.' );
		if ( ptr )
			bv.bv_len = ptr - bv.bv_val;
		c->value_dn.bv_len = snprintf(c->value_dn.bv_val, sizeof( c->log ), "cn=" SLAP_X_ORDERED_FMT, c->depth);
		if ( c->value_dn.bv_len >= sizeof( c->log ) ) {
			/* FIXME: how can indicate error? */
			return -1;
		}
		strncpy( c->value_dn.bv_val + c->value_dn.bv_len, bv.bv_val,
			bv.bv_len );
		c->value_dn.bv_len += bv.bv_len;
		c->value_dn.bv_val[c->value_dn.bv_len] ='\0';

		c->private = cf;
		e = config_build_entry( op, rs, ceparent, c, &c->value_dn,
			&CFOC_SCHEMA, NULL );
		if ( !e ) {
			return -1;
		} else if ( e && cf->c_kids ) {
			c->private = cf->c_kids;
			config_build_schema_inc( c, e->e_private, op, rs );
		}
	}
	return 0;
}

static int
config_build_includes( ConfigArgs *c, CfEntryInfo *ceparent,
	Operation *op, SlapReply *rs )
{
	Entry *e;
	int i;
	ConfigFile *cf = c->private;

	for (i=0; cf; cf=cf->c_sibs, i++) {
		c->value_dn.bv_val = c->log;
		c->value_dn.bv_len = snprintf(c->value_dn.bv_val, sizeof( c->log ), "cn=include" SLAP_X_ORDERED_FMT, i);
		if ( c->value_dn.bv_len >= sizeof( c->log ) ) {
			/* FIXME: how can indicate error? */
			return -1;
		}
		c->private = cf;
		e = config_build_entry( op, rs, ceparent, c, &c->value_dn,
			&CFOC_INCLUDE, NULL );
		if ( ! e ) {
			return -1;
		} else if ( e && cf->c_kids ) {
			c->private = cf->c_kids;
			config_build_includes( c, e->e_private, op, rs );
		}
	}
	return 0;
}

#ifdef SLAPD_MODULES

static int
config_build_modules( ConfigArgs *c, CfEntryInfo *ceparent,
	Operation *op, SlapReply *rs )
{
	int i;
	ModPaths *mp;

	for (i=0, mp=&modpaths; mp; mp=mp->mp_next, i++) {
		if ( BER_BVISNULL( &mp->mp_path ) && !mp->mp_loads )
			continue;
		c->value_dn.bv_val = c->log;
		c->value_dn.bv_len = snprintf(c->value_dn.bv_val, sizeof( c->log ), "cn=module" SLAP_X_ORDERED_FMT, i);
		if ( c->value_dn.bv_len >= sizeof( c->log ) ) {
			/* FIXME: how can indicate error? */
			return -1;
		}
		c->private = mp;
		if ( ! config_build_entry( op, rs, ceparent, c, &c->value_dn, &CFOC_MODULE, NULL )) {
			return -1;
		}
	}
        return 0;
}
#endif

static int
config_back_db_open( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	struct berval rdn;
	Entry *e, *parent;
	CfEntryInfo *ce, *ceparent;
	int i, unsupp = 0;
	BackendInfo *bi;
	ConfigArgs c;
	Connection conn = {0};
	OperationBuffer opbuf;
	Operation *op;
	slap_callback cb = { NULL, slap_null_cb, NULL, NULL };
	SlapReply rs = {REP_RESULT};
	void *thrctx = NULL;

	Debug( LDAP_DEBUG_TRACE, "config_back_db_open\n", 0, 0, 0);
	/* If we read the config from back-ldif, nothing to do here */
	if ( cfb->cb_got_ldif )
		return 0;

	if ( cfb->cb_use_ldif ) {
		thrctx = ldap_pvt_thread_pool_context();
		op = (Operation *) &opbuf;
		connection_fake_init( &conn, op, thrctx );

		op->o_tag = LDAP_REQ_ADD;
		op->o_callback = &cb;
		op->o_bd = &cfb->cb_db;
		op->o_dn = op->o_bd->be_rootdn;
		op->o_ndn = op->o_bd->be_rootndn;
	} else {
		op = NULL;
	}

	/* create root of tree */
	rdn = config_rdn;
	c.private = cfb->cb_config;
	c.be = frontendDB;
	e = config_build_entry( op, &rs, NULL, &c, &rdn, &CFOC_GLOBAL, NULL );
	if ( !e ) {
		return -1;
	}
	ce = e->e_private;
	cfb->cb_root = ce;

	parent = e;
	ceparent = ce;

	/* Create includeFile nodes */
	if ( cfb->cb_config->c_kids ) {
		c.depth = 0;
		c.private = cfb->cb_config->c_kids;
		if ( config_build_includes( &c, ceparent, op, &rs ) ) {
			return -1;
		}
	}

#ifdef SLAPD_MODULES
	/* Create Module nodes... */
	if ( modpaths.mp_loads ) {
		if ( config_build_modules( &c, ceparent, op, &rs ) ){
			return -1;
		}
	}
#endif

	/* Create schema nodes... cn=schema will contain the hardcoded core
	 * schema, read-only. Child objects will contain runtime loaded schema
	 * files.
	 */
	rdn = schema_rdn;
	c.private = NULL;
	e = config_build_entry( op, &rs, ceparent, &c, &rdn, &CFOC_SCHEMA, NULL );
	if ( !e ) {
		return -1;
	}
	ce = e->e_private;
	ce->ce_private = cfb->cb_config;

	/* Create schema nodes for included schema... */
	if ( cfb->cb_config->c_kids ) {
		c.depth = 0;
		c.private = cfb->cb_config->c_kids;
		if (config_build_schema_inc( &c, ce, op, &rs )) {
			return -1;
		}
	}

	/* Create backend nodes. Skip if they don't provide a cf_table.
	 * There usually aren't any of these.
	 */
	
	c.line = 0;
	LDAP_STAILQ_FOREACH( bi, &backendInfo, bi_next) {
		if (!bi->bi_cf_ocs) {
			/* If it only supports the old config mech, complain. */
			if ( bi->bi_config ) {
				Debug( LDAP_DEBUG_ANY,
					"WARNING: No dynamic config support for backend %s.\n",
					bi->bi_type, 0, 0 );
				unsupp++;
			}
			continue;
		}
		if (!bi->bi_private) continue;

		rdn.bv_val = c.log;
		rdn.bv_len = snprintf(rdn.bv_val, sizeof( c.log ),
			"%s=%s", cfAd_backend->ad_cname.bv_val, bi->bi_type);
		if ( rdn.bv_len >= sizeof( c.log ) ) {
			/* FIXME: holler ... */ ;
		}
		c.bi = bi;
		e = config_build_entry( op, &rs, ceparent, &c, &rdn, &CFOC_BACKEND,
			bi->bi_cf_ocs );
		if ( !e ) {
			return -1;
		}
	}

	/* Create database nodes... */
	frontendDB->be_cf_ocs = &CFOC_FRONTEND;
	LDAP_STAILQ_NEXT(frontendDB, be_next) = LDAP_STAILQ_FIRST(&backendDB);
	for ( i = -1, be = frontendDB ; be;
		i++, be = LDAP_STAILQ_NEXT( be, be_next )) {
		slap_overinfo *oi = NULL;

		if ( overlay_is_over( be )) {
			oi = be->bd_info->bi_private;
			bi = oi->oi_orig;
		} else {
			bi = be->bd_info;
		}

		/* If this backend supports the old config mechanism, but not
		 * the new mech, complain.
		 */
		if ( !be->be_cf_ocs && bi->bi_db_config ) {
			Debug( LDAP_DEBUG_ANY,
				"WARNING: No dynamic config support for database %s.\n",
				bi->bi_type, 0, 0 );
			unsupp++;
		}
		rdn.bv_val = c.log;
		rdn.bv_len = snprintf(rdn.bv_val, sizeof( c.log ),
			"%s=" SLAP_X_ORDERED_FMT "%s", cfAd_database->ad_cname.bv_val,
			i, bi->bi_type);
		if ( rdn.bv_len >= sizeof( c.log ) ) {
			/* FIXME: holler ... */ ;
		}
		c.be = be;
		c.bi = bi;
		e = config_build_entry( op, &rs, ceparent, &c, &rdn, &CFOC_DATABASE,
			be->be_cf_ocs );
		if ( !e ) {
			return -1;
		}
		ce = e->e_private;
		if ( be->be_cf_ocs && be->be_cf_ocs->co_cfadd )
			be->be_cf_ocs->co_cfadd( op, &rs, e, &c );
		/* Iterate through overlays */
		if ( oi ) {
			slap_overinst *on;
			Entry *oe;
			int j;

			for (j=0,on=oi->oi_list; on; j++,on=on->on_next) {
				if ( on->on_bi.bi_db_config && !on->on_bi.bi_cf_ocs ) {
					Debug( LDAP_DEBUG_ANY,
						"WARNING: No dynamic config support for overlay %s.\n",
						on->on_bi.bi_type, 0, 0 );
					unsupp++;
				}
				rdn.bv_val = c.log;
				rdn.bv_len = snprintf(rdn.bv_val, sizeof( c.log ),
					"%s=" SLAP_X_ORDERED_FMT "%s",
					cfAd_overlay->ad_cname.bv_val, j, on->on_bi.bi_type );
				if ( rdn.bv_len >= sizeof( c.log ) ) {
					/* FIXME: holler ... */ ;
				}
				c.be = be;
				c.bi = &on->on_bi;
				oe = config_build_entry( op, &rs, ce, &c, &rdn,
					&CFOC_OVERLAY, c.bi->bi_cf_ocs );
				if ( !oe ) {
					return -1;
				}
				if ( c.bi->bi_cf_ocs && c.bi->bi_cf_ocs->co_cfadd )
					c.bi->bi_cf_ocs->co_cfadd( op, &rs, oe, &c );
			}
		}
	}
	if ( thrctx )
		ldap_pvt_thread_pool_context_reset( thrctx );

	if ( unsupp  && cfb->cb_use_ldif ) {
		Debug( LDAP_DEBUG_ANY, "\nWARNING: The converted cn=config "
			"directory is incomplete and may not work.\n\n", 0, 0, 0 );
	}

	return 0;
}

static void
cfb_free_cffile( ConfigFile *cf )
{
	ConfigFile *next;

	for (; cf; cf=next) {
		next = cf->c_sibs;
		if ( cf->c_kids )
			cfb_free_cffile( cf->c_kids );
		ch_free( cf->c_file.bv_val );
		ber_bvarray_free( cf->c_dseFiles );
		ch_free( cf );
	}
}

static void
cfb_free_entries( CfEntryInfo *ce )
{
	CfEntryInfo *next;

	for (; ce; ce=next) {
		next = ce->ce_sibs;
		if ( ce->ce_kids )
			cfb_free_entries( ce->ce_kids );
		ce->ce_entry->e_private = NULL;
		entry_free( ce->ce_entry );
		ch_free( ce );
	}
}

static int
config_back_db_close( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;

	cfb_free_entries( cfb->cb_root );
	cfb->cb_root = NULL;

	if ( cfb->cb_db.bd_info ) {
		backend_shutdown( &cfb->cb_db );
	}

	return 0;
}

static int
config_back_db_destroy( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;

	cfb_free_cffile( cfb->cb_config );

	ch_free( cfdir.bv_val );

	avl_free( CfOcTree, NULL );

	if ( cfb->cb_db.bd_info ) {
		cfb->cb_db.be_suffix = NULL;
		cfb->cb_db.be_nsuffix = NULL;
		BER_BVZERO( &cfb->cb_db.be_rootdn );
		BER_BVZERO( &cfb->cb_db.be_rootndn );

		backend_destroy_one( &cfb->cb_db, 0 );
	}

	free( be->be_private );

	loglevel_destroy();

	return 0;
}

static int
config_back_db_init( BackendDB *be )
{
	struct berval dn;
	CfBackInfo *cfb;

	cfb = ch_calloc( 1, sizeof(CfBackInfo));
	cfb->cb_config = ch_calloc( 1, sizeof(ConfigFile));
	cfn = cfb->cb_config;
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

static int
config_back_destroy( BackendInfo *bi )
{
	ldif_must_b64_encode_release();
	return 0;
}

static int
config_tool_entry_open( BackendDB *be, int mode )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;

	if ( bi && bi->bi_tool_entry_open )
		return bi->bi_tool_entry_open( &cfb->cb_db, mode );
	else
		return -1;
	
}

static int
config_tool_entry_close( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;

	if ( bi && bi->bi_tool_entry_close )
		return bi->bi_tool_entry_close( &cfb->cb_db );
	else
		return -1;
}

static ID
config_tool_entry_first( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;

	if ( bi && bi->bi_tool_entry_first )
		return bi->bi_tool_entry_first( &cfb->cb_db );
	else
		return NOID;
}

static ID
config_tool_entry_next( BackendDB *be )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;

	if ( bi && bi->bi_tool_entry_next )
		return bi->bi_tool_entry_next( &cfb->cb_db );
	else
		return NOID;
}

static Entry *
config_tool_entry_get( BackendDB *be, ID id )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;

	if ( bi && bi->bi_tool_entry_get )
		return bi->bi_tool_entry_get( &cfb->cb_db, id );
	else
		return NULL;
}

static ID
config_tool_entry_put( BackendDB *be, Entry *e, struct berval *text )
{
	CfBackInfo *cfb = be->be_private;
	BackendInfo *bi = cfb->cb_db.bd_info;
	ConfigArgs ca;

	if ( bi && bi->bi_tool_entry_put &&
		config_add_internal( cfb, e, &ca, NULL, NULL ) == 0 )
		return bi->bi_tool_entry_put( &cfb->cb_db, e, text );
	else
		return NOID;
}

static struct {
	char *name;
	AttributeDescription **desc;
} ads[] = {
	{ "backend", &cfAd_backend },
	{ "database", &cfAd_database },
	{ "include", &cfAd_include },
	{ "overlay", &cfAd_overlay },
	{ NULL, NULL }
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
	ConfigTable		*ct = config_back_cf_table;
	char			*argv[4];
	int			i;
	AttributeDescription	*ad = NULL;
	const char		*text;
	static char		*controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		NULL
	};

	bi->bi_controls = controls;

	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = config_back_destroy;

	bi->bi_db_init = config_back_db_init;
	bi->bi_db_config = 0;
	bi->bi_db_open = config_back_db_open;
	bi->bi_db_close = config_back_db_close;
	bi->bi_db_destroy = config_back_db_destroy;

	bi->bi_op_bind = config_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = config_back_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = config_back_modify;
	bi->bi_op_modrdn = config_back_modrdn;
	bi->bi_op_add = config_back_add;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

#ifdef SLAP_OVERLAY_ACCESS
	bi->bi_access_allowed = slap_access_always_allowed;
#endif /* SLAP_OVERLAY_ACCESS */

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	bi->bi_tool_entry_open = config_tool_entry_open;
	bi->bi_tool_entry_close = config_tool_entry_close;
	bi->bi_tool_entry_first = config_tool_entry_first;
	bi->bi_tool_entry_next = config_tool_entry_next;
	bi->bi_tool_entry_get = config_tool_entry_get;
	bi->bi_tool_entry_put = config_tool_entry_put;

	/* Make sure we don't exceed the bits reserved for userland */
	assert( ( ( CFG_LAST - 1 ) & ARGS_USERLAND ) == ( CFG_LAST - 1 ) );

	argv[3] = NULL;
	for (i=0; OidMacros[i].name; i++ ) {
		argv[1] = OidMacros[i].name;
		argv[2] = OidMacros[i].oid;
		parse_oidm( "slapd", i, 3, argv, 0, NULL );
	}

	bi->bi_cf_ocs = cf_ocs;

	i = config_register_schema( ct, cf_ocs );
	if ( i ) return i;

	/* setup olcRootPW to be base64-encoded when written in LDIF form;
	 * basically, we don't care if it fails */
	i = slap_str2ad( "olcRootPW", &ad, &text );
	if ( i ) {
		Debug( LDAP_DEBUG_ANY, "config_back_initialize: "
			"warning, unable to get \"olcRootPW\" "
			"attribute description: %d: %s\n",
			i, text, 0 );
	} else {
		(void)ldif_must_b64_encode_register( ad->ad_cname.bv_val,
			ad->ad_type->sat_oid );
	}

	/* set up the notable AttributeDescriptions */
	i = 0;
	for (;ct->name;ct++) {
		if (strcmp(ct->name, ads[i].name)) continue;
		*ads[i].desc = ct->ad;
		i++;
		if (!ads[i].name) break;
	}

	return 0;
}

