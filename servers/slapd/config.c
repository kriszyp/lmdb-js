/* config.c - configuration file handling routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2005 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/errno.h>

#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif
#include "lutil.h"
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif /* HAVE_LIMITS_H */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif /* ! PATH_MAX */
#include "config.h"

#define ARGS_STEP	512

/*
 * defaults for various global variables
 */
slap_mask_t		global_allows = 0;
slap_mask_t		global_disallows = 0;
int		global_gentlehup = 0;
int		global_idletimeout = 0;
char	*global_host = NULL;
char	*global_realm = NULL;
char		*ldap_srvtab = "";
char		**default_passwd_hash = NULL;
struct berval default_search_base = BER_BVNULL;
struct berval default_search_nbase = BER_BVNULL;

ber_len_t sockbuf_max_incoming = SLAP_SB_MAX_INCOMING_DEFAULT;
ber_len_t sockbuf_max_incoming_auth= SLAP_SB_MAX_INCOMING_AUTH;

int	slap_conn_max_pending = SLAP_CONN_MAX_PENDING_DEFAULT;
int	slap_conn_max_pending_auth = SLAP_CONN_MAX_PENDING_AUTH;

char   *slapd_pid_file  = NULL;
char   *slapd_args_file = NULL;

char   *strtok_quote_ptr;

int use_reverse_lookup = 0;

/* These do nothing in slapd, they're kept only to make them
 * editable in back-config
 */
static char *replica_pidFile, *replica_argsFile;
static int replicationInterval;

static char	*passwd_salt;
static char	*logfileName;

#ifdef LDAP_SLAPI
int slapi_plugins_used = 0;
#endif

static int fp_getline(FILE *fp, ConfigArgs *c);
static void fp_getline_init(ConfigArgs *c);
static int fp_parse_line(ConfigArgs *c);

static char	*strtok_quote(char *line, char *sep);


int read_config_file(const char *fname, int depth, ConfigArgs *cf);

static int add_syncrepl LDAP_P(( Backend *, char **, int ));
static int parse_syncrepl_line LDAP_P(( char **, int, syncinfo_t *));
static void syncrepl_unparse LDAP_P (( syncinfo_t *, struct berval *));

/* All of these table entries and handlers really belong
 * in back-config, only the parser/table engine belongs here.
 */
/* state info for back-config */
static ConfigFile cf_prv, *cfn = &cf_prv;

static int config_fname(ConfigArgs *c);
static int config_generic(ConfigArgs *c);
static int config_search_base(ConfigArgs *c);
static int config_passwd_hash(ConfigArgs *c);
static int config_schema_dn(ConfigArgs *c);
static int config_sizelimit(ConfigArgs *c);
static int config_timelimit(ConfigArgs *c);
static int config_limits(ConfigArgs *c); 
static int config_overlay(ConfigArgs *c);
static int config_suffix(ConfigArgs *c); 
static int config_deref_depth(ConfigArgs *c);
static int config_rootdn(ConfigArgs *c);
static int config_rootpw(ConfigArgs *c);
static int config_restrict(ConfigArgs *c);
static int config_allows(ConfigArgs *c);
static int config_disallows(ConfigArgs *c);
static int config_requires(ConfigArgs *c);
static int config_security(ConfigArgs *c);
static int config_referral(ConfigArgs *c);
static int config_loglevel(ConfigArgs *c);
static int config_syncrepl(ConfigArgs *c);
static int config_replica(ConfigArgs *c);
static int config_updatedn(ConfigArgs *c);
static int config_updateref(ConfigArgs *c);
static int config_include(ConfigArgs *c);
#ifdef HAVE_TLS
static int config_tls_option(ConfigArgs *c);
static int config_tls_config(ConfigArgs *c);
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

static ConfigTable SystemConfiguration[] = {
	/* This attr is read-only */
	{ "", "", 0, 0, 0, ARG_MAGIC,
		&config_fname, "( OLcfgAt:78 NAME 'olcConfigFile' "
			"DESC 'File for slapd configuration directives' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
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
			"SYNTAX OMsDirectoryString )", NULL, NULL },
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
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "authz-policy", "policy", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, "( OLcfgAt:7 NAME 'olcAuthzPolicy' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "authz-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, "( OLcfgAt:8 NAME 'olcAuthzRegexp' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString X-ORDERED 'VALUES' )", NULL, NULL },
	{ "backend", "type", 2, 2, 0, ARG_PRE_DB|ARG_MAGIC|CFG_BACKEND,
		&config_generic, "( OLcfgAt:9 NAME 'olcBackend' "
			"DESC 'A type of backend' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "concurrency", "level", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_CONCUR,
		&config_generic, "( OLcfgAt:10 NAME 'olcConcurrency' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "conn_max_pending", "max", 2, 2, 0, ARG_LONG,
		&slap_conn_max_pending, "( OLcfgAt:11 NAME 'olcConnMaxPending' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "conn_max_pending_auth", "max", 2, 2, 0, ARG_LONG,
		&slap_conn_max_pending_auth, "( OLcfgAt:12 NAME 'olcConnMaxPendingAuth' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "database", "type", 2, 2, 0, ARG_MAGIC|CFG_DATABASE,
		&config_generic, "( OLcfgAt:13 NAME 'olcDatabase' "
			"DESC 'The backend type for a database instance' "
			"SUP olcBackend )", NULL, NULL },
	{ "defaultSearchBase", "dn", 2, 2, 0, ARG_PRE_BI|ARG_PRE_DB|ARG_DN|ARG_MAGIC,
		&config_search_base, "( OLcfgAt:14 NAME 'olcDefaultSearchBase' "
			"SYNTAX OMsDN )", NULL, NULL },
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
			"SYNTAX OMsBoolean )", NULL, NULL },
	{ "idletimeout", "timeout", 2, 2, 0, ARG_INT,
		&global_idletimeout, "( OLcfgAt:18 NAME 'olcIdleTimeout' "
			"SYNTAX OMsInteger )", NULL, NULL },
/* XXX -- special case? */
	{ "include", "file", 2, 2, 0, ARG_MAGIC,
		&config_include, "( OLcfgAt:19 NAME 'olcInclude' "
			"SUP labeledURI )", NULL, NULL },
	{ "index_substr_if_minlen", "min", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MIN,
		&config_generic, "( OLcfgAt:20 NAME 'olcIndexSubstrIfMinLen' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "index_substr_if_maxlen", "max", 2, 2, 0, ARG_INT|ARG_NONZERO|ARG_MAGIC|CFG_SSTR_IF_MAX,
		&config_generic, "( OLcfgAt:21 NAME 'olcIndexSubstrIfMaxLen' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "index_substr_any_len", "len", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_len, "( OLcfgAt:22 NAME 'olcIndexSubstrAnyLen' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "index_substr_step", "step", 2, 2, 0, ARG_INT|ARG_NONZERO,
		&index_substr_any_step, "( OLcfgAt:23 NAME 'olcIndexSubstrAnyStep' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "lastmod", "on|off", 2, 2, 0, ARG_DB|ARG_ON_OFF|ARG_MAGIC|CFG_LASTMOD,
		&config_generic, "( OLcfgAt:24 NAME 'olcLastMod' "
			"SYNTAX OMsBoolean )", NULL, NULL },
	{ "limits", "limits", 2, 0, 0, ARG_DB|ARG_MAGIC|CFG_LIMITS,
		&config_generic, "( OLcfgAt:25 NAME 'olcLimits' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "localSSF", "ssf", 2, 2, 0, ARG_LONG,
		&local_ssf, "( OLcfgAt:26 NAME 'olcLocalSSF' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "logfile", "file", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_LOGFILE,
		&config_generic, "( OLcfgAt:27 NAME 'olcLogFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "loglevel", "level", 2, 0, 0, ARG_MAGIC,
		&config_loglevel, "( OLcfgAt:28 NAME 'olcLogLevel' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "maxDerefDepth", "depth", 2, 2, 0, ARG_DB|ARG_INT|ARG_MAGIC|CFG_DEPTH,
		&config_generic, "( OLcfgAt:29 NAME 'olcMaxDerefDepth' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "moduleload",	"file", 2, 0, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODLOAD, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:30 NAME 'olcModuleLoad' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "modulepath", "path", 2, 2, 0,
#ifdef SLAPD_MODULES
		ARG_MAGIC|CFG_MODPATH, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:31 NAME 'olcModulePath' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	/* use standard schema */
	{ "objectclass", "objectclass", 2, 0, 0, ARG_PAREN|ARG_MAGIC|CFG_OC,
		&config_generic, NULL, NULL, NULL },
	{ "objectidentifier", NULL,	0, 0, 0, ARG_MAGIC|CFG_OID,
		&config_generic, "( OLcfgAt:33 NAME 'olcObjectIdentifier' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "overlay", "overlay", 2, 2, 0, ARG_MAGIC,
		&config_overlay, "( OLcfgAt:34 NAME 'olcOverlay' "
			"SUP olcDatabase )", NULL, NULL },
	{ "password-crypt-salt-format", "salt", 2, 2, 0, ARG_STRING|ARG_MAGIC|CFG_SALT,
		&config_generic, "( OLcfgAt:35 NAME 'olcPasswordCryptSaltFormat' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "password-hash", "hash", 2, 2, 0, ARG_MAGIC,
		&config_passwd_hash, "( OLcfgAt:36 NAME 'olcPasswordHash' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "pidfile", "file", 2, 2, 0, ARG_STRING,
		&slapd_pid_file, "( OLcfgAt:37 NAME 'olcPidFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
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
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "readonly", "on|off", 2, 2, 0, ARG_MAY_DB|ARG_ON_OFF|ARG_MAGIC|CFG_RO,
		&config_generic, "( OLcfgAt:40 NAME 'olcReadOnly' "
			"SYNTAX OMsBoolean )", NULL, NULL },
	{ "referral", "url", 2, 2, 0, ARG_MAGIC,
		&config_referral, "( OLcfgAt:41 NAME 'olcReferral' "
			"SUP labeledURI )", NULL, NULL },
	{ "replica", "host or uri", 2, 0, 0, ARG_DB|ARG_MAGIC,
		&config_replica, "( OLcfgAt:42 NAME 'olcReplica' "
			"SUP labeledURI )", NULL, NULL },
	{ "replica-argsfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_argsFile, "( OLcfgAt:43 NAME 'olcReplicaArgsFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "replica-pidfile", NULL, 0, 0, 0, ARG_STRING,
		&replica_pidFile, "( OLcfgAt:44 NAME 'olcReplicaPidFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "replicationInterval", NULL, 0, 0, 0, ARG_INT,
		&replicationInterval, "( OLcfgAt:45 NAME 'olcReplicationInterval' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "replogfile", "filename", 2, 2, 0, ARG_MAY_DB|ARG_MAGIC|ARG_STRING|CFG_REPLOG,
		&config_generic, "( OLcfgAt:46 NAME 'olcReplogFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
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
			"SYNTAX OMsBoolean )", NULL, NULL },
	{ "rootdn", "dn", 2, 2, 0, ARG_DB|ARG_DN|ARG_MAGIC,
		&config_rootdn, "( OLcfgAt:50 NAME 'olcRootDN' "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "rootDSE", "file", 2, 2, 0, ARG_MAGIC|CFG_ROOTDSE,
		&config_generic, "( OLcfgAt:51 NAME 'olcRootDSE' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "rootpw", "password", 2, 2, 0, ARG_STRING|ARG_DB|ARG_MAGIC,
		&config_rootpw, "( OLcfgAt:52 NAME 'olcRootPW' "
			"SYNTAX OMsOctetString )", NULL, NULL },
	{ "sasl-authz-policy", NULL, 2, 2, 0, ARG_MAGIC|CFG_AZPOLICY,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-host", "host", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_host,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:53 NAME 'olcSaslHost' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "sasl-realm", "realm", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_STRING|ARG_UNIQUE, &global_realm,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:54 NAME 'olcSaslRealm' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "sasl-regexp", NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "sasl-secprops", "properties", 2, 2, 0,
#ifdef HAVE_CYRUS_SASL
		ARG_MAGIC|CFG_SASLSECP, &config_generic,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:56 NAME 'olcSaslSecProps' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "saslRegexp",	NULL, 3, 3, 0, ARG_MAGIC|CFG_AZREGEXP,
		&config_generic, NULL, NULL, NULL },
	{ "schemacheck", "on|off", 2, 2, 0, ARG_ON_OFF|ARG_MAGIC|CFG_CHECK,
		&config_generic, "( OLcfgAt:57 NAME 'olcSchemaCheck' "
			"SYNTAX OMsBoolean )", NULL, NULL },
	{ "schemadn", "dn", 2, 2, 0, ARG_MAY_DB|ARG_DN|ARG_MAGIC,
		&config_schema_dn, "( OLcfgAt:58 NAME 'olcSchemaDN' "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "security", "factors", 2, 0, 0, ARG_MAY_DB|ARG_MAGIC,
		&config_security, "( OLcfgAt:59 NAME 'olcSecurity' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "sizelimit", "limit",	2, 2, 0, ARG_MAY_DB|ARG_MAGIC|CFG_SIZE,
		&config_sizelimit, "( OLcfgAt:60 NAME 'olcSizeLimit' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "sockbuf_max_incoming", "max", 2, 2, 0, ARG_LONG,
		&sockbuf_max_incoming, "( OLcfgAt:61 NAME 'olcSockbufMaxIncoming' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "sockbuf_max_incoming_auth", "max", 2, 2, 0, ARG_LONG,
		&sockbuf_max_incoming_auth, "( OLcfgAt:62 NAME 'olcSockbufMaxIncomingAuth' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "srvtab", "file", 2, 2, 0,
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		ARG_STRING, &ldap_srvtab,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:63 NAME 'olcSrvtab' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "suffix",	"suffix", 2, 2, 0, ARG_DB|ARG_DN|ARG_MAGIC,
		&config_suffix, "( OLcfgAt:64 NAME 'olcSuffix' "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "syncrepl", NULL, 0, 0, 0, ARG_DB|ARG_MAGIC,
		&config_syncrepl, "( OLcfgAt:65 NAME 'olcSyncrepl' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "threads", "count", 2, 2, 0, ARG_INT|ARG_MAGIC|CFG_THREADS,
		&config_generic, "( OLcfgAt:66 NAME 'olcThreads' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "timelimit", "limit", 2, 2, 0, ARG_MAY_DB|ARG_MAGIC|CFG_TIME,
		&config_timelimit, "( OLcfgAt:67 NAME 'olcTimeLimit' "
			"SYNTAX OMsInteger )", NULL, NULL },
	{ "TLSCACertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:68 NAME 'olcTLSCACertificateFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCACertificatePath", NULL,	0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CA_PATH|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:69 NAME 'olcTLSCACertificatePath' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCertificateFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_FILE|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:70 NAME 'olcTLSCertificateFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCertificateKeyFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CERT_KEY|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:71 NAME 'olcTLSCertificateKeyFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCipherSuite",	NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CIPHER|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:72 NAME 'olcTLSCipherSuite' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSCRLCheck", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_CRLCHECK|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:73 NAME 'olcTLSCRLCheck' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSRandFile", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_RAND|ARG_STRING|ARG_MAGIC, &config_tls_option,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:74 NAME 'olcTLSRandFile' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "TLSVerifyClient", NULL, 0, 0, 0,
#ifdef HAVE_TLS
		CFG_TLS_VERIFY|ARG_STRING|ARG_MAGIC, &config_tls_config,
#else
		ARG_IGNORED, NULL,
#endif
		"( OLcfgAt:75 NAME 'olcTLSVerifyClient' "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ "ucdata-path", "path", 2, 2, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL },
	{ "updatedn", "dn", 2, 2, 0, ARG_DB|ARG_MAGIC,
		&config_updatedn, "( OLcfgAt:76 NAME 'olcUpdateDN' "
			"SYNTAX OMsDN )", NULL, NULL },
	{ "updateref", "url", 2, 2, 0, ARG_DB|ARG_MAGIC,
		&config_updateref, "( OLcfgAt:77 NAME 'olcUpdateRef' "
			"SUP labeledURI )", NULL, NULL },
	{ NULL,	NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};


ConfigArgs *
new_config_args( BackendDB *be, const char *fname, int lineno, int argc, char **argv )
{
	ConfigArgs *c;
	c = ch_calloc( 1, sizeof( ConfigArgs ) );
	if ( c == NULL ) return(NULL);
	c->be     = be; 
	c->fname  = fname;
	c->argc   = argc;
	c->argv   = argv; 
	c->lineno = lineno;
	snprintf( c->log, sizeof( c->log ), "%s: line %lu", fname, lineno );
	return(c);
}

int parse_config_table(ConfigTable *Conf, ConfigArgs *c) {
	int i, rc, arg_user, arg_type, iarg;
	long larg;
	ber_len_t barg;
	for(i = 0; Conf[i].name; i++)
		if( (Conf[i].length && (!strncasecmp(c->argv[0], Conf[i].name, Conf[i].length))) ||
			(!strcasecmp(c->argv[0], Conf[i].name)) ) break;
	if(!Conf[i].name) return(ARG_UNKNOWN);
	arg_type = Conf[i].arg_type;
	if(arg_type == ARG_IGNORED) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> ignored\n",
			c->log, Conf[i].name, 0);
		return(0);
	}
	if(Conf[i].min_args && (c->argc < Conf[i].min_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> missing <%s> argument\n",
			c->log, Conf[i].name, Conf[i].what);
		return(ARG_BAD_CONF);
	}
	if(Conf[i].max_args && (c->argc > Conf[i].max_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: extra cruft after <%s> in <%s> line (ignored)\n",
			c->log, Conf[i].what, Conf[i].name);
	}
	if((arg_type & ARG_DB) && !c->be) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> allowed only within database declaration\n",
			c->log, Conf[i].name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PRE_BI) && c->bi) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> must appear before any backend %sdeclaration\n",
			c->log, Conf[i].name, ((arg_type & ARG_PRE_DB)
			? "or database " : "") );
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PRE_DB) && c->be && c->be != frontendDB) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> must appear before any database declaration\n",
			c->log, Conf[i].name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PAREN) && *c->argv[1] != '(' /*')'*/) {
		Debug(LDAP_DEBUG_CONFIG, "%s: old <%s> format not supported\n",
			c->log, Conf[i].name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARGS_POINTER) && !Conf[i].arg_item) {
		Debug(LDAP_DEBUG_CONFIG, "%s: null arg_item for <%s>\n",
			c->log, Conf[i].name, 0);
		return(ARG_BAD_CONF);
	}
	c->type = arg_user = (arg_type & ARGS_USERLAND);
	memset(&c->values, 0, sizeof(c->values));
	if(arg_type & ARGS_NUMERIC) {
		int j;
		iarg = 0; larg = 0; barg = 0;
		switch(arg_type & ARGS_NUMERIC) {
			case ARG_INT:		iarg = atoi(c->argv[1]);		break;
			case ARG_LONG:		larg = atol(c->argv[1]);		break;
			case ARG_BER_LEN_T:	barg = (ber_len_t)atol(c->argv[1]);	break;
			case ARG_ON_OFF:
				if(!strcasecmp(c->argv[1], "on") ||
					!strcasecmp(c->argv[1], "true")) {
					iarg = 1;
				} else if(!strcasecmp(c->argv[1], "off") ||
					!strcasecmp(c->argv[1], "false")) {
					iarg = 0;
				} else {
					Debug(LDAP_DEBUG_CONFIG, "%s: ignoring ", c->log, 0, 0);
					Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%s) in <%s> line\n",
						Conf[i].what, c->argv[1], Conf[i].name);
					return(0);
				}
				break;
		}
		j = (arg_type & ARG_NONZERO) ? 1 : 0;
		if(iarg < j || larg < j || barg < j ) {
			larg = larg ? larg : (barg ? barg : iarg);
			Debug(LDAP_DEBUG_CONFIG, "%s: " , c->log, 0, 0);
			Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%ld) in <%s> line\n", Conf[i].what, larg, Conf[i].name);
			return(ARG_BAD_CONF);
		}
		switch(arg_type & ARGS_NUMERIC) {
			case ARG_ON_OFF:
			case ARG_INT:		c->value_int = iarg;		break;
			case ARG_LONG:		c->value_long = larg;		break;
			case ARG_BER_LEN_T:	c->value_ber_t = barg;		break;
		}
	} else if(arg_type & ARG_STRING) {
		 c->value_string = ch_strdup(c->argv[1]);
	} else if(arg_type & ARG_DN) {
		struct berval bv;
		ber_str2bv( c->argv[1], 0, 0, &bv );
		rc = dnPrettyNormal( NULL, &bv, &c->value_dn, &c->value_ndn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug(LDAP_DEBUG_CONFIG, "%s: " , c->log, 0, 0);
			Debug(LDAP_DEBUG_CONFIG, "%s DN is invalid %d (%s)\n",
				Conf[i].name, rc, ldap_err2string( rc ));
			return(ARG_BAD_CONF);
		}
	}
	if(arg_type & ARG_MAGIC) {
		if(!c->be) c->be = frontendDB;
		rc = (*((ConfigDriver*)Conf[i].arg_item))(c);
		if(c->be == frontendDB) c->be = NULL;
		if(rc) {
			Debug(LDAP_DEBUG_CONFIG, "%s: handler for <%s> exited with %d!",
				c->log, Conf[i].name, rc);
			return(ARG_BAD_CONF);
		}
		return(0);
	}
	if(arg_type & ARGS_POINTER) switch(arg_type & ARGS_POINTER) {
			case ARG_ON_OFF:
			case ARG_INT: 		*((int*)Conf[i].arg_item)		= iarg;			break;
			case ARG_LONG:  	*((long*)Conf[i].arg_item)		= larg;			break;
			case ARG_BER_LEN_T: 	*((ber_len_t*)Conf[i].arg_item)		= barg;			break;
			case ARG_STRING: {
				char *cc = *((char**)Conf[i].arg_item);
				if(cc) {
					if (arg_type & ARG_UNIQUE) {
						Debug(LDAP_DEBUG_CONFIG, "%s: already set %s!\n",
							c->log, Conf[i].name, 0 );
						return(ARG_BAD_CONF);
					}
					ch_free(cc);	/* potential memory leak */
				}
				*(char **)Conf[i].arg_item = c->value_string;
				break;
				}
	}
	return(arg_user);
}

int
config_get_vals(ConfigTable *cf, ConfigArgs *c)
{
	int rc = 0;
	struct berval bv;

	if ( cf->arg_type & ARG_IGNORED ) {
		return 1;
	}

	memset(&c->values, 0, sizeof(c->values));
	c->rvalue_vals = NULL;
	c->rvalue_nvals = NULL;
	c->emit = 1;
	c->type = cf->arg_type & ARGS_USERLAND;

	if ( cf->arg_type & ARG_MAGIC ) {
		rc = (*((ConfigDriver*)cf->arg_item))(c);
		if ( rc ) return rc;
	} else {
		switch(cf->arg_type & ARGS_POINTER) {
		case ARG_ON_OFF:
		case ARG_INT:	c->value_int = *(int *)cf->arg_item; break;
		case ARG_LONG:	c->value_long = *(long *)cf->arg_item; break;
		case ARG_BER_LEN_T:	c->value_ber_t = *(ber_len_t *)cf->arg_item; break;
		case ARG_STRING:
			if ( *(char **)cf->arg_item )
				c->value_string = ch_strdup(*(char **)cf->arg_item);
			break;
		}
	}
	if ( cf->arg_type & ARGS_POINTER) {
		bv.bv_val = c->log;
		switch(cf->arg_type & ARGS_POINTER) {
		case ARG_INT: bv.bv_len = sprintf(bv.bv_val, "%d", c->value_int); break;
		case ARG_LONG: bv.bv_len = sprintf(bv.bv_val, "%l", c->value_long); break;
		case ARG_BER_LEN_T: bv.bv_len =sprintf(bv.bv_val, "%l",c->value_ber_t); break;
		case ARG_ON_OFF: bv.bv_len = sprintf(bv.bv_val, "%s",
			c->value_int ? "TRUE" : "FALSE"); break;
		case ARG_STRING:
			if ( c->value_string && c->value_string[0]) {
				ber_str2bv( c->value_string, 0, 0, &bv);
			} else {
				return 1;
			}
			break;
		}
		if (( cf->arg_type & ARGS_POINTER ) == ARG_STRING )
			ber_bvarray_add(&c->rvalue_vals, &bv);
		else
			value_add_one(&c->rvalue_vals, &bv);
	}
	return rc;
}

int
init_config_attrs(ConfigTable *ct) {
	LDAPAttributeType *at;
	int i, code;
	const char *err;

	for (i=0; ct[i].name; i++ ) {
		if ( !ct[i].attribute ) continue;
		at = ldap_str2attributetype( ct[i].attribute,
			&code, &err, LDAP_SCHEMA_ALLOW_ALL );
		if ( !at ) {
			fprintf( stderr, "init_config_schema: AttributeType \"%s\": %s, %s\n",
				ct[i].attribute, ldap_scherr2str(code), err );
			return code;
		}
		code = at_add( at, &err );
		if ( code ) {
			fprintf( stderr, "init_config_schema: AttributeType \"%s\": %s, %s\n",
				ct[i].attribute, scherr2str(code), err );
			return code;
		}
		code = slap_str2ad( at->at_names[0], &ct[i].ad, &err );
		if ( code ) {
			fprintf( stderr, "init_config_schema: AttributeType \"%s\": %s\n",
				ct[i].attribute, err );
			return code;
		}
		ldap_memfree( at );
	}

	return 0;
}

int
read_config(const char *fname, int depth) {
	int i;
	char *argv[3];

	/* Schema initialization should normally be part of bi_open */
	for (i=0; OidMacros[i].name; i++ ) {
		argv[1] = OidMacros[i].name;
		argv[2] = OidMacros[i].oid;
		parse_oidm( "slapd", i, 3, argv );
	}
	i = init_config_attrs(SystemConfiguration);
	if ( i ) return i;
	i = config_back_init( &cf_prv, SystemConfiguration );
	if ( i ) return i;
	return read_config_file(fname, depth, NULL);
}

int
read_config_file(const char *fname, int depth, ConfigArgs *cf)
{
	FILE *fp;
	ConfigArgs *c;
	int rc;

	c = ch_calloc( 1, sizeof( ConfigArgs ) );
	if ( c == NULL ) {
		return 1;
	}

	if ( depth ) {
		memcpy( c, cf, sizeof( ConfigArgs ) );
	} else {
		c->depth = depth; /* XXX */
		c->bi = NULL;
		c->be = NULL;
	}

	c->fname = fname;
	c->argv = ch_calloc( ARGS_STEP + 1, sizeof( *c->argv ) );
	c->argv_size = ARGS_STEP + 1;

	fp = fopen( fname, "r" );
	if ( fp == NULL ) {
		ldap_syslog = 1;
		Debug(LDAP_DEBUG_ANY,
		    "could not open config file \"%s\": %s (%d)\n",
		    fname, strerror(errno), errno);
		return(1);
	}
#ifdef SLAPD_MODULES
	cfn->c_modlast = &cfn->c_modpaths;
#endif
	ber_str2bv( fname, 0, 1, &cfn->c_file );
	fname = cfn->c_file.bv_val;

	Debug(LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0);

	fp_getline_init(c);

	while ( fp_getline( fp, c ) ) {
		/* skip comments and blank lines */
		if ( c->line[0] == '#' || c->line[0] == '\0' ) {
			continue;
		}

		snprintf( c->log, sizeof( c->log ), "%s: line %lu",
				c->fname, c->lineno );

		if ( fp_parse_line( c ) ) {
			goto badline;
		}

		if ( c->argc < 1 ) {
			Debug(LDAP_DEBUG_CONFIG, "%s: bad config line (ignored)\n", c->log, 0, 0);
			continue;
		}

		rc = parse_config_table( SystemConfiguration, c );
		if ( !rc ) {
			continue;
		}
		if ( rc & ARGS_USERLAND ) {
			switch(rc) {	/* XXX a usertype would be opaque here */
			default:
				Debug(LDAP_DEBUG_CONFIG, "%s: unknown user type <%d>\n",
					c->log, *c->argv, 0);
				goto badline;
			}

		} else if ( rc == ARG_BAD_CONF || rc != ARG_UNKNOWN ) {
			goto badline;
			
		} else if ( c->bi && c->bi->bi_config ) {		/* XXX to check: could both be/bi_config? oops */
			rc = (*c->bi->bi_config)(c->bi, c->fname, c->lineno, c->argc, c->argv);
			if ( rc ) {
				switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug(LDAP_DEBUG_CONFIG, "%s: "
						"unknown directive <%s> inside backend info definition (ignored)\n",
				   		c->log, *c->argv, 0);
					continue;
				default:
					goto badline;
				}
			}
			
		} else if ( c->be && c->be->be_config ) {
			rc = (*c->be->be_config)(c->be, c->fname, c->lineno, c->argc, c->argv);
			if ( rc ) {
				switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug( LDAP_DEBUG_CONFIG, "%s: "
						"unknown directive <%s> inside backend database definition (ignored)\n",
						c->log, *c->argv, 0);
					continue;
				default:
					goto badline;
				}
			}

		} else if ( frontendDB->be_config ) {
			rc = (*frontendDB->be_config)(frontendDB, c->fname, (int)c->lineno, c->argc, c->argv);
			if ( rc ) {
				switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug( LDAP_DEBUG_CONFIG, "%s: "
						"unknown directive <%s> inside global database definition (ignored)\n",
						c->log, *c->argv, 0);
					continue;
				default:
					goto badline;
				}
			}
			
		} else {
			Debug(LDAP_DEBUG_CONFIG, "%s: "
				"unknown directive <%s> outside backend info and database definitions (ignored)\n",
				c->log, *c->argv, 0);
			continue;

		}
	}

	fclose(fp);

	if ( BER_BVISNULL( &frontendDB->be_schemadn ) ) {
		ber_str2bv( SLAPD_SCHEMA_DN, STRLENOF( SLAPD_SCHEMA_DN ), 1,
			&frontendDB->be_schemadn );
		rc = dnNormalize( 0, NULL, NULL, &frontendDB->be_schemadn, &frontendDB->be_schemandn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug(LDAP_DEBUG_ANY, "%s: "
				"unable to normalize default schema DN \"%s\"\n",
				c->log, frontendDB->be_schemadn.bv_val, 0 );
			/* must not happen */
			assert( 0 );
		}
	}

	ch_free(c->argv);
	ch_free(c);
	return(0);

badline:
	fclose(fp);
	ch_free(c->argv);
	ch_free(c);
	return(1);
}

static int
config_generic(ConfigArgs *c) {
	char *p;
	int i;

	if ( c->emit ) {
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
		case CFG_LIMITS:	/* FIXME */
			rc = 1;
			break;
		case CFG_RO:
			c->value_int = (c->be->be_restrictops & SLAP_RESTRICT_OP_WRITES) != 0;
			break;
		case CFG_AZPOLICY:
			c->value_string = ch_strdup( slap_sasl_getpolicy());
			break;
		case CFG_AZREGEXP:
			rc = 1;
			break;
#ifdef HAVE_CYRUS_SASL
		case CFG_SASLSECP:	/* FIXME */
			rc = 1;
			break;
#endif
		case CFG_DEPTH:
			c->value_int = c->be->be_max_deref_depth;
			break;
		case CFG_OID:	/* FIXME */
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
		case CFG_PLUGIN:	/* FIXME */
			rc = 1;
			break;
#endif
#ifdef SLAP_AUTH_REWRITE
		case CFG_REWRITE:	/* FIXME */
			rc = 1;
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
			if(parse_oidm(c->fname, c->lineno, c->argc, c->argv)) return(1);
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
		case CFG_REWRITE:
			if(slap_sasl_rewrite_config(c->fname, c->lineno, c->argc, c->argv))
				return(1);
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
	if(c->emit && c->line) {
		ConfigFile *cf = (ConfigFile *)c->line;
		value_add_one( &c->rvalue_vals, &cf->c_file );
		return 0;
	}
	return(1);
}

static int
config_search_base(ConfigArgs *c) {
	struct berval dn;

	if(c->emit) {
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
	if (c->emit) {
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
	struct berval dn;
	int rc;
	if ( c->emit ) {
		value_add_one(&c->rvalue_vals, &c->be->be_schemadn);
		value_add_one(&c->rvalue_nvals, &c->be->be_schemandn);
		return 0;
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
	if (c->emit) {	/* FIXME */
		return 1;
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
	if (c->emit) {
		return 1;	/* FIXME */
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
	if (c->emit) {
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
	if (c->emit) {
		if ( !BER_BVISNULL( &c->be->be_suffix[0] )) {
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
	if (c->emit) {
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
	if (c->emit) {
		if (!BER_BVISEMPTY(&c->be->be_rootpw)) {
			c->value_string=ch_strdup("*");
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

/* restrictops, allows, disallows, requires, loglevel */

struct verb_mask_list { char *word; int mask; };

int
verb_to_mask(ConfigArgs *c, struct verb_mask_list *v, int word) {
	int j;
	for(j = 0; v[j].word; j++)
		if(!strcasecmp(c->argv[word], v[j].word))
			break;
	return(j);
}

int
verbs_to_mask(ConfigArgs *c, struct verb_mask_list *v, slap_mask_t *m) {
	int i, j;
	for(i = 1; i < c->argc; i++) {
		j = verb_to_mask(c, v, i);
		if(!v[j].word) return(1);
		while (!v[j].mask) j--;
		*m |= v[j].mask;
	}
	return(0);
}

int
mask_to_verbs(ConfigArgs *c, struct verb_mask_list *v, slap_mask_t m) {
	int i, j;
	struct berval bv;

	if (!m) return 1;
	for (i=0; v[i].word; i++) {
		if (!v[i].mask) continue;
		if (( m & v[i].mask ) == v[i].mask ) {
			ber_str2bv( v[i].word, 0, 0, &bv );
			value_add_one( &c->rvalue_vals, &bv );
		}
	}
	return 0;
}

static int
config_restrict(ConfigArgs *c) {
	slap_mask_t restrictops = 0;
	int i;
	struct verb_mask_list restrictable_ops[] = {
		{ "bind",		SLAP_RESTRICT_OP_BIND },
		{ "add",		SLAP_RESTRICT_OP_ADD },
		{ "modify",		SLAP_RESTRICT_OP_MODIFY },
		{ "rename",		SLAP_RESTRICT_OP_RENAME },
		{ "modrdn",		0 },
		{ "delete",		SLAP_RESTRICT_OP_DELETE },
		{ "search",		SLAP_RESTRICT_OP_SEARCH },
		{ "compare",	SLAP_RESTRICT_OP_COMPARE },
		{ "read",		SLAP_RESTRICT_OP_READS },
		{ "write",		SLAP_RESTRICT_OP_WRITES },
		{ "extended",	SLAP_RESTRICT_OP_EXTENDED },
		{ "extended=" LDAP_EXOP_START_TLS,		SLAP_RESTRICT_EXOP_START_TLS },
		{ "extended=" LDAP_EXOP_MODIFY_PASSWD,	SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
		{ "extended=" LDAP_EXOP_X_WHO_AM_I,		SLAP_RESTRICT_EXOP_WHOAMI },
		{ "extended=" LDAP_EXOP_X_CANCEL,		SLAP_RESTRICT_EXOP_CANCEL },
		{ NULL,	0 }
	};

	if (c->emit) {
		return mask_to_verbs( c, restrictable_ops, c->be->be_restrictops );
	}
	i = verbs_to_mask( c, restrictable_ops, &restrictops );
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
	struct verb_mask_list allowable_ops[] = {
		{ "bind_v2",		SLAP_ALLOW_BIND_V2 },
		{ "bind_anon_cred",	SLAP_ALLOW_BIND_ANON_CRED },
		{ "bind_anon_dn",	SLAP_ALLOW_BIND_ANON_DN },
		{ "update_anon",	SLAP_ALLOW_UPDATE_ANON },
		{ NULL,	0 }
	};
	if (c->emit) {
		return mask_to_verbs( c, allowable_ops, global_allows );
	}
	i = verbs_to_mask(c, allowable_ops, &allows);
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
	struct verb_mask_list disallowable_ops[] = {
		{ "bind_anon",		SLAP_DISALLOW_BIND_ANON },
		{ "bind_simple",	SLAP_DISALLOW_BIND_SIMPLE },
		{ "bind_krb4",		SLAP_DISALLOW_BIND_KRBV4 },
		{ "tls_2_anon",		SLAP_DISALLOW_TLS_2_ANON },
		{ "tls_authc",		SLAP_DISALLOW_TLS_AUTHC },
		{ NULL, 0 }
	};
	if (c->emit) {
		return mask_to_verbs( c, disallowable_ops, global_disallows );
	}
	i = verbs_to_mask(c, disallowable_ops, &disallows);
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
	struct verb_mask_list requires_ops[] = {
		{ "bind",		SLAP_REQUIRE_BIND },
		{ "LDAPv3",		SLAP_REQUIRE_LDAP_V3 },
		{ "authc",		SLAP_REQUIRE_AUTHC },
		{ "sasl",		SLAP_REQUIRE_SASL },
		{ "strong",		SLAP_REQUIRE_STRONG },
		{ NULL, 0 }
	};
	if (c->emit) {
		return mask_to_verbs( c, requires_ops, c->be->be_requires );
	}
	i = verbs_to_mask(c, requires_ops, &requires);
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
	struct verb_mask_list loglevel_ops[] = {
		{ "Trace",	LDAP_DEBUG_TRACE },
		{ "Packets",	LDAP_DEBUG_PACKETS },
		{ "Args",	LDAP_DEBUG_ARGS },
		{ "Conns",	LDAP_DEBUG_CONNS },
		{ "BER",	LDAP_DEBUG_BER },
		{ "Filter",	LDAP_DEBUG_FILTER },
		{ "Config",	LDAP_DEBUG_CONFIG },
		{ "ACL",	LDAP_DEBUG_ACL },
		{ "Stats",	LDAP_DEBUG_STATS },
		{ "Stats2",	LDAP_DEBUG_STATS2 },
		{ "Shell",	LDAP_DEBUG_SHELL },
		{ "Parse",	LDAP_DEBUG_PARSE },
		{ "Cache",	LDAP_DEBUG_CACHE },
		{ "Index",	LDAP_DEBUG_INDEX },
		{ "Any",	-1 },
		{ NULL,	0 }
	};

	if (c->emit) {
		return mask_to_verbs( c, loglevel_ops, ldap_syslog );
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
			int j = verb_to_mask(c, loglevel_ops, c->argv[i][0]);
			if(!loglevel_ops[j].word) {
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
	if (c->emit) {
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
	if (c->emit) {
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
	if (c->emit) {
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

static struct verb_mask_list tlskey[] = {
	{ "no",		SB_TLS_OFF },
	{ "yes",		SB_TLS_ON },
	{ "critical",	SB_TLS_CRITICAL }
};

static struct verb_mask_list methkey[] = {
	{ "simple",	LDAP_AUTH_SIMPLE },
#ifdef HAVE_CYRUS_SASL
	{ "sasl",	LDAP_AUTH_SASL },
#endif
	{ NULL, 0 }
};

typedef struct cf_aux_table {
	struct berval key;
	int off;
	int quote;
	struct verb_mask_list *aux;
} cf_aux_table;

static cf_aux_table bindkey[] = {
	{ BER_BVC("starttls="), offsetof(slap_bindconf, sb_tls), 0, tlskey },
	{ BER_BVC("bindmethod="), offsetof(slap_bindconf, sb_method), 0, methkey },
	{ BER_BVC("binddn="), offsetof(slap_bindconf, sb_binddn), 1, NULL },
	{ BER_BVC("credentials="), offsetof(slap_bindconf, sb_cred), 1, NULL },
	{ BER_BVC("saslmech="), offsetof(slap_bindconf, sb_saslmech), 0, NULL },
	{ BER_BVC("secprops="), offsetof(slap_bindconf, sb_secprops), 0, NULL },
	{ BER_BVC("realm="), offsetof(slap_bindconf, sb_realm), 0, NULL },
	{ BER_BVC("authcID="), offsetof(slap_bindconf, sb_authcId), 0, NULL },
	{ BER_BVC("authzID="), offsetof(slap_bindconf, sb_authzId), 1, NULL },
	{ BER_BVNULL, 0, 0, NULL }
};

int bindconf_parse( char *word, slap_bindconf *bc ) {
	int i, rc = 0;
	char **cptr;
	cf_aux_table *tab;

	for (tab = bindkey; !BER_BVISNULL(&tab->key); tab++) {
		if ( !strncasecmp( word, tab->key.bv_val, tab->key.bv_len )) {
			cptr = (char **)((char *)bc + tab->off);
			if ( tab->aux ) {
				int j;
				rc = 1;
				for (j=0; tab->aux[j].word; j++) {
					if (!strcasecmp(word+tab->key.bv_len, tab->aux[j].word)) {
						int *ptr = (int *)cptr;
						*ptr = tab->aux[j].mask;
						rc = 0;
					}
				}
				if (rc ) {
					Debug(LDAP_DEBUG_ANY, "invalid bind config value %s\n",
						word, 0, 0 );
				}
				return rc;
			}
			*cptr = ch_strdup(word+tab->key.bv_len);
			return 0;
		}
	}
	return rc;
}

int bindconf_unparse( slap_bindconf *bc, struct berval *bv ) {
	char buf[BUFSIZ], *ptr;
	cf_aux_table *tab;
	char **cptr;
	struct berval tmp;

	ptr = buf;
	for (tab = bindkey; !BER_BVISNULL(&tab->key); tab++) {
		cptr = (char **)((char *)bc + tab->off);
		if ( tab->aux ) {
			int *ip = (int *)cptr, i;
			for ( i=0; tab->aux[i].word; i++ ) {
				if ( *ip == tab->aux[i].mask ) {
					*ptr++ = ' ';
					ptr = lutil_strcopy( ptr, tab->key.bv_val );
					ptr = lutil_strcopy( ptr, tab->aux[i].word );
					break;
				}
			}
		} else if ( *cptr ) {
			*ptr++ = ' ';
			ptr = lutil_strcopy( ptr, tab->key.bv_val );
			if ( tab->quote ) *ptr++ = '"';
			ptr = lutil_strcopy( ptr, *cptr );
			if ( tab->quote ) *ptr++ = '"';
		}
	}
	tmp.bv_val = buf;
	tmp.bv_len = ptr - buf;
	ber_dupbv( bv, &tmp );
	return 0;
}

void bindconf_free( slap_bindconf *bc ) {
	if ( bc->sb_binddn ) {
		ch_free( bc->sb_binddn );
	}
	if ( bc->sb_cred ) {
		ch_free( bc->sb_cred );
	}
	if ( bc->sb_saslmech ) {
		ch_free( bc->sb_saslmech );
	}
	if ( bc->sb_secprops ) {
		ch_free( bc->sb_secprops );
	}
	if ( bc->sb_realm ) {
		ch_free( bc->sb_realm );
	}
	if ( bc->sb_authcId ) {
		ch_free( bc->sb_authcId );
	}
	if ( bc->sb_authzId ) {
		ch_free( bc->sb_authzId );
	}
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

	if (c->emit) {
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
	if (c->emit) {
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
	if (c->emit) {
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
	if (c->emit) {
		return 1;
	}
	cf = ch_calloc( 1, sizeof(ConfigFile));
	if ( cfn->c_kids ) {
		for (cf2=cfn->c_kids; cf2 && cf2->c_sibs; cf2=cf2->c_sibs) ;
		cf2->c_sibs = cf;
	} else {
		cfn->c_kids = cf;
	}
	cfn = cf;
	rc = read_config_file(c->argv[1], c->depth + 1, c);
	c->lineno = savelineno - 1;
	cfn = cfsave;
	if ( rc ) {
		if ( cf2 ) cf2->c_sibs = NULL;
		else cfn->c_kids = NULL;
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
	if (c->emit) {
		return ldap_pvt_tls_get_option( NULL, flag, &c->value_string );
	}
	ch_free(c->value_string);
	return(ldap_pvt_tls_set_option(NULL, flag, c->argv[1]));
}

/* FIXME: this ought to be provided by libldap */
static int
config_tls_config(ConfigArgs *c) {
	int i, flag;
	struct verb_mask_list crlkeys[] = {
		{ "none",	LDAP_OPT_X_TLS_CRL_NONE },
		{ "peer",	LDAP_OPT_X_TLS_CRL_PEER },
		{ "all",	LDAP_OPT_X_TLS_CRL_ALL },
		{ NULL, 0 }
	};
	struct verb_mask_list vfykeys[] = {
		{ "never",	LDAP_OPT_X_TLS_NEVER },
		{ "demand",	LDAP_OPT_X_TLS_DEMAND },
		{ "try",	LDAP_OPT_X_TLS_TRY },
		{ "hard",	LDAP_OPT_X_TLS_HARD },
		{ NULL, 0 }
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
	if (c->emit) {
		ldap_pvt_tls_get_option( NULL, flag, &c->value_int );
		for (i=0; keys[i].word; i++) {
			if (keys[i].mask == c->value_int) {
				c->value_string = ch_strdup( keys[i].word );
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

/* -------------------------------------- */


static char *
strtok_quote( char *line, char *sep )
{
	int		inquote;
	char		*tmp;
	static char	*next;

	strtok_quote_ptr = NULL;
	if ( line != NULL ) {
		next = line;
	}
	while ( *next && strchr( sep, *next ) ) {
		next++;
	}

	if ( *next == '\0' ) {
		next = NULL;
		return( NULL );
	}
	tmp = next;

	for ( inquote = 0; *next; ) {
		switch ( *next ) {
		case '"':
			if ( inquote ) {
				inquote = 0;
			} else {
				inquote = 1;
			}
			AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
			break;

		case '\\':
			if ( next[1] )
				AC_MEMCPY( next,
					    next + 1, strlen( next + 1 ) + 1 );
			next++;		/* dont parse the escaped character */
			break;

		default:
			if ( ! inquote ) {
				if ( strchr( sep, *next ) != NULL ) {
					strtok_quote_ptr = next;
					*next++ = '\0';
					return( tmp );
				}
			}
			next++;
			break;
		}
	}

	return( tmp );
}

static char	buf[BUFSIZ];
static char	*line;
static size_t lmax, lcur;

#define CATLINE( buf ) \
	do { \
		size_t len = strlen( buf ); \
		while ( lcur + len + 1 > lmax ) { \
			lmax += BUFSIZ; \
			line = (char *) ch_realloc( line, lmax ); \
		} \
		strcpy( line + lcur, buf ); \
		lcur += len; \
	} while( 0 )

static void
fp_getline_init(ConfigArgs *c) {
	c->lineno = -1;
	buf[0] = '\0';
}

static int
fp_getline( FILE *fp, ConfigArgs *c )
{
	char	*p;

	lcur = 0;
	CATLINE(buf);
	c->lineno++;

	/* avoid stack of bufs */
	if ( strncasecmp( line, "include", STRLENOF( "include" ) ) == 0 ) {
		buf[0] = '\0';
		c->line = line;
		return(1);
	}

	while ( fgets( buf, sizeof( buf ), fp ) ) {
		p = strchr( buf, '\n' );
		if ( p ) {
			if ( p > buf && p[-1] == '\r' ) {
				--p;
			}
			*p = '\0';
		}
		/* XXX ugly */
		c->line = line;
		if ( line[0]
				&& ( p = line + strlen( line ) - 1 )[0] == '\\'
				&& p[-1] != '\\' )
		{
			p[0] = '\0';
			lcur--;
			
		} else {
			if ( !isspace( (unsigned char)buf[0] ) ) {
				return(1);
			}
			buf[0] = ' ';
		}
		CATLINE(buf);
		c->lineno++;
	}

	buf[0] = '\0';
	c->line = line;
	return(line[0] ? 1 : 0);
}

static int
fp_parse_line(ConfigArgs *c)
{
	char *token;
	char *tline = ch_strdup(c->line);
	char *hide[] = { "rootpw", "replica", "bindpw", "pseudorootpw", "dbpasswd", '\0' };
	int i;

	c->argc = 0;
	token = strtok_quote(tline, " \t");

	if(token) for(i = 0; hide[i]; i++) if(!strcasecmp(token, hide[i])) break;
	if(strtok_quote_ptr) *strtok_quote_ptr = ' ';
	Debug(LDAP_DEBUG_CONFIG, "line %lu (%s%s)\n", c->lineno, hide[i] ? hide[i] : c->line, hide[i] ? " ***" : "");
	if(strtok_quote_ptr) *strtok_quote_ptr = '\0';

	for(; token; token = strtok_quote(NULL, " \t")) {
		if(c->argc == c->argv_size - 1) {
			char **tmp;
			tmp = ch_realloc(c->argv, (c->argv_size + ARGS_STEP) * sizeof(*c->argv));
			if(!tmp) {
				Debug(LDAP_DEBUG_ANY, "line %lu: out of memory\n", c->lineno, 0, 0);
				return -1;
			}
			c->argv = tmp;
			c->argv_size += ARGS_STEP;
		}
		c->argv[c->argc++] = token;
	}
	c->argv[c->argc] = NULL;
	return(0);
}

void
config_destroy( )
{
	ucdata_unload( UCDATA_ALL );
	if ( frontendDB ) {
		/* NOTE: in case of early exit, frontendDB can be NULL */
		if ( frontendDB->be_schemandn.bv_val )
			free( frontendDB->be_schemandn.bv_val );
		if ( frontendDB->be_schemadn.bv_val )
			free( frontendDB->be_schemadn.bv_val );
		if ( frontendDB->be_acl )
			acl_destroy( frontendDB->be_acl, NULL );
	}
	free( line );
	if ( slapd_args_file )
		free ( slapd_args_file );
	if ( slapd_pid_file )
		free ( slapd_pid_file );
	if ( default_passwd_hash )
		ldap_charray_free( default_passwd_hash );
}

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

char **
slap_str2clist( char ***out, char *in, const char *brkstr )
{
	char	*str;
	char	*s;
	char	*lasts;
	int	i, j;
	char	**new;

	/* find last element in list */
	for (i = 0; *out && (*out)[i]; i++);

	/* protect the input string from strtok */
	str = ch_strdup( in );

	if ( *str == '\0' ) {
		free( str );
		return( *out );
	}

	/* Count words in string */
	j=1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			j++;
		}
	}

	*out = ch_realloc( *out, ( i + j + 1 ) * sizeof( char * ) );
	new = *out + i;
	for ( s = ldap_pvt_strtok( str, brkstr, &lasts );
		s != NULL;
		s = ldap_pvt_strtok( NULL, brkstr, &lasts ) )
	{
		*new = ch_strdup( s );
		new++;
	}

	*new = NULL;
	free( str );
	return( *out );
}
