/* config.c - configuration file handling routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
unsigned		num_subordinates = 0;

ber_len_t sockbuf_max_incoming = SLAP_SB_MAX_INCOMING_DEFAULT;
ber_len_t sockbuf_max_incoming_auth= SLAP_SB_MAX_INCOMING_AUTH;

int	slap_conn_max_pending = SLAP_CONN_MAX_PENDING_DEFAULT;
int	slap_conn_max_pending_auth = SLAP_CONN_MAX_PENDING_AUTH;

char   *slapd_pid_file  = NULL;
char   *slapd_args_file = NULL;

char   *strtok_quote_ptr;

int use_reverse_lookup = 0;

#ifdef LDAP_SLAPI
int slapi_plugins_used = 0;
#endif

static int fp_getline(FILE *fp, ConfigArgs *c);
static void fp_getline_init(ConfigArgs *c);
static int fp_parse_line(ConfigArgs *c);

static char	*strtok_quote(char *line, char *sep);
#if 0
static int load_ucdata(char *path);
#endif

static int add_syncrepl LDAP_P(( Backend *, char **, int ));
static int parse_syncrepl_line LDAP_P(( char **, int, syncinfo_t *));

int config_generic(ConfigArgs *c);
int config_search_base(ConfigArgs *c);
int config_passwd_hash(ConfigArgs *c);
int config_schema_dn(ConfigArgs *c);
int config_sizelimit(ConfigArgs *c);
int config_timelimit(ConfigArgs *c);
int config_limits(ConfigArgs *c); 
int config_overlay(ConfigArgs *c);
int config_suffix(ConfigArgs *c); 
int config_deref_depth(ConfigArgs *c);
int config_rootdn(ConfigArgs *c);
int config_rootpw(ConfigArgs *c);
int config_restrict(ConfigArgs *c);
int config_allows(ConfigArgs *c);
int config_disallows(ConfigArgs *c);
int config_requires(ConfigArgs *c);
int config_security(ConfigArgs *c);
int config_referral(ConfigArgs *c);
int config_loglevel(ConfigArgs *c);
int config_syncrepl(ConfigArgs *c);
int config_replica(ConfigArgs *c);
int config_updatedn(ConfigArgs *c);
int config_updateref(ConfigArgs *c);
int config_include(ConfigArgs *c);
#ifdef HAVE_TLS
int config_tls_option(ConfigArgs *c);
int config_tls_verify(ConfigArgs *c);
#endif
#ifdef LDAP_SLAPI
int config_plugin(ConfigArgs *c);
#endif
int config_pluginlog(ConfigArgs *c);

enum {
	CFG_DATABASE = 1,
	CFG_BACKEND,
	CFG_TLS_RAND,
	CFG_TLS_CIPHER,
	CFG_TLS_CERT_FILE,
	CFG_TLS_CERT_KEY,
	CFG_TLS_CERT_PATH,
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
	CFG_SUB,
	CFG_SASLOPT,
	CFG_REWRITE,
	CFG_DEPTH,
	CFG_OID,
	CFG_OC,
	CFG_DIT,
	CFG_ATTR,
	CFG_ATOPT,
	CFG_CHECK,
	CFG_ACL,
	CFG_AUDITLOG,
	CFG_REPLOG,
	CFG_ROOTDSE,
	CFG_LOGFILE,
	CFG_PLUGIN,
	CFG_MODLOAD,
	CFG_MODPATH,
	CFG_LASTMOD
};

/* original config.c ordering */

ConfigTable SystemConfiguration[] = {
  { "backend",			2,  2,  0,  "type",	ARG_PRE_DB|ARG_MAGIC|CFG_BACKEND, &config_generic,	NULL, NULL, NULL },
  { "database",			2,  2,  0,  "type",	ARG_MAGIC|CFG_DATABASE,	&config_generic,		NULL, NULL, NULL },
  { "localSSF",			2,  2,  0,  "ssf",	ARG_LONG,		&local_ssf,			NULL, NULL, NULL },
  { "concurrency",		2,  2,  0,  "level",	ARG_LONG|ARG_NONZERO|ARG_MAGIC|CFG_CONCUR, &config_generic, NULL, NULL, NULL },
  { "index_substr_if_minlen",	2,  2,  0,  "min",	ARG_INT|ARG_NONZERO,	&index_substr_if_minlen,	NULL, NULL, NULL },
  { "index_substr_if_maxlen",	2,  2,  0,  "max",	ARG_INT|ARG_NONZERO|ARG_SPECIAL, &index_substr_if_maxlen, NULL, NULL, NULL },
  { "index_substr_any_len",	2,  2,  0,  "len",	ARG_INT|ARG_NONZERO,	&index_substr_any_len,		NULL, NULL, NULL },
  { "index_substr_step",	2,  2,  0,  "step",	ARG_INT|ARG_NONZERO,	&index_substr_any_step,		NULL, NULL, NULL },
  { "sockbuf_max_incoming",	2,  2,  0,  "max",	ARG_LONG,		&sockbuf_max_incoming,		NULL, NULL, NULL },
  { "sockbuf_max_incoming_auth",2,  2,  0,  "max",	ARG_LONG,		&sockbuf_max_incoming_auth, 	NULL, NULL, NULL },
  { "conn_max_pending",		2,  2,  0,  "max",	ARG_LONG,		&slap_conn_max_pending,		NULL, NULL, NULL },
  { "conn_max_pending_auth",	2,  2,  0,  "max",	ARG_LONG,		&slap_conn_max_pending_auth,	NULL, NULL, NULL },
  { "defaultSearchBase",	2,  2,  0,  "dn",	ARG_MAGIC,		&config_search_base,		NULL, NULL, NULL },
  { "threads",			2,  2,  0,  "count",	ARG_INT|ARG_MAGIC|CFG_THREADS, &config_generic,		NULL, NULL, NULL },
  { "pidfile",			2,  2,  0,  "file",	ARG_STRING,		&slapd_pid_file,		NULL, NULL, NULL },
  { "argsfile",			2,  2,  0,  "file",	ARG_STRING,		&slapd_args_file,		NULL, NULL, NULL },
  { "password-hash",		2,  2,  0,  "hash",	ARG_MAGIC,		&config_passwd_hash,		NULL, NULL, NULL },
  { "password-crypt-salt-format",2, 2,  0,  "salt",	ARG_MAGIC|CFG_SALT,	&config_generic,		NULL, NULL, NULL },
#ifdef SLAP_AUTH_REWRITE
  { "auth-rewrite",		2,  2, 14,  NULL,	ARG_MAGIC|CFG_REWRITE,	&config_generic,		NULL, NULL, NULL },
#endif
  { "sasl",			2,  2,  4,  NULL,	ARG_MAGIC|CFG_SASLOPT,	&config_generic,		NULL, NULL, NULL },	/* XXX */
  { "auth",			2,  2,  4,  NULL,	ARG_MAGIC|CFG_SASLOPT,	&config_generic,		NULL, NULL, NULL },
  { "schemadn",			2,  2,  0,  "dn",	ARG_MAGIC,		&config_schema_dn,		NULL, NULL, NULL },
  { "ucdata-path",		2,  2,  0,  "path",	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
  { "sizelimit",		2,  2,  0,  "limit",	ARG_MAGIC|CFG_SIZE,	&config_sizelimit,		NULL, NULL, NULL },
  { "timelimit",		2,  2,  0,  "limit",	ARG_MAGIC|CFG_TIME,	&config_timelimit,		NULL, NULL, NULL },
  { "limits",			2,  2,  0,  "limits",	ARG_DB|ARG_MAGIC|CFG_LIMITS, &config_generic,		NULL, NULL, NULL },
  { "subordinate",		1,  1,  0,  "sub",	ARG_DB|ARG_MAGIC|CFG_SUB, &config_generic,		NULL, NULL, NULL },
  { "overlay",			2,  2,  0,  "overlay",	ARG_DB|ARG_MAGIC,	&config_overlay,		NULL, NULL, NULL },
  { "suffix",			2,  2,  0,  "suffix",	ARG_DB|ARG_MAGIC,	&config_suffix,			NULL, NULL, NULL },
  { "maxDerefDepth",		2,  2,  0,  "depth",	ARG_DB|ARG_INT|ARG_MAGIC|CFG_DEPTH, &config_generic,	NULL, NULL, NULL },
  { "rootdn",			2,  2,  0,  "dn",	ARG_DB|ARG_MAGIC,	&config_rootdn,			NULL, NULL, NULL },
  { "rootpw",			2,  2,  0,  "password",	ARG_DB|ARG_MAGIC,	&config_rootpw,			NULL, NULL, NULL },
  { "readonly",			2,  2,  0,  "on|off",	ARG_ON_OFF|ARG_MAGIC|CFG_RO, &config_generic,		NULL, NULL, NULL },
  { "restrict",			2,  0,  0,  "op_list",	ARG_MAGIC,		&config_restrict,		NULL, NULL, NULL },
  { "allows",			2,  0,  5,  "features",	ARG_PRE_DB|ARG_MAGIC,	&config_allows,			NULL, NULL, NULL },
  { "disallows",		2,  0,  8,  "features",	ARG_PRE_DB|ARG_MAGIC,	&config_disallows,		NULL, NULL, NULL },
  { "require",			2,  0,  7,  "features",	ARG_MAGIC,		&config_requires,		NULL, NULL, NULL },
  { "security",			2,  0,  0,  "factors",	ARG_MAGIC,		&config_security,		NULL, NULL, NULL },
  { "referral",			2,  2,  0,  "url",	ARG_MAGIC,		&config_referral,		NULL, NULL, NULL },
  { "logfile",			2,  2,  0,  "file",	ARG_MAGIC|CFG_LOGFILE,	&config_generic,		NULL, NULL, NULL },
  { "objectidentifier",		0,  0,  0,  NULL,	ARG_MAGIC|CFG_OID,	&config_generic, 		NULL, NULL, NULL },
  { "objectclass",		2,  0,  0,  "objectclass", ARG_PAREN|ARG_MAGIC|CFG_OC, &config_generic,		NULL, NULL, NULL },
  { "ditcontentrule",		0,  0,  0,  NULL,	ARG_MAGIC|CFG_DIT,	&config_generic,		NULL, NULL, NULL },
  { "attribute",		2,  0,  9,  "attribute", ARG_PAREN|ARG_MAGIC|CFG_ATTR, &config_generic,		NULL, NULL, NULL },
  { "attributeoptions",		0,  0,  0,  NULL,	ARG_MAGIC|CFG_ATOPT,	&config_generic, 		NULL, NULL, NULL },
  { "schemacheck",		2,  2,  0,  "on|off",	ARG_ON_OFF|ARG_MAGIC|CFG_CHECK,	&config_generic,	NULL, NULL, NULL },
  { "access",			0,  0,  0,  NULL,	ARG_MAGIC|CFG_ACL,	&config_generic,		NULL, NULL, NULL },
  { "loglevel",			2,  0,  0,  "level",	ARG_MAGIC,		&config_loglevel,		NULL, NULL, NULL },
  { "syncrepl",			0,  0,  0,  NULL,	ARG_DB|ARG_MAGIC,	&config_syncrepl,		NULL, NULL, NULL },
  { "replica",			2,  0,  0,  "host or uri", ARG_DB|ARG_MAGIC,	&config_replica,		NULL, NULL, NULL },
  { "replicationInterval",	0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
  { "updatedn",			2,  2,  0,  "dn",	ARG_DB|ARG_MAGIC,	&config_updatedn,		NULL, NULL, NULL },
  { "updateref",		2,  2,  0,  "url",	ARG_DB|ARG_MAGIC,	&config_updateref,		NULL, NULL, NULL },
  { "replogfile",		2,  2,  0,  "filename", ARG_MAGIC|ARG_STRING|CFG_REPLOG,	&config_generic,		NULL, NULL, NULL },
  { "rootDSE",			2,  2,  0,  "filename", ARG_MAGIC|CFG_ROOTDSE,	&config_generic,		NULL, NULL, NULL },
  { "lastmod",			2,  2,  0,  "on|off",	ARG_DB|ARG_ON_OFF|ARG_MAGIC|CFG_LASTMOD, &config_generic, NULL, NULL, NULL },
#ifdef SIGHUP
  { "gentlehup",		2,  2,  0,  "on|off",	ARG_ON_OFF,		&global_gentlehup,		NULL, NULL, NULL },
#else
  { "gentlehup",		2,  2,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
#endif
  { "idletimeout",		2,  2,  0,  "timeout",	ARG_INT,		&global_idletimeout,		NULL, NULL, NULL },
/* XXX -- special case? */
  { "include",			2,  2,  0,  "filename",	ARG_MAGIC,		&config_include,		NULL, NULL, NULL },
  { "srvtab",			2,  2,  0,  "filename",	ARG_STRING,		&ldap_srvtab,			NULL, NULL, NULL },
#ifdef SLAPD_MODULES
  { "moduleload",		2,  2,  0,  "filename",	ARG_MAGIC|CFG_MODLOAD,	&config_generic,		NULL, NULL, NULL },
  { "modulepath",		2,  2,  0,  "path",	ARG_MAGIC|CFG_MODPATH,	&config_generic,		NULL, NULL, NULL },
#endif
#ifdef HAVE_TLS
  { "TLSRandFile",		0,  0,  0,  NULL,	CFG_TLS_RAND|ARG_MAGIC,		&config_tls_option,	NULL, NULL, NULL },
  { "TLSCipherSuite",		0,  0,  0,  NULL,	CFG_TLS_CIPHER|ARG_MAGIC, 	&config_tls_option,	NULL, NULL, NULL },
  { "TLSCertificateFile",	0,  0,  0,  NULL,	CFG_TLS_CERT_FILE|ARG_MAGIC,	&config_tls_option,	NULL, NULL, NULL },
  { "TLSCertificateKeyFile",	0,  0,  0,  NULL,	CFG_TLS_CERT_KEY|ARG_MAGIC,	&config_tls_option,	NULL, NULL, NULL },
  { "TLSCertificatePath",	0,  0,  0,  NULL,	CFG_TLS_CERT_PATH|ARG_MAGIC,	&config_tls_option,	NULL, NULL, NULL },
  { "TLSCACertificateFile",	0,  0,  0,  NULL,	CFG_TLS_CA_FILE|ARG_MAGIC,	&config_tls_option,	NULL, NULL, NULL },
#ifdef HAVE_OPENSSL_CRL
  { "TLSCRLCheck",		0,  0,  0,  NULL,	CFG_TLS_CRLCHECK|ARG_MAGIC,	&config_tls_option,	NULL, NULL, NULL },
#else
  { "TLSCRLCheck",		0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
#endif
  { "TLSVerifyClient",		0,  0,  0,  NULL,	CFG_TLS_VERIFY|ARG_MAGIC,	&config_tls_verify,	NULL, NULL, NULL },
#endif
#ifdef SLAPD_RLOOKUPS
  { "reverse-lookup",		2,  2,  0,  "on|off",	ARG_ON_OFF,		&use_reverse_lookup,		NULL, NULL, NULL },
#else
  { "reverse-lookup",		2,  2,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
#endif
#ifdef LDAP_SLAPI
  { "plugin",			0,  0,  0,  NULL,	ARG_MAGIC|CFG_PLUGIN,	&config_generic,		NULL, NULL, NULL },
  { "pluginlog",		2,  2,  0,  "filename",	ARG_STRING,		&slapi_log_file,		NULL, NULL, NULL },
#else
  { "plugin",			0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
  { "pluginlog",		0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
#endif
  { "replica-pidfile",		0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
  { "replica-argsfile",		0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL },
  { NULL,			0,  0,  0,  NULL,	ARG_IGNORED,		NULL,				NULL, NULL, NULL }
};


ConfigArgs *
new_config_args(BackendDB *be, const char *fname, int lineno, int argc, char **argv) {
	ConfigArgs *c;
	if(!(c = ch_calloc(1, sizeof(ConfigArgs)))) return(NULL);
	c->be     = be; 
	c->fname  = fname;
	c->argc   = argc;
	c->argv   = argv; 
	c->lineno = lineno;
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
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: keyword <%s> ignored\n",
			c->fname, c->lineno, Conf[i].name);
		return(0);
	}
	if(Conf[i].min_args && (c->argc < Conf[i].min_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: ", c->fname, c->lineno, 0);
		Debug(LDAP_DEBUG_CONFIG, "keyword <%s> missing <%s> argument\n", Conf[i].name, Conf[i].what, 0);
		return(ARG_BAD_CONF);
	}
	if(Conf[i].max_args && (c->argc > Conf[i].max_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: ", c->fname, c->lineno, 0);
		Debug(LDAP_DEBUG_CONFIG, "extra cruft after <%s> in <%s> line (ignored)\n", Conf[i].what, Conf[i].name, 0);
	}
	if((arg_type & ARG_DB) && !c->be) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: keyword <%s> allowed only within database declaration\n",
			c->fname, c->lineno, Conf[i].name);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PRE_DB) && c->be) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: keyword <%s> must appear before any database declaration\n",
			c->fname, c->lineno, Conf[i].name);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PAREN) && *c->argv[1] != '(' /*')'*/) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: old <%s> format not supported\n", c->fname, c->lineno, Conf[i].name);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARGS_POINTER) && !Conf[i].arg_item) {
		Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: null arg_item for <%s>\n", c->fname, c->lineno, Conf[i].name);
		return(ARG_BAD_CONF);
	}
	c->type = arg_user = (arg_type & ARGS_USERLAND);
	c->value_int = c->value_long = c->value_ber_t = 0;
	c->value_string = NULL;
	if(arg_type & ARGS_NUMERIC) {
		iarg = 0; larg = 0; barg = 0;
		switch(arg_type & ARGS_NUMERIC) {
			case ARG_INT:		iarg = atoi(c->argv[1]);		break;
			case ARG_LONG:		larg = atol(c->argv[1]);		break;
			case ARG_BER_LEN_T:	barg = (ber_len_t)atol(c->argv[1]);	break;
			case ARG_ON_OFF:
				if(!strcasecmp(c->argv[1], "on")) {
					iarg = 1;
				} else if(!strcasecmp(c->argv[1], "off")) {
					iarg = 0;
				} else {
					Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: ignoring ", c->fname, c->lineno, 0);
					Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%s) in <%s> line\n",
						Conf[i].what, c->argv[1], Conf[i].name);
					return(0);
				}
				break;
		}
		i = (arg_type & ARG_NONZERO) ? 1 : 0;
		rc = (Conf == SystemConfiguration) ? ((arg_type & ARG_SPECIAL) && (larg < index_substr_if_maxlen)) : 0;
		if(iarg < i || larg < i || barg < i || rc) {
			larg = larg ? larg : (barg ? barg : iarg);
			Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: " , c->fname, c->lineno, 0);
			Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%ld) in <%s> line\n", Conf[i].what, larg, Conf[i].name);
			return(ARG_BAD_CONF);
		}
		c->value_int = iarg;
		c->value_long = larg;
		c->value_ber_t = barg;
	}
	if(arg_type & ARG_STRING) c->value_string = ch_strdup(c->argv[1]);
	if(arg_type & ARG_MAGIC) {
		if(!c->be) c->be = frontendDB;
		rc = (*((ConfigDriver*)Conf[i].arg_item))(c);
		if(c->be == frontendDB) c->be = NULL;
		if(rc) {
			Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: ", c->fname, c->lineno, 0);
			Debug(LDAP_DEBUG_CONFIG, "handler for <%s> exited with %d!", Conf[i].name, rc, 0);
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
				if(cc) ch_free(cc);	/* potential memory leak */
				cc = c->value_string;
				/* memcpy(Conf[i].arg_item, &c->value_string, sizeof(void *)); */
				break;
				}
	}
	return(arg_user);
}

int
read_config(const char *fname, int depth) {
	return(read_config_file(fname, depth, NULL));
}

int
read_config_file(char *fname, int depth, ConfigArgs *cf)
{
	FILE *fp;
	char *line, *savefname;
	ConfigArgs *c;
	int rc, i;

	c = ch_calloc(1, sizeof(ConfigArgs));

	if(depth) {
		memcpy(c, cf, sizeof(ConfigArgs));
	} else {
		c->depth = depth; /* XXX */
		c->bi = NULL;
		c->be = NULL;
	}

	c->fname = fname;
	c->argv = ch_calloc(ARGS_STEP + 1, sizeof(*c->argv));
	c->argv_size = ARGS_STEP + 1;

	if((fp = fopen(fname, "r")) == NULL) {
		ldap_syslog = 1;
		Debug(LDAP_DEBUG_ANY,
		    "could not open config file \"%s\": %s (%d)\n",
		    fname, strerror(errno), errno);
		return(1);
	}

	Debug(LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0);

	fp_getline_init(c);

	while(fp_getline(fp, c)) {
		/* skip comments and blank lines */
		if(c->line[0] == '#' || c->line[0] == '\0') continue;
		if(fp_parse_line(c)) goto badline;

		if(c->argc < 1) {
			Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: bad config line (ignored)\n", fname, c->lineno, 0);
			continue;
		}

		rc = parse_config_table(SystemConfiguration, c);
		if(!rc) continue;
		if(rc & ARGS_USERLAND) switch(rc) {	/* XXX a usertype would be opaque here */
			default:	Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: unknown user type <%d>\n",
						c->fname, c->lineno, *c->argv);
					goto badline;
		} else if(rc == ARG_BAD_CONF || rc != ARG_UNKNOWN) {
			goto badline;
		} else if(c->bi && c->bi->bi_config) {		/* XXX to check: could both be/bi_config? oops */
			if(rc = (*c->bi->bi_config)(c->bi, c->fname, c->lineno, c->argc, c->argv)) switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: "
						"unknown directive <%s> inside backend info definition (ignored)\n",
				   		c->fname, c->lineno, *c->argv);
					continue;
				default:
					goto badline;
			}
		} else if(c->be && c->be->be_config) {
			if(rc = (*c->be->be_config)(c->be, c->fname, c->lineno, c->argc, c->argv)) switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug( LDAP_DEBUG_CONFIG, "%s: line %lu: "
						"unknown directive <%s> inside backend database definition (ignored)\n",
						c->fname, c->lineno, *c->argv);
					continue;
				default:
					goto badline;
			}
		} else if(frontendDB->be_config) {
			if(rc = (*frontendDB->be_config)(frontendDB, c->fname, (int)c->lineno, c->argc, c->argv)) switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug( LDAP_DEBUG_CONFIG, "%s: line %lu: "
						"%s: line %lu: unknown directive <%s> inside global database definition (ignored)\n",
						c->fname, c->lineno, *c->argv);
					continue;
				default:
					goto badline;
			}
		} else {
			Debug(LDAP_DEBUG_CONFIG, "%s: line %lu: "
				"unknown directive <%s> outside backend info and database definitions (ignored)\n",
				c->fname, c->lineno, *c->argv);
			continue;

		}
	}

	fclose(fp);

	if ( BER_BVISNULL( &frontendDB->be_schemadn ) ) {
		ber_str2bv( SLAPD_SCHEMA_DN, sizeof(SLAPD_SCHEMA_DN)-1, 1,
			&frontendDB->be_schemadn );
		dnNormalize( 0, NULL, NULL, &frontendDB->be_schemadn, &frontendDB->be_schemandn, NULL );
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

int
config_generic(ConfigArgs *c) {
	char *p = strchr(c->line,'(' /*')'*/);
	int i;

	switch(c->type) {
		case CFG_BACKEND:
			if(!(c->bi = backend_info(c->argv[1]))) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"backend %s failed init!\n", c->fname, c->lineno, c->argv[1]);
				return(1);
			}
			break;

		case CFG_DATABASE:
			c->bi = NULL;
			if(!(c->be = backend_db_init(c->argv[1]))) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"database %s failed init!\n", c->fname, c->lineno, c->argv[1]);
				return(1);
			}
			break;

		case CFG_CONCUR:
			ldap_pvt_thread_set_concurrency(c->value_long);
			break;

		case CFG_THREADS:
			ldap_pvt_thread_pool_maxthreads(&connection_pool, c->value_int);
			connection_pool_max = c->value_int;	/* save for reference */
			break;

		case CFG_SALT:
			lutil_salt_format(c->argv[1]);
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

		case CFG_SUB:
			SLAP_DBFLAGS(c->be) |= SLAP_DBFLAG_GLUE_SUBORDINATE;
			num_subordinates++;
			break;

		case CFG_SASLOPT:
			/* XXX slap_sasl_config doesn't actually use the line argument */
			if(slap_sasl_config(c->argc, c->argv, c->line, c->fname, c->lineno))
				return(1);
			break;

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
			if(!global_schemacheck) Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
				"schema checking disabled! your mileage may vary!\n",
				c->fname, c->lineno, 0);
			break;

		case CFG_ACL:
			parse_acl(c->be, c->fname, c->lineno, c->argc, c->argv);
			break;

#if 0
		case CFG_AUDITLOG:
			c->be->be_auditlogfile = c->value_string;
			break;
#endif

		case CFG_REPLOG:
			if(SLAP_MONITOR(c->be)) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"\"replogfile\" should not be used "
					"inside monitor database\n",
					c->fname, c->lineno, 0);
				return(0);	/* FIXME: should this be an error? */
			}

			c->be->be_replogfile = c->value_string;
			break;

		case CFG_ROOTDSE:
			if(read_root_dse_file(c->argv[1])) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"could not read \"rootDSE <filename>\" line\n",
					c->fname, c->lineno, 0);
				return(1);
			}
			break;

		case CFG_LOGFILE: {
			FILE *logfile = fopen(c->argv[1], "w");
			if(logfile) lutil_debug_file(logfile);
			break;
			}

		case CFG_LASTMOD:
			if(SLAP_NOLASTMODCMD(c->be)) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"lastmod not available for %s databases\n",
					c->fname, c->lineno, c->be->bd_info->bi_type);
				return(1);
			}
			if(c->value_int)
				SLAP_DBFLAGS(c->be) &= ~SLAP_DBFLAG_NOLASTMOD;
			else
				SLAP_DBFLAGS(c->be) |= SLAP_DBFLAG_NOLASTMOD;
			break;

#ifdef SLAPD_MODULES
		case CFG_MODLOAD:
			if(module_load(c->argv[1], c->argc - 2, (c->argc > 2) ? c->argv + 2 : NULL))
				return(1);
			break;

		case CFG_MODPATH:
			if(module_path(c->argv[1])) return(1);
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
			Debug(LDAP_DEBUG_ANY, "%s: line %lu: unknown CFG_TYPE %d"
				"(ignored)\n", c->fname, c->lineno, c->type);

	}
	return(0);
}


int
config_search_base(ConfigArgs *c) {
	struct berval dn;
	int rc;
	if(c->bi || c->be) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: defaultSearchBase line must appear "
			"prior to any backend or database definition\n",
			c->fname, c->lineno, 0);
		return(1);
	}

	if(default_search_nbase.bv_len) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"default search base \"%s\" already defined "
			"(discarding old)\n",
			c->fname, c->lineno, default_search_base.bv_val);
		free(default_search_base.bv_val);
		free(default_search_nbase.bv_val);
	}

	ber_str2bv(c->argv[1], 0, 1, &dn);
	rc = dnPrettyNormal(NULL, &dn, &default_search_base, &default_search_nbase, NULL);

	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY,
			"%s: line %lu: defaultSearchBase DN is invalid\n",
			c->fname, c->lineno, 0 );
		return(1);
	}
	return(0);
}

int
config_passwd_hash(ConfigArgs *c) {
	int i;
	if(default_passwd_hash) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"already set default password_hash\n",
			c->fname, c->lineno, 0);
		return(1);
	}
	for(i = 1; i < c->argc; i++) {
		if(!lutil_passwd_scheme(c->argv[i])) {
			Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
				"password scheme \"%s\" not available\n",
				c->fname, c->lineno, c->argv[i] );
		} else {
			ldap_charray_add(&default_passwd_hash, c->argv[i]);
		}
		if(!default_passwd_hash) {
			Debug(LDAP_DEBUG_ANY, "%s: line %lu: no valid hashes found\n",
				c->fname, c->lineno, 0 );
			return(1);
		}
	}
	return(0);
}

int
config_schema_dn(ConfigArgs *c) {
	struct berval dn;
	int rc;
	ber_str2bv(c->argv[1], 0, 1, &dn);
	rc = dnPrettyNormal(NULL, &dn, &c->be->be_schemadn, &c->be->be_schemandn, NULL);
	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"schema DN is invalid\n", c->fname, c->lineno, 0);
		return(1);
	}
	return(0);
}

int
config_sizelimit(ConfigArgs *c) {
	int i, rc = 0;
	char *next;
	struct slap_limits_set *lim = &c->be->be_def_limit;
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "size", 4)) {
			if(rc = limits_parse_one(c->argv[i], lim)) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"unable to parse value \"%s\" in \"sizelimit <limit>\" line\n",
					c->fname, c->lineno, c->argv[i]);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_s_soft = -1;
			} else {
				lim->lms_s_soft = strtol(c->argv[i], &next, 0);
				if(next == c->argv[i]) {
					Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"unable to parse limit \"%s\" in \"sizelimit <limit>\" line\n",
						c->fname, c->lineno, c->argv[i]);
					return(1);
				} else if(next[0] != '\0') {
					Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"trailing chars \"%s\" in \"sizelimit <limit>\" line (ignored)\n",
						c->fname, c->lineno, next);
				}
			}
			lim->lms_s_hard = 0;
		}
	}
	return(0);
}

int
config_timelimit(ConfigArgs *c) {
	int i, rc = 0;
	char *next;
	struct slap_limits_set *lim = &c->be->be_def_limit;
	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "time", 4)) {
			if(rc = limits_parse_one(c->argv[i], lim)) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"unable to parse value \"%s\" in \"timelimit <limit>\" line\n",
					c->fname, c->lineno, c->argv[i]);
				return(1);
			}
		} else {
			if(!strcasecmp(c->argv[i], "unlimited")) {
				lim->lms_t_soft = -1;
			} else {
				lim->lms_t_soft = strtol(c->argv[i], &next, 0);
				if(next == c->argv[i]) {
					Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"unable to parse limit \"%s\" in \"timelimit <limit>\" line\n",
						c->fname, c->lineno, c->argv[i]);
					return(1);
				} else if(next[0] != '\0') {
					Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"trailing chars \"%s\" in \"timelimit <limit>\" line (ignored)\n",
						c->fname, c->lineno, next);
				}
			}
			lim->lms_t_hard = 0;
		}
	}
	return(0);
}

int
config_overlay(ConfigArgs *c) {
	if(c->argv[1][0] == '-' && overlay_config(c->be, &c->argv[1][1])) {
		/* log error */
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: (optional) %s",
			c->fname, c->lineno, c->be == frontendDB ? "global " : "");
		Debug(LDAP_DEBUG_ANY, "overlay \"%s\" configuration "
			"failed (ignored)\n", c->argv[1][1], 0, 0);
	} else if(overlay_config(c->be, c->argv[1])) {
		return(1);
	}
	return(0);
}

int
config_suffix(ConfigArgs *c) {
	Backend *tbe;
	struct berval dn, pdn, ndn;
	int rc;
#ifdef SLAPD_MONITOR_DN
	if(!strcasecmp(c->argv[1], SLAPD_MONITOR_DN)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"%s\" is reserved for monitoring slapd\n",
			c->fname, c->lineno, SLAPD_MONITOR_DN);
		return(1);
	}
#endif
	ber_str2bv(c->argv[1], 0, 1, &dn);

	rc = dnPrettyNormal(NULL, &dn, &pdn, &ndn, NULL);
	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: suffix DN is invalid\n",
			c->fname, c->lineno, 0);
		return(1);
	}
	tbe = select_backend(&ndn, 0, 0);
	if(tbe == c->be) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: suffix already served by this backend! (ignored)\n",
			c->fname, c->lineno, 0);
		free(pdn.bv_val);
		free(ndn.bv_val);
	} else if(tbe) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: suffix already served by a preceding backend \"%s\"\n",
			c->fname, c->lineno, tbe->be_suffix[0].bv_val);
		free(pdn.bv_val);
		free(ndn.bv_val);
		return(1);
	} else if(pdn.bv_len == 0 && default_search_nbase.bv_len) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: suffix DN empty and default search "
			"base provided \"%s\" (assuming okay)\n",
			c->fname, c->lineno, default_search_base.bv_val);
	}
	ber_bvarray_add(&c->be->be_suffix, &pdn);
	ber_bvarray_add(&c->be->be_nsuffix, &ndn);
	return(0);
}

int
config_rootdn(ConfigArgs *c) {
	struct berval dn;
	int rc;

	ber_str2bv(c->argv[1], 0, 1, &dn);

	rc = dnPrettyNormal(NULL, &dn, &c->be->be_rootdn, &c->be->be_rootndn, NULL);

	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"rootdn DN is invalid\n", c->fname, c->lineno, 0);
		return(1);
	}
	return(0);
}

int
config_rootpw(ConfigArgs *c) {
	Backend *tbe = select_backend(&c->be->be_rootndn, 0, 0);
	if(tbe != c->be) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"rootpw can only be set when rootdn is under suffix\n",
			c->fname, c->lineno, 0);
		return(1);
	}
	ber_str2bv(c->argv[1], 0, 1, &c->be->be_rootpw);
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
		*m |= v[j].mask;
	}
	return(0);
}

int
config_restrict(ConfigArgs *c) {
	slap_mask_t restrictops = 0;
	int i, j;
	struct verb_mask_list restrictable_exops[] = {
		{ LDAP_EXOP_START_TLS,		SLAP_RESTRICT_EXOP_START_TLS },
		{ LDAP_EXOP_MODIFY_PASSWD,	SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
		{ LDAP_EXOP_X_WHO_AM_I,		SLAP_RESTRICT_EXOP_WHOAMI },
		{ LDAP_EXOP_X_CANCEL,		SLAP_RESTRICT_EXOP_CANCEL },
		{ NULL,	0 }
	};
	struct verb_mask_list restrictable_ops[] = {
		{ "bind",		SLAP_RESTRICT_OP_BIND },
		{ "add",		SLAP_RESTRICT_OP_ADD },
		{ "modify",		SLAP_RESTRICT_OP_MODIFY },
		{ "modrdn",		SLAP_RESTRICT_OP_RENAME },
		{ "rename",		SLAP_RESTRICT_OP_RENAME },
		{ "delete",		SLAP_RESTRICT_OP_DELETE },
		{ "search",		SLAP_RESTRICT_OP_SEARCH },
		{ "compare",		SLAP_RESTRICT_OP_COMPARE },
		{ "read",		SLAP_RESTRICT_OP_READS },
		{ "write",		SLAP_RESTRICT_OP_WRITES },
		{ NULL,	0 }
	};

	for(i = 1; i < c->argc; i++) {
		j = verb_to_mask(c, restrictable_ops, i);
		if(restrictable_ops[j].word) {
			restrictops |= restrictable_ops[j].mask;
			continue;
		} else if(!strncasecmp(c->argv[i], "extended", STRLENOF("extended"))) {
			char *e = c->argv[i] + STRLENOF("extended");
			if(e[0] == '=') {
				int k = verb_to_mask(c, restrictable_exops, e[1]);
				if(restrictable_exops[k].word) {
					restrictops |= restrictable_exops[k].mask;
					continue;
				} else break;
			} else if(!e[0]) {
				restrictops &= ~SLAP_RESTRICT_EXOP_MASK;
				restrictops |= SLAP_RESTRICT_OP_EXTENDED;
			} else break;
		}
	}
	if(i < c->argc) {
		c->be->be_restrictops |= restrictops;
		return(0);
	}
	Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
		"unknown operation %s in \"restrict <features>\" line\n",
		c->fname, c->lineno, c->argv[i]);
	return(1);
}

int
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
	if(i = verbs_to_mask(c, allowable_ops, &allows)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"unknown feature %s in \"allow <features>\" line\n",
			c->fname, c->lineno, c->argv[i]);
		return(1);
	}
	global_allows |= allows;
	return(0);
}

int
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
	if(i = verbs_to_mask(c, disallowable_ops, &disallows)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"unknown feature %s in \"disallow <features>\" line\n",
			c->fname, c->lineno, c->argv[i]);
		return(1);
	}
	global_disallows |= disallows;
	return(0);
}

int
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
	if(i = verbs_to_mask(c, requires_ops, &requires)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"unknown feature %s in \"require <features>\" line\n",
			c->fname, c->lineno, c->argv[i]);
		return(1);
	}
	c->be->be_requires = requires;
	return(0);
}

int
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
	ldap_syslog = 0;

	for( i=1; i < c->argc; i++ ) {
		int	level;

		if ( isdigit( c->argv[i][0] ) ) {
			level = strtol( c->argv[i], &next, 10 );
			if ( next == NULL || next[0] != '\0' ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %lu: unable to parse level \"%s\" "
					"in \"loglevel <level> [...]\" line.\n",
					c->fname, c->lineno , c->argv[i] );
				return( 1 );
			}
		} else {
			int j = verb_to_mask(c, loglevel_ops, c->argv[i][0]);
			if(!loglevel_ops[j].word) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %lu: unknown level \"%s\" "
					"in \"loglevel <level> [...]\" line.\n",
					c->fname, c->lineno , c->argv[i] );
				return( 1 );
			}
			level = loglevel_ops[j].mask;
		}
		ldap_syslog |= level;
	}
	return(0);
}

int
config_syncrepl(ConfigArgs *c) {
	if(SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"syncrepl: database already shadowed.\n",
			c->fname, c->lineno, 0);
		return(1);
	} else if(add_syncrepl(c->be, c->argv, c->argc)) {
		return(1);
	}
	SLAP_DBFLAGS(c->be) |= (SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SYNC_SHADOW);
	return(0);
}

int
config_referral(ConfigArgs *c) {
	struct berval vals[2];
	if(validate_global_referral(c->argv[1])) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"invalid URL (%s) in \"referral\" line.\n",
			c->fname, c->lineno, c->argv[1] );
		return(1);
	}

	ber_str2bv(c->argv[1], 0, 1, &vals[0]);
	vals[1].bv_val = NULL; vals[1].bv_len = 0;
	if(value_add(&default_referral, vals)) return(LDAP_OTHER);
	return(0);
}

int
config_security(ConfigArgs *c) {
	slap_ssf_set_t *set = &c->be->be_ssf_set;
	char *next;
	int i;
	for(i = 1; i < c->argc; i++) {
		slap_ssf_t *tgt;
		char *src;
		if(!strncasecmp(c->argv[i], "ssf=", 4)) {
			tgt = &set->sss_ssf;
			src = &c->argv[i][4];
		} else if(!strncasecmp(c->argv[i], "transport=", 10)) {
			tgt = &set->sss_transport;
			src = &c->argv[i][10];
		} else if(!strncasecmp(c->argv[i], "tls=", 4)) {
			tgt = &set->sss_tls;
			src = &c->argv[i][4];
		} else if(!strncasecmp(c->argv[i], "sasl=", 5)) {
			tgt = &set->sss_sasl;
			src = &c->argv[i][5];
		} else if(!strncasecmp(c->argv[i], "update_ssf=", 11)) {
			tgt = &set->sss_update_ssf;
			src = &c->argv[i][11];
		} else if(!strncasecmp(c->argv[i], "update_transport=", 17)) {
			tgt = &set->sss_update_transport;
			src = &c->argv[i][17];
		} else if(!strncasecmp(c->argv[i], "update_tls=", 11)) {
			tgt = &set->sss_update_tls;
			src = &c->argv[i][11];
		} else if(!strncasecmp(c->argv[i], "update_sasl=", 12)) {
			tgt = &set->sss_update_sasl;
			src = &c->argv[i][12];
		} else if(!strncasecmp(c->argv[i], "simple_bind=", 12)) {
			tgt = &set->sss_simple_bind;
			src = &c->argv[i][12];
		} else {
			Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
				"unknown factor %s in \"security <factors>\" line\n",
				c->fname, c->lineno, c->argv[i]);
			return(1);
		}

		*tgt = strtol(src, &next, 10);
		if(next == NULL || next[0] != '\0' ) {
			Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
				"unable to parse factor \"%s\" in \"security <factors>\" line\n",
				c->fname, c->lineno, c->argv[i]);
			return(1);
		}
	}
	return(0);
}

int
config_replica(ConfigArgs *c) {
	int i, nr = -1;
	char *replicahost;
	LDAPURLDesc *ludp;

	if(SLAP_MONITOR(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"\"replica\" should not be used inside monitor database\n",
			c->fname, c->lineno, 0);
		return(0);	/* FIXME: should this be an error? */
	}

	for(i = 1; i < c->argc; i++) {
		if(!strncasecmp(c->argv[i], "host=", 5)) {
			nr = add_replica_info(c->be, c->argv[i] + 5);
			break;
		} else if(!strncasecmp(c->argv[i], "uri=", 4)) {
			if(ldap_url_parse(c->argv[i] + 4, &ludp) != LDAP_SUCCESS) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"replica line contains invalid "
					"uri definition.\n", c->fname, c->lineno, 0);
				return(1);
			}
			if(!ludp->lud_host) {
				Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
					"replica line contains invalid "
					"uri definition - missing hostname.\n", c->fname, c->lineno, 0);
				return(1);
			}
			replicahost = ch_malloc(strlen(c->argv[i]));
			if(!replicahost) {
				Debug(LDAP_DEBUG_ANY,
					"out of memory in read_config\n", 0, 0, 0);
				ldap_free_urldesc(ludp);
				exit(EXIT_FAILURE);
			}
			sprintf(replicahost, "%s:%d", ludp->lud_host, ludp->lud_port);
			nr = add_replica_info(c->be, replicahost);
			ldap_free_urldesc(ludp);
			ch_free(replicahost);
			break;
		}
	}
	if(i == c->argc) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"missing host or uri in \"replica\" line\n",
			c->fname, c->lineno, 0);
		return(1);
	} else if(nr == -1) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"unable to add replica \"%s\"\n",
			c->fname, c->lineno, c->argv[i] + 5);
		return(1);
	} else {
		for(i = 1; i < c->argc; i++) {
			if(!strncasecmp(c->argv[i], "suffix=", 7)) {
				switch(add_replica_suffix(c->be, nr, c->argv[i] + 7)) {
					case 1:
						Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"suffix \"%s\" in \"replica\" line is not valid for backend (ignored)\n",
						c->fname, c->lineno, c->argv[i] + 7);
						break;
					case 2:
						Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"unable to normalize suffix in \"replica\" line (ignored)\n",
						c->fname, c->lineno, 0);
						break;
				}

			} else if(!strncasecmp(c->argv[i], "attr", 4)) {
				int exclude = 0;
				char *arg = c->argv[i] + 4;
				if(arg[0] == '!') {
					arg++;
					exclude = 1;
				}
				if(arg[0] != '=') {
					continue;
				}
				if(add_replica_attrs(c->be, nr, arg + 1, exclude)) {
					Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"attribute \"%s\" in \"replica\" line is unknown\n",
						c->fname, c->lineno, arg + 1);
					return(1);
				}
			}
		}
	}
	return(0);
}

int
config_updatedn(ConfigArgs *c) {
	struct berval dn;
	int rc;
	if(SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"updatedn: database already shadowed.\n",
			c->fname, c->lineno, 0);
		return(1);
	}

	ber_str2bv(c->argv[1], 0, 0, &dn);

	rc = dnNormalize(0, NULL, NULL, &dn, &c->be->be_update_ndn, NULL);

	if(rc != LDAP_SUCCESS) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"updatedn DN is invalid\n", c->fname, c->lineno, 0);
		return(1);
	}

	SLAP_DBFLAGS(c->be) |= (SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SLURP_SHADOW);
	return(0);
}

int
config_updateref(ConfigArgs *c) {
	struct berval vals[2];
	if(!SLAP_SHADOW(c->be)) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"updateref line must after syncrepl or updatedn.\n",
			c->fname, c->lineno, 0);
		return(1);
	}

	if(validate_global_referral(c->argv[1])) {
		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
			"invalid URL (%s) in \"updateref\" line.\n",
			c->fname, c->lineno, c->argv[1]);
		return(1);
	}
	ber_str2bv(c->argv[1], 0, 0, &vals[0]);
	vals[1].bv_val = NULL;
	if(value_add(&c->be->be_update_refs, vals)) return(LDAP_OTHER);
	return(0);
}

/* XXX meaningless in ldif */

int
config_include(ConfigArgs *c) {
	char *savefname = ch_strdup(c->argv[1]);
	unsigned long savelineno = c->lineno;
	int rc;
	rc = read_config_file(savefname, c->depth + 1, c);
	free(savefname);
	c->lineno = savelineno - 1;
	return(rc);
}

#ifdef HAVE_TLS
int
config_tls_option(ConfigArgs *c) {
	int flag;
	switch(c->type) {
		CFG_TLS_RAND:		flag = LDAP_OPT_X_TLS_RANDOM_FILE;	break;
		CFG_TLS_CIPHER:		flag = LDAP_OPT_X_TLS_CIPHER_SUITE;	break;
		CFG_TLS_CERT_FILE:	flag = LDAP_OPT_X_TLS_CERTFILE;		break;	
		CFG_TLS_CERT_KEY:	flag = LDAP_OPT_X_TLS_KEYFILE;		break;
		CFG_TLS_CERT_PATH:	flag = LDAP_OPT_X_TLS_CACERTDIR;	break;
		CFG_TLS_CA_FILE:	flag = LDAP_OPT_X_TLS_CACERTFILE;	break;
#ifdef HAVE_OPENSSL_CRL
		CFG_TLS_CRLCHECK:	flag = LDAP_OPT_X_TLS_CRLCHECK;		break;
#endif
		default:		Debug(LDAP_DEBUG_ANY, "%s: line %lu: "
						"unknown tls_option <%x>\n",
						c->fname, c->lineno, c->type);
	}
	return(ldap_pvt_tls_set_option(NULL, flag, c->argv[1]));
}

int
config_tls_verify(ConfigArgs *c) {
	int i;
	if(isdigit((unsigned char)c->argv[1][0])) {
		i = atoi(c->argv[1]);
		return(ldap_pvt_tls_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &i));
	} else {
		return(ldap_int_tls_config(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, c->argv[1]));
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
fp_getline(FILE *fp, ConfigArgs *c)
{
	char	*p;

	lcur = 0;
	CATLINE(buf);
	c->lineno++;

	/* avoid stack of bufs */
	if(strncasecmp(line, "include", 7) == 0) {
		buf[0] = '\0';
		c->line = line;
		return(1);
	}

	while(fgets(buf, sizeof(buf), fp)) {
		if(p = strchr(buf, '\n')) {
			if(p > buf && p[-1] == '\r') --p;
			*p = '\0';
		}
		/* XXX ugly */
		c->line = line;
		if(line[0] && (p = line + strlen(line) - 1)[0] == '\\' && p[-1] != '\\' ) {
			p[0] = '\0';
			lcur--;
		} else {
			if(!isspace((unsigned char)buf[0])) return(1);
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
	char logbuf[STRLENOF("pseudorootpw ***")]; /* longest secret */
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


#if 0
/* Loads ucdata, returns 1 if loading, 0 if already loaded, -1 on error */
static int
load_ucdata( char *path )
{
#if 0
	static int loaded = 0;
	int err;
	
	if ( loaded ) {
		return( 0 );
	}
	err = ucdata_load( path ? path : SLAPD_DEFAULT_UCDATA, UCDATA_ALL );
	if ( err ) {
		Debug( LDAP_DEBUG_ANY, "error loading ucdata (error %d)\n",
		       err, 0, 0 );

		return( -1 );
	}
	loaded = 1;
	return( 1 );
#else
	/* ucdata is now hardcoded */
	return( 0 );
#endif
}
#endif

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
	syncinfo_t *si_entry;
	int	rc = 0;
	int duplicated_replica_id = 0;

	si = (syncinfo_t *) ch_calloc( 1, sizeof( syncinfo_t ) );

	if ( si == NULL ) {
		Debug( LDAP_DEBUG_ANY, "out of memory in add_syncrepl\n", 0, 0, 0 );
		return 1;
	}

	si->si_tls = SYNCINFO_TLS_OFF;
	if ( be->be_rootndn.bv_val ) {
		ber_dupbv( &si->si_updatedn, &be->be_rootndn );
	}
	si->si_bindmethod = LDAP_AUTH_SIMPLE;
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
	si->si_syncCookie.ctxcsn = NULL;
	si->si_syncCookie.octet_str = NULL;
	si->si_syncCookie.sid = -1;
	si->si_manageDSAit = 0;
	si->si_tlimit = 0;
	si->si_slimit = 0;
	si->si_syncUUID_ndn.bv_val = NULL;
	si->si_syncUUID_ndn.bv_len = 0;

	si->si_presentlist = NULL;
	LDAP_LIST_INIT( &si->si_nonpresentlist );

	rc = parse_syncrepl_line( cargv, cargc, si );

	LDAP_STAILQ_FOREACH( si_entry, &be->be_syncinfo, si_next ) {
		if ( si->si_rid == si_entry->si_rid ) {
			Debug( LDAP_DEBUG_ANY,
				"add_syncrepl: duplicated replica id\n",0, 0, 0 );
			duplicated_replica_id = 1;
			break;
		}
	}

	if ( rc < 0 || duplicated_replica_id ) {
		Debug( LDAP_DEBUG_ANY, "failed to add syncinfo\n", 0, 0, 0 );
		syncinfo_free( si );	
		return 1;
	} else {
		Debug( LDAP_DEBUG_CONFIG,
			"Config: ** successfully added syncrepl \"%s\"\n",
			si->si_provideruri == NULL ? "(null)" : si->si_provideruri, 0, 0 );
		if ( !si->si_schemachecking ) {
			SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NO_SCHEMA_CHECK;
		}
		si->si_be = be;
		LDAP_STAILQ_INSERT_TAIL( &be->be_syncinfo, si, si_next );
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
#define UPDATEDNSTR		"updatedn"
#define BINDMETHSTR		"bindmethod"
#define SIMPLESTR			"simple"
#define SASLSTR				"sasl"
#define BINDDNSTR		"binddn"
#define SASLMECHSTR		"saslmech"
#define AUTHCSTR		"authcID"
#define AUTHZSTR		"authzID"
#define CREDSTR			"credentials"
#define REALMSTR		"realm"
#define SECPROPSSTR		"secprops"

/* FIXME: undocumented */
#define OLDAUTHCSTR		"bindprincipal"
#define STARTTLSSTR		"starttls"
#define CRITICALSTR			"critical"
#define EXATTRSSTR		"exattrs"
#define MANAGEDSAITSTR		"manageDSAit"
#define RETRYSTR		"retry"

/* FIXME: unused */
#define LASTMODSTR		"lastmod"
#define LMGENSTR		"gen"
#define LMNOSTR			"no"
#define LMREQSTR		"req"
#define SRVTABSTR		"srvtab"
#define SUFFIXSTR		"suffix"

/* mandatory */
#define GOT_ID			0x0001
#define GOT_PROVIDER		0x0002
#define GOT_METHOD		0x0004

/* check */
#define GOT_ALL			(GOT_ID|GOT_PROVIDER|GOT_METHOD)

static int
parse_syncrepl_line(
	char		**cargv,
	int		cargc,
	syncinfo_t	*si
)
{
	int	gots = 0;
	int	i, j;
	char	*hp, *val;
	int	nr_attr = 0;

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
			si->si_provideruri = ch_strdup( val );
			si->si_provideruri_bv = (BerVarray)
				ch_calloc( 2, sizeof( struct berval ));
			ber_str2bv( si->si_provideruri, strlen( si->si_provideruri ),
				1, &si->si_provideruri_bv[0] );
			si->si_provideruri_bv[1].bv_len = 0;
			si->si_provideruri_bv[1].bv_val = NULL;
			gots |= GOT_PROVIDER;
		} else if ( !strncasecmp( cargv[ i ], STARTTLSSTR "=",
					STRLENOF(STARTTLSSTR "=") ) )
		{
			val = cargv[ i ] + STRLENOF( STARTTLSSTR "=" );
			if( !strcasecmp( val, CRITICALSTR ) ) {
				si->si_tls = SYNCINFO_TLS_CRITICAL;
			} else {
				si->si_tls = SYNCINFO_TLS_ON;
			}
		} else if ( !strncasecmp( cargv[ i ], UPDATEDNSTR "=",
					STRLENOF( UPDATEDNSTR "=" ) ) )
		{
			struct berval updatedn = BER_BVNULL;

			val = cargv[ i ] + STRLENOF( UPDATEDNSTR "=" );
			ber_str2bv( val, 0, 0, &updatedn );
			ch_free( si->si_updatedn.bv_val );
			dnNormalize( 0, NULL, NULL, &updatedn, &si->si_updatedn, NULL );
		} else if ( !strncasecmp( cargv[ i ], BINDMETHSTR "=",
				STRLENOF( BINDMETHSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( BINDMETHSTR "=" );
			if ( !strcasecmp( val, SIMPLESTR )) {
				si->si_bindmethod = LDAP_AUTH_SIMPLE;
				gots |= GOT_METHOD;
			} else if ( !strcasecmp( val, SASLSTR )) {
#ifdef HAVE_CYRUS_SASL
				si->si_bindmethod = LDAP_AUTH_SASL;
				gots |= GOT_METHOD;
#else /* HAVE_CYRUS_SASL */
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"not compiled with SASL support\n" );
				return -1;
#endif /* HAVE_CYRUS_SASL */
			} else {
				si->si_bindmethod = -1;
			}
		} else if ( !strncasecmp( cargv[ i ], BINDDNSTR "=",
					STRLENOF( BINDDNSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( BINDDNSTR "=" );
			si->si_binddn = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], CREDSTR "=",
					STRLENOF( CREDSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( CREDSTR "=" );
			si->si_passwd = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], SASLMECHSTR "=",
					STRLENOF( SASLMECHSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( SASLMECHSTR "=" );
			si->si_saslmech = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], SECPROPSSTR "=",
					STRLENOF( SECPROPSSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( SECPROPSSTR "=" );
			si->si_secprops = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], REALMSTR "=",
					STRLENOF( REALMSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( REALMSTR "=" );
			si->si_realm = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], AUTHCSTR "=",
					STRLENOF( AUTHCSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( AUTHCSTR "=" );
			if ( si->si_authcId )
				ch_free( si->si_authcId );
			si->si_authcId = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], OLDAUTHCSTR "=",
					STRLENOF( OLDAUTHCSTR "=" ) ) ) 
		{
			/* Old authcID is provided for some backwards compatibility */
			val = cargv[ i ] + STRLENOF( OLDAUTHCSTR "=" );
			if ( si->si_authcId )
				ch_free( si->si_authcId );
			si->si_authcId = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ], AUTHZSTR "=",
					STRLENOF( AUTHZSTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( AUTHZSTR "=" );
			si->si_authzId = ch_strdup( val );
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
			struct berval bv;
			val = cargv[ i ] + STRLENOF( SEARCHBASESTR "=" );
			if ( si->si_base.bv_val ) {
				ch_free( si->si_base.bv_val );
			}
			ber_str2bv( val, 0, 0, &bv );
			if ( dnNormalize( 0, NULL, NULL, &bv, &si->si_base, NULL )) {
				fprintf( stderr, "Invalid base DN \"%s\"\n", val );
				return -1;
			}
		} else if ( !strncasecmp( cargv[ i ], SCOPESTR "=",
					STRLENOF( SCOPESTR "=" ) ) )
		{
			val = cargv[ i ] + STRLENOF( SCOPESTR "=" );
			if ( !strncasecmp( val, "base", STRLENOF( "base" ) )) {
				si->si_scope = LDAP_SCOPE_BASE;
			} else if ( !strncasecmp( val, "one", STRLENOF( "one" ) )) {
				si->si_scope = LDAP_SCOPE_ONELEVEL;
#ifdef LDAP_SCOPE_SUBORDINATE
			} else if ( !strcasecmp( val, "subordinate" ) ||
				!strcasecmp( val, "children" ))
			{
				si->si_scope = LDAP_SCOPE_SUBORDINATE;
#endif
			} else if ( !strncasecmp( val, "sub", STRLENOF( "sub" ) )) {
				si->si_scope = LDAP_SCOPE_SUBTREE;
			} else {
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
				ch_free( attr_fname );
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
				int j;
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
			char *str;
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
		} else {
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

char **
slap_str2clist( char ***out, char *in, const char *brkstr )
{
	char	*str;
	char	*s;
	char	*lasts;
	int	i, j;
	const char *text;
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
