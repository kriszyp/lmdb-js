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

int use_reverse_lookup = 0;

#ifdef LDAP_SLAPI
int slapi_plugins_used = 0;
#endif

static int fp_getline(FILE *fp, ConfigArgs *c);
static void fp_getline_init(ConfigArgs *c);
static int fp_parse_line(ConfigArgs *c);

static char	*strtok_quote(char *line, char *sep, char **quote_ptr);

int read_config_file(const char *fname, int depth, ConfigArgs *cf);

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

void
init_config_argv( ConfigArgs *c )
{
	c->argv = ch_calloc( ARGS_STEP + 1, sizeof( *c->argv ) );
	c->argv_size = ARGS_STEP + 1;
}

ConfigTable *config_find_keyword(ConfigTable *Conf, ConfigArgs *c) {
	int i;

	for(i = 0; Conf[i].name; i++)
		if( (Conf[i].length && (!strncasecmp(c->argv[0], Conf[i].name, Conf[i].length))) ||
			(!strcasecmp(c->argv[0], Conf[i].name)) ) break;
	if ( !Conf[i].name ) return NULL;
	return Conf+i;
}

int config_check_vals(ConfigTable *Conf, ConfigArgs *c, int check_only ) {
	int i, rc, arg_user, arg_type, iarg;
	long larg;
	ber_len_t barg;
	void *ptr;
	
	arg_type = Conf->arg_type;
	if(arg_type == ARG_IGNORED) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> ignored\n",
			c->log, Conf->name, 0);
		return(0);
	}
	if((arg_type & ARG_DN) && c->argc == 1) {
		c->argc = 2;
		c->argv[1] = "";
	}
	if(Conf->min_args && (c->argc < Conf->min_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> missing <%s> argument\n",
			c->log, Conf->name, Conf->what);
		return(ARG_BAD_CONF);
	}
	if(Conf->max_args && (c->argc > Conf->max_args)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: extra cruft after <%s> in <%s> line (ignored)\n",
			c->log, Conf->what, Conf->name);
	}
	if((arg_type & ARG_DB) && !c->be) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> allowed only within database declaration\n",
			c->log, Conf->name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PRE_BI) && c->bi) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> must appear before any backend %sdeclaration\n",
			c->log, Conf->name, ((arg_type & ARG_PRE_DB)
			? "or database " : "") );
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PRE_DB) && c->be && c->be != frontendDB) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> must appear before any database declaration\n",
			c->log, Conf->name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARG_PAREN) && *c->argv[1] != '(' /*')'*/) {
		Debug(LDAP_DEBUG_CONFIG, "%s: old <%s> format not supported\n",
			c->log, Conf->name, 0);
		return(ARG_BAD_CONF);
	}
	if((arg_type & ARGS_POINTER) && !Conf->arg_item && !(arg_type & ARG_OFFSET)) {
		Debug(LDAP_DEBUG_CONFIG, "%s: null arg_item for <%s>\n",
			c->log, Conf->name, 0);
		return(ARG_BAD_CONF);
	}
	c->type = arg_user = (arg_type & ARGS_USERLAND);
	memset(&c->values, 0, sizeof(c->values));
	if(arg_type & ARGS_NUMERIC) {
		int j;
		iarg = 0; larg = 0; barg = 0;
		switch(arg_type & ARGS_NUMERIC) {
			case ARG_INT:		iarg = atoi(c->argv[1]);		break;
			case ARG_LONG:		larg = strtol(c->argv[1], NULL, 0);	break;
			case ARG_BER_LEN_T:	barg = (ber_len_t)atol(c->argv[1]);	break;
			case ARG_ON_OFF:
				if(c->argc == 1) {
					iarg = 1;
				} else if(!strcasecmp(c->argv[1], "on") ||
					!strcasecmp(c->argv[1], "true")) {
					iarg = 1;
				} else if(!strcasecmp(c->argv[1], "off") ||
					!strcasecmp(c->argv[1], "false")) {
					iarg = 0;
				} else {
					Debug(LDAP_DEBUG_CONFIG, "%s: ignoring ", c->log, 0, 0);
					Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%s) in <%s> line\n",
						Conf->what, c->argv[1], Conf->name);
					return(0);
				}
				break;
		}
		j = (arg_type & ARG_NONZERO) ? 1 : 0;
		if(iarg < j && larg < j && barg < j ) {
			larg = larg ? larg : (barg ? barg : iarg);
			Debug(LDAP_DEBUG_CONFIG, "%s: " , c->log, 0, 0);
			Debug(LDAP_DEBUG_CONFIG, "invalid %s value (%ld) in <%s> line\n", Conf->what, larg, Conf->name);
			return(ARG_BAD_CONF);
		}
		switch(arg_type & ARGS_NUMERIC) {
			case ARG_ON_OFF:
			case ARG_INT:		c->value_int = iarg;		break;
			case ARG_LONG:		c->value_long = larg;		break;
			case ARG_BER_LEN_T:	c->value_ber_t = barg;		break;
		}
	} else if(arg_type & ARG_STRING) {
		if ( !check_only )
			c->value_string = ch_strdup(c->argv[1]);
	} else if(arg_type & ARG_BERVAL) {
		if ( !check_only )
			ber_str2bv( c->argv[1], 0, 1, &c->value_bv );
	} else if(arg_type & ARG_DN) {
		struct berval bv;
		ber_str2bv( c->argv[1], 0, 0, &bv );
		rc = dnPrettyNormal( NULL, &bv, &c->value_dn, &c->value_ndn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug(LDAP_DEBUG_CONFIG, "%s: " , c->log, 0, 0);
			Debug(LDAP_DEBUG_CONFIG, "%s DN is invalid %d (%s)\n",
				Conf->name, rc, ldap_err2string( rc ));
			return(ARG_BAD_CONF);
		}
		if ( check_only ) {
			ch_free( c->value_ndn.bv_val );
			ch_free( c->value_dn.bv_val );
		}
	}
	return 0;
}

int config_set_vals(ConfigTable *Conf, ConfigArgs *c) {
	int i, rc, arg_type, iarg;
	long larg;
	ber_len_t barg;
	void *ptr;

	arg_type = Conf->arg_type;
	if(arg_type & ARG_MAGIC) {
		if(!c->be) c->be = frontendDB;
		rc = (*((ConfigDriver*)Conf->arg_item))(c);
#if 0
		if(c->be == frontendDB) c->be = NULL;
#endif
		if(rc) {
			Debug(LDAP_DEBUG_CONFIG, "%s: handler for <%s> exited with %d!\n",
				c->log, Conf->name, rc);
			return(ARG_BAD_CONF);
		}
		return(0);
	}
	if(arg_type & ARG_OFFSET) {
		if (c->be)
			ptr = c->be->be_private;
		else if (c->bi)
			ptr = c->bi->bi_private;
		else {
			Debug(LDAP_DEBUG_CONFIG, "%s: offset for <%s> missing base pointer!\n",
				c->log, Conf->name, 0);
			return(ARG_BAD_CONF);
		}
		ptr = (void *)((char *)ptr + (int)Conf->arg_item);
	} else if (arg_type & ARGS_POINTER) {
		ptr = Conf->arg_item;
	}
	if(arg_type & ARGS_POINTER)
		switch(arg_type & ARGS_POINTER) {
			case ARG_ON_OFF:
			case ARG_INT: 		*(int*)ptr = iarg;			break;
			case ARG_LONG:  	*(long*)ptr = larg;			break;
			case ARG_BER_LEN_T: 	*(ber_len_t*)ptr = barg;			break;
			case ARG_STRING: {
				char *cc = *(char**)ptr;
				if(cc) {
					if (arg_type & ARG_UNIQUE) {
						Debug(LDAP_DEBUG_CONFIG, "%s: already set %s!\n",
							c->log, Conf->name, 0 );
						return(ARG_BAD_CONF);
					}
					ch_free(cc);
				}
				*(char **)ptr = c->value_string;
				break;
				}
			case ARG_BERVAL:
				*(struct berval *)ptr = c->value_bv;
				break;
		}
	return(0);
}

int config_add_vals(ConfigTable *Conf, ConfigArgs *c) {
	int i, rc, arg_type, iarg;

	arg_type = Conf->arg_type;
	if(arg_type == ARG_IGNORED) {
		Debug(LDAP_DEBUG_CONFIG, "%s: keyword <%s> ignored\n",
			c->log, Conf->name, 0);
		return(0);
	}
	rc = config_check_vals( Conf, c, 0 );
	if ( rc ) return rc;
	return config_set_vals( Conf, c );
}

int
config_del_vals(ConfigTable *cf, ConfigArgs *c)
{
	int rc = 0;
}

int
config_get_vals(ConfigTable *cf, ConfigArgs *c)
{
	int rc = 0;
	struct berval bv;
	void *ptr;

	if ( cf->arg_type & ARG_IGNORED ) {
		return 1;
	}

	memset(&c->values, 0, sizeof(c->values));
	c->rvalue_vals = NULL;
	c->rvalue_nvals = NULL;
	c->op = SLAP_CONFIG_EMIT;
	c->type = cf->arg_type & ARGS_USERLAND;

	if ( cf->arg_type & ARG_MAGIC ) {
		rc = (*((ConfigDriver*)cf->arg_item))(c);
		if ( rc ) return rc;
	} else {
		if ( cf->arg_type & ARG_OFFSET ) {
			if ( c->be )
				ptr = c->be->be_private;
			else if ( c->bi )
				ptr = c->bi->bi_private;
			else
				return 1;
			ptr = (void *)((char *)ptr + (int)cf->arg_item);
		} else {
			ptr = cf->arg_item;
		}
		
		switch(cf->arg_type & ARGS_POINTER) {
		case ARG_ON_OFF:
		case ARG_INT:	c->value_int = *(int *)ptr; break;
		case ARG_LONG:	c->value_long = *(long *)ptr; break;
		case ARG_BER_LEN_T:	c->value_ber_t = *(ber_len_t *)ptr; break;
		case ARG_STRING:
			if ( *(char **)ptr )
				c->value_string = ch_strdup(*(char **)ptr);
			break;
		case ARG_BERVAL:
			ber_dupbv( &c->value_bv, (struct berval *)ptr ); break;
		}
	}
	if ( cf->arg_type & ARGS_POINTER) {
		bv.bv_val = c->log;
		switch(cf->arg_type & ARGS_POINTER) {
		case ARG_INT: bv.bv_len = sprintf(bv.bv_val, "%d", c->value_int); break;
		case ARG_LONG: bv.bv_len = sprintf(bv.bv_val, "%ld", c->value_long); break;
		case ARG_BER_LEN_T: bv.bv_len = sprintf(bv.bv_val, "%ld", c->value_ber_t); break;
		case ARG_ON_OFF: bv.bv_len = sprintf(bv.bv_val, "%s",
			c->value_int ? "TRUE" : "FALSE"); break;
		case ARG_STRING:
			if ( c->value_string && c->value_string[0]) {
				ber_str2bv( c->value_string, 0, 0, &bv);
			} else {
				return 1;
			}
			break;
		case ARG_BERVAL:
			if ( !BER_BVISEMPTY( &c->value_bv )) {
				bv = c->value_bv;
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
			fprintf( stderr, "init_config_attrs: AttributeType \"%s\": %s, %s\n",
				ct[i].attribute, ldap_scherr2str(code), err );
			return code;
		}
		code = at_add( at, &err );
		if ( code && code != SLAP_SCHERR_ATTR_DUP ) {
			fprintf( stderr, "init_config_attrs: AttributeType \"%s\": %s, %s\n",
				ct[i].attribute, scherr2str(code), err );
			return code;
		}
		code = slap_str2ad( at->at_names[0], &ct[i].ad, &err );
		if ( code ) {
			fprintf( stderr, "init_config_attrs: AttributeType \"%s\": %s\n",
				ct[i].attribute, err );
			return code;
		}
		ldap_memfree( at );
	}

	return 0;
}

int
init_config_ocs( ConfigOCs *ocs ) {
	int i;

	for (i=0;ocs[i].def;i++) {
		LDAPObjectClass *oc;
		int code;
		const char *err;

		oc = ldap_str2objectclass( ocs[i].def, &code, &err,
			LDAP_SCHEMA_ALLOW_ALL );
		if ( !oc ) {
			fprintf( stderr, "init_config_ocs: objectclass \"%s\": %s, %s\n",
				ocs[i].def, ldap_scherr2str(code), err );
			return code;
		}
		code = oc_add(oc,0,&err);
		if ( code && code != SLAP_SCHERR_CLASS_DUP ) {
			fprintf( stderr, "init_config_ocs: objectclass \"%s\": %s, %s\n",
				ocs[i].def, scherr2str(code), err );
			return code;
		}
		if ( ocs[i].oc ) {
			*ocs[i].oc = oc_find(oc->oc_names[0]);
		}
		ldap_memfree(oc);
	}
	return 0;
}

int
config_parse_vals(ConfigTable *ct, ConfigArgs *c, int valx)
{
	int rc = 0;

	snprintf( c->log, sizeof( c->log ), "%s: value #%d",
		ct->ad->ad_cname.bv_val, valx );
	c->argc = 1;
	c->argv[0] = ct->ad->ad_cname.bv_val;
	if ( fp_parse_line( c ) ) {
		rc = 1;
	} else {
		rc = config_check_vals( ct, c, 1 );
	}

	ch_free( c->tline );
	return rc;
}

int
config_parse_add(ConfigTable *ct, ConfigArgs *c, int valx)
{
	int rc = 0;

	snprintf( c->log, sizeof( c->log ), "%s: value #%d",
		ct->ad->ad_cname.bv_val, valx );
	c->argc = 1;
	c->argv[0] = ct->ad->ad_cname.bv_val;
	if ( fp_parse_line( c ) ) {
		rc = 1;
	} else {
		c->op = LDAP_MOD_ADD;
		rc = config_add_vals( ct, c );
	}

	ch_free( c->tline );
	return rc;
}

int
read_config_file(const char *fname, int depth, ConfigArgs *cf)
{
	FILE *fp;
	ConfigTable *ct;
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
	init_config_argv( c );

	fp = fopen( fname, "r" );
	if ( fp == NULL ) {
		ldap_syslog = 1;
		Debug(LDAP_DEBUG_ANY,
		    "could not open config file \"%s\": %s (%d)\n",
		    fname, strerror(errno), errno);
		return(1);
	}

	Debug(LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0);

	fp_getline_init(c);

	c->tline = NULL;

	while ( fp_getline( fp, c ) ) {
		/* skip comments and blank lines */
		if ( c->line[0] == '#' || c->line[0] == '\0' ) {
			continue;
		}

		snprintf( c->log, sizeof( c->log ), "%s: line %lu",
				c->fname, c->lineno );

		c->argc = 0;
		ch_free( c->tline );
		if ( fp_parse_line( c ) ) {
			rc = 1;
			goto leave;
		}

		if ( c->argc < 1 ) {
			Debug(LDAP_DEBUG_CONFIG, "%s: bad config line (ignored)\n", c->log, 0, 0);
			continue;
		}

		c->op = LDAP_MOD_ADD;

		ct = config_find_keyword( config_back_cf_table, c );
		if ( ct ) {
			rc = config_add_vals( ct, c );
			if ( !rc ) continue;

			if ( rc & ARGS_USERLAND ) {
				/* XXX a usertype would be opaque here */
				Debug(LDAP_DEBUG_CONFIG, "%s: unknown user type <%s>\n",
					c->log, c->argv[0], 0);
				rc = 1;
				goto leave;

			} else if ( rc == ARG_BAD_CONF ) {
				rc = 1;
				goto leave;
			}
			
		} else if ( c->bi ) {
			rc = SLAP_CONF_UNKNOWN;
			if ( c->bi->bi_cf_table ) {
				ct = config_find_keyword( c->bi->bi_cf_table, c );
				if ( ct ) {
					rc = config_add_vals( ct, c );
				}
			}
			if ( c->bi->bi_config && rc == SLAP_CONF_UNKNOWN ) {
				rc = (*c->bi->bi_config)(c->bi, c->fname, c->lineno,
					c->argc, c->argv);
			}
			if ( rc ) {
				switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug(LDAP_DEBUG_CONFIG, "%s: "
						"unknown directive <%s> inside backend info definition (ignored)\n",
						c->log, *c->argv, 0);
					continue;
				default:
					rc = 1;
					goto leave;
				}
			}

		} else if ( c->be ) {
			rc = SLAP_CONF_UNKNOWN;
			if ( c->be->be_cf_table ) {
				ct = config_find_keyword( c->be->be_cf_table, c );
				if ( ct ) {
					rc = config_add_vals( ct, c );
				}
			}
			if ( c->be->be_config && rc == SLAP_CONF_UNKNOWN ) {
				rc = (*c->be->be_config)(c->be, c->fname, c->lineno,
					c->argc, c->argv);
			}
			if ( rc ) {
				switch(rc) {
				case SLAP_CONF_UNKNOWN:
					Debug( LDAP_DEBUG_CONFIG, "%s: "
						"unknown directive <%s> inside backend database "
						"definition (ignored)\n",
						c->log, *c->argv, 0);
					continue;
				default:
					rc = 1;
					goto leave;
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
					rc = 1;
					goto leave;
				}
			}
			
		} else {
			Debug(LDAP_DEBUG_CONFIG, "%s: "
				"unknown directive <%s> outside backend info and database definitions (ignored)\n",
				c->log, *c->argv, 0);
			continue;

		}
	}

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
	rc = 0;

leave:
	ch_free(c->tline);
	fclose(fp);
	ch_free(c->argv);
	ch_free(c);
	return(rc);
}

/* restrictops, allows, disallows, requires, loglevel */

int
verb_to_mask(const char *word, slap_verbmasks *v) {
	int i;
	for(i = 0; !BER_BVISNULL(&v[i].word); i++)
		if(!strcasecmp(word, v[i].word.bv_val))
			break;
	return(i);
}

int
verbs_to_mask(int argc, char *argv[], slap_verbmasks *v, slap_mask_t *m) {
	int i, j;
	for(i = 1; i < argc; i++) {
		j = verb_to_mask(argv[i], v);
		if(BER_BVISNULL(&v[j].word)) return(1);
		while (!v[j].mask) j--;
		*m |= v[j].mask;
	}
	return(0);
}

int
mask_to_verbs(slap_verbmasks *v, slap_mask_t m, BerVarray *bva) {
	int i, j;
	struct berval bv;

	if (!m) return 1;
	for (i=0; !BER_BVISNULL(&v[i].word); i++) {
		if (!v[i].mask) continue;
		if (( m & v[i].mask ) == v[i].mask ) {
			value_add_one( bva, &v[i].word );
		}
	}
	return 0;
}

static slap_verbmasks tlskey[] = {
	{ BER_BVC("no"),		SB_TLS_OFF },
	{ BER_BVC("yes"),		SB_TLS_ON },
	{ BER_BVC("critical"),	SB_TLS_CRITICAL },
	{ BER_BVNULL, 0 }
};

static slap_verbmasks methkey[] = {
	{ BER_BVC("simple"),	LDAP_AUTH_SIMPLE },
#ifdef HAVE_CYRUS_SASL
	{ BER_BVC("sasl"),	LDAP_AUTH_SASL },
#endif
	{ BER_BVNULL, 0 }
};

typedef struct cf_aux_table {
	struct berval key;
	int off;
	int quote;
	slap_verbmasks *aux;
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

int bindconf_parse( const char *word, slap_bindconf *bc ) {
	int i, rc = 0;
	char **cptr;
	cf_aux_table *tab;

	for (tab = bindkey; !BER_BVISNULL(&tab->key); tab++) {
		if ( !strncasecmp( word, tab->key.bv_val, tab->key.bv_len )) {
			cptr = (char **)((char *)bc + tab->off);
			if ( tab->aux ) {
				int j;
				rc = 1;
				for (j=0; !BER_BVISNULL(&tab->aux[j].word); j++) {
					if (!strcasecmp(word+tab->key.bv_len, tab->aux[j].word.bv_val)) {
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
			for ( i=0; !BER_BVISNULL(&tab->aux[i].word); i++ ) {
				if ( *ip == tab->aux[i].mask ) {
					*ptr++ = ' ';
					ptr = lutil_strcopy( ptr, tab->key.bv_val );
					ptr = lutil_strcopy( ptr, tab->aux[i].word.bv_val );
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


/* -------------------------------------- */


static char *
strtok_quote( char *line, char *sep, char **quote_ptr )
{
	int		inquote;
	char		*tmp;
	static char	*next;

	*quote_ptr = NULL;
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
					*quote_ptr = next;
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
	char *hide[] = { "rootpw", "replica", "bindpw", "pseudorootpw", "dbpasswd", '\0' };
	char *quote_ptr;
	int i;

	c->tline = ch_strdup(c->line);
	token = strtok_quote(c->tline, " \t", &quote_ptr);

	if(token) for(i = 0; hide[i]; i++) if(!strcasecmp(token, hide[i])) break;
	if(quote_ptr) *quote_ptr = ' ';
	Debug(LDAP_DEBUG_CONFIG, "line %lu (%s%s)\n", c->lineno,
		hide[i] ? hide[i] : c->line, hide[i] ? " ***" : "");
	if(quote_ptr) *quote_ptr = '\0';

	for(; token; token = strtok_quote(NULL, " \t", &quote_ptr)) {
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

int config_generic_wrapper( Backend *be, const char *fname, int lineno,
	int argc, char **argv )
{
	ConfigArgs c = { 0 };
	ConfigTable *ct;
	int rc;

	c.be = be;
	c.fname = fname;
	c.lineno = lineno;
	c.argc = argc;
	c.argv = argv;
	sprintf( c.log, "%s: line %lu", fname, lineno );

	rc = SLAP_CONF_UNKNOWN;
	ct = config_find_keyword( be->be_cf_table, &c );
	if ( ct )
		rc = config_add_vals( ct, &c );
	return rc;
}
