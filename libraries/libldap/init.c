/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldap_defaults.h"

struct ldapoptions ldap_int_global_options =
	{ LDAP_UNINITIALIZED, LDAP_DEBUG_NONE };  

#undef gopts
#define gopts ldap_int_global_options

#define ATTR_NONE	0
#define ATTR_BOOL	1
#define ATTR_INT	2
#define ATTR_KV		3
#define ATTR_STRING	4
#define ATTR_TLS	5
#define ATTR_URIS	6

struct ol_keyvalue {
	const char *		key;
	int			value;
};

static const struct ol_keyvalue deref_kv[] = {
	{"never", LDAP_DEREF_NEVER},
	{"searching", LDAP_DEREF_SEARCHING},
	{"finding", LDAP_DEREF_FINDING},
	{"always", LDAP_DEREF_ALWAYS},
	{NULL, 0}
};

static const struct ol_attribute {
	int			useronly;
	int			type;
	const char *	name;
	const void *	data;
	size_t		offset;
} attrs[] = {
	{0, ATTR_KV,		"DEREF",	deref_kv, /* or &deref_kv[0] */
		offsetof(struct ldapoptions, ldo_deref)},
	{0, ATTR_INT,		"SIZELIMIT",	NULL,
		offsetof(struct ldapoptions, ldo_sizelimit)},
	{0, ATTR_INT,		"TIMELIMIT",	NULL,
		offsetof(struct ldapoptions, ldo_timelimit)},
	{1, ATTR_STRING,	"BINDDN",		NULL,
		offsetof(struct ldapoptions, ldo_defbinddn)},
	{0, ATTR_STRING,	"BASE",			NULL,
		offsetof(struct ldapoptions, ldo_defbase)},
	{0, ATTR_INT,		"PORT",			NULL,
		offsetof(struct ldapoptions, ldo_defport)},
	/* **** keep this around for backward compatibility */
	{0, ATTR_URIS,		"HOST",			NULL,	1},
	/* **** */
	{0, ATTR_URIS,		"URI",			NULL,	0},
	{0, ATTR_BOOL,		"REFERRALS",	NULL,	LDAP_BOOL_REFERRALS},
	{0, ATTR_BOOL,		"RESTART",		NULL,	LDAP_BOOL_RESTART},
	{0, ATTR_BOOL,		"DNS",			NULL,	LDAP_BOOL_DNS},
  	{0, ATTR_TLS,		"TLS",			NULL,	LDAP_OPT_X_TLS},
	{0, ATTR_TLS,		"TLS_CERT",		NULL,	LDAP_OPT_X_TLS_CERTFILE},
	{0, ATTR_TLS,		"TLS_KEY",		NULL,	LDAP_OPT_X_TLS_KEYFILE},
  	{0, ATTR_TLS,		"TLS_CACERT",	NULL,	LDAP_OPT_X_TLS_CACERTFILE},
  	{0, ATTR_TLS,		"TLS_CACERTDIR",NULL,	LDAP_OPT_X_TLS_CACERTDIR},
  	{0, ATTR_TLS,		"TLS_REQCERT",	NULL,	LDAP_OPT_X_TLS_REQUIRE_CERT},
	{0, ATTR_NONE,		NULL,		NULL,	0}
};

#define MAX_LDAP_ATTR_LEN  sizeof("TLS_CACERTDIR")
#define MAX_LDAP_ENV_PREFIX_LEN 8

static void openldap_ldap_init_w_conf(
	const char *file, int userconf )
{
	char linebuf[128];
	FILE *fp;
	int i;
	char *cmd, *opt;
	char *start, *end;

	if (file == NULL) {
		/* no file name */
		return;
	}

	fp = fopen(file, "r");
	if(fp == NULL) {
		/* could not open file */
		return;
	}

	while((start = fgets(linebuf, sizeof(linebuf), fp)) != NULL) {
		/* skip lines starting with '#' */
		if(*start == '#') continue;

		/* trim leading white space */
		while((*start != '\0') && isspace((unsigned char) *start))
			start++;

		/* anything left? */
		if(*start == '\0') continue;

		/* trim trailing white space */
		end = &start[strlen(start)-1];
		while(isspace((unsigned char)*end)) end--;
		end[1] = '\0';

		/* anything left? */
		if(*start == '\0') continue;
		

		/* parse the command */
		cmd=start;
		while((*start != '\0') && !isspace((unsigned char)*start)) {
			start++;
		}
		if(*start == '\0') {
			/* command has no argument */
			continue;
		} 

		*start++ = '\0';

		/* we must have some non-whitespace to skip */
		while(isspace((unsigned char)*start)) start++;
		opt = start;

		for(i=0; attrs[i].type != ATTR_NONE; i++) {
			void *p;

			if( !userconf && !attrs[i].useronly ) {
				continue;
			}

			if(strcasecmp(cmd, attrs[i].name) != 0) {
				continue;
			}

			switch(attrs[i].type) {
			case ATTR_BOOL:
				if((strcasecmp(opt, "on") == 0) 
					|| (strcasecmp(opt, "yes") == 0)
					|| (strcasecmp(opt, "true") == 0))
				{
					LDAP_BOOL_SET(&gopts, attrs[i].offset);

				} else {
					LDAP_BOOL_CLR(&gopts, attrs[i].offset);
				}

				break;

			case ATTR_INT:
				p = &((char *) &gopts)[attrs[i].offset];
				* (int*) p = atoi(opt);
				break;

			case ATTR_KV: {
					const struct ol_keyvalue *kv;

					for(kv = attrs[i].data;
						kv->key != NULL;
						kv++) {

						if(strcasecmp(opt, kv->key) == 0) {
							p = &((char *) &gopts)[attrs[i].offset];
							* (int*) p = kv->value;
							break;
						}
					}
				} break;

			case ATTR_STRING:
				p = &((char *) &gopts)[attrs[i].offset];
				if (* (char**) p != NULL) LDAP_FREE(* (char**) p);
				* (char**) p = LDAP_STRDUP(opt);
				break;
			case ATTR_TLS:
#ifdef HAVE_TLS
			   	ldap_pvt_tls_config( &gopts, attrs[i].offset, opt );
#endif
				break;
			case ATTR_URIS:
				if (attrs[i].offset == 0) {
					ldap_set_option( NULL, LDAP_OPT_URI, opt );
				} else {
					ldap_set_option( NULL, LDAP_OPT_HOST_NAME, opt );
				}
				break;
			}
		}
	}

	fclose(fp);
}

static void openldap_ldap_init_w_sysconf(const char *file)
{
	openldap_ldap_init_w_conf( file, 0 );
}

static void openldap_ldap_init_w_userconf(const char *file)
{
	char *home;
	char *path;

	if (file == NULL) {
		/* no file name */
		return;
	}

	home = getenv("HOME");

	if (home != NULL) {
		path = LDAP_MALLOC(strlen(home) + strlen(file) + 3);
	} else {
		path = LDAP_MALLOC(strlen(file) + 3);
	}

	if(home != NULL && path != NULL) {
		/* we assume UNIX path syntax is used... */

		/* try ~/file */
		sprintf(path, "%s/%s", home, file);
		openldap_ldap_init_w_conf(path, 1);

		/* try ~/.file */
		sprintf(path, "%s/.%s", home, file);
		openldap_ldap_init_w_conf(path, 1);
	}

	if(path != NULL) {
		LDAP_FREE(path);
	}

	/* try file */
	openldap_ldap_init_w_conf(file, 1);
}

static void openldap_ldap_init_w_env(const char *prefix)
{
	char buf[MAX_LDAP_ATTR_LEN+MAX_LDAP_ENV_PREFIX_LEN];
	int len;
	int i;
	void *p;
	char *value;

	if (prefix == NULL) {
		prefix = LDAP_ENV_PREFIX;
	}

	strncpy(buf, prefix, MAX_LDAP_ENV_PREFIX_LEN);
	buf[MAX_LDAP_ENV_PREFIX_LEN] = '\0';
	len = strlen(buf);

	for(i=0; attrs[i].type != ATTR_NONE; i++) {
		strcpy(&buf[len], attrs[i].name);
		value = getenv(buf);

		if(value == NULL) {
			continue;
		}

		switch(attrs[i].type) {
		case ATTR_BOOL:
			if((strcasecmp(value, "on") == 0) 
				|| (strcasecmp(value, "yes") == 0)
				|| (strcasecmp(value, "true") == 0))
			{
				LDAP_BOOL_SET(&gopts, attrs[i].offset);

			} else {
				LDAP_BOOL_CLR(&gopts, attrs[i].offset);
			}
			break;

		case ATTR_INT:
			p = &((char *) &gopts)[attrs[i].offset];
			* (int*) p = atoi(value);
			break;

		case ATTR_KV: {
				const struct ol_keyvalue *kv;

				for(kv = attrs[i].data;
					kv->key != NULL;
					kv++) {

					if(strcasecmp(value, kv->key) == 0) {
						p = &((char *) &gopts)[attrs[i].offset];
						* (int*) p = kv->value;
						break;
					}
				}
			} break;

		case ATTR_STRING:
			p = &((char *) &gopts)[attrs[i].offset];
			if (* (char**) p != NULL) LDAP_FREE(* (char**) p);
			if (*value == '\0') {
				* (char**) p = NULL;
			} else {
				* (char**) p = LDAP_STRDUP(value);
			}
			break;
		case ATTR_TLS:
#ifdef HAVE_TLS
		   	ldap_pvt_tls_config( &gopts, attrs[i].offset, value );
#endif			 	
		   	break;
		case ATTR_URIS:
			if (attrs[i].offset == 0) {
				ldap_set_option( NULL, LDAP_OPT_URI, value );
			} else {
				ldap_set_option( NULL, LDAP_OPT_HOST_NAME, value );
			}
			break;
		}
	}
}

void ldap_int_initialize( void )
{
	if ( gopts.ldo_valid == LDAP_INITIALIZED ) {
		return;
	}

	ldap_int_utils_init();

#ifdef HAVE_TLS
   	ldap_pvt_tls_init();
#endif

#ifdef HAVE_CYRUS_SASL
	ldap_pvt_sasl_init();
#endif

	if ( ldap_int_tblsize == 0 )
		ldap_int_ip_init();

	gopts.ldo_debug = 0;

	gopts.ldo_version =	LDAP_VERSION2;
	gopts.ldo_deref =	LDAP_DEREF_NEVER;
	gopts.ldo_timelimit = LDAP_NO_LIMIT;
	gopts.ldo_sizelimit = LDAP_NO_LIMIT;

	gopts.ldo_tm_api = (struct timeval *)NULL;
	gopts.ldo_tm_net = (struct timeval *)NULL;

	ldap_url_parselist(&gopts.ldo_defludp, "ldap://localhost/");
	gopts.ldo_defport = LDAP_PORT;

	gopts.ldo_refhoplimit = LDAP_DEFAULT_REFHOPLIMIT;

	LDAP_BOOL_ZERO(&gopts);

	LDAP_BOOL_SET(&gopts, LDAP_BOOL_REFERRALS);

#ifdef HAVE_TLS
   	gopts.ldo_tls_ctx = NULL;
#endif

	gopts.ldo_valid = LDAP_INITIALIZED;

	if( getenv("LDAPNOINIT") != NULL ) {
		return;
	}

	openldap_ldap_init_w_sysconf(LDAP_CONF_FILE);
	openldap_ldap_init_w_userconf(LDAP_USERRC_FILE);

	{
		char *altfile = getenv(LDAP_ENV_PREFIX "CONF");

		if( altfile != NULL ) {
			openldap_ldap_init_w_sysconf( altfile );
		}
	}

	{
		char *altfile = getenv(LDAP_ENV_PREFIX "RC");

		if( altfile != NULL ) {
			openldap_ldap_init_w_userconf( altfile );
		}
	}

	openldap_ldap_init_w_env(NULL);
}
