#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"
#include "ldapconfig.h"

struct ldapoptions openldap_ldap_global_options; 

#undef gopts
#define gopts openldap_ldap_global_options

int	openldap_ldap_initialized = 0;

#define ATTR_NONE	0
#define ATTR_BOOL	1
#define ATTR_INT	2
#define ATTR_KV		3
#define ATTR_STRING	4

struct ol_keyvalue {
	char*		key;
	int			value;
};

struct ol_keyvalue deref_kv[] = {
	{"never", LDAP_DEREF_NEVER},
	{"searching", LDAP_DEREF_SEARCHING},
	{"finding", LDAP_DEREF_FINDING},
	{"always", LDAP_DEREF_ALWAYS},
	{NULL, 0}
};

struct ol_attribute {
	int			type;
	char*		name;
	void*		data;
	size_t		offset;
} attrs[] = {
	{ATTR_KV,		"DEREF",	deref_kv, /* or &deref_kv[0] */
		offsetof(struct ldapoptions, ldo_deref)},
	{ATTR_INT,		"SIZELIMIT",	NULL,
		offsetof(struct ldapoptions, ldo_sizelimit)},
	{ATTR_INT,		"TIMELIMIT",	NULL,
		offsetof(struct ldapoptions, ldo_timelimit)},
	{ATTR_STRING,	"BASE",			NULL,
		offsetof(struct ldapoptions, ldo_defbase)},
	{ATTR_STRING,	"HOST",			NULL,
		offsetof(struct ldapoptions, ldo_defhost)},
	{ATTR_INT,		"PORT",			NULL,
		offsetof(struct ldapoptions, ldo_defport)},
	{ATTR_BOOL,		"REFERRALS",	(void *) LDAP_BOOL_REFERRALS, 0},
	{ATTR_BOOL,		"RESTART",		(void *) LDAP_BOOL_RESTART, 0},
	{ATTR_BOOL,		"DNS",			(void *) LDAP_BOOL_DNS, 0},
	{ATTR_NONE,		NULL,		NULL,	0}
};

#define MAX_LDAP_ATTR_LEN  sizeof("SIZELIMIT")
#define MAX_LDAP_ENV_PREFIX_LEN 8

static void openldap_ldap_init_w_conf(const char *file)
{
	char linebuf[128];
	FILE *fp;
	int i;
	char *cmd, *opt;
	char *start, *end;

	fp = fopen(file, "r");
	if(fp == NULL) {
		/* could not open file */
		return;
	}

	while((start = fgets(linebuf, sizeof(linebuf), fp)) != NULL) {
		/* skip lines starting with '#' */
		if(*start == '#') continue;

		/* trim leading white space */
		while((*start != '\0') && isspace(*start)) start++;

		/* anything left? */
		if(*start == '\0') continue;

		/* trim trailing white space */
		end = &start[strlen(start)-1];
		while(isspace(*end)) end--;
		end[1] = '\0';

		/* anything left? */
		if(*start == '\0') continue;
		

		/* parse the command */
		cmd=start;
		while((*start != '\0') && !isspace(*start)) {
			start++;
		}
		if(*start == '\0') {
			/* command has no argument */
			continue;
		} 

		*start++ = '\0';

		/* we must have some non-whitespace to skip */
		while(isspace(*start)) start++;
		opt = start;

		for(i=0; attrs[i].type != ATTR_NONE; i++) {
			void *p;

			if(strcasecmp(cmd, attrs[i].name) != 0) {
				continue;
			}

			p = &((char *) &gopts)[attrs[i].offset];

			switch(attrs[i].type) {
			case ATTR_BOOL:
				if((strcasecmp(opt, "on") == 0) 
					|| (strcasecmp(opt, "yes") == 0)
					|| (strcasecmp(opt, "true") == 0))
				{
					LDAP_BOOL_SET(&gopts, (int) attrs[i].data);

				} else {
					LDAP_BOOL_CLR(&gopts, (int) attrs[i].data);
				}

				break;

			case ATTR_INT:
				* (int*) p = atoi(opt);
				break;

			case ATTR_KV: {
					struct ol_keyvalue *kv;

					for(kv = (struct ol_keyvalue *) attrs[i].data;
						kv->key != NULL;
						kv++) {

						if(strcasecmp(opt, kv->key) == 0) {
							* (int*) p = kv->value;
							break;
						}
					}
				} break;

			case ATTR_STRING:
				if (* (char**) p != NULL) free(* (char**) p);
				* (char**) p = strdup(opt);
				break;
			}
		}
	}
}

static void openldap_ldap_init_w_userconf(const char *file)
{
	char *home = getenv("HOME");
	char *path;
	
	if (home != NULL) {
		path = malloc(strlen(home) + strlen(file) + 3);
	} else {
		path = malloc(strlen(file) + 3);
	}


	if(home != NULL && path != NULL) {
		/* try ~/file */
		sprintf(path, "%s/%s", home, file);
		openldap_ldap_init_w_conf(path);

		/* try ~/.file */
		sprintf(path, "%s/.%s", home, file);
		openldap_ldap_init_w_conf(path);
	}

	/* try file */
	openldap_ldap_init_w_conf(file);

	if(path == NULL) {
		/* try .file */
		sprintf(path, ".%s", file);
		openldap_ldap_init_w_conf(path);
	}
}

static void openldap_ldap_init_w_env(const char *prefix)
{
	char buf[MAX_LDAP_ATTR_LEN+MAX_LDAP_ENV_PREFIX_LEN];
	int len;
	int i;
	void *p;
	char *value;

	if (prefix == NULL) {
		prefix = DEFAULT_LDAP_ENV_PREFIX;
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

		p = &((char *) &gopts)[attrs[i].offset];

		switch(attrs[i].type) {
		case ATTR_BOOL:
			if((strcasecmp(value, "on") == 0) 
				|| (strcasecmp(value, "yes") == 0)
				|| (strcasecmp(value, "true") == 0))
			{
				LDAP_BOOL_SET(&gopts, (int) attrs[i].data);

			} else {
				LDAP_BOOL_CLR(&gopts, (int) attrs[i].data);
			}
			break;

		case ATTR_INT:
			* (int*) p = atoi(value);
			break;

		case ATTR_KV: {
				struct ol_keyvalue *kv;

				for(kv = (struct ol_keyvalue *) attrs[i].data;
					kv->key != NULL;
					kv++) {

					if(strcasecmp(value, kv->key) == 0) {
						* (int*) p = kv->value;
						break;
					}
				}
			} break;

		case ATTR_STRING:
			if (* (char**) p != NULL) free(* (char**) p);
			if (*value == '\0') {
				* (char**) p = NULL;
			} else {
				* (char**) p = strdup(value);
			}
			break;
		}
	}
}

void openldap_ldap_initialize( void )
{
	if ( openldap_ldap_initialized ) {
		return;
	}

	gopts.ldo_version =	LDAP_VERSION2;
	gopts.ldo_deref =	LDAP_DEREF_NEVER;
	gopts.ldo_timelimit = LDAP_NO_LIMIT;
	gopts.ldo_sizelimit = LDAP_NO_LIMIT;

	gopts.ldo_defhost = strdup("localhost");
	gopts.ldo_defport = LDAP_PORT;

	gopts.ldo_refhoplimit = LDAP_DEFAULT_REFHOPLIMIT;

	LDAP_BOOL_ZERO(&gopts);

#if defined( LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS ) || \
	LDAP_VERSION_MAX > LDAP_VERSION2
	LDAP_BOOL_SET(&gopts, LDAP_BOOL_REFERRALS);
#endif

	openldap_ldap_init_w_conf(DEFAULT_LDAP_CONF_FILE);
	openldap_ldap_init_w_userconf(DEFAULT_LDAP_USERRC_FILE);
	openldap_ldap_init_w_env(NULL);

	openldap_ldap_initialized = 1;
}
