/*
 *	Copyright 1998, David E. Storey, All rights reserved.
 *	This software is not subject to any license of The Murphy Group, Inc.
 *	or George Mason University.
 *
 *	Redistribution and use in source and binary forms are permitted only
 *	as authorized by the OpenLDAP Public License.  A copy of this
 *	license is available at http://www.OpenLDAP.org/license.html or
 *	in file LICENSE in the top-level directory of the distribution.
 *
 * ldappasswd.c - program to modify passwords in an LDAP tree
 *
 *	Created: 1998-11-26
 *	Author: David E. Storey <dave@tamos.net>
 *	Last Modified: 1998-12-05
 *
 *		ToDo: passwd style change of password (termcap?)
 *			option for referral handling
 *			cracklib support?
 *			kerberos support? (is this really necessary?)
 *			update "shadow" fields?
 *			create/view/change password policies?
 *
 *		  Note: I am totally FOR comments and suggestions!
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include <ac/string.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>
#include <lutil.h>
#include <lutil_md5.h>
#include <lutil_sha1.h>

#include "ldapconfig.h"

#define LDAP_PASSWD_ATTRIB "userPassword"

typedef enum {
	HASHTYPE_NONE,
	HASHTYPE_CRYPT,
	HASHTYPE_MD5,
	HASHTYPE_SHA1
} HashTypes;

struct hash_t {
	char *name;
	int namesz;
	int (*func)(const char *, char *);
	HashTypes type;
};

const char crypt64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./";
char	 *base = NULL;
char	 *binddn = NULL;
char	 *bindpw = NULL;
char	 *ldaphost = "localhost";
char	 *pwattr = LDAP_PASSWD_ATTRIB;
char	 *targetdn = NULL;
char	 *filtpattern = NULL;
int	  ldapport = LDAP_PORT;
int	  noupdates = 0;
int	  verbose = 0;
int	  hashtype = HASHTYPE_CRYPT;
int	  scope = LDAP_SCOPE_SUBTREE;

/*** functions ***/

/*
 * if you'd like to write a better salt generator, please, be my guest.
 * I just needed *something*. It's actually halfway effective for small,
 * two character salts and it can come up with sequentially different
 * salts.
 */

void
crypt_make_salt(char *salt)
{
	struct timeval tv;
	int i;
	char t_salt[5];

	/* grab current time */
	gettimeofday(&tv, (struct timezone *) 0);
	i += tv.tv_usec + (int)&salt;
	strncpy(t_salt, (char *)&i, sizeof(i));

	for (i = 0; i < sizeof(i); i++)
		salt[i] = crypt64[t_salt[i] % (sizeof(crypt64) - 1)];
	salt[i] = '\0';
}

int
hash_none(const char *pw_in, char *pw_out)
{
	strcpy(pw_out, pw_in);
	return(1);
}

int
hash_crypt(const char *pw_in, char *pw_out)
{
	char salt[5];
	crypt_make_salt(salt);
	strcpy(pw_out, crypt(pw_in, salt));
	return(1);
}

int
hash_md5(const char *pw_in, char *pw_out)
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[16];
	char base64digest[25];  /* ceiling(sizeof(input)/3) * 4 + 1 */

	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context, (unsigned char *)pw_in, strlen(pw_in));
	lutil_MD5Final(MD5digest, &MD5context);
	if (lutil_b64_ntop(MD5digest, sizeof(MD5digest), base64digest, sizeof(base64digest)) < 0)
		return (0);

	strcpy(pw_out, base64digest);
	return(1);
}

int
hash_sha1(const char *pw_in, char *pw_out)
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[20];
	char base64digest[29];  /* ceiling(sizeof(input)/3) * 4 + 1 */

	lutil_SHA1Init(&SHA1context);
	lutil_SHA1Update(&SHA1context, (unsigned char *)pw_in, strlen(pw_in));
	lutil_SHA1Final(SHA1digest, &SHA1context);
	if (lutil_b64_ntop(SHA1digest, sizeof(SHA1digest), base64digest, sizeof(base64digest)) < 0)
		return(0);

	strcpy(pw_out, base64digest);
	return(1);
}

static struct hash_t hashes[] = {
	{"none",  4, hash_none,  HASHTYPE_NONE},
	{"crypt", 5, hash_crypt, HASHTYPE_CRYPT},
	{"md5",   3, hash_md5,   HASHTYPE_MD5},
	{"sha",   3, hash_sha1,  HASHTYPE_SHA1},
	{NULL,	0, NULL,	   HASHTYPE_NONE}
};

int
modify_dn(LDAP *ld, char *targetdn, char *newpw)
{
	int ret = 0;
	char hashed_pw[128] = {'\0'};
	char buf[128] = {'\0'};
	char *strvals[2] = {buf, NULL};
	LDAPMod mod, *mods[2] = {&mod, NULL};

	if (!ld || !targetdn || !newpw)
		return(1);

	/* hash password */
	hashes[hashtype].func(newpw, hashed_pw);
	if (hashtype)
		sprintf(buf, "{%s}%s", hashes[hashtype].name, hashed_pw);
	else
		sprintf(buf, "%s", hashed_pw);

	if (verbose > 0)
	{
		printf("%s", targetdn);
		if (verbose > 1)
		{
			printf(":%s", buf);
			if (verbose > 2)
				printf(":%s", newpw);
		}
		printf("\n");
	}

	mod.mod_vals.modv_strvals = strvals;
	mod.mod_type = pwattr;
	mod.mod_op = LDAP_MOD_REPLACE;

	if (!noupdates && (ret = ldap_modify_s(ld, targetdn, mods)) != LDAP_SUCCESS)
		ldap_perror(ld, "ldap_modify_s");
	return(ret);
}

void
usage(char *s)
{
	fprintf(stderr, "usage: %s [options] [filter]\n", s);
	fprintf(stderr, "	-a attrib   password attribute (default: userPassword)\n");
	fprintf(stderr, "	-b basedn   basedn to perform searches\n");
	fprintf(stderr, "	-c hash	 hash type: none, crypt, md5, sha (default: crypt)\n");
	fprintf(stderr, "	-D binddn   bind dn\n");
	fprintf(stderr, "	-d level	debugging level\n");
	fprintf(stderr, "	-h host	 ldap server (default: localhost)\n");
	fprintf(stderr, "	-l time	 time limit\n");
	fprintf(stderr, "	-n		  make no modifications\n");
	fprintf(stderr, "	-p port	 ldap port\n");
	fprintf(stderr, "	-s scope	search scope: base, one, sub (default: sub)\n");
	fprintf(stderr, "	-t targetdn dn to change password\n");
	fprintf(stderr, "	-W newpass  new password\n");
	fprintf(stderr, "	-w passwd   bind password (for simple authentication)\n");
	fprintf(stderr, "	-v		  verbose\n");
	fprintf(stderr, "	-z size	 size limit\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	char *newpw = NULL;
	int i, j;
	int sizelimit = LDAP_NO_LIMIT;
	int timelimit = LDAP_NO_LIMIT;
	LDAP *ld;

	while ((i = getopt(argc, argv, "D:W:a:b:c:d:h:l:np:s:t:vw:z:")) != EOF)
	{
		switch(i)
		{
		case 'D':	   /* bind distinguished name */
			binddn = strdup(optarg);
			break;

		case 'W':	   /* new password */
			if (optarg)
				newpw = strdup(optarg);
			break;

		case 'a':	   /* password attribute */
			if (optarg)
				pwattr = strdup(optarg);
			break;

		case 'b':	   /* base search dn */
			if (optarg)
				base = strdup(optarg);
			break;

		case 'c':	   /* hashes */
			for (j = 0; hashes[j].name; j++)
			{
				if (!strncasecmp(optarg, hashes[j].name, hashes[j].namesz))
				{
					hashtype = hashes[j].type;
					break;
				}
			}

			if (!hashes[j].name)
			{
				fprintf(stderr, "hash type: %s is unknown\n", optarg);
				usage(argv[0]);
			}
			break;

		case 'd':	   /* debugging option */
#ifdef LDAP_DEBUG
			ldap_debug = lber_debug = atoi(optarg);   /* */
#else
			fprintf(stderr, "compile with -DLDAP_DEBUG for debugging\n");
#endif
			break;

		case 'h':	   /* ldap host */
			if (optarg)
				ldaphost = strdup(optarg);
			break;

		case 'l':	   /* time limit */
			if (optarg)
				timelimit = strtol(optarg, NULL, 10);
			break;

		case 'n':	   /* don't update entry(s) */
			noupdates++;
			break;

		case 'p':	   /* ldap port */
			if (optarg)
				ldapport = strtol(optarg, NULL, 10);
			break;

		case 's':	   /* scope */
			if (strncasecmp(optarg, "base", 4) == 0)
				scope = LDAP_SCOPE_BASE;
			else if (strncasecmp(optarg, "one", 3) == 0)
				scope = LDAP_SCOPE_ONELEVEL;
			else if (strncasecmp(optarg, "sub", 3) == 0)
				scope = LDAP_SCOPE_SUBTREE;
			else {
				fprintf(stderr, "scope should be base, one, or sub\n" );
				usage(argv[0]);
			}
			break;

		case 't':	   /* password type */
			if (optarg)
				targetdn = strdup(optarg);
			else
				targetdn = binddn;
			break;

		case 'v':	   /* verbose */
			verbose++;
			break;

		case 'w':	   /* bind password */
			bindpw = strdup(optarg);
			break;

		case 'z':	   /* time limit */
			if (optarg)
				sizelimit = strtol(optarg, NULL, 10);
			break;

		default:
			usage(argv[0]);
		}
	}

	if (!(argc - optind < 1))
		filtpattern = strdup(argv[optind]);

	if (!filtpattern && !targetdn)
	{
		fprintf(stderr, "No filter or targetdn(-t)\n");
		usage(argv[0]);
	}

	if (!newpw)
	{
		fprintf(stderr, "Need a password (-W)\n");
		usage(argv[0]);
	}

	/* connect to server */
	if ((ld = ldap_open(ldaphost, ldapport)) == NULL)
	{
		perror(ldaphost);
		return(1);
	}

	/* set options */
	ldap_set_option(ld, LDAP_OPT_TIMELIMIT, (void *)&timelimit);
	ldap_set_option(ld, LDAP_OPT_SIZELIMIT, (void *)&sizelimit);

	/* authenticate to server */
	if (ldap_bind_s(ld, binddn, bindpw, LDAP_AUTH_SIMPLE) != LDAP_SUCCESS)
	{
		ldap_perror(ld, "ldap_bind");
		return(1);
	}

	if (filtpattern)
	{
		char filter[BUFSIZ];
		LDAPMessage *result = NULL, *e = NULL;
		char *attrs[] = {"dn", NULL};

		/* search */
		sprintf(filter, "%s", filtpattern);
		i = ldap_search_s(ld, base, scope, filter, attrs, 1, &result);
		if (i != LDAP_SUCCESS && i != LDAP_TIMELIMIT_EXCEEDED && i != LDAP_SIZELIMIT_EXCEEDED)
		{
			ldap_perror(ld, "ldap_search_s");
			return(1);
		}

		for (e = ldap_first_entry(ld, result); e; e = ldap_next_entry(ld, e))
		{
			char *dn = ldap_get_dn(ld, e);
			if (dn)
			{
				modify_dn(ld, dn, newpw);
				free(dn);
			}
		}
	}

	if (targetdn)
		modify_dn(ld, targetdn, newpw);

	/* disconnect from server */
	ldap_unbind(ld);
	return(0);
}
