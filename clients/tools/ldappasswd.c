/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
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
 *	ldappasswd.c - program to modify passwords in an LDAP tree
 *
 *	Author: David E. Storey <dave@tamos.net>
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>
#include <lutil.h>
#include <lutil_md5.h>
#include <lutil_sha1.h>

#include "ldap_defaults.h"

/* local macros */
#define CEILING(x)	((double)(x) > (int)(x) ? (int)(x) + 1 : (int)(x))

#define LDAP_PASSWD_ATTRIB "userPassword"
#define LDAP_PASSWD_CONF   LDAP_SYSCONFDIR LDAP_DIRSEP "passwd.conf"

#define HS_NONE  0
#define HS_PLAIN 1
#define HS_CONV  2

typedef enum
{
	HASHTYPE_NONE,
	HASHTYPE_CRYPT,
	HASHTYPE_MD5,
	HASHTYPE_SMD5,
	HASHTYPE_SHA1,
	HASHTYPE_SSHA1
}
HashTypes;

typedef struct salt_t
{
	unsigned char  *salt;
	unsigned int    len;
}
Salt;

typedef struct hash_t
{
	const char     *name;
	unsigned int    namesz;
	char           *(*func) (const char *, Salt *);
	unsigned char   takes_salt;
	HashTypes       type;
	HashTypes       type_salted;
	unsigned int    default_salt_len;
}
Hash;

static int	noupdates = 0;
static int	verbose = 0;
static int	want_entryhash = 0;
static int	auto_gen_pw = 0;

/*** functions ***/

/*
 * pw_encode() essentially base64 encodes a password and its salt
 */

static char *
pw_encode (unsigned char *passwd, Salt * salt, unsigned int len)
{
	int		salted = salt && salt->salt && salt->len;
	int		b64_len = 0;
	char	       *base64digest = NULL;
	unsigned char  *npasswd = passwd;

	if (salted)
	{
		npasswd = (unsigned char *)malloc (len + salt->len);
		memcpy (npasswd, passwd, len);
		memcpy (&npasswd[len], salt->salt, salt->len);
		len += salt->len;
	}

	b64_len = CEILING (len / 3) * 4 + 1;
	base64digest = (char *)malloc (b64_len);
	if (lutil_b64_ntop (npasswd, len, base64digest, b64_len) < 0)
	{
		free (base64digest);
		base64digest = NULL;
	}

	if (salted)
		free (npasswd);

	return (base64digest);
}

/*
 * if you'd like to write a better salt generator, please, be my guest.
 */

static void
make_salt (Salt * salt, unsigned int len)
{

	if (!salt)
		return;

	salt->len = len;
	salt->salt = (unsigned char *)malloc (len);

	for (len = 0; len < salt->len; len++)
		salt->salt[len] = rand () & 0xff;
}

/*
 * password generator
 */

static char *
gen_pass (unsigned int len)
{
	static const unsigned char autogen[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890.,";
	unsigned int i;
	Salt		salt;

	salt.salt = NULL;
	salt.len = 0;

	make_salt (&salt, len);
	for (i = 0; i < len; i++)
		salt.salt[i] = autogen[salt.salt[i] % (sizeof (autogen) - 1)];

	return ((char *)salt.salt);
}

#ifdef SLAPD_CLEARTEXT
static char *
hash_none (const char *pw_in, Salt * salt)
{
	return (strdup (pw_in));
}
#endif

#ifdef SLAPD_CRYPT
static char *
hash_crypt (const char *pw_in, Salt * salt)
{
	static const unsigned char crypt64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";
	char   *crypted_pw = NULL;
	Salt	lsalt;

	if (salt && salt->salt && strlen ((char *)salt->salt) >= 2)
	{
		/* sanity check */
		if (!(isalnum(salt->salt[0]) || salt->salt[0] == '.' || salt->salt[0] == '/'))
			salt->salt[0] = crypt64[salt->salt[0] % (sizeof (crypt64) - 1)];
		if (!(isalnum(salt->salt[1]) || salt->salt[1] == '.' || salt->salt[1] == '/'))
			salt->salt[1] = crypt64[salt->salt[1] % (sizeof (crypt64) - 1)];

		crypted_pw = crypt (pw_in, (char *)salt->salt);
	}
	else
	{
		make_salt (&lsalt, 2);
		lsalt.salt[0] = crypt64[lsalt.salt[0] % (sizeof (crypt64) - 1)];
		lsalt.salt[1] = crypt64[lsalt.salt[1] % (sizeof (crypt64) - 1)];
		crypted_pw = crypt (pw_in, (char *)lsalt.salt);
		free (lsalt.salt);
	}
	return (strdup (crypted_pw));
}
#endif

static char *
hash_md5 (const char *pw_in, Salt * salt)
{
	lutil_MD5_CTX	MD5context;
	unsigned char	MD5digest[16];

	lutil_MD5Init (&MD5context);
	lutil_MD5Update (&MD5context,
			 (const unsigned char *)pw_in, strlen(pw_in));
	if (salt && salt->salt && salt->len)
		lutil_MD5Update (&MD5context, salt->salt, salt->len);
	lutil_MD5Final (MD5digest, &MD5context);

	return (pw_encode (MD5digest, salt, sizeof (MD5digest)));
}

static char *
hash_sha1 (const char *pw_in, Salt * salt)
{
	lutil_SHA1_CTX	SHA1context;
	unsigned char	SHA1digest[20];

	lutil_SHA1Init (&SHA1context);
	lutil_SHA1Update (&SHA1context,
			  (const unsigned char *)pw_in, strlen(pw_in));
	if (salt && salt->salt && salt->len)
		lutil_SHA1Update (&SHA1context, salt->salt, salt->len);
	lutil_SHA1Final (SHA1digest, &SHA1context);

	return (pw_encode (SHA1digest, salt, sizeof (SHA1digest)));
}

static const Hash hashes[] =
{
#ifdef SLAPD_CLEARTEXT
	{"none",  4, hash_none,  0, HASHTYPE_NONE,  HASHTYPE_NONE,  0},
#endif
#ifdef SLAPD_CRYPT
	{"crypt", 5, hash_crypt, 1, HASHTYPE_CRYPT, HASHTYPE_CRYPT, 2},
#endif
	{"md5",   3, hash_md5,   0, HASHTYPE_MD5,   HASHTYPE_SMD5,  0},
	{"smd5",  4, hash_md5,   1, HASHTYPE_SMD5,  HASHTYPE_SMD5,  4},
	{"sha",   3, hash_sha1,  0, HASHTYPE_SHA1,  HASHTYPE_SSHA1, 0},
	{"ssha",  4, hash_sha1,  1, HASHTYPE_SSHA1, HASHTYPE_SSHA1, 4},
	{NULL,    0, NULL,       0, HASHTYPE_NONE,  HASHTYPE_NONE,  0}
};

static int
modify_dn (LDAP * ld, char *targetdn, char *pwattr, char *oldpw,
	   char *newpw, HashTypes htype, Salt * salt)
{
	int		ret = 0;
	int		salted = salt->salt ? 1 : 0;
	int		want_salt = salt->len && !salted;
	char	       *buf = NULL;
	char	       *hashed_pw = NULL;
	char	       *strvals[2];
	LDAPMod		mod, *mods[2];

	if (!ld || !targetdn || !newpw)
		return (1);

	/* auto-generate password */
	if (auto_gen_pw)
		newpw = gen_pass (auto_gen_pw);

	/* handle salt */
	if (want_salt)
	{
		make_salt (salt, salt->len);
		htype = hashes[htype].type_salted;
	}
	else if (hashes[htype].default_salt_len)
	{
		/* user chose a salted hash and needs a salt */
		if (!salted)
		{
			want_salt++;
			salt->len = hashes[htype].default_salt_len;
			make_salt (salt, salt->len);
		}
	}

	/* hash password */
	hashed_pw = hashes[htype].func (newpw, salt->len ? salt : NULL);

	/* return salt back to its original state */
	if (want_salt)
	{
		free (salt->salt);
		salt->salt = NULL;
	}

	buf = (char *)malloc (hashes[htype].namesz + 3 + strlen (hashed_pw));
	if (htype)
		sprintf (buf, "{%s}%s", hashes[htype].name, hashed_pw);
	else
		sprintf (buf, "%s", hashed_pw);

	if (verbose > 0)
	{
		printf ("%s", targetdn);
		if (verbose > 1)
		{
			printf (":%s", buf);
			if (verbose > 2)
				printf (":%s", newpw);
		}
		printf ("\n");
	}

	strvals[0] = buf;
	strvals[1] = NULL;
	mod.mod_values = strvals;
	mod.mod_type = pwattr;
	mod.mod_op = LDAP_MOD_REPLACE;
	mods[0] = &mod;
	mods[1] =NULL;

	if (!noupdates && (ret = ldap_modify_s (ld, targetdn, mods)) != LDAP_SUCCESS)
		ldap_perror (ld, "ldap_modify");

	free (hashed_pw);
	free (buf);
	return (ret);
}

static void
usage(const char *s)
{
	fprintf (stderr, "Usage: %s [options] [filter]\n", s);
	fprintf (stderr, "  -a attrib\tpassword attribute (default: " LDAP_PASSWD_ATTRIB ")\n");
	fprintf (stderr, "  -b basedn\tbasedn to perform searches\n");
/*      fprintf (stderr, "  -C\t\tuse entry's current hash mechanism\n"); */
	fprintf (stderr, "  -D binddn\tbind dn\n");
	fprintf (stderr, "  -d level\tdebugging level\n");
	fprintf (stderr, "  -E\t\tprompt for new password\n");
	fprintf (stderr, "  -e passwd\tnew password\n");
	fprintf (stderr, "  -g passlen\tauto-generate passwords with length pwlen\n");
	fprintf (stderr, "  -H hash\thash type (default: crypt)\n");
	fprintf (stderr, "  -h host\tldap server (default: localhost)\n");
#ifdef HAVE_KERBEROS
	fprintf (stderr, "  -K\t\tuse Kerberos step 1\n");
	fprintf (stderr, "  -k\t\tuse Kerberos\n");
#endif
	fprintf (stderr, "  -l time\ttime limit\n");
	fprintf (stderr, "  -n\t\tmake no modifications\n");
	fprintf (stderr, "  -P version\tprotocol version (2 or 3)\n");
	fprintf (stderr, "  -p port\tldap port\n");
	fprintf (stderr, "  -s scope\tsearch scope: base, one, sub (default: sub)\n");
	fprintf (stderr, "  -t targetdn\tdn to change password\n");
	fprintf (stderr, "  -v\t\tverbose (more v's, more verbose)\n");
	fprintf (stderr, "  -W\t\tprompt for bind password\n");
	fprintf (stderr, "  -w passwd\tbind password (for simple authentication)\n");
	fprintf (stderr, "  -Y saltlen\tsalt length to use\n");
/*      fprintf (stderr, "  -y salt\tsalt to use\n"); */
	fprintf (stderr, "  -z size\tsize limit\n");
	exit( EXIT_FAILURE );
}

int
main (int argc, char *argv[])
{
	char	       *base = NULL;
	char	       *binddn = NULL;
	char	       *bindpw = NULL;
	char	       *filtpattern = NULL;
	char	       *ldaphost = NULL;
	char	       *targetdn = NULL;
	char	       *pwattr = LDAP_PASSWD_ATTRIB;
	char	       *newpw = NULL;
	int		authmethod = LDAP_AUTH_SIMPLE;
	int		hashtype = HASHTYPE_CRYPT;
	int		i, j;
	int		ldapport = 0;
	int		debug = 0;
	int		scope = LDAP_SCOPE_SUBTREE;
	int		sizelimit = -1;
	int		timelimit = -1;
	int		version = -1;
	int		want_bindpw = 0;
	int		want_newpw = 0;
	LDAP	       *ld;
	Salt		salt;

	salt.salt = NULL;
	salt.len = 0;

	if (argc == 1)
		usage (argv[0]);

	while ((i = getopt (argc, argv, "a:b:C:D:d:Ee:g:H:h:Kkl:nP:p:s:t:vWw:Y:y:z:")) != EOF)
	{
		switch (i)
		{
		case 'a':	/* password attribute */
			pwattr = strdup (optarg);
			break;

		case 'b':	/* base search dn */
			base = strdup (optarg);
			break;

		case 'C':
			want_entryhash++;
			break;

		case 'D':	/* bind distinguished name */
			binddn = strdup (optarg);
			break;

		case 'd':	/* debugging option */
			debug |= atoi (optarg);
			break;

		case 'E':	/* prompt for new password */
			want_newpw++;
			break;

		case 'e':	/* new password */
			newpw = strdup (optarg);
			break;

		case 'g':
			auto_gen_pw = strtol (optarg, NULL, 10);
			break;

		case 'H':	/* hashes */
			for (j = 0; hashes[j].name; j++)
			{
				if (!strncasecmp (optarg, hashes[j].name, hashes[j].namesz))
				{
					hashtype = hashes[j].type;
					break;
				}
			}

			if (!hashes[j].name)
			{
				fprintf (stderr, "hash type: %s is unknown\n", optarg);
				usage (argv[0]);
			}
			break;

		case 'h':	/* ldap host */
			ldaphost = strdup (optarg);
			break;

		case 'K':	/* use kerberos bind, 1st part only */
#ifdef HAVE_KERBEROS
			authmethod = LDAP_AUTH_KRBV41;
#else
			fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
			usage (argv[0]);
#endif
			break;

		case 'k':	/* use kerberos bind */
#ifdef HAVE_KERBEROS
			authmethod = LDAP_AUTH_KRBV4;
#else
			fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
			usage (argv[0]);
#endif
			break;

		case 'l':	/* time limit */
			timelimit = strtol (optarg, NULL, 10);
			break;

		case 'n':	/* don't update entry(s) */
			noupdates++;
			break;

		case 'P':
			switch( atoi( optarg ) ) {
			case 2:
				version = LDAP_VERSION2;
				break;
			case 3:
				version = LDAP_VERSION3;
				break;
			default:
				fprintf( stderr, "protocol version should be 2 or 3\n" );
				usage( argv[0] );
			}
			break;

		case 'p':	/* ldap port */
			ldapport = strtol (optarg, NULL, 10);
			break;

		case 's':	/* scope */
			if (strcasecmp (optarg, "base") == 0)
				scope = LDAP_SCOPE_BASE;
			else if (strcasecmp (optarg, "one") == 0)
				scope = LDAP_SCOPE_ONELEVEL;
			else if (strcasecmp (optarg, "sub") == 0)
				scope = LDAP_SCOPE_SUBTREE;
			else
			{
				fprintf (stderr, "scope should be base, one, or sub\n");
				usage (argv[0]);
			}
			break;

		case 't':	/* target dn */
			targetdn = strdup (optarg);
			break;

		case 'v':	/* verbose */
			verbose++;
			break;

		case 'W':	/* promt for bind password */
			want_bindpw++;
			break;

		case 'w':	/* bind password */
			bindpw = strdup (optarg);
			{
				char* p;

				for( p = optarg; *p == '\0'; p++ ) {
					*p = '*';
				}
			}
			break;

		case 'Y':	/* salt length */
			salt.len = strtol (optarg, NULL, 10);
			break;

		case 'y':	/* user specified salt */
			salt.len = strlen (optarg);
			salt.salt = (unsigned char *)strdup (optarg);
			break;

		case 'z':	/* time limit */
			sizelimit = strtol (optarg, NULL, 10);
			break;

		default:
			usage (argv[0]);
		}
	}

	/* grab filter */
	if (!(argc - optind < 1))
		filtpattern = strdup (argv[optind]);

	/* check for target(s) */
	if (!filtpattern && !targetdn)
		targetdn = binddn;

	/* handle bind password */
	if (want_bindpw)
		bindpw = strdup (getpass ("Enter LDAP password: "));

	/* handle new password */
	if (!newpw)
	{
		char *cknewpw;
		newpw = strdup (getpass ("New password: "));
		cknewpw = getpass ("Re-enter new password: ");

		if (strncmp (newpw, cknewpw, strlen (newpw)))
		{
			fprintf (stderr, "passwords do not match\n");
			return ( EXIT_FAILURE );
		}
	}

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug ) != LBER_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif
	/* seed random number generator */

#ifdef HAVE_GETTIMEOFDAY
	/* this is of questionable value
	 * gettimeofday may not provide much usec
	 */
	{
		struct timeval tv;
		gettimeofday (&tv, NULL);
		srand(tv.tv_sec * (tv.tv_usec + 1));
	}
#else
	/* The traditional seed */
	srand((unsigned)time( NULL ));
#endif

	/* connect to server */
	if ((ld = ldap_init (ldaphost, ldapport)) == NULL)
	{
		perror ("ldap_init");
		return ( EXIT_FAILURE );
	}

	/* set options */
	if (timelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_TIMELIMIT, (void *) &timelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_TIMELIMIT %d\n", timelimit );
	}
	if (sizelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_SIZELIMIT, (void *) &sizelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_SIZELIMIT %d\n", sizelimit );
	}

	/* this seems prudent */
	{
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref);
	}

	if (version != -1 &&
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	/* authenticate to server */
	if (ldap_bind_s (ld, binddn, bindpw, authmethod) != LDAP_SUCCESS)
	{
		ldap_perror (ld, "ldap_bind");
		return ( EXIT_FAILURE );
	}

	if (targetdn)
	{
		if (want_entryhash)
		{
			/* insert code here =) */
		}
		else
			modify_dn (ld, targetdn, pwattr, NULL, newpw, hashtype, &salt);
	}

	if (filtpattern)
	{
		char		filter[BUFSIZ];
		LDAPMessage	*result = NULL, *e;
		char		*attrs[2];
		attrs[0] = pwattr;
		attrs[1] = NULL;

		/* search */
		sprintf (filter, "%s", filtpattern);
		i = ldap_search_s (ld, base, scope, filter, attrs, 0, &result);
		if (i != LDAP_SUCCESS &&
		    i != LDAP_TIMELIMIT_EXCEEDED &&
		    i != LDAP_SIZELIMIT_EXCEEDED)
		{
			ldap_perror (ld, "ldap_search");
			return ( EXIT_FAILURE );
		}

		for (e = ldap_first_entry (ld, result); e; e = ldap_next_entry (ld, e))
		{
			char *dn = ldap_get_dn (ld, e);
			if (dn)
			{
				struct berval **pw_vals = ldap_get_values_len (ld, e, pwattr);
				modify_dn (ld, dn, pwattr, pw_vals ? pw_vals[0]->bv_val : NULL, newpw, hashtype, &salt);
				if (pw_vals)
					ldap_value_free_len (pw_vals);
				free (dn);
			}
		}
	}

	/* disconnect from server */
	ldap_unbind (ld);

	return ( EXIT_SUCCESS );
}
