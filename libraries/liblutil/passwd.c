/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * lutil_password(credentials, password)
 *
 * Returns true if user supplied credentials matches
 * the stored password. 
 *
 * Due to the use of the crypt(3) function 
 * this routine is NOT thread-safe.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/crypt.h>

#include <lber.h>

#include "lutil_md5.h"
#include "lutil_sha1.h"
#include "lutil.h"

#ifdef HAVE_SHADOW_H
#	include <shadow.h>
#endif
#ifdef HAVE_PWD_H
#	include <pwd.h>
#endif

struct pw_scheme;

typedef int (*PASSWD_CHK_FUNC)(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

typedef char * (*PASSWD_GEN_FUNC) (
	const struct pw_scheme *scheme,
	const char *passwd );

struct pw_scheme {
	char *name;
	size_t namelen;
	PASSWD_CHK_FUNC chk_fn;
	PASSWD_GEN_FUNC gen_fn;
};

/* password check routines */
static int chk_md5(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

static int chk_smd5(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

static int chk_ssha1(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

static int chk_sha1(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

static int chk_crypt(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );

static int chk_unix(
	const struct pw_scheme *scheme,
	const char *passwd,
	const char *cred );


/* password generation routines */
static char *gen_sha1(
	const struct pw_scheme *scheme,
	const char *passwd );

static char *gen_ssha1(
	const struct pw_scheme *scheme,
	const char *passwd );

static char *gen_smd5(
	const struct pw_scheme *scheme,
	const char *passwd );

static char *gen_md5(
	const struct pw_scheme *scheme,
	const char *passwd );

static char *gen_crypt(
	const struct pw_scheme *scheme,
	const char *passwd );


static const struct pw_scheme pw_schemes[] =
{
	{ "{SSHA}", sizeof("{SSHA}")-1, chk_ssha1, gen_ssha1 },
	{ "{SHA}", sizeof("{SHA}")-1, chk_sha1, gen_sha1 },

	{ "{SMD5}", sizeof("{SMD5}")-1, chk_smd5, gen_smd5 },
	{ "{MD5}", sizeof("{MD5}")-1, chk_md5, gen_md5 },

#ifdef SLAPD_CRYPT
	{ "{CRYPT}", sizeof("{CRYPT}")-1, chk_crypt, gen_crypt },
#endif
# if defined( HAVE_GETSPNAM ) \
  || ( defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD ) )
	{ "{UNIX}",	sizeof("{UNIX}")-1, chk_unix, NULL },
#endif

#ifdef SLAPD_CLEARTEXT
	/* psuedo scheme */
	{ "{CLEARTEXT}", 0, NULL, NULL },
#endif

	NULL,
};

static const struct pw_scheme *get_scheme(
	const char* scheme )
{
	int i;

	for( i=0; pw_schemes[i].name != NULL; i++) {
		if( pw_schemes[i].namelen == 0 ) continue;

		if( strncasecmp(scheme, pw_schemes[i].name,
			pw_schemes[i].namelen) == 0 )
		{
			return &pw_schemes[i];
		}
	}

	return NULL;
}


static int is_allowed_scheme( 
	const char* scheme,
	const char** schemes )
{
	int i;

	if( schemes == NULL ) return 1;

	for( i=0; schemes[i] != NULL; i++ ) {
		if( strcasecmp( scheme, schemes[i] ) == 0 ) {
			return 1;
		}
	}
	return 0;
}

static const char *passwd_scheme(
	const struct pw_scheme *scheme,
	const char* passwd,
	const char** allowed )
{
	if( !is_allowed_scheme( scheme->name, allowed ) ) {
		return NULL;
	}

	if( strncasecmp( passwd, scheme->name, scheme->namelen ) == 0 ) {
		return &passwd[scheme->namelen];
	}

	return NULL;
}

/*
 * Return 0 if creds are good.
 */
int
lutil_passwd(
	const char *passwd,	/* stored passwd */
	const char *cred,	/* user cred */
	const char **schemes )
{
	int i;

	if (cred == NULL || passwd == NULL) {
		return -1;
	}

	for( i=0; pw_schemes[i].name != NULL; i++ ) {
		if( pw_schemes[i].chk_fn ) {
			const char *p = passwd_scheme( &pw_schemes[i],
				passwd, schemes );

			if( p != NULL ) {
				return (pw_schemes[i].chk_fn)( &pw_schemes[i], p, cred );
			}
		}
	}

#ifdef SLAPD_CLEARTEXT
	if( is_allowed_scheme("{CLEARTEXT}", schemes ) ) {
		return strcmp( cred, passwd );
	}
#else
	return 1;
#endif

}

char * lutil_passwd_generate(
	const char * passwd,
	const char * method )
{
	const struct pw_scheme *sc = get_scheme( method );

	if( sc == NULL ) return NULL;
	if( ! sc->gen_fn ) return NULL;

	return (sc->gen_fn)( sc, passwd );
}

static char * pw_string(
	const struct pw_scheme *sc,
	const char *passwd)
{
	size_t pwlen = strlen( passwd );
	char *pw = ber_memalloc( sc->namelen + pwlen + 1 );

	if( pw == NULL ) return NULL;

	memcpy( pw, sc->name, sc->namelen );
	memcpy( &pw[sc->namelen], passwd, pwlen );
	pw[sc->namelen + pwlen] = '\0';

	return pw;
}

static char * pw_string64(
	const struct pw_scheme *sc,
	const unsigned char *hash, size_t hashlen,
	const unsigned char *salt, size_t saltlen )
{
	int rc;
	char *string;
	size_t b64len;
	size_t len = hashlen + saltlen;
	char *b64;

	if( saltlen ) {
		/* need to base64 combined string */
		string = ber_memalloc( hashlen + saltlen );

		if( string == NULL ) {
			return NULL;
		}

		memcpy( string, hash, len );
		memcpy( &string[len], salt, saltlen );

	} else {
		string = (char *) hash;
	}

	b64len = LUTIL_BASE64_ENCODE_LEN( len ) + 1;
	b64 = ber_memalloc( b64len + sc->namelen );

	if( b64 == NULL ) {
		if( saltlen ) ber_memfree( string );
		return NULL;
	}

	memcpy(b64, sc->name, sc->namelen);

	rc = lutil_b64_ntop( string, len, &b64[sc->namelen], b64len );

	if( saltlen ) ber_memfree( string );

	if( rc < 0 ) {
		free( b64 );
		return NULL;
	}

	return b64;
}

/* PASSWORD CHECK ROUTINES */

static int chk_ssha1(
	const struct pw_scheme *sc,
	const char* passwd,
	const char* cred )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	int pw_len = strlen(passwd);
	int rc;
	unsigned char *orig_pass = NULL;
 
	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(pw_len) + 1) );

	if( orig_pass == NULL ) return -1;

	if ((rc = lutil_b64_pton(passwd, orig_pass, pw_len)) < 0) {
		ber_memfree(orig_pass);
		return 1;
	}
 
	/* hash credentials with salt */
	lutil_SHA1Init(&SHA1context);
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) cred, strlen(cred));
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) &orig_pass[sizeof(SHA1digest)],
		rc - sizeof(SHA1digest));
	lutil_SHA1Final(SHA1digest, &SHA1context);
 
	/* compare */
	rc = memcmp((char *)orig_pass, (char *)SHA1digest, sizeof(SHA1digest));
	ber_memfree(orig_pass);
	return rc;
}

static int chk_sha1(
	const struct pw_scheme *sc,
	const char* passwd,
	const char* cred )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	char base64digest[LUTIL_BASE64_ENCODE_LEN(sizeof(SHA1digest))+1]; 

	lutil_SHA1Init(&SHA1context);
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) cred, strlen(cred));
	lutil_SHA1Final(SHA1digest, &SHA1context);

	if (lutil_b64_ntop(SHA1digest, sizeof(SHA1digest),
		base64digest, sizeof(base64digest)) < 0)
	{
		return 1;
	}

	return strcmp(passwd, base64digest);
}

static int chk_smd5(
	const struct pw_scheme *sc,
	const char* passwd,
	const char* cred )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	int pw_len = strlen(passwd);
	int rc;
	unsigned char *orig_pass = NULL;

	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(pw_len) + 1) );

	if( orig_pass == NULL ) return -1;

	if ((rc = lutil_b64_pton(passwd, orig_pass, pw_len)) < 0) {
		ber_memfree(orig_pass);
		return 1;
	}

	/* hash credentials with salt */
	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context,
		(const unsigned char *) cred, strlen(cred));
	lutil_MD5Update(&MD5context,
		(const unsigned char *) &orig_pass[sizeof(MD5digest)],
		rc - sizeof(MD5digest));
	lutil_MD5Final(MD5digest, &MD5context);

	/* compare */
	rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
	ber_memfree(orig_pass);
	return rc;
}

static int chk_md5(
	const struct pw_scheme *sc,
	const char* passwd,
	const char* cred )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	char base64digest[LUTIL_BASE64_ENCODE_LEN(sizeof(MD5digest))+1]; 

	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context,
		(const unsigned char *)cred, strlen(cred));
	lutil_MD5Final(MD5digest, &MD5context);

	if ( lutil_b64_ntop(MD5digest, sizeof(MD5digest),
		base64digest, sizeof(base64digest)) < 0 )
	{
		return 1;
	}

	return strcmp(passwd, base64digest);
}

#ifdef SLAPD_CRYPT
static int chk_crypt(
	const struct pw_scheme *sc,
	const char* passwd,
	const char* cred )
{
	return strcmp(passwd, crypt(cred, passwd));
}

# if defined( HAVE_GETSPNAM ) \
  || ( defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD ) )
static int chk_unix(
	const struct pw_scheme *sc,
	const char* cred,
	const char* p )
{
#  ifdef HAVE_GETSPNAM
	struct spwd *spwd = getspnam(p);

	if(spwd == NULL) {
		return 1;	/* not found */
	}

	return strcmp(spwd->sp_pwdp, crypt(cred, spwd->sp_pwdp));
#  else
	struct passwd *pwd = getpwnam(p);

	if(pwd == NULL) {
		return 1;	/* not found */
	}

	return strcmp(pwd->pw_passwd, crypt(cred, pwd->pw_passwd));
#  endif
# endif
}
#endif

/* PASSWORD CHECK ROUTINES */
static char *gen_ssha1(
	const struct pw_scheme *scheme,
	const char *passwd )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[LUTIL_SHA1_BYTES];
	unsigned char   salt[4];

	if( lutil_entropy( salt, sizeof(salt)) < 0 ) {
		return NULL; 
	}

	lutil_SHA1Init( &SHA1context );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)passwd, strlen(passwd) );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)salt, sizeof(salt) );
	lutil_SHA1Final( SHA1digest, &SHA1context );

	return pw_string64( scheme,
		SHA1digest, sizeof(SHA1digest),
		salt, sizeof(salt));
}

static char *gen_sha1(
	const struct pw_scheme *scheme,
	const char *passwd )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[20];
     
	lutil_SHA1Init( &SHA1context );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)passwd, strlen(passwd) );
	lutil_SHA1Final( SHA1digest, &SHA1context );
            
	return pw_string64( scheme,
		SHA1digest, sizeof(SHA1digest),
		NULL, 0);
}

static char *gen_smd5(
	const struct pw_scheme *scheme,
	const char *passwd )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];
	unsigned char   salt[4];

	if( lutil_entropy( salt, sizeof(salt)) < 0 ) {
		return NULL; 
	}

	lutil_MD5Init( &MD5context );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) passwd, strlen(passwd) );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) salt, sizeof(salt) );
	lutil_MD5Final( MD5digest, &MD5context );

	return pw_string64( scheme,
		MD5digest, sizeof(MD5digest),
		salt, sizeof(salt) );
}

static char *gen_md5(
	const struct pw_scheme *scheme,
	const char *passwd )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];

	lutil_MD5Init( &MD5context );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) passwd, strlen(passwd) );

	lutil_MD5Final( MD5digest, &MD5context );

	return pw_string64( scheme,
		MD5digest, sizeof(MD5digest),
		NULL, 0 );
}

#ifdef SLAPD_CRYPT
static char *gen_crypt(
	const struct pw_scheme *scheme,
	const char *passwd )
{
	static const unsigned char crypt64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

	char *hash = NULL;
	unsigned char salt[2];

	if( lutil_entropy( salt, sizeof(salt)) < 0 ) {
		return NULL; 
	}

	salt[0] = crypt64[ salt[0] % (sizeof(crypt64)-1) ];
	salt[1] = crypt64[ salt[1] % (sizeof(crypt64)-1) ];

	hash = crypt( passwd, salt );

	if( hash = NULL ) return NULL;

	return pw_string( scheme, hash );
}
#endif
