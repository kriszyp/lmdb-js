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

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/unistd.h>

#include "lutil_md5.h"
#include "lutil_sha1.h"
#include "lutil.h"

#ifdef HAVE_SHADOW_H
#	include <shadow.h>
#endif
#ifdef HAVE_PWD_H
#	include <pwd.h>
#endif

static int is_allowed_scheme(
	const char* scheme,
	const char** schemes )
{
	int i;

	if(schemes == NULL) {
		return 1;
	}

	for(i=0; schemes[i] != NULL; i++) {
		if(strcasecmp(scheme, schemes[i]) == 0) {
			return 1;
		}
	}

	return 0;
}

const char *lutil_passwd_schemes[] = {
#ifdef SLAPD_CRYPT
	"{CRYPT}",
#endif
	"{MD5}", "{SMD5}",
	"{SHA}", "{SSHA}",
# if defined( HAVE_GETSPNAM ) \
  || ( defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD ) )
	"{UNIX}",
#endif
#ifdef SLAPD_CLEARTEXT
	"{CLEARTEXT}",		/* psuedo scheme */
#endif
	NULL,
};

int lutil_passwd_scheme( char *scheme ) {
	return is_allowed_scheme( scheme, lutil_passwd_schemes );
}

static const char *passwd_scheme(
	const char* passwd,
	const char* scheme,
	const char** schemes )
{
	int len;

	if( !is_allowed_scheme( scheme, schemes ) ) {
		return NULL;
	}

	len = strlen(scheme);

	if( strncasecmp( passwd, scheme, len ) == 0 ) {
		return &passwd[len];
	}

	return NULL;
}

/*
 * Return 0 if creds are good.
 */
int
lutil_passwd(
	const char *cred,
	const char *passwd,
	const char **schemes)
{
	const char *p;

	if (cred == NULL || passwd == NULL) {
		return -1;
	}

	if ((p = passwd_scheme( passwd, "{MD5}", schemes )) != NULL ) {
		lutil_MD5_CTX MD5context;
		unsigned char MD5digest[16];
		char base64digest[25];  /* ceiling(sizeof(input)/3) * 4 + 1 */

		lutil_MD5Init(&MD5context);
		lutil_MD5Update(&MD5context,
			       (const unsigned char *)cred, strlen(cred));
		lutil_MD5Final(MD5digest, &MD5context);

		if ( lutil_b64_ntop(MD5digest, sizeof(MD5digest),
			base64digest, sizeof(base64digest)) < 0)
		{
			return ( 1 );
		}

		return( strcmp(p, base64digest) );

	} else if ((p = passwd_scheme( passwd, "{SHA}", schemes )) != NULL ) {
		lutil_SHA1_CTX SHA1context;
		unsigned char SHA1digest[20];
		char base64digest[29];  /* ceiling(sizeof(input)/3) * 4 + 1 */

		lutil_SHA1Init(&SHA1context);
		lutil_SHA1Update(&SHA1context,
				(const unsigned char *) cred, strlen(cred));
		lutil_SHA1Final(SHA1digest, &SHA1context);

		if (lutil_b64_ntop(SHA1digest, sizeof(SHA1digest),
			base64digest, sizeof(base64digest)) < 0)
		{
			return ( 1 );
		}

		return( strcmp(p, base64digest) );

	} else if ((p = passwd_scheme( passwd, "{SSHA}", schemes )) != NULL ) {
		lutil_SHA1_CTX SHA1context;
		unsigned char SHA1digest[20];
		int pw_len = strlen(p);
		int rc;
		unsigned char *orig_pass = NULL;
 
		/* base64 un-encode password */
		orig_pass = (unsigned char *)malloc((size_t)(pw_len * 0.75 + 1));
		if ((rc = lutil_b64_pton(p, orig_pass, pw_len)) < 0)
		{
			free(orig_pass);
			return ( 1 );
		}
 
		/* hash credentials with salt */
		lutil_SHA1Init(&SHA1context);
		lutil_SHA1Update(&SHA1context,
				(const unsigned char *) cred, strlen(cred));
		lutil_SHA1Update(&SHA1context,
				(const unsigned char *) orig_pass + sizeof(SHA1digest),
				rc - sizeof(SHA1digest));
		lutil_SHA1Final(SHA1digest, &SHA1context);
 
		/* compare */
		rc = memcmp((char *)orig_pass, (char *)SHA1digest, sizeof(SHA1digest));
		free(orig_pass);
		return(rc);

	} else if ((p = passwd_scheme( passwd, "{SMD5}", schemes )) != NULL ) {
		lutil_MD5_CTX MD5context;
		unsigned char MD5digest[16];
		int pw_len = strlen(p);
		int rc;
		unsigned char *orig_pass = NULL;

		/* base64 un-encode password */
		orig_pass = (unsigned char *)malloc((size_t)(pw_len * 0.75 + 1));
		if ((rc = lutil_b64_pton(p, orig_pass, pw_len)) < 0)
		{
			free(orig_pass);
			return ( 1 );
		}

		/* hash credentials with salt */
		lutil_MD5Init(&MD5context);
		lutil_MD5Update(&MD5context,
				(const unsigned char *) cred, strlen(cred));
		lutil_MD5Update(&MD5context,
				(const unsigned char *) orig_pass + sizeof(MD5digest),
				rc - sizeof(MD5digest));
		lutil_MD5Final(MD5digest, &MD5context);

		/* compare */
		rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
		free(orig_pass);
		return ( rc );

#ifdef SLAPD_CRYPT
	} else if ((p = passwd_scheme( passwd, "{CRYPT}", schemes )) != NULL ) {
		return( strcmp(p, crypt(cred, p)) );

# if defined( HAVE_GETSPNAM ) \
  || ( defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD ) )
	} else if ((p = passwd_scheme( passwd, "{UNIX}", schemes )) != NULL ) {

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
#endif
	}

#ifdef SLAPD_CLEARTEXT
	return is_allowed_scheme("{CLEARTEXT}", schemes ) &&
		strcmp(passwd, cred) != 0;
#else
	return( 1 );
#endif

}
