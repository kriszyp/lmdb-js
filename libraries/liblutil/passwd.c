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

#include <ac/string.h>
#include <ac/unistd.h>

#include "lutil_md5.h"
#include "lutil_sha1.h"
#include "lutil.h"

/*
 * Return 0 if creds are good.
 */

int
lutil_passwd(
	const char *cred,
	const char *passwd)
{

	if (cred == NULL || passwd == NULL) {
		return -1;
	}

	if (strncasecmp(passwd, "{MD5}", sizeof("{MD5}") - 1) == 0 ) {
		lutil_MD5_CTX MD5context;
		unsigned char MD5digest[16];
		char base64digest[25];  /* ceiling(sizeof(input)/3) * 4 + 1 */

		const char *p = passwd + (sizeof("{MD5}") - 1);

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

	} else if (strncasecmp(passwd, "{SHA}",sizeof("{SHA}") - 1) == 0 ) {
		lutil_SHA1_CTX SHA1context;
		unsigned char SHA1digest[20];
		char base64digest[29];  /* ceiling(sizeof(input)/3) * 4 + 1 */
		const char *p = passwd + (sizeof("{SHA}") - 1);

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

#ifdef SLAPD_CRYPT
	} else if (strncasecmp(passwd, "{CRYPT}", sizeof("{CRYPT}") - 1) == 0 ) {
		const char *p = passwd + (sizeof("{CRYPT}") - 1);

		return( strcmp(p, crypt(cred, p)) );

#endif
	}

#ifdef SLAPD_CLEARTEXT
	return( strcmp(passwd, cred) );
#else
	return( 1 );
#endif

}
