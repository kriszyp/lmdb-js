/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * int lutil_passwd(
 *	const struct berval *passwd,
 *	const struct berval *cred,
 *	const char **schemes )
 *
 * Returns true if user supplied credentials (cred) matches
 * the stored password (passwd). 
 *
 * Due to the use of the crypt(3) function 
 * this routine is NOT thread-safe.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>

#ifdef SLAPD_SPASSWD
#	include <sasl.h>
#endif

#ifdef SLAPD_KPASSWD
#	include <ac/krb.h>
#	include <ac/krb5.h>
#endif

#include <ac/param.h>

#include <ac/unistd.h>
#include <ac/crypt.h>

#ifdef HAVE_SHADOW_H
#	include <shadow.h>
#endif
#ifdef HAVE_PWD_H
#	include <pwd.h>
#endif
#ifdef HAVE_AIX_SECURITY
#	include <userpw.h>
#endif

#include <lber.h>

#include "lutil_md5.h"
#include "lutil_sha1.h"
#include "lutil.h"

static const unsigned char crypt64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

struct pw_scheme;

typedef int (*PASSWD_CHK_FUNC)(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

typedef struct berval * (*PASSWD_HASH_FUNC) (
	const struct pw_scheme *scheme,
	const struct berval *passwd );

struct pw_scheme {
	struct berval name;
	PASSWD_CHK_FUNC chk_fn;
	PASSWD_HASH_FUNC hash_fn;
};

/* password check routines */
static int chk_md5(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

static int chk_smd5(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

static int chk_ssha1(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

static int chk_sha1(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

#ifdef SLAPD_SPASSWD
static int chk_sasl(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );
#endif

#ifdef SLAPD_KPASSWD
static int chk_kerberos(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );
#endif

#ifdef SLAPD_CRYPT
static int chk_crypt(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );

#if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
static int chk_unix(
	const struct pw_scheme *scheme,
	const struct berval *passwd,
	const struct berval *cred );
#endif
#endif


/* password hash routines */
static struct berval *hash_sha1(
	const struct pw_scheme *scheme,
	const struct berval *passwd );

static struct berval *hash_ssha1(
	const struct pw_scheme *scheme,
	const struct berval *passwd );

static struct berval *hash_smd5(
	const struct pw_scheme *scheme,
	const struct berval *passwd );

static struct berval *hash_md5(
	const struct pw_scheme *scheme,
	const struct berval *passwd );

#ifdef SLAPD_CRYPT
static struct berval *hash_crypt(
	const struct pw_scheme *scheme,
	const struct berval *passwd );
#endif


static const struct pw_scheme pw_schemes[] =
{
	{ {sizeof("{SSHA}")-1, "{SSHA}"},	chk_ssha1, hash_ssha1 },
	{ {sizeof("{SHA}")-1, "{SHA}"},		chk_sha1, hash_sha1 },

	{ {sizeof("{SMD5}")-1, "{SMD5}"},	chk_smd5, hash_smd5 },
	{ {sizeof("{MD5}")-1, "{MD5}"},		chk_md5, hash_md5 },

#ifdef SLAPD_SPASSWD
	{ {sizeof("{SASL}")-1, "{SASL}"}, chk_sasl, NULL },
#endif

#ifdef SLAPD_KPASSWD
	{ {sizeof("{KERBEROS}")-1, "{KERBEROS}"}, chk_kerberos, NULL },
#endif

#ifdef SLAPD_CRYPT
	{ {sizeof("{CRYPT}")-1, "{CRYPT}"},	chk_crypt, hash_crypt },
# if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
	{ {sizeof("{UNIX}")-1, "{UNIX}"},	chk_unix, NULL },
# endif
#endif

#ifdef SLAPD_CLEARTEXT
	/* psuedo scheme */
	{ {0, "{CLEARTEXT}"}, NULL, NULL },
#endif

	{ {0, NULL}, NULL, NULL }
};

static const struct pw_scheme *get_scheme(
	const char* scheme )
{
	int i;

	for( i=0; pw_schemes[i].name.bv_val; i++) {
		if( pw_schemes[i].name.bv_len == 0 ) continue;

		if( strncasecmp(scheme, pw_schemes[i].name.bv_val,
			pw_schemes[i].name.bv_len) == 0 )
		{
			return &pw_schemes[i];
		}
	}

	return NULL;
}

int lutil_passwd_scheme(
	const char* scheme )
{
	if( scheme == NULL ) {
		return 0;
	}

	return get_scheme(scheme) != NULL;
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

static struct berval *passwd_scheme(
	const struct pw_scheme *scheme,
	const struct berval * passwd,
	const char** allowed )
{
	if( !is_allowed_scheme( scheme->name.bv_val, allowed ) ) {
		return NULL;
	}

	if( passwd->bv_len >= scheme->name.bv_len ) {
		if( strncasecmp( passwd->bv_val, scheme->name.bv_val, scheme->name.bv_len ) == 0 ) {
			struct berval *bv = ber_memalloc( sizeof(struct berval) );

			if( bv == NULL ) return NULL;

			bv->bv_val = &passwd->bv_val[scheme->name.bv_len];
			bv->bv_len = passwd->bv_len - scheme->name.bv_len;

			return bv;
		}
	}

	return NULL;
}

/*
 * Return 0 if creds are good.
 */
int
lutil_passwd(
	const struct berval *passwd,	/* stored passwd */
	const struct berval *cred,		/* user cred */
	const char **schemes )
{
	int i;

	if (cred == NULL || cred->bv_len == 0 ||
		passwd == NULL || passwd->bv_len == 0 )
	{
		return -1;
	}

	for( i=0; pw_schemes[i].name.bv_val != NULL; i++ ) {
		if( pw_schemes[i].chk_fn ) {
			struct berval *p = passwd_scheme( &pw_schemes[i],
				passwd, schemes );

			if( p != NULL ) {
				int rc = (pw_schemes[i].chk_fn)( &pw_schemes[i], p, cred );

				/* only free the berval structure as the bv_val points
				 * into passwd->bv_val
				 */
				ber_memfree( p );
				
				return rc;
			}
		}
	}

#ifdef SLAPD_CLEARTEXT
	if( is_allowed_scheme("{CLEARTEXT}", schemes ) ) {
		return passwd->bv_len == cred->bv_len
			? memcmp( passwd->bv_val, cred->bv_val, passwd->bv_len )
			: 1;
	}
#else
	return 1;
#endif

}

struct berval * lutil_passwd_generate( ber_len_t len )
{
	struct berval *pw;

	if( len < 1 ) return NULL;

	pw = ber_memalloc( sizeof( struct berval ) );
	if( pw == NULL ) return NULL;

	pw->bv_len = len;
	pw->bv_val = ber_memalloc( len + 1 );

	if( pw->bv_val == NULL ) {
		ber_memfree( pw );
		return NULL;
	}

	if( lutil_entropy( pw->bv_val, pw->bv_len) < 0 ) {
		ber_bvfree( pw );
		return NULL; 
	}

	for( len = 0; len < pw->bv_len; len++ ) {
		pw->bv_val[len] = crypt64[
			pw->bv_val[len] % (sizeof(crypt64)-1) ];
	}

	pw->bv_val[len] = '\0';
	
	return pw;
}

struct berval * lutil_passwd_hash(
	const struct berval * passwd,
	const char * method )
{
	const struct pw_scheme *sc = get_scheme( method );

	if( sc == NULL ) return NULL;
	if( ! sc->hash_fn ) return NULL;

	return (sc->hash_fn)( sc, passwd );
}

static struct berval * pw_string(
	const struct pw_scheme *sc,
	const struct berval *passwd )
{
	struct berval *pw = ber_memalloc( sizeof( struct berval ) );
	if( pw == NULL ) return NULL;

	pw->bv_len = sc->name.bv_len + passwd->bv_len;
	pw->bv_val = ber_memalloc( pw->bv_len + 1 );

	if( pw->bv_val == NULL ) {
		ber_memfree( pw );
		return NULL;
	}

	memcpy( pw->bv_val, sc->name.bv_val, sc->name.bv_len );
	memcpy( &pw->bv_val[sc->name.bv_len], passwd->bv_val, passwd->bv_len );

	pw->bv_val[pw->bv_len] = '\0';
	return pw;
}

static struct berval * pw_string64(
	const struct pw_scheme *sc,
	const struct berval *hash,
	const struct berval *salt )
{
	int rc;
	struct berval string;
	struct berval *b64 = ber_memalloc( sizeof(struct berval) );
	size_t b64len;

	if( b64 == NULL ) return NULL;

	if( salt ) {
		/* need to base64 combined string */
		string.bv_len = hash->bv_len + salt->bv_len;
		string.bv_val = ber_memalloc( string.bv_len + 1 );

		if( string.bv_val == NULL ) {
			ber_memfree( b64 );
			return NULL;
		}

		memcpy( string.bv_val, hash->bv_val,
			hash->bv_len );
		memcpy( &string.bv_val[hash->bv_len], salt->bv_val,
			salt->bv_len );
		string.bv_val[string.bv_len] = '\0';

	} else {
		string = *hash;
	}

	b64len = LUTIL_BASE64_ENCODE_LEN( string.bv_len ) + 1;
	b64->bv_len = b64len + sc->name.bv_len;
	b64->bv_val = ber_memalloc( b64->bv_len + 1 );

	if( b64->bv_val == NULL ) {
		if( salt ) ber_memfree( string.bv_val );
		ber_memfree( b64 );
		return NULL;
	}

	memcpy(b64->bv_val, sc->name.bv_val, sc->name.bv_len);

	rc = lutil_b64_ntop(
		string.bv_val, string.bv_len,
		&b64->bv_val[sc->name.bv_len], b64len );

	if( salt ) ber_memfree( string.bv_val );
	
	if( rc < 0 ) {
		ber_bvfree( b64 );
		return NULL;
	}

	/* recompute length */
	b64->bv_len = sc->name.bv_len + rc;
	assert( strlen(b64->bv_val) == b64->bv_len );
	return b64;
}

/* PASSWORD CHECK ROUTINES */

static int chk_ssha1(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;
 
	/* decode base64 password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);

	if(rc < 0) {
		ber_memfree(orig_pass);
		return -1;
	}
 
	/* hash credentials with salt */
	lutil_SHA1Init(&SHA1context);
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) cred->bv_val, cred->bv_len);
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) &orig_pass[sizeof(SHA1digest)],
		rc - sizeof(SHA1digest));
	lutil_SHA1Final(SHA1digest, &SHA1context);
 
	/* compare */
	rc = memcmp((char *)orig_pass, (char *)SHA1digest, sizeof(SHA1digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

static int chk_sha1(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;
 
	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);

	if( rc != sizeof(SHA1digest) ) {
		ber_memfree(orig_pass);
		return -1;
	}
 
	/* hash credentials with salt */
	lutil_SHA1Init(&SHA1context);
	lutil_SHA1Update(&SHA1context,
		(const unsigned char *) cred->bv_val, cred->bv_len);
	lutil_SHA1Final(SHA1digest, &SHA1context);
 
	/* compare */
	rc = memcmp((char *)orig_pass, (char *)SHA1digest, sizeof(SHA1digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

static int chk_smd5(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;

	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);
	if ( rc < 0 ) {
		ber_memfree(orig_pass);
		return -1;
	}

	/* hash credentials with salt */
	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context,
		(const unsigned char *) cred->bv_val, cred->bv_len );
	lutil_MD5Update(&MD5context,
		(const unsigned char *) &orig_pass[sizeof(MD5digest)],
		rc - sizeof(MD5digest));
	lutil_MD5Final(MD5digest, &MD5context);

	/* compare */
	rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

static int chk_md5(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;

	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);
	if ( rc != sizeof(MD5digest) ) {
		ber_memfree(orig_pass);
		return -1;
	}

	/* hash credentials with salt */
	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context,
		(const unsigned char *) cred->bv_val, cred->bv_len );
	lutil_MD5Final(MD5digest, &MD5context);

	/* compare */
	rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

#ifdef SLAPD_SPASSWD
#ifdef HAVE_CYRUS_SASL
sasl_conn_t *lutil_passwd_sasl_conn = NULL;
#endif

static int chk_sasl(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	int i;
	int rtn;

	for( i=0; i<cred->bv_len; i++) {
		if(cred->bv_val[i] == '\0') {
			return 1;	/* NUL character in password */
		}
	}

	if( cred->bv_val[i] != '\0' ) {
		return 1;	/* cred must behave like a string */
	}

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return 1;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return 1;	/* passwd must behave like a string */
	}

	rtn = 1;

#ifdef HAVE_CYRUS_SASL
	if( lutil_passwd_sasl_conn != NULL ) {
		const char *errstr = NULL;
		int sc;

		sc = sasl_checkpass( lutil_passwd_sasl_conn,
			passwd->bv_val, passwd->bv_len,
			cred->bv_val, cred->bv_len,
			&errstr );

		rtn = ( sc != SASL_OK );
	}
#endif

	return rtn;
}
#endif

#ifdef SLAPD_KPASSWD
static int chk_kerberos(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	int i;
	int rtn;

	for( i=0; i<cred->bv_len; i++) {
		if(cred->bv_val[i] == '\0') {
			return 1;	/* NUL character in password */
		}
	}

	if( cred->bv_val[i] != '\0' ) {
		return 1;	/* cred must behave like a string */
	}

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return 1;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return 1;	/* passwd must behave like a string */
	}

	rtn = 1;

#ifdef HAVE_KRB5 /* HAVE_HEIMDAL_KRB5 */
	{
/* Portions:
 * Copyright (c) 1997, 1998, 1999 Kungliga Tekniska H\xf6gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

		krb5_context context;
   		krb5_error_code ret;
   		krb5_creds creds;
   		krb5_get_init_creds_opt get_options;
   		krb5_verify_init_creds_opt verify_options;
		krb5_principal client, server;
#ifdef notdef
		krb5_preauthtype pre_auth_types[] = {KRB5_PADATA_ENC_TIMESTAMP};
#endif

		ret = krb5_init_context( &context );
		if (ret) {
			return 1;
		}

#ifdef notdef
		krb5_get_init_creds_opt_set_preauth_list(&get_options,
			pre_auth_types, 1);
#endif

   		krb5_get_init_creds_opt_init( &get_options );

		krb5_verify_init_creds_opt_init( &verify_options );
	
		ret = krb5_parse_name( context, passwd->bv_val, &client );

		if (ret) {
			krb5_free_context( context );
			return 1;
		}

		ret = krb5_get_init_creds_password( context,
			&creds, client, cred->bv_val, NULL,
			NULL, 0, NULL, &get_options );

		if (ret) {
			krb5_free_principal( context, client );
			krb5_free_context( context );
			return 1;
		}

		{
			char host[MAXHOSTNAMELEN];

			if( gethostname( host, MAXHOSTNAMELEN ) != 0 ) {
				krb5_free_principal( context, client );
				krb5_free_context( context );
				return 1;
			}

			ret = krb5_sname_to_principal( context,
				host, "ldap", KRB5_NT_SRV_HST, &server );
		}

		if (ret) {
			krb5_free_principal( context, client );
			krb5_free_context( context );
			return 1;
		}

		ret = krb5_verify_init_creds( context,
			&creds, server, NULL, NULL, &verify_options );

		krb5_free_principal( context, client );
		krb5_free_principal( context, server );
		krb5_free_creds_contents( context, &creds );
		krb5_free_context( context );

		rtn = !!ret;
	}
#elif	defined(HAVE_KRB4)
	{
		/* Borrowed from Heimdal kpopper */
/* Portions:
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

		int status;
		char lrealm[REALM_SZ];
		char tkt[MAXHOSTNAMELEN];

		status = krb_get_lrealm(lrealm,1);
		if (status == KFAILURE) {
			return 1;
		}

		snprintf(tkt, sizeof(tkt), "%s_slapd.%u",
			TKT_ROOT, (unsigned)getpid());
		krb_set_tkt_string (tkt);

		status = krb_verify_user( passwd->bv_val, "", lrealm,
			cred->bv_val, 1, "ldap");

		dest_tkt(); /* no point in keeping the tickets */

		return status == KFAILURE;
	}
#endif

	return rtn;
}
#endif /* SLAPD_KPASSWD */

#ifdef SLAPD_CRYPT
static int chk_crypt(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	char *cr;
	int i;

	for( i=0; i<cred->bv_len; i++) {
		if(cred->bv_val[i] == '\0') {
			return 1;	/* NUL character in password */
		}
	}

	if( cred->bv_val[i] != '\0' ) {
		return -1;	/* cred must behave like a string */
	}

	if( passwd->bv_len < 2 ) {
		return -1;	/* passwd must be at least two characters long */
	}

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return -1;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return -1;	/* passwd must behave like a string */
	}

	cr = crypt( cred->bv_val, passwd->bv_val );

	if( cr == NULL || cr[0] == '\0' ) {
		/* salt must have been invalid */
		return -1;
	}

	return strcmp( passwd->bv_val, cr ) ? 1 : 0;
}

# if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
static int chk_unix(
	const struct pw_scheme *sc,
	const struct berval * passwd,
	const struct berval * cred )
{
	int i;
	char *pw,*cr;

	for( i=0; i<cred->bv_len; i++) {
		if(cred->bv_val[i] == '\0') {
			return -1;	/* NUL character in password */
		}
	}
	if( cred->bv_val[i] != '\0' ) {
		return -1;	/* cred must behave like a string */
	}

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return -1;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return -1;	/* passwd must behave like a string */
	}

	{
		struct passwd *pwd = getpwnam(passwd->bv_val);

		if(pwd == NULL) {
			return -1;	/* not found */
		}

		pw = pwd->pw_passwd;
	}
#  ifdef HAVE_GETSPNAM
	{
		struct spwd *spwd = getspnam(passwd->bv_val);

		if(spwd != NULL) {
			pw = spwd->sp_pwdp;
		}
	}
#  endif
#  ifdef HAVE_AIX_SECURITY
	{
		struct userpw *upw = getuserpw(passwd->bv_val);

		if (upw != NULL) {
			pw = upw->upw_passwd;
		}
	}
#  endif

	if( pw == NULL || pw[0] == '\0' || pw[1] == '\0' ) {
		/* password must must be at least two characters long */
		return -1;
	}

	cr = crypt(cred->bv_val, pw);

	if( cr == NULL || cr[0] == '\0' ) {
		/* salt must have been invalid */
		return -1;
	}

	return strcmp(pw, cr) ? 1 : 0;

}
# endif
#endif

/* PASSWORD GENERATION ROUTINES */

static struct berval *hash_ssha1(
	const struct pw_scheme *scheme,
	const struct berval  *passwd )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[LUTIL_SHA1_BYTES];
	unsigned char   saltdata[4];
	struct berval digest;
	struct berval salt;

	digest.bv_val = SHA1digest;
	digest.bv_len = sizeof(SHA1digest);
	salt.bv_val = saltdata;
	salt.bv_len = sizeof(saltdata);

	if( lutil_entropy( salt.bv_val, salt.bv_len) < 0 ) {
		return NULL; 
	}

	lutil_SHA1Init( &SHA1context );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)passwd->bv_val, passwd->bv_len );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)salt.bv_val, salt.bv_len );
	lutil_SHA1Final( SHA1digest, &SHA1context );

	return pw_string64( scheme, &digest, &salt);
}

static struct berval *hash_sha1(
	const struct pw_scheme *scheme,
	const struct berval  *passwd )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[20];
	struct berval digest;
	digest.bv_val = SHA1digest;
	digest.bv_len = sizeof(SHA1digest);
     
	lutil_SHA1Init( &SHA1context );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)passwd->bv_val, passwd->bv_len );
	lutil_SHA1Final( SHA1digest, &SHA1context );
            
	return pw_string64( scheme, &digest, NULL);
}

static struct berval *hash_smd5(
	const struct pw_scheme *scheme,
	const struct berval  *passwd )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];
	unsigned char   saltdata[4];
	struct berval digest;
	struct berval salt;

	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);
	salt.bv_val = saltdata;
	salt.bv_len = sizeof(saltdata);

	if( lutil_entropy( salt.bv_val, salt.bv_len) < 0 ) {
		return NULL; 
	}

	lutil_MD5Init( &MD5context );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) passwd->bv_val, passwd->bv_len );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) salt.bv_val, salt.bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	return pw_string64( scheme, &digest, &salt );
}

static struct berval *hash_md5(
	const struct pw_scheme *scheme,
	const struct berval  *passwd )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[16];

	struct berval digest;

	digest.bv_val = MD5digest;
	digest.bv_len = sizeof(MD5digest);

	lutil_MD5Init( &MD5context );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) passwd->bv_val, passwd->bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	return pw_string64( scheme, &digest, NULL );
;
}

#ifdef SLAPD_CRYPT
static struct berval *hash_crypt(
	const struct pw_scheme *scheme,
	const struct berval *passwd )
{
	struct berval hash;
	unsigned char salt[3];
	int i;

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return NULL;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return NULL;	/* passwd must behave like a string */
	}

	if( lutil_entropy( salt, sizeof(salt)) < 0 ) {
		return NULL; 
	}

	salt[0] = crypt64[ salt[0] % (sizeof(crypt64)-1) ];
	salt[1] = crypt64[ salt[1] % (sizeof(crypt64)-1) ];
	salt[2] = '\0';

	hash.bv_val = crypt( passwd->bv_val, salt );

	if( hash.bv_val == NULL ) return NULL;

	hash.bv_len = strlen( hash.bv_val );

	if( hash.bv_len == 0 ) {
		return NULL;
	}

	return pw_string( scheme, &hash );
}
#endif
