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
#include <ac/unistd.h>

#ifdef SLAPD_SPASSWD
#	ifdef HAVE_SASL_SASL_H
#		include <sasl/sasl.h>
#	else
#		include <sasl.h>
#	endif
#endif

#if defined(SLAPD_LMHASH)
#	include <openssl/des.h>
#endif /* SLAPD_LMHASH */

#include <ac/param.h>

#ifdef SLAPD_CRYPT
# include <ac/crypt.h>

# if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
#  ifdef HAVE_SHADOW_H
#	include <shadow.h>
#  endif
#  ifdef HAVE_PWD_H
#	include <pwd.h>
#  endif
#  ifdef HAVE_AIX_SECURITY
#	include <userpw.h>
#  endif
# endif
#endif

#include <lber.h>

#include "ldap_pvt.h"
#include "lber_pvt.h"

#include "lutil_md5.h"
#include "lutil_sha1.h"
#include "lutil.h"

static const unsigned char crypt64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890./";

#ifdef SLAPD_CRYPT
static char *salt_format = NULL;
#endif

struct pw_scheme {
	struct berval name;
	LUTIL_PASSWD_CHK_FUNC *chk_fn;
	LUTIL_PASSWD_HASH_FUNC *hash_fn;
};

struct pw_slist {
	struct pw_slist *next;
	struct pw_scheme s;
};

/* password check routines */

#define	SALT_SIZE	4

static LUTIL_PASSWD_CHK_FUNC chk_md5;
static LUTIL_PASSWD_CHK_FUNC chk_smd5;
static LUTIL_PASSWD_HASH_FUNC hash_smd5;
static LUTIL_PASSWD_HASH_FUNC hash_md5;


#ifdef LUTIL_SHA1_BYTES
static LUTIL_PASSWD_CHK_FUNC chk_ssha1;
static LUTIL_PASSWD_CHK_FUNC chk_sha1;
static LUTIL_PASSWD_HASH_FUNC hash_sha1;
static LUTIL_PASSWD_HASH_FUNC hash_ssha1;
#endif

#ifdef SLAPD_LMHASH
static LUTIL_PASSWD_CHK_FUNC chk_lanman;
static LUTIL_PASSWD_HASH_FUNC hash_lanman;
#endif

#ifdef SLAPD_SPASSWD
static LUTIL_PASSWD_CHK_FUNC chk_sasl;
#endif

#ifdef SLAPD_CRYPT
static LUTIL_PASSWD_CHK_FUNC chk_crypt;
static LUTIL_PASSWD_HASH_FUNC hash_crypt;

#if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
static LUTIL_PASSWD_CHK_FUNC chk_unix;
#endif
#endif

/* password hash routines */

#ifdef SLAPD_CLEARTEXT
static LUTIL_PASSWD_HASH_FUNC hash_clear;
#endif

static struct pw_slist *pw_schemes;

static const struct pw_scheme pw_schemes_default[] =
{
#ifdef LUTIL_SHA1_BYTES
	{ BER_BVC("{SSHA}"),		chk_ssha1, hash_ssha1 },
	{ BER_BVC("{SHA}"),			chk_sha1, hash_sha1 },
#endif

	{ BER_BVC("{SMD5}"),		chk_smd5, hash_smd5 },
	{ BER_BVC("{MD5}"),			chk_md5, hash_md5 },

#ifdef SLAPD_LMHASH
	{ BER_BVC("{LANMAN}"),		chk_lanman, hash_lanman },
#endif /* SLAPD_LMHASH */

#ifdef SLAPD_SPASSWD
	{ BER_BVC("{SASL}"),		chk_sasl, NULL },
#endif

#ifdef SLAPD_CRYPT
	{ BER_BVC("{CRYPT}"),		chk_crypt, hash_crypt },
# if defined( HAVE_GETPWNAM ) && defined( HAVE_PW_PASSWD )
	{ BER_BVC("{UNIX}"),		chk_unix, NULL },
# endif
#endif

#ifdef SLAPD_CLEARTEXT
	/* pseudo scheme */
	{ {0, "{CLEARTEXT}"},		NULL, hash_clear },
#endif

	{ BER_BVNULL, NULL, NULL }
};

int lutil_passwd_add(
	struct berval *scheme,
	LUTIL_PASSWD_CHK_FUNC *chk,
	LUTIL_PASSWD_HASH_FUNC *hash )
{
	struct pw_slist *ptr;

	ptr = ber_memalloc( sizeof( struct pw_slist ));
	if (!ptr) return -1;
	ptr->next = pw_schemes;
	ptr->s.name = *scheme;
	ptr->s.chk_fn = chk;
	ptr->s.hash_fn = hash;
	pw_schemes = ptr;
	return 0;
}

void lutil_passwd_init()
{
	struct pw_slist *ptr;
	struct pw_scheme *s;

	for( s=(struct pw_scheme *)pw_schemes_default; s->name.bv_val; s++) {
		if ( lutil_passwd_add( &s->name, s->chk_fn, s->hash_fn )) break;
	}
}

void lutil_passwd_destroy()
{
	struct pw_slist *ptr, *next;

	for( ptr=pw_schemes; ptr; ptr=next ) {
		next = ptr->next;
		ber_memfree( ptr );
	}
}

static const struct pw_scheme *get_scheme(
	const char* scheme )
{
	struct pw_slist *pws;

	if (!pw_schemes) lutil_passwd_init();

	for( pws=pw_schemes; pws; pws=pws->next ) {
		if( strcasecmp(scheme, pws->s.name.bv_val ) == 0 ) {
			return &(pws->s);
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
	struct berval *bv,
	const char** allowed )
{
	if( !is_allowed_scheme( scheme->name.bv_val, allowed ) ) {
		return NULL;
	}

	if( passwd->bv_len >= scheme->name.bv_len ) {
		if( strncasecmp( passwd->bv_val, scheme->name.bv_val, scheme->name.bv_len ) == 0 ) {
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
	const char **schemes,
	const char **text )
{
	struct pw_slist *pws;

	if ( text ) *text = NULL;

	if (cred == NULL || cred->bv_len == 0 ||
		passwd == NULL || passwd->bv_len == 0 )
	{
		return -1;
	}

	if (!pw_schemes) lutil_passwd_init();

	for( pws=pw_schemes; pws; pws=pws->next ) {
		if( pws->s.chk_fn ) {
			struct berval x;
			struct berval *p = passwd_scheme( &(pws->s),
				passwd, &x, schemes );

			if( p != NULL ) {
				return (pws->s.chk_fn)( &(pws->s.name), p, cred, text );
			}
		}
	}

#ifdef SLAPD_CLEARTEXT
	if( is_allowed_scheme("{CLEARTEXT}", schemes ) ) {
		return (( passwd->bv_len == cred->bv_len ) &&
				( passwd->bv_val[0] != '{' /*'}'*/ ))
			? memcmp( passwd->bv_val, cred->bv_val, passwd->bv_len )
			: 1;
	}
#endif
	return 1;
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

	if( lutil_entropy( (unsigned char *) pw->bv_val, pw->bv_len) < 0 ) {
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
	const char * method,
	const char **text )
{
	const struct pw_scheme *sc = get_scheme( method );

	if( sc == NULL ) {
		if( text ) *text = "scheme not recognized";
		return NULL;
	}

	if( ! sc->hash_fn ) {
		if( text ) *text = "scheme provided no hash function";
		return NULL;
	}

	if( text ) *text = NULL;

	return (sc->hash_fn)( &sc->name, passwd, text );
}

/* pw_string is only called when SLAPD_LMHASH or SLAPD_CRYPT is defined */
#if defined(SLAPD_LMHASH) || defined(SLAPD_CRYPT)
static struct berval * pw_string(
	const struct berval *sc,
	const struct berval *passwd )
{
	struct berval *pw = ber_memalloc( sizeof( struct berval ) );
	if( pw == NULL ) return NULL;

	pw->bv_len = sc->bv_len + passwd->bv_len;
	pw->bv_val = ber_memalloc( pw->bv_len + 1 );

	if( pw->bv_val == NULL ) {
		ber_memfree( pw );
		return NULL;
	}

	AC_MEMCPY( pw->bv_val, sc->bv_val, sc->bv_len );
	AC_MEMCPY( &pw->bv_val[sc->bv_len], passwd->bv_val, passwd->bv_len );

	pw->bv_val[pw->bv_len] = '\0';
	return pw;
}
#endif /* SLAPD_LMHASH || SLAPD_CRYPT */

static struct berval * pw_string64(
	const struct berval *sc,
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

		AC_MEMCPY( string.bv_val, hash->bv_val,
			hash->bv_len );
		AC_MEMCPY( &string.bv_val[hash->bv_len], salt->bv_val,
			salt->bv_len );
		string.bv_val[string.bv_len] = '\0';

	} else {
		string = *hash;
	}

	b64len = LUTIL_BASE64_ENCODE_LEN( string.bv_len ) + 1;
	b64->bv_len = b64len + sc->bv_len;
	b64->bv_val = ber_memalloc( b64->bv_len + 1 );

	if( b64->bv_val == NULL ) {
		if( salt ) ber_memfree( string.bv_val );
		ber_memfree( b64 );
		return NULL;
	}

	AC_MEMCPY(b64->bv_val, sc->bv_val, sc->bv_len);

	rc = lutil_b64_ntop(
		(unsigned char *) string.bv_val, string.bv_len,
		&b64->bv_val[sc->bv_len], b64len );

	if( salt ) ber_memfree( string.bv_val );
	
	if( rc < 0 ) {
		ber_bvfree( b64 );
		return NULL;
	}

	/* recompute length */
	b64->bv_len = sc->bv_len + rc;
	assert( strlen(b64->bv_val) == b64->bv_len );
	return b64;
}

/* PASSWORD CHECK ROUTINES */

#ifdef LUTIL_SHA1_BYTES
static int chk_ssha1(
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;

	/* safety check */
	if (LUTIL_BASE64_DECODE_LEN(passwd->bv_len) <
		sizeof(SHA1digest)+SALT_SIZE) {
		return -1;
	}

	/* decode base64 password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);

	if (rc < (int)(sizeof(SHA1digest)+SALT_SIZE)) {
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
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	lutil_SHA1_CTX SHA1context;
	unsigned char SHA1digest[LUTIL_SHA1_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;
 
	/* safety check */
	if (LUTIL_BASE64_DECODE_LEN(passwd->bv_len) < sizeof(SHA1digest)) {
		return -1;
	}

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
#endif

static int chk_smd5(
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;

	/* safety check */
	if (LUTIL_BASE64_DECODE_LEN(passwd->bv_len) <
		sizeof(MD5digest)+SALT_SIZE) {
		return -1;
	}

	/* base64 un-encode password */
	orig_pass = (unsigned char *) ber_memalloc( (size_t) (
		LUTIL_BASE64_DECODE_LEN(passwd->bv_len) + 1) );

	if( orig_pass == NULL ) return -1;

	rc = lutil_b64_pton(passwd->bv_val, orig_pass, passwd->bv_len);

	if (rc < (int)(sizeof(MD5digest)+SALT_SIZE)) {
		ber_memfree(orig_pass);
		return -1;
	}

	/* hash credentials with salt */
	lutil_MD5Init(&MD5context);
	lutil_MD5Update(&MD5context,
		(const unsigned char *) cred->bv_val,
		cred->bv_len );
	lutil_MD5Update(&MD5context,
		&orig_pass[sizeof(MD5digest)],
		rc - sizeof(MD5digest));
	lutil_MD5Final(MD5digest, &MD5context);

	/* compare */
	rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

static int chk_md5(
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	lutil_MD5_CTX MD5context;
	unsigned char MD5digest[LUTIL_MD5_BYTES];
	int rc;
	unsigned char *orig_pass = NULL;

	/* safety check */
	if (LUTIL_BASE64_DECODE_LEN(passwd->bv_len) < sizeof(MD5digest)) {
		return -1;
	}

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
		(const unsigned char *) cred->bv_val,
		cred->bv_len );
	lutil_MD5Final(MD5digest, &MD5context);

	/* compare */
	rc = memcmp((char *)orig_pass, (char *)MD5digest, sizeof(MD5digest));
	ber_memfree(orig_pass);
	return rc ? 1 : 0;
}

#ifdef SLAPD_LMHASH
/* pseudocode from RFC2433
 * A.2 LmPasswordHash()
 * 
 *    LmPasswordHash(
 *    IN  0-to-14-oem-char Password,
 *    OUT 16-octet         PasswordHash )
 *    {
 *       Set UcasePassword to the uppercased Password
 *       Zero pad UcasePassword to 14 characters
 * 
 *       DesHash( 1st 7-octets of UcasePassword,
 *                giving 1st 8-octets of PasswordHash )
 * 
 *       DesHash( 2nd 7-octets of UcasePassword,
 *                giving 2nd 8-octets of PasswordHash )
 *    }
 * 
 * 
 * A.3 DesHash()
 * 
 *    DesHash(
 *    IN  7-octet Clear,
 *    OUT 8-octet Cypher )
 *    {
 *        *
 *        * Make Cypher an irreversibly encrypted form of Clear by
 *        * encrypting known text using Clear as the secret key.
 *        * The known text consists of the string
 *        *
 *        *              KGS!@#$%
 *        *
 * 
 *       Set StdText to "KGS!@#$%"
 *       DesEncrypt( StdText, Clear, giving Cypher )
 *    }
 * 
 * 
 * A.4 DesEncrypt()
 * 
 *    DesEncrypt(
 *    IN  8-octet Clear,
 *    IN  7-octet Key,
 *    OUT 8-octet Cypher )
 *    {
 *        *
 *        * Use the DES encryption algorithm [4] in ECB mode [9]
 *        * to encrypt Clear into Cypher such that Cypher can
 *        * only be decrypted back to Clear by providing Key.
 *        * Note that the DES algorithm takes as input a 64-bit
 *        * stream where the 8th, 16th, 24th, etc.  bits are
 *        * parity bits ignored by the encrypting algorithm.
 *        * Unless you write your own DES to accept 56-bit input
 *        * without parity, you will need to insert the parity bits
 *        * yourself.
 *        *
 *    }
 */

static void lmPasswd_to_key(
	const unsigned char *lmPasswd,
	des_cblock *key)
{
	/* make room for parity bits */
	((char *)key)[0] = lmPasswd[0];
	((char *)key)[1] = ((lmPasswd[0]&0x01)<<7) | (lmPasswd[1]>>1);
	((char *)key)[2] = ((lmPasswd[1]&0x03)<<6) | (lmPasswd[2]>>2);
	((char *)key)[3] = ((lmPasswd[2]&0x07)<<5) | (lmPasswd[3]>>3);
	((char *)key)[4] = ((lmPasswd[3]&0x0F)<<4) | (lmPasswd[4]>>4);
	((char *)key)[5] = ((lmPasswd[4]&0x1F)<<3) | (lmPasswd[5]>>5);
	((char *)key)[6] = ((lmPasswd[5]&0x3F)<<2) | (lmPasswd[6]>>6);
	((char *)key)[7] = ((lmPasswd[6]&0x7F)<<1);
		
	des_set_odd_parity( key );
}	

static int chk_lanman(
	const struct berval *scheme,
	const struct berval *passwd,
	const struct berval *cred,
	const char **text )
{
	int i;
	char UcasePassword[15];
	des_cblock key;
	des_key_schedule schedule;
	des_cblock StdText = "KGS!@#$%";
	des_cblock PasswordHash1, PasswordHash2;
	char PasswordHash[33], storedPasswordHash[33];
	
	for( i=0; i<cred->bv_len; i++) {
		if(cred->bv_val[i] == '\0') {
			return -1;	/* NUL character in password */
		}
	}
	
	if( cred->bv_val[i] != '\0' ) {
		return -1;	/* passwd must behave like a string */
	}
	
	strncpy( UcasePassword, cred->bv_val, 14 );
	UcasePassword[14] = '\0';
	ldap_pvt_str2upper( UcasePassword );
	
	lmPasswd_to_key( UcasePassword, &key );
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &PasswordHash1, schedule , DES_ENCRYPT );
	
	lmPasswd_to_key( &UcasePassword[7], &key );
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &PasswordHash2, schedule , DES_ENCRYPT );
	
	sprintf( PasswordHash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
		PasswordHash1[0],PasswordHash1[1],PasswordHash1[2],PasswordHash1[3],
		PasswordHash1[4],PasswordHash1[5],PasswordHash1[6],PasswordHash1[7],
		PasswordHash2[0],PasswordHash2[1],PasswordHash2[2],PasswordHash2[3],
		PasswordHash2[4],PasswordHash2[5],PasswordHash2[6],PasswordHash2[7] );
	
	/* as a precaution convert stored password hash to lower case */
	strncpy( storedPasswordHash, passwd->bv_val, 32 );
	storedPasswordHash[32] = '\0';
	ldap_pvt_str2lower( storedPasswordHash );
	
	return memcmp( PasswordHash, storedPasswordHash, 32) ? 1 : 0;
}
#endif /* SLAPD_LMHASH */

#ifdef SLAPD_SPASSWD
#ifdef HAVE_CYRUS_SASL
sasl_conn_t *lutil_passwd_sasl_conn = NULL;
#endif

static int chk_sasl(
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	unsigned int i;
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
		int sc;
# if SASL_VERSION_MAJOR < 2
		sc = sasl_checkpass( lutil_passwd_sasl_conn,
			passwd->bv_val, passwd->bv_len,
			cred->bv_val, cred->bv_len,
			text );
# else
		sc = sasl_checkpass( lutil_passwd_sasl_conn,
			passwd->bv_val, passwd->bv_len,
			cred->bv_val, cred->bv_len );
# endif
		rtn = ( sc != SASL_OK );
	}
#endif

	return rtn;
}
#endif

#ifdef SLAPD_CRYPT
static int chk_crypt(
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	char *cr;
	unsigned int i;

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
	const struct berval *sc,
	const struct berval * passwd,
	const struct berval * cred,
	const char **text )
{
	unsigned int i;
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

#ifdef LUTIL_SHA1_BYTES
static struct berval *hash_ssha1(
	const struct berval *scheme,
	const struct berval  *passwd,
	const char **text )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[LUTIL_SHA1_BYTES];
	char            saltdata[SALT_SIZE];
	struct berval digest;
	struct berval salt;

	digest.bv_val = (char *) SHA1digest;
	digest.bv_len = sizeof(SHA1digest);
	salt.bv_val = saltdata;
	salt.bv_len = sizeof(saltdata);

	if( lutil_entropy( (unsigned char *) salt.bv_val, salt.bv_len) < 0 ) {
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
	const struct berval *scheme,
	const struct berval  *passwd,
	const char **text )
{
	lutil_SHA1_CTX  SHA1context;
	unsigned char   SHA1digest[LUTIL_SHA1_BYTES];
	struct berval digest;
	digest.bv_val = (char *) SHA1digest;
	digest.bv_len = sizeof(SHA1digest);
     
	lutil_SHA1Init( &SHA1context );
	lutil_SHA1Update( &SHA1context,
		(const unsigned char *)passwd->bv_val, passwd->bv_len );
	lutil_SHA1Final( SHA1digest, &SHA1context );
            
	return pw_string64( scheme, &digest, NULL);
}
#endif

static struct berval *hash_smd5(
	const struct berval *scheme,
	const struct berval  *passwd,
	const char **text )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[LUTIL_MD5_BYTES];
	char            saltdata[SALT_SIZE];
	struct berval digest;
	struct berval salt;

	digest.bv_val = (char *) MD5digest;
	digest.bv_len = sizeof(MD5digest);
	salt.bv_val = saltdata;
	salt.bv_len = sizeof(saltdata);

	if( lutil_entropy( (unsigned char *) salt.bv_val, salt.bv_len) < 0 ) {
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
	const struct berval *scheme,
	const struct berval  *passwd,
	const char **text )
{
	lutil_MD5_CTX   MD5context;
	unsigned char   MD5digest[LUTIL_MD5_BYTES];

	struct berval digest;

	digest.bv_val = (char *) MD5digest;
	digest.bv_len = sizeof(MD5digest);

	lutil_MD5Init( &MD5context );
	lutil_MD5Update( &MD5context,
		(const unsigned char *) passwd->bv_val, passwd->bv_len );
	lutil_MD5Final( MD5digest, &MD5context );

	return pw_string64( scheme, &digest, NULL );
;
}

#ifdef SLAPD_LMHASH 
static struct berval *hash_lanman(
	const struct berval *scheme,
	const struct berval *passwd,
	const char **text )
{

	int i;
	char UcasePassword[15];
	des_cblock key;
	des_key_schedule schedule;
	des_cblock StdText = "KGS!@#$%";
	des_cblock PasswordHash1, PasswordHash2;
	char PasswordHash[33];
	struct berval hash;
	
	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return NULL;	/* NUL character in password */
		}
	}
	
	if( passwd->bv_val[i] != '\0' ) {
		return NULL;	/* passwd must behave like a string */
	}
	
	strncpy( UcasePassword, passwd->bv_val, 14 );
	UcasePassword[14] = '\0';
	ldap_pvt_str2upper( UcasePassword );
	
	lmPasswd_to_key( UcasePassword, &key );
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &PasswordHash1, schedule , DES_ENCRYPT );
	
	lmPasswd_to_key( &UcasePassword[7], &key );
	des_set_key_unchecked( &key, schedule );
	des_ecb_encrypt( &StdText, &PasswordHash2, schedule , DES_ENCRYPT );
	
	sprintf( PasswordHash, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
		PasswordHash1[0],PasswordHash1[1],PasswordHash1[2],PasswordHash1[3],
		PasswordHash1[4],PasswordHash1[5],PasswordHash1[6],PasswordHash1[7],
		PasswordHash2[0],PasswordHash2[1],PasswordHash2[2],PasswordHash2[3],
		PasswordHash2[4],PasswordHash2[5],PasswordHash2[6],PasswordHash2[7] );
	
	hash.bv_val = PasswordHash;
	hash.bv_len = 32;
	
	return pw_string( scheme, &hash );
}
#endif /* SLAPD_LMHASH */

#ifdef SLAPD_CRYPT
static struct berval *hash_crypt(
	const struct berval *scheme,
	const struct berval *passwd,
	const char **text )
{
	struct berval hash;
	unsigned char salt[32];	/* salt suitable for most anything */
	unsigned int i;

	for( i=0; i<passwd->bv_len; i++) {
		if(passwd->bv_val[i] == '\0') {
			return NULL;	/* NUL character in password */
		}
	}

	if( passwd->bv_val[i] != '\0' ) {
		return NULL;	/* passwd must behave like a string */
	}

	if( lutil_entropy( salt, sizeof( salt ) ) < 0 ) {
		return NULL; 
	}

	for( i=0; i< ( sizeof(salt) - 1 ); i++ ) {
		salt[i] = crypt64[ salt[i] % (sizeof(crypt64)-1) ];
	}
	salt[sizeof( salt ) - 1 ] = '\0';

	if( salt_format != NULL ) {
		/* copy the salt we made into entropy before snprintfing
		   it back into the salt */
		char entropy[sizeof(salt)];
		strcpy( entropy, (char *) salt );
		snprintf( (char *) salt, sizeof(entropy), salt_format, entropy );
	}

	hash.bv_val = crypt( passwd->bv_val, (char *) salt );

	if( hash.bv_val == NULL ) return NULL;

	hash.bv_len = strlen( hash.bv_val );

	if( hash.bv_len == 0 ) {
		return NULL;
	}

	return pw_string( scheme, &hash );
}
#endif

int lutil_salt_format(const char *format)
{
#ifdef SLAPD_CRYPT
	free( salt_format );

	salt_format = format != NULL ? strdup( format ) : NULL;
#endif

	return 0;
}

#ifdef SLAPD_CLEARTEXT
static struct berval *hash_clear(
	const struct berval *scheme,
	const struct berval  *passwd,
	const char **text )
{
	return ber_bvdup( (struct berval *) passwd );
}
#endif

