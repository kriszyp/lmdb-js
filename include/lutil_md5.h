/* See md5.c for explanation and copyright information.  */

#ifndef _LDAP_MD5_H_
#define _LDAP_MD5_H_

#include <ldap_cdefs.h>
#include <ac/bytes.h>

LDAP_BEGIN_DECL

/* Unlike previous versions of this code, uint32 need not be exactly
   32 bits, merely 32 bits or more.  Choosing a data type which is 32
   bits instead of 64 is not important; speed is considerably more
   important.  ANSI guarantees that "unsigned long" will be big enough,
   and always using it seems to have few disadvantages.  */

#ifndef LDAP_UINT32
typedef LDAP_UINT4 uint32;
#endif

struct ldap_MD5Context {
	uint32 buf[4];
	uint32 bits[2];
	unsigned char in[64];
};

LDAP_F void ldap_MD5Init LDAP_P((
	struct ldap_MD5Context *context));

LDAP_F void ldap_MD5Update LDAP_P((
	struct ldap_MD5Context *context,
	unsigned char const *buf,
	unsigned len));

LDAP_F void ldap_MD5Final LDAP_P((
	unsigned char digest[16],
	struct ldap_MD5Context *context));

LDAP_F void ldap_MD5Transform LDAP_P((
	uint32 buf[4],
	const unsigned char in[64]));

/*
 * This is needed to make RSAREF happy on some MS-DOS compilers.
 */
typedef struct ldap_MD5Context ldap_MD5_CTX;

LDAP_END_DECL

#endif /* _LDAP_MD5_H_ */
