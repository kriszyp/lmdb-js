/* This version is based on:
 *	$OpenBSD: sha1.h,v 1.8 1997/07/15 01:54:23 millert Exp $	*/

#ifndef _LDAP_SHA1_H_
#define _LDAP_SHA1_H_

#include <ldap_cdefs.h>
#include <ac/bytes.h>

LDAP_BEGIN_DECL

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef LDAP_UINT32
#define LDAP_UINT32 1
typedef LDAP_UINT4 uint32;
#endif

typedef struct {
    uint32 state[5];
    uint32 count[2];  
    unsigned char buffer[64];
} ldap_SHA1_CTX;
  
LDAP_F void ldap_SHA1Transform
	LDAP_P((uint32 state[5], const unsigned char buffer[64]));

LDAP_F void ldap_SHA1Init
	LDAP_P((ldap_SHA1_CTX *context));

LDAP_F void ldap_SHA1Update
	LDAP_P((ldap_SHA1_CTX *context, const unsigned char *data, u_int len));

LDAP_F void ldap_SHA1Final
	LDAP_P((unsigned char digest[20], ldap_SHA1_CTX *context));

LDAP_F char *ldap_SHA1End
	LDAP_P((ldap_SHA1_CTX *, char *));

LDAP_F char *ldap_SHA1File
	LDAP_P((char *, char *));

LDAP_F char *ldap_SHA1Data
	LDAP_P((const unsigned char *, size_t, char *));

LDAP_END_DECL

#endif /* _LDAP_SHA1_H_ */
