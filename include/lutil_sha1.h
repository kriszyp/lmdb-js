/* This version is based on:
 *	$OpenBSD: sha1.h,v 1.8 1997/07/15 01:54:23 millert Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

/* XXX   I wonder if this will work on 64bit architectures... */
#ifndef LDAP_UINT32
#define LDAP_UINT32
typedef unsigned long uint32;
#endif

typedef struct {
    uint32 state[5];
    uint32 count[2];  
    unsigned char buffer[64];
} SHA1_CTX;
  
void ldap_SHA1Transform __P((uint32 state[5], const unsigned char buffer[64]));
void ldap_SHA1Init __P((SHA1_CTX *context));
void ldap_SHA1Update __P((SHA1_CTX *context, const unsigned char *data, u_int len));
void ldap_SHA1Final __P((unsigned char digest[20], SHA1_CTX *context));
char *ldap_SHA1End __P((SHA1_CTX *, char *));
char *ldap_SHA1File __P((char *, char *));
char *ldap_SHA1Data __P((const unsigned char *, size_t, char *));
