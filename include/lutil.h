#ifndef _LUTIL_H
#define _LUTIL_H 1

#include <ldap_cdefs.h>
/*
 * Include file for LDAP utility routine
 */

/* ISC Base64 Routines */

LDAP_BEGIN_DECL

LDAP_F int b64_ntop LDAP_P((u_char const *, size_t, char *, size_t));
LDAP_F int b64_pton LDAP_P((char const *, u_char *, size_t));

LDAP_END_DECL

#endif /* _LUTIL_H */
