#ifndef _LUTIL_H
#define _LUTIL_H 1

#include <ldap_cdefs.h>
/*
 * Include file for LDAP utility routine
 */

LDAP_BEGIN_DECL

/* ISC Base64 Routines */
/* base64.c */
LDAP_F int lutil_b64_ntop LDAP_P((u_char const *, size_t, char *, size_t));
LDAP_F int lutil_b64_pton LDAP_P((char const *, u_char *, size_t));
/* detach.c */
LDAP_F void lutil_detach LDAP_P((int debug, int do_close));
/* passwd.c */
LDAP_F int lutil_passwd LDAP_P((const char *cred, const char *passwd));

LDAP_END_DECL

#endif /* _LUTIL_H */
