#ifndef _LUTIL_H
#define _LUTIL_H 1

/*
 * Include file for LDAP utility routine
 */

/* ISC Base64 Routines */
extern int b64_ntop(u_char const *, size_t, char *, size_t);
extern int b64_pton(char const *, u_char *, size_t);

#endif /* _LUTIL_H */
