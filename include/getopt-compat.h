/*
 * getopt(3) declarations
 */
#ifndef _GETOPT_COMPAT_H
#define _GETOPT_COMPAT_H

#include <ldap_cdefs.h>

extern char *optarg;
extern int optind, opterr, optopt;

LDAP_F int getopt LDAP_P((int, char * const [], const char *));

#endif /* _GETOPT_COMPAT_H */
