/* Generic unistd.h */

#ifndef _AC_UNISTD_H
#define _AC_UNISTD_H

#if HAVE_SYS_TYPES_H
#	include <sys/types.h>
#endif

#if HAVE_UNISTD_H
#	include <unistd.h>
#endif

/* crypt() may be defined in a separate include file */
#if HAVE_CRYPT_H
#	include <crypt.h>
#else
	extern char *crypt();
#endif

/* getopt() defines may be in separate include file */
#if HAVE_GETOPT_H
#	include <getopt.h>

#elif !defined(HAVE_GETOPT)
	/* no getopt, assume we need getopt-compat.h */
#	include <getopt-compat.h>

#else
	/* assume we need to declare these externs */
	extern char *optarg;
	extern int optind, opterr, optopt;
#endif

#ifndef HAVE_TEMPNAM
	extern char *tempnam(const char *tmpdir, const char *prefix);
#endif
#ifndef HAVE_MKTEMP
	extern char *mktemp(char *);
#endif

/* use _POSIX_VERSION for POSIX.1 code */

#endif /* _AC_UNISTD_H */
