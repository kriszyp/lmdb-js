/* Generic unistd.h */

#ifndef _AC_UNISTD_H
#define _AC_UNISTD_H

#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#if HAVE_UNISTD_H
# include <unistd.h>
#endif

/* getopt() defines may be in separate include file */
#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#ifndef HAVE_GETOPT
/* no getopt, assume we need getopt-compat.h */
# include <getopt-compat.h>
#endif

/* use _POSIX_VERSION for POSIX.1 code */

#endif /* _AC_UNISTD_H */
