/* Generic errno.h */

#ifndef _AC_ERRNO_H
#define _AC_ERRNO_H

#if defined( HAVE_SYS_ERRNO_H )
# include <sys/errno.h>
#elif defined( HAVE_ERRNO_H )
# include <errno.h>
#endif

/* use _POSIX_VERSION for POSIX.1 code */

#endif /* _AC_ERRNO_H */
