/* Generic errno.h */

#ifndef _AC_ERRNO_H
#define _AC_ERRNO_H

#if defined( HAVE_ERRNO_H )
# include <errno.h>
#elif defined( HAVE_SYS_ERRNO_H )
# include <sys/errno.h>
#endif

#ifdef DECL_SYS_ERRLIST 
extern int      sys_nerr;
extern char     *sys_errlist[];
#endif
    
/* use _POSIX_VERSION for POSIX.1 code */

#endif /* _AC_ERRNO_H */
