/* Generic errno.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_ERRNO_H
#define _AC_ERRNO_H

#if defined( HAVE_ERRNO_H )
# include <errno.h>
#elif defined( HAVE_SYS_ERRNO_H )
# include <sys/errno.h>
#endif

#ifdef DECL_SYS_ERRLIST 
#ifndef HAVE_SYS_ERRLIST
#define		sys_nerr	0
#define		sys_errlist	((char **)0)
#else
extern int      sys_nerr;
extern char     *sys_errlist[];
#endif
#endif
    
#if !defined( EWOULDBLOCK ) && defined( WSAEWOULDBLOCK )
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

/* use _POSIX_VERSION for POSIX.1 code */

#endif /* _AC_ERRNO_H */
