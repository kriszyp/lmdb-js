/* Generic errno.h */
/* $OpenLDAP$ */
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

#ifndef HAVE_SYS_ERRLIST
	/* no sys_errlist */
#	define		sys_nerr	0
#	define		sys_errlist	((char **)0)
#elif DECL_SYS_ERRLIST 
	/* have sys_errlist but need declaration */
	extern int      sys_nerr;
	extern char     *sys_errlist[];
#endif

#ifdef HAVE_STRERROR
#define	STRERROR(err)	strerror(err)
#else
#define	STRERROR(err) \
	((err) > -1 && (err) < sys_nerr ? sys_errlist[(err)] : "unknown")
#endif

extern char* strerror_r();
    
#endif /* _AC_ERRNO_H */
