/*
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

/* This file SHOULD go away !!! */

#ifndef _LDAP_BRIDGE_H
#define _LDAP_BRIDGE_H

/*
 * portable.h for LDAP -- this is where we define common stuff to make
 * life easier on various Unix systems.
 *
 * Unless you are porting LDAP to a new platform, you should not need to
 * edit this file.
 */

#ifndef LDAP_LIBUI
#ifndef NO_USERINTERFACE
#define NO_USERINTERFACE
#endif
#endif

#ifndef SYSV
#if defined( hpux ) || defined( sunos5 ) || defined ( sgi ) || defined( SVR4 )
#	define SYSV
#endif
#endif


/*
 * under System V, use sysconf() instead of getdtablesize
 */
#if defined( HAVE_SYSCONF ) && !defined( HAVE_GETDTABLESIZE )
#define USE_SYSCONF
#endif


/*
 * under System V, daemons should use setsid() instead of detaching from their
 * tty themselves
 */
#if defined( HAVE_SETSID )
#define USE_SETSID
#endif


/*
 * System V has socket options in filio.h
 */
#if defined( HAVE_FILIO_H )
#define NEED_FILIO
#endif

/*
 * use lockf() under System V
 */
#if !defined( HAVE_LOCKF ) && !defined( HAVE_FLOCK )
#define USE_LOCKF
#endif

/*
 * on most systems, we should use waitpid() instead of waitN()
 */
#if defined( HAVE_WAITPID ) && !defined( nextstep )
#define USE_WAITPID
#endif


/*
 * define the wait status argument type
 */
#if !defined( WAITSTATUSTYPE )
#if !defined( HAVE_SYS_WAIT_H )
#define WAITSTATUSTYPE	union wait
#else
#define WAITSTATUSTYPE	int
#endif
#endif

/*
 * define the flags for wait
 */
#if !defined( WAIT_FLAGS )
#ifdef sunos5
#define WAIT_FLAGS	( WNOHANG | WUNTRACED | WCONTINUED )
#else
#define WAIT_FLAGS	( WNOHANG | WUNTRACED )
#endif
#endif


/*
 * defined the options for openlog (syslog)
 */
#if !defined( OPENLOG_OPTIONS )
#ifdef ultrix
#define OPENLOG_OPTIONS		LOG_PID
#else
#define OPENLOG_OPTIONS		( LOG_PID | LOG_NOWAIT )
#endif
#endif


/*
 * many systems do not have the setpwfile() library routine... we just
 * enable use for those systems we know have it.
 */
#ifdef NOTDEF
#ifndef HAVE_SETPWFILE
#if defined( sunos4 ) || defined( ultrix ) || defined( __osf__ )
#define HAVE_SETPWFILE
#endif
#endif
#endif NOTDEF

#ifndef DISABLE_BRIDGE 
/*
 * Are sys_errlist and sys_nerr declared in stdio.h?
 */
#ifndef SYSERRLIST_IN_STDIO
#if !defined( DECL_SYS_ERRLIST ) 
#define SYSERRLIST_IN_STDIO
#endif
#endif

/*
 * for select()
 */
#if !defined(FD_SET) && !defined(WINSOCK)
#define NFDBITS         32
#define FD_SETSIZE      32
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif /* FD_SET */
#endif

#if defined( hpux ) && defined( __STDC__ )
/*
 * Under HP/UX, select seems to want (int *) instead of fd_set.  Non-ANSI
 * compilers don't like recursive macros, so ignore the problem if __STDC__
 * is not defined.
 */
#define select(a,b,c,d,e) select(a, (int *)b, (int *)c, (int *)d, e)
#endif /* hpux && __STDC__ */


/*
 * for signal() -- what do signal handling functions return?
 */
#ifdef RETSIGTYPE
#define SIG_FN RETSIGTYPE
#endif


/*
 * call signal or sigset (signal does not block the signal while
 * in the handler on sys v and sigset does not exist on bsd)
 */
#ifndef SIGNAL
#ifdef HAVE_SIGSET
#define SIGNAL sigset
#else
#define SIGNAL signal
#endif
#endif

/*
 * toupper and tolower macros are different under bsd and sys v
 */
#if defined( SYSV ) && !defined( hpux )
#define TOUPPER(c)	(isascii(c) && islower(c) ? _toupper(c) : c)
#define TOLOWER(c)	(isascii(c) && isupper(c) ? _tolower(c) : c)
#else
#define TOUPPER(c)	(isascii(c) && islower(c) ? toupper(c) : c)
#define TOLOWER(c)	(isascii(c) && isupper(c) ? tolower(c) : c)
#endif

/*
 * put a cover on the tty-related ioctl calls we need to use
 */
#if !defined( HAVE_TERMIOS_H )
#define TERMIO_TYPE struct sgttyb
#define TERMFLAG_TYPE int
#define GETATTR( fd, tiop )	ioctl((fd), TIOCGETP, (caddr_t)(tiop))
#define SETATTR( fd, tiop )	ioctl((fd), TIOCSETP, (caddr_t)(tiop))
#define GETFLAGS( tio )		(tio).sg_flags
#define SETFLAGS( tio, flags )	(tio).sg_flags = (flags)
#else
#define USE_TERMIOS
#define TERMIO_TYPE struct termios
#define TERMFLAG_TYPE tcflag_t
#define GETATTR( fd, tiop )	tcgetattr((fd), (tiop))
#define SETATTR( fd, tiop )	tcsetattr((fd), TCSANOW /* 0 */, (tiop))
#define GETFLAGS( tio )		(tio).c_lflag
#define SETFLAGS( tio, flags )	(tio).c_lflag = (flags)
#endif


#if defined( ultrix ) || defined( nextstep )
extern char *strdup();
#endif /* ultrix || nextstep */

#endif /* _LDAP_BRIDGE_H */
