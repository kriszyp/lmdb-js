/* Generic signal.h */
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

#ifndef _AC_SIGNAL_H
#define _AC_SIGNAL_H

#include <signal.h>

#undef SIGNAL
#ifdef HAVE_SIGSET
#define SIGNAL sigset
#else
#define SIGNAL signal
#endif

#if !defined( LDAP_SIGUSR1 ) || !defined( LDAP_SIGUSR2 )
#undef LDAP_SIGUSR1
#undef LDAP_SIGUSR2

#	if defined(WINNT) || defined(_WINNT)
#		define LDAP_SIGUSR1	SIGILL
#		define LDAP_SIGUSR2	SIGTERM

#	elif !defined(HAVE_LINUX_THREADS)
#		define LDAP_SIGUSR1	SIGUSR1
#		define LDAP_SIGUSR2	SIGUSR2

#	else
		/*
		LinuxThreads implemented unfortunately uses the only
		two signals reserved for user applications.  This forces
		OpenLDAP to use, hopefullly unused, signals reserved
		for other uses.
		*/
	    
#		if defined( SIGSTKFLT )
#			define LDAP_SIGUSR1	SIGSTKFLT
#		elif defined ( SIGSYS )
#			define LDAP_SIGUSR1	SIGSYS
#		endif

#		if defined( SIGUNUSED )
#			define LDAP_SIGUSR2	SIGUNUSED
#		elif defined ( SIGINFO )
#			define LDAP_SIGUSR2	SIGINFO
#		elif defined ( SIGEMT )
#			define LDAP_SIGUSR2	SIGEMT
#		endif
#	endif
#endif

#ifndef LDAP_SIGCHLD
#ifdef SIGCHLD
#define LDAP_SIGCHLD SIGCHLD
#elif SIGCLD
#define LDAP_SIGCHLD SIGCLD
#endif
#endif

#endif /* _AC_SIGNAL_H */
