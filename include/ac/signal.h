/* Generic signal.h */

#ifndef _AC_SIGNAL_H
#define _AC_SIGNAL_H

#include <signal.h>

#ifdef HAVE_SIGSET
#define SIGNAL sigset
#else
#define SIGNAL signal
#endif

#if !defined( LDAP_SIGUSR1 ) || !defined( LDAP_SIGUSR2 )
#undef LDAP_SIGUSR1
#undef LDAP_SIGUSR2

#	ifndef HAVE_LINUX_THREADS
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

#		ifdef defined( SIGUNUSED )
#			define LDAP_SIGUSR2	SIGUNUSED
#		elif defined ( SIGINFO )
#			define LDAP_SIGUSR1	SIGINFO
#		elif defined ( SIGEMT )
#			define LDAP_SIGUSR1	SIGEMT
#		endif
#	endif
#endif

#endif /* _AC_SIGNAL_H */
