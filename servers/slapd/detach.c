/*
 * Copyright (c) 1990, 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/signal.h>
#include <ac/unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/ioctl.h>

detach()
{
	int		i, sd, nbits;
#ifdef LDAP_DEBUG
	extern int	ldap_debug;
#endif

#ifdef HAVE_SYSCONF
	nbits = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	nbits = getdtablesize();
#else
	nbits = FD_SETSIZE
#endif 

#ifdef FD_SETSIZE
	if ( nbits > FD_SETSIZE ) {
		nbits = FD_SETSIZE;
	}
#endif /* FD_SETSIZE */

#ifdef LDAP_DEBUG
	if ( ldap_debug == 0 ) {
#endif
		for ( i = 0; i < 5; i++ ) {
#if defined( HAVE_THR )
			switch ( fork1() ) {
#else
			switch ( fork() ) {
#endif
			case -1:
				sleep( 5 );
				continue;

			case 0:
				break;

			default:
				_exit( 0 );
			}
			break;
		}

/*
		for ( i = 3; i < nbits; i++ )
			close( i );
*/

		(void) chdir( "/" );

		if ( (sd = open( "/dev/null", O_RDWR )) == -1 ) {
			perror( "/dev/null" );
			exit( 1 );
		}
		if ( isatty( 0 ) )
			(void) dup2( sd, 0 );
		if ( isatty( 1 ) )
			(void) dup2( sd, 1 );
		if ( isatty(2) )
			(void) dup2( sd, 2 );
		close( sd );

#ifdef HAVE_SETSID
		setsid();
#else /* HAVE_SETSID */
		if ( (sd = open( "/dev/tty", O_RDWR )) != -1 ) {
			(void) ioctl( sd, TIOCNOTTY, NULL );
			(void) close( sd );
		}
#endif /* HAVE_SETSID */
#ifdef LDAP_DEBUG
	} 
#endif

	(void) SIGNAL( SIGPIPE, SIG_IGN );
}
