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

#include <stdio.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include "portable.h"

#ifdef USE_SYSCONF
#include <unistd.h>
#endif /* USE_SYSCONF */

detach( debug )
int	debug;
{
	int	i, sd, nbits;

#ifdef USE_SYSCONF
	nbits = sysconf( _SC_OPEN_MAX );
#else /* USE_SYSCONF */
	nbits = getdtablesize();
#endif /* USE_SYSCONF */

#ifdef FD_SETSIZE
	if (nbits > FD_SETSIZE) {
		nbits = FD_SETSIZE;
	}
#endif	/* FD_SETSIZE*/


	if ( debug == 0 || !(isatty( 1 )) ) {
		for ( i = 0; i < 5; i++ ) {
			switch ( fork() ) {
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

		for ( i = 3; i < nbits; i++ )
			close( i );

		(void) chdir( "/" );

		if ( (sd = open( "/dev/null", O_RDWR )) == -1 ) {
			if ( debug ) perror( "/dev/null" );
			exit( 1 );
		}
		if ( isatty( 0 ) )
			(void) dup2( sd, 0 );
		if ( isatty( 1 ) )
			(void) dup2( sd, 1 );
		if ( isatty(2) )
			(void) dup2( sd, 2 );
		close( sd );

#ifdef USE_SETSID
		(void) setsid();
#else /* USE_SETSID */
		if ( (sd = open( "/dev/tty", O_RDWR )) != -1 ) {
			(void) ioctl( sd, TIOCNOTTY, NULL );
			(void) close( sd );
		}
#endif /* USE_SETSID */
	} 

	(void) signal( SIGPIPE, SIG_IGN );
}
