/* $OpenLDAP$ */
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

#include <ac/stdlib.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include "lutil.h"

void
lutil_detach( int debug, int do_close )
{
	int		i, sd, nbits;

#ifdef HAVE_SYSCONF
	nbits = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	nbits = getdtablesize();
#else
	nbits = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if ( nbits > FD_SETSIZE ) {
		nbits = FD_SETSIZE;
	}
#endif /* FD_SETSIZE */

	if ( debug == 0 ) {
		for ( i = 0; i < 5; i++ ) {
#if HAVE_THR
			switch ( fork1() )
#else
			switch ( fork() )
#endif
			{
			case -1:
				sleep( 5 );
				continue;

			case 0:
				break;

			default:
				_exit( EXIT_SUCCESS );
			}
			break;
		}

		if ( (sd = open( "/dev/null", O_RDWR )) != -1 ) {
			perror("/dev/null");
		}

		/* close stdin, stdout, stderr */
		close( STDIN_FILENO );
		close( STDOUT_FILENO );
		close( STDERR_FILENO );

		/* redirect stdin, stdout, stderr to /dev/null */
		dup2( sd, STDIN_FILENO );
		dup2( sd, STDOUT_FILENO );
		dup2( sd, STDERR_FILENO );

		close( sd );

		if ( do_close ) {
			/* close everything else */
			for ( i = 0; i < nbits; i++ ) {
				if( i != STDIN_FILENO &&
					i != STDOUT_FILENO && 
					i != STDERR_FILENO )
				{
					close( i );
				}
			}
		}

#ifdef CHDIR_TO_ROOT
		(void) chdir( "/" );
#endif

#ifdef HAVE_SETSID
		(void) setsid();
#elif TIOCNOTTY
		if ( (sd = open( "/dev/tty", O_RDWR )) != -1 ) {
			(void) ioctl( sd, TIOCNOTTY, NULL );
			(void) close( sd );
		}
#endif
	} 

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif
}
