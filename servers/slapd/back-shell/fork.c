/* fork.c - fork and exec a process, connecting stdin/out w/pipes */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

forkandexec(
    char	**args,
    FILE	**rfp,
    FILE	**wfp
)
{
	int	p2c[2], c2p[2];
	int	pid;

	if ( pipe( p2c ) != 0 || pipe( c2p ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "pipe failed\n", 0, 0, 0 );
		return( -1 );
	}

	/*
	 * what we're trying to set up looks like this:
	 *	parent *wfp -> p2c[1] | p2c[0] -> stdin child
	 *	parent *rfp <- c2p[0] | c2p[1] <- stdout child
	 */

	switch ( (pid = fork()) ) {
	case 0:		/* child */
		close( p2c[1] );
		close( c2p[0] );
		if ( dup2( p2c[0], 0 ) == -1 || dup2( c2p[1], 1 ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "dup2 failed\n", 0, 0, 0 );
			exit( -1 );
		}

		execv( args[0], args );

		Debug( LDAP_DEBUG_ANY, "execv failed\n", 0, 0, 0 );
		exit( -1 );

	case -1:	/* trouble */
		Debug( LDAP_DEBUG_ANY, "fork failed\n", 0, 0, 0 );
		return( -1 );

	default:	/* parent */
		close( p2c[0] );
		close( c2p[1] );
		break;
	}

	if ( (*rfp = fdopen( c2p[0], "r" )) == NULL || (*wfp = fdopen( p2c[1],
	    "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "fdopen failed\n", 0, 0, 0 );
		close( c2p[0] );
		close( p2c[1] );

		return( -1 );
	}

	return( pid );
}
