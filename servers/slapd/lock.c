/* lock.c - routines to open and apply an advisory lock to a file */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <sys/file.h>
#include <sys/param.h>
#include "slap.h"

FILE *
lock_fopen( char *fname, char *type, FILE **lfp )
{
	FILE	*fp;
	char	buf[MAXPATHLEN];

	/* open the lock file */
	strcpy( buf, fname );
	strcat( buf, ".lock" );
	if ( (*lfp = fopen( buf, "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "could not open \"%s\"\n", buf, 0, 0 );
		return( NULL );
	}

	/* acquire the lock */
#ifdef USE_LOCKF
	while ( lockf( fileno( *lfp ), F_LOCK, 0 ) != 0 ) {
#else
	while ( flock( fileno( *lfp ), LOCK_EX ) != 0 ) {
#endif
		;	/* NULL */
	}

	/* open the log file */
	if ( (fp = fopen( fname, type )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "could not open \"%s\"\n", fname, 0, 0 );
#ifdef USE_LOCKF
		lockf( fileno( *lfp ), F_ULOCK, 0 );
#else
		flock( fileno( *lfp ), LOCK_UN );
#endif
		return( NULL );
	}

	return( fp );
}

int
lock_fclose( FILE *fp, FILE *lfp )
{
	/* unlock */
#ifdef USE_LOCKF
	lockf( fileno( lfp ), F_ULOCK, 0 );
#else
	flock( fileno( lfp ), LOCK_UN );
#endif
	fclose( lfp );

	return( fclose( fp ) );
}
