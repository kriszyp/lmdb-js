/* lock.c - routines to open and apply an advisory lock to a file */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
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
	while ( ldap_lockf( *lfp ) != 0 ) {
		;	/* NULL */
	}

	/* open the log file */
	if ( (fp = fopen( fname, type )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "could not open \"%s\"\n", fname, 0, 0 );
		ldap_unlockf( *lfp );
		fclose( *lfp );
		*lfp = NULL;
		return( NULL );
	}

	return( fp );
}

int
lock_fclose( FILE *fp, FILE *lfp )
{
	/* unlock */
	ldap_unlockf( lfp );
	fclose( lfp );

	return( fclose( fp ) );
}
