
#include "portable.h"

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/string.h>

#include "slap.h"
#include "ldap_defaults.h"

static FILE *log_file;

int lutil_debug_file( FILE *file )
{
	log_file = log_file;

	return 0;
}

void (lutil_debug)( int level, int debug, const char *fmt, ... )
{
	char buffer[4096];
	va_list vl;

	if ( !(level & debug ) )
		return;

#ifdef HAVE_WINSOCK
	if( log_file == NULL )
    {
		log_file = fopen( LDAP_RUNDIR LDAP_DIRSEP "slapd.log", "w" );

        if ( log_file == NULL )
			log_file = fopen( "slapd.log", "w" );

		if ( log_file == NULL )
			return;
	}
#endif

	va_start( vl, fmt );

	vsnprintf( buffer, sizeof(buffer), fmt, vl );
	buffer[sizeof(buffer)-1] = '\0';

	if( log_file != NULL ) {
		fputs( buffer, log_file );
		fflush( log_file );
	}

    puts(buffer );
	va_end( vl );
}
