
#include "portable.h"

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/string.h>

#include "slap.h"

static FILE *log_file;

void (Debug)( int level, const char *fmt, ... )
{
	char buffer[4096];
	va_list vl;

	if ( !(level & ldap_debug ) )
		return;

	if( log_file == NULL )
    {
		log_file = fopen( LDAP_RUNDIR LDAP_DIRSEP "slapd.log", "w" );

        if ( log_file == NULL )
			log_file = fopen( "slapd.log", "w" );

		if ( log_file == NULL )
			return;
	}

	va_start( vl, fmt );
	vsprintf( buffer, fmt, vl );
	fprintf( log_file, "%s", buffer );

    printf ("%s", buffer);

	fflush( log_file );
	va_end( vl );
}
