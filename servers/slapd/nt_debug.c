#include <stdio.h>
#include <stdarg.h>

#include "portable.h"
#include "slap.h"

static FILE *log_file;

void Debug( int level, char *fmt, ... )
{
	char buffer[4096];
	va_list vl;

	if ( !(level & ldap_debug ) )
		return;

	if( log_file == NULL )
    {
		log_file = fopen( "C:\\OpenLDAP\\run\\slapd.log", "w" );

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
