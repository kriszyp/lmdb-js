#include <stdio.h>
#include <stdarg.h>

static FILE *log_file;

void Debug( int level, char *fmt, ... )
{
	char buffer[4096];
	va_list vl;

	if( log_file == NULL )
		log_file = fopen( "C:\\OpenLDAP\\run\\slapd.log", "w" );

	va_start( vl, fmt );
	vsprintf( buffer, fmt, vl );
	fprintf( log_file, "%s\n", buffer );
	fflush( log_file );
	va_end( vl );
}
