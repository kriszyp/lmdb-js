/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1996, 1998 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdarg.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_log.h"
#include "ldap_defaults.h"
#include "lber.h"

static FILE *log_file;

struct M2S
{
	char *mnemonic;
	int  subsys;
};

struct DEBUGLEVEL
{
	char *subsystem;
	int  level;
};

static struct DEBUGLEVEL **levelArray;
static long   numLevels = 0;

int global_level = 0;

static void addSubsys( const char *subsys, int level )
{
	int i, j;
	for( i = 0; i < numLevels; i++ )
	{
		if ( levelArray[i] == NULL )
		{
			levelArray[i] = (struct DEBUGLEVEL*)ber_memalloc( sizeof( struct DEBUGLEVEL ) );
			levelArray[i]->subsystem = (char*)ber_memalloc( strlen( subsys ) + 1 );
			strcpy ( levelArray[i]->subsystem, subsys );
			levelArray[i]->level = level;
			return;
		}
		if( !strcasecmp( subsys, levelArray[i]->subsystem ) )
		{
			levelArray[i]->level = level;
			return;
		}
	}
	levelArray = (struct DEBUGLEVEL**)ber_memrealloc( levelArray, sizeof( struct DEBUGLEVEL* ) * (numLevels + 10) );
	for( j = numLevels; j < (numLevels + 10); j++ )
	{
		levelArray[j] = NULL;
	}
	numLevels += 10;
	levelArray[i] = (struct DEBUGLEVEL*)ber_memalloc( sizeof( struct DEBUGLEVEL ) );
	levelArray[i]->subsystem = (char*)ber_memalloc( strlen( subsys ) + 1 );
	strcpy( levelArray[i]->subsystem, subsys );
	levelArray[i]->level = level;
	return;
}

void lutil_set_debug_level( char* subsys, int level )
{
	addSubsys( subsys, level );
}

int lutil_debug_file( FILE *file )
{
	log_file = file;
	ber_set_option( NULL, LBER_OPT_LOG_PRINT_FILE, file );

	return 0;
}

void lutil_log_int(FILE* file, char *subsys, int level, const char *fmt, va_list vl )
{
	char buffer[4096];
	time_t now;
	struct tm *today;
	int i;

        /*
         * Look for the subsystem in the level array.  When we find it, break out of the
         * loop.
         */
	for( i = 0; i < numLevels; i++ )
	{
		if ( ! strcasecmp( levelArray[i]->subsystem, subsys ) ) break;
	}

        /*
         * If we didn't find the subsystem, or the set level is less than
         * the requested output level, don't output it.
         */
	if ( (level > global_level) && 
             ((i > numLevels ) || ( level > levelArray[i]->level )) )
		return;

#if 0
#ifdef HAVE_WINSOCK
	if( log_file == NULL ) {
		log_file = fopen( LDAP_RUNDIR LDAP_DIRSEP "openldap.log", "w" );

		if ( log_file == NULL )
			log_file = fopen( "openldap.log", "w" );

		if ( log_file == NULL )
			return;

		ber_set_option( NULL, LBER_OPT_LOG_PRINT_FILE, log_file );
	}
#endif
#endif

        /*
         * Stick the time in the buffer to output.  Kurt doesn't like
         * doing this here, but NT can't pipe to a timestamp program
         * like Unix can, and I don't think it costs much.
         */
	time( &now );
	today = localtime( &now );
	sprintf( buffer, "%4d%02d%02d:%02d:%02d:%02d ",
		today->tm_year + 1900, today->tm_mon + 1,
		today->tm_mday, today->tm_hour,
		today->tm_min, today->tm_sec );

        /*
         * format the output data.
         */
#ifdef HAVE_VSNPRINTF
	vsnprintf( &buffer[18], sizeof(buffer)-18, fmt, vl );
#else
	vsprintf( &buffer[18], fmt, vl );
#endif
	buffer[sizeof(buffer)-1] = '\0';

        /*
         * If the user set up a file using 
         * ber_set_option( NULL, LBER_OPT_LOG_PRINT_FILE, file), use
         * it.  Otherwise, just output to stderr.
         */
	if( file != NULL ) {
		fputs( buffer, file );
		fflush( file );
	}
        else
        {
            fputs( buffer, stderr );
        }

/*
 * Kurt or someone needs to decide what to do about this.  This
 * code will log to syslog if the level is less than a normal
 * debug level (meaning a warning or error of some kind).  However,
 * having the code here means that ldap_syslog has to be defined.
 */
#if 0
#ifdef LDAP_SYSLOG
	if ( level < LDAP_LEVEL_ENTRY && level >= ldap_syslog )
	{
		syslog( level, buffer );
	}
#endif
#endif
}

/*
 * The primary logging routine.  Takes the subsystem being logged from, the
 * level of the log output and the format and data.  Send this on to the
 * internal routine with the print file, if any.
 */
void lutil_log( char *subsys, int level, const char *fmt, ... )
{
	FILE* outfile = NULL;
	va_list vl;
	va_start( vl, fmt );
	ber_get_option( NULL, LBER_OPT_LOG_PRINT_FILE, &outfile );
	lutil_log_int( outfile, subsys, level, fmt, vl );
	va_end( vl );
}

void lutil_log_initialize(int argc, char **argv)
{
    int i;
    /*
     * Start by setting the hook for the libraries to use this logging
     * routine.
     */
    ber_set_option( NULL, LBER_OPT_LOG_PROC, (void*)lutil_log_int );

    if ( argc == 0 ) return;
    /*
     * Now go through the command line options to set the debugging
     * levels
     */
    for( i = 0; i < argc; i++ )
    {
        char *next = argv[i];
        if ( i < argc-1 && next[0] == '-' && next[1] == 'd' )
        {
            char subsys[64];
            int level;
            char *optarg = argv[i+1];
            char *index = strchr( optarg, '=' );
            if ( index != NULL )
            {
                *index = 0;
                strcpy ( subsys, optarg );
                level = atoi( index+1 );
                lutil_set_debug_level( subsys, level );
                printf( "setting debug level of %s to %d\n", subsys, level );
                *index = '=';
            }
            else
            {
                global_level = atoi( optarg );
                printf( "setting global level to %d\n", global_level );
            }
        }
    }
}

void (lutil_debug)( int debug, int level, const char *fmt, ... )
{
	char buffer[4096];
	va_list vl;

	if ( !(level & debug ) )
		return;

#ifdef HAVE_WINSOCK
	if( log_file == NULL ) {
		log_file = fopen( LDAP_RUNDIR LDAP_DIRSEP "openldap.log", "w" );

		if ( log_file == NULL )
			log_file = fopen( "openldap.log", "w" );

		if ( log_file == NULL )
			return;

		ber_set_option( NULL, LBER_OPT_LOG_PRINT_FILE, log_file );
	}
#endif
	va_start( vl, fmt );

#ifdef HAVE_VSNPRINTF
	vsnprintf( buffer, sizeof(buffer), fmt, vl );
#else
	vsprintf( buffer, fmt, vl );
#endif
	buffer[sizeof(buffer)-1] = '\0';

	if( log_file != NULL ) {
		fputs( buffer, log_file );
		fflush( log_file );
	}

    fputs( buffer, stderr );
	va_end( vl );
}
