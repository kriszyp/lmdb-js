/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/stdarg.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap_log.h"
#include "ldap_defaults.h"
#include "lber.h"

struct DEBUGLEVEL
{
	char *subsystem;
	int  level;
};

static struct DEBUGLEVEL **levelArray;
static long   numLevels = 0;

static FILE *log_file = NULL;
static int global_level = 0;

#if 0
#ifdef LDAP_SYSLOG
static int use_syslog = 0;

static int debug2syslog(int l) {
	switch (l) {
	/* insert mapping cases here */
	default:
	}
	return LOG_DEBUG
}
#endif
#endif

static char *lutil_levels[] = {"emergency", "alert", "critical",
			   "error", "warning", "notice",
			   "information", "entry", "args",
			   "results", "detail1", "detail2",
			   NULL};

int lutil_mnem2level( char *level )
{
    int i;
    for( i = 0; lutil_levels[i] != NULL; i++ )
    {
	if ( !strcasecmp( level, lutil_levels[i] ) )
	{
	    return i;
	}
    }
    return 0;
}

static void addSubsys( const char *subsys, int level )
{
	int i, j;

	if ( !strcasecmp( subsys, "global") ) global_level = level;

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

void lutil_log_int(
	FILE* file,
	char *subsys, int level,
	const char *fmt, va_list vl )
{
	time_t now;
	struct tm *today;
	int i;

	if ( levelArray == NULL ) return; /* logging isn't set up */

	/*
	 * Look for the subsystem in the level array.  When we find it,
	 * break out of the loop.
	 */
	for( i = 0; i < numLevels; i++ ) {
		if ( levelArray[i] == NULL ) return; 
		if ( ! strcasecmp( levelArray[i]->subsystem, subsys ) ) break;
	}

	/*
	 * If we didn't find the subsystem, or the set level is less than
	 * the requested output level, don't output it.
	 */
	if ( (level > global_level) &&
		((i > numLevels ) || ( level > levelArray[i]->level )) )
	{
		return;
	}

#if 0
#ifdef LDAP_SYSLOG
	/* we're configured to use syslog */
	if( use_syslog ) {
		vsyslog( debug2syslog(level), fmt, vl );
		return;
	}
#endif
#endif

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

	if( file == NULL ) {
		/*
		 * Use stderr unless file was specified via:
		 *   ber_set_option( NULL, LBER_OPT_LOG_PRINT_FILE, file)
		 */
		file = stderr;
	}

#ifdef HAVE_WINSOCK
	/*
	 * Stick the time in the buffer to output when using Winsock
	 * as NT can't pipe to a timestamp program like Unix can.
	 * This, of course, makes some logs hard to read.
     */
	time( &now );
	today = localtime( &now );
	fprintf( file, "%4d%02d%02d:%02d:%02d:%02d ",
		today->tm_year + 1900, today->tm_mon + 1,
		today->tm_mday, today->tm_hour,
		today->tm_min, today->tm_sec );
#endif

	/*
	 * format the output data.
	 */
	vfprintf( file, fmt, vl );
}

/*
 * The primary logging routine.	 Takes the subsystem being logged from, the
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
		if ( level <= 0 ) level = lutil_mnem2level( index + 1 );
		lutil_set_debug_level( subsys, level );
		*index = '=';
	    }
	    else
	    {
		global_level = atoi( optarg );
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
