/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * (C) Copyright IBM Corp. 1997,2002
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is 
 * given to IBM Corporation. This software is provided ``as is'' 
 * without express or implied warranty.
 */

#include <portable.h>
#include <slapi_common.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#include <ldap.h>
#include <ldap_config.h>
#include <slap.h>
#include <slapi.h>

#include <ldap_pvt_thread.h>

/* Single threads access to routine */
ldap_pvt_thread_mutex_t slapi_printmessage_mutex; 
char			*slapi_log_file = NULL;
int			slapi_log_level = SLAPI_LOG_PLUGIN;

int 
vLogError(
	int		level, 	
	char		*subsystem, 
	char		*fmt, 
	va_list		arglist ) 
{
	int		rc = 0;
	FILE		*fp = NULL;

	char		timeStr[100];
	struct tm	*ltm;
	time_t		currentTime;

	assert( subsystem != NULL );
	assert( fmt != NULL );

	ldap_pvt_thread_mutex_lock( &slapi_printmessage_mutex ) ;

	/* for now, we log all severities */
	if ( level <= slapi_log_level ) {
		fp = fopen( slapi_log_file, "a" );
		if ( fp == NULL) {
			rc = -1;
			goto done;
		}

		/*
		 * FIXME: could block
		 */
		while ( lockf( fileno( fp ), F_LOCK, 0 ) != 0 ) {
			/* DO NOTHING */ ;
		}

		time( &currentTime );
		ltm = localtime( &currentTime );
		strftime( timeStr, sizeof(timeStr), "%x %X", ltm );
		fputs( timeStr, fp );

		fprintf( fp, " %s: ", subsystem );
		vfprintf( fp, fmt, arglist );
		if ( fmt[ strlen( fmt ) - 1 ] != '\n' ) {
			fputs( "\n", fp );
		}
		fflush( fp );

		lockf( fileno( fp ), F_ULOCK, 0 );

		fclose( fp );

	} else {
		rc = -1;
	}

done:
	ldap_pvt_thread_mutex_unlock( &slapi_printmessage_mutex );

	return rc;
}
