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
static ldap_pvt_thread_mutex_t PrintMessage_mutex; 
static int PrintMessage_mutex_inited = 0;

static void
InitMutex () 
{
	if (PrintMessage_mutex_inited == 0) {
		PrintMessage_mutex_inited = 1;
		ldap_pvt_thread_mutex_init(&PrintMessage_mutex);
	}
}

int 
vLogError(
	int level, 	
	char *subsystem, 
	char *fmt, 
	va_list arglist ) 
{
	int rc = 0;
	char *tmpFmt;
	FILE * fp = NULL;
	char *p, *sval;
	int ival;

	char timeStr[100];
	struct tm *ltm;
	time_t currentTime;

	tmpFmt = fmt;
	fmt = (char*)ch_calloc(strlen(subsystem) + strlen(tmpFmt) + 3, 1);
	sprintf(fmt, "%s: %s", subsystem, tmpFmt);

	InitMutex() ;
	ldap_pvt_thread_mutex_lock( &PrintMessage_mutex ) ;

	/* for now, we log all severities */
	if ( 1 ) {
		fp = fopen( LDAP_RUNDIR LDAP_DIRSEP "errors", "a" );
		if (fp == NULL) 
			fp = fopen( "errors", "a" );
			
		if ( fp != NULL) {
			while ( lockf(fileno(fp), F_LOCK, 0 ) != 0 ) {}

			time (&currentTime);
			ltm = localtime( &currentTime );
			strftime( timeStr, sizeof(timeStr), "%x %X ", ltm );
			fprintf(fp, timeStr);
			for (p = fmt; *p; p++) {
				if (*p != '%') {
					fprintf(fp, "%c", *p);
					continue;
				}
				switch(*++p) {
				case 'd':
					ival = va_arg( arglist, int);
					fprintf(fp, "%d", ival);
					break;
				case 's':
					for (sval = va_arg(arglist, char *); *sval; sval++)
						fprintf(fp, "%c", *sval);
					break;
				default:
					fprintf(fp, "%c", *p);
					break;
				
				}
			}
	
			fflush(fp);

			lockf( fileno(fp), F_ULOCK, 0 );

			fclose(fp);
		} else {
#if 0 /* unused */
			int save_errno = (int)errno;
#endif /* unused */
			rc = ( -1);
		}
	} else {
		rc = ( -1);
	}

	ldap_pvt_thread_mutex_unlock( &PrintMessage_mutex );
	ch_free(fmt);

	return (rc);
}
