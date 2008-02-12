/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *     Howard Chu
 */


/* 
 * main.c - main routine for slurpd.
 */

#include "portable.h"

#include <stdio.h>
#include <sys/stat.h>
#include <ac/stdlib.h>
#include <ac/unistd.h>

#include "slurp.h"
#include "globals.h"
#include "lutil.h"

#include <ldap_pvt.h>

#ifdef HAVE_NT_SERVICE_MANAGER
#define	MAIN_RETURN(x)	return
#define SERVICE_EXIT( e, n )	do { \
	if ( is_NT_Service ) { \
		lutil_ServiceStatus.dwWin32ExitCode = (e); \
		lutil_ServiceStatus.dwServiceSpecificExitCode = (n); \
	} \
} while ( 0 )
#else
#define SERVICE_EXIT( e, n )
#define	MAIN_RETURN(x)	return(x)
#endif

#ifndef HAVE_MKVERSION
const char Versionstr[] =
	OPENLDAP_PACKAGE " " OPENLDAP_VERSION " Standalone LDAP Replicator (slurpd)";
#endif

#ifdef HAVE_NT_SERVICE_MANAGER
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv )
#else
int main( int argc, char **argv )
#endif
{
#ifdef NO_THREADS
    /* Haven't yet written the non-threaded version */
    fputs( "slurpd currently requires threads support\n", stderr );
    return( 1 );
#else

    int			i, rc = 0;

    /* initialize thread package */
    ldap_pvt_thread_initialize();

    /* 
     * Create and initialize globals.  init_globals() also initializes
     * the main replication queue.
     */
    if (( sglob = init_globals()) == NULL ) {
	fprintf( stderr, "Out of memory initializing globals\n" );
	SERVICE_EXIT( ERROR_NOT_ENOUGH_MEMORY, 0 );
	rc = 1;
	goto stop;
    }

#ifdef HAVE_NT_SERVICE_MANAGER
	{
		int *i;
		char *newConfigFile;
		char *regService = NULL;

		if ( is_NT_Service ) {
			sglob->serverName = argv[0];
			lutil_CommenceStartupProcessing( sglob->serverName, slurp_set_shutdown );
			if ( strcmp(sglob->serverName, SERVICE_NAME) )
			    regService = sglob->serverName;
		}

		i = (int*)lutil_getRegParam( regService, "DebugLevel" );
		if ( i != NULL ) 
		{
			ldap_debug = *i;
			Debug( LDAP_DEBUG_ANY, "new debug level from registry is: %d\n", ldap_debug, 0, 0 );
		}

		newConfigFile = (char*)lutil_getRegParam( regService, "ConfigFile" );
		if ( newConfigFile != NULL ) 
		{
			sglob->slapd_configfile = newConfigFile;
			Debug ( LDAP_DEBUG_ANY, "new config file from registry is: %s\n", sglob->slapd_configfile, 0, 0 );

		}
	}
#endif

    /*
     * Process command-line args and fill in globals.
     */
    if ( doargs( argc, argv, sglob ) < 0 ) {
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 15 );
	rc = 1;
	goto stop;
    }

    if ( sglob->version ) {
		fprintf(stderr, "%s\n", Versionstr);
		if (sglob->version > 1 ) {
			rc = 1;
			goto stop;
		}
    }

	Debug ( LDAP_DEBUG_ANY, "%s\n", Versionstr, 0, 0 );
    
    /*
     * Read slapd config file and initialize Re (per-replica) structs.
     */
    if ( slurpd_read_config( sglob->slapd_configfile ) < 0 ) {
	fprintf( stderr,
		"Errors encountered while processing config file \"%s\"\n",
		sglob->slapd_configfile );
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 19 );
	rc = 1;
	goto stop;
    }

#ifdef HAVE_TLS
	if( ldap_pvt_tls_init() || ldap_pvt_tls_init_def_ctx( 0 ) ) {
		rc = 0;
		/* See if we actually need TLS */
		for ( i=0; i < sglob->num_replicas; i++ ) {
			if ( sglob->replicas[i]->ri_tls || ( sglob->replicas[i]->ri_uri &&
				!strncmp( sglob->replicas[i]->ri_uri, "ldaps:", 6 ))) {
				rc = 1;
				break;
			}
		}
		if ( rc ) {
			fprintf( stderr, "TLS Initialization failed.\n" );
			SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 20 );
			goto stop;
		}
	}
#endif

    /* 
     * Make sure our directory exists
     */
    if ( mkdir(sglob->slurpd_rdir, 0755) == -1 && errno != EEXIST) {
	perror(sglob->slurpd_rdir);
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 16 );
	rc = 1;
	goto stop;
    }

    /*
     * Get any saved state information off the disk.
     */
    if ( sglob->st->st_read( sglob->st )) {
	fprintf( stderr, "Malformed slurpd status file \"%s\"\n",
		sglob->slurpd_status_file );
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 17 );
	rc = 1;
	goto stop;
    }

    /*
     * All readonly data should now be initialized. 
     * Check for any fatal error conditions before we get started
     */
     if ( sanity() < 0 ) {
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 18 );
	rc = 1;
	goto stop;
    }


    /*
     * Detach from the controlling terminal
     * unless the -d flag is given or in one-shot mode.
     */
#ifndef HAVE_WINSOCK
	if ( ! (sglob->no_detach || sglob->one_shot_mode) ) {
		lutil_detach( 0, 0 );
	}
#endif

	/*
	 * don't open pid/args file in one-shot mode (ITS#4152)
	 *
	 * bail out if files were specified but cannot be opened (ITS#4074)
	 */
	if ( !sglob->one_shot_mode) {
		if ( slurpd_pid_file != NULL ) {
			FILE *fp = fopen( slurpd_pid_file, "w" );

			if ( fp == NULL ) {
				int save_errno = errno;

				fprintf( stderr, "unable to open pid file "
					"\"%s\": %d (%s)\n",
					slurpd_pid_file,
					save_errno, strerror( save_errno ) );

				free( slurpd_pid_file );
				slurpd_pid_file = NULL;

				rc = 1;
				goto stop;
			}

			fprintf( fp, "%d\n", (int) getpid() );
			fclose( fp );
		}

		if ( slurpd_args_file != NULL ) {
			FILE *fp = fopen( slurpd_args_file, "w" );

			if ( fp == NULL ) {
				int save_errno = errno;

				fprintf( stderr, "unable to open args file "
					"\"%s\": %d (%s)\n",
					slurpd_args_file,
					save_errno, strerror( save_errno ) );

				free( slurpd_args_file );
				slurpd_pid_file = NULL;

				rc = 1;
				goto stop;
			}

			for ( i = 0; i < argc; i++ ) {
				fprintf( fp, "%s ", argv[i] );
			}
			fprintf( fp, "\n" );
			fclose( fp );
		}
	}

    if ( (rc = lutil_pair( sglob->wake_sds )) < 0 ) {
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 16 );
	rc = 1;
	goto stop;
    }
	
#ifdef HAVE_NT_EVENT_LOG
	if (is_NT_Service) lutil_LogStartedEvent( sglob->serverName, ldap_debug, sglob->slapd_configfile, "n/a" );
#endif

    /*
     * Start the main file manager thread (in fm.c).
     */
    if ( ldap_pvt_thread_create( &(sglob->fm_tid),
		0, fm, (void *) NULL ) != 0 )
	{
	Debug( LDAP_DEBUG_ANY, "file manager ldap_pvt_thread_create failed\n",
		0, 0, 0 );
	SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 21 );
	rc = 1;
	goto stop;

    }

    /*
     * wait for fm to finish if in oneshot mode
     */
    if ( sglob->one_shot_mode ) {
	ldap_pvt_thread_join( sglob->fm_tid, (void *) NULL );
    }

    /*
     * Start threads - one thread for each replica
     */
    for ( i = 0; sglob->replicas[ i ] != NULL; i++ ) {
	start_replica_thread( sglob->replicas[ i ]);
    }

#ifdef HAVE_NT_SERVICE_MANAGER
    if ( started_event ) ldap_pvt_thread_cond_signal( &started_event );
#endif

    /*
     * Wait for the fm thread to finish.
     */
    if ( !sglob->one_shot_mode ) {
	ldap_pvt_thread_join( sglob->fm_tid, (void *) NULL );
    }

    /*
     * Wait for the replica threads to finish.
     */
    for ( i = 0; sglob->replicas[ i ] != NULL; i++ ) {
	ldap_pvt_thread_join( sglob->replicas[ i ]->ri_tid, (void *) NULL );
    }

stop:
#ifdef HAVE_NT_SERVICE_MANAGER
	if (is_NT_Service) {
		ldap_pvt_thread_cond_destroy( &started_event );
		lutil_LogStoppedEvent( sglob->serverName );
		lutil_ReportShutdownComplete();
	}
#endif
    /* destroy the thread package */
    ldap_pvt_thread_destroy();

#ifdef HAVE_TLS
    ldap_pvt_tls_destroy();
#endif

    Debug( LDAP_DEBUG_ANY, "slurpd: terminated.\n", 0, 0, 0 );

    if ( slurpd_pid_file != NULL ) {
	unlink( slurpd_pid_file );
    }
    if ( slurpd_args_file != NULL ) {
	unlink( slurpd_args_file );
    }


	MAIN_RETURN(rc);
#endif /* !NO_THREADS */
}
