/* $OpenLDAP$ */
/*
 * Copyright (c) 1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */


/* 
 * main.c - main routine for slurpd.
 */

#include "portable.h"

#include <ac/stdlib.h>

#include <stdio.h>

#include "slurp.h"
#include "globals.h"
#include "lutil.h"


int
main(
    int		argc,
    char	**argv
)
{
#ifdef NO_THREADS
    /* Haven't yet written the non-threaded version */
    fputs( "slurpd currently requires threads support\n", stderr );
    return( 1 );
#else

    int			i;

    /* initialize thread package */
    ldap_pvt_thread_initialize();

    /* 
     * Create and initialize globals.  init_globals() also initializes
     * the main replication queue.
     */
    if (( sglob = init_globals()) == NULL ) {
	fprintf( stderr, "Out of memory initializing globals\n" );
	exit( EXIT_FAILURE );
    }

    /*
     * Process command-line args and fill in globals.
     */
    if ( doargs( argc, argv, sglob ) < 0 ) {
	exit( EXIT_FAILURE );
    }

    /*
     * Read slapd config file and initialize Re (per-replica) structs.
     */
    if ( slurpd_read_config( sglob->slapd_configfile ) < 0 ) {
	fprintf( stderr,
		"Errors encountered while processing config file \"%s\"\n",
		sglob->slapd_configfile );
	exit( EXIT_FAILURE );
    }

    /* 
     * Make sure our directory exists
     */
    if ( mkdir(sglob->slurpd_rdir, 0755) == -1 && errno != EEXIST) {
	perror(sglob->slurpd_rdir);
	exit( 1 );
    }

    /*
     * Get any saved state information off the disk.
     */
    if ( sglob->st->st_read( sglob->st )) {
	fprintf( stderr, "Malformed slurpd status file \"%s\"\n",
		sglob->slurpd_status_file, 0, 0 );
	exit( EXIT_FAILURE );
    }

    /*
     * All readonly data should now be initialized. 
     * Check for any fatal error conditions before we get started
     */
     if ( sanity() < 0 ) {
	exit( EXIT_FAILURE );
    }

    /*
     * Detach from the controlling terminal
     * unless the -d flag is given or in one-shot mode.
     */
    if ( ! (sglob->no_detach || sglob->one_shot_mode) )
	lutil_detach( 0, 0 );

    /*
     * Start threads - one thread for each replica
     */
    for ( i = 0; sglob->replicas[ i ] != NULL; i++ ) {
	start_replica_thread( sglob->replicas[ i ]);
    }

    /*
     * Start the main file manager thread (in fm.c).
     */
    if ( ldap_pvt_thread_create( &(sglob->fm_tid),
		0, fm, (void *) NULL ) != 0 )
	{
	Debug( LDAP_DEBUG_ANY, "file manager ldap_pvt_thread_create failed\n",
		0, 0, 0 );
	exit( EXIT_FAILURE );

    }

    /*
     * Wait for the fm thread to finish.
     */
    ldap_pvt_thread_join( sglob->fm_tid, (void *) NULL );

    /*
     * Wait for the replica threads to finish.
     */
    for ( i = 0; sglob->replicas[ i ] != NULL; i++ ) {
	ldap_pvt_thread_join( sglob->replicas[ i ]->ri_tid, (void *) NULL );
    }

	/* destroy the thread package */
	ldap_pvt_thread_destroy();

    Debug( LDAP_DEBUG_ANY, "slurpd: terminated.\n", 0, 0, 0 );
	return 0;
#endif /* !NO_THREADS */
}
