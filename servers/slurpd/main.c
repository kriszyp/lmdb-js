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

    /* 
     * Create and initialize globals.  init_globals() also initializes
     * the main replication queue.
     */
    if (( sglob = init_globals()) == NULL ) {
	fprintf( stderr, "Out of memory initializing globals\n" );
	exit( 1 );
    }

    /*
     * Process command-line args and fill in globals.
     */
    if ( doargs( argc, argv, sglob ) < 0 ) {
	exit( 1 );
    }

    /*
     * Read slapd config file and initialize Re (per-replica) structs.
     */
    if ( slurpd_read_config( sglob->slapd_configfile ) < 0 ) {
	fprintf( stderr,
		"Errors encountered while processing config file \"%s\"\n",
		sglob->slapd_configfile );
	exit( 1 );
    }

    /*
     * Get any saved state information off the disk.
     */
    if ( sglob->st->st_read( sglob->st )) {
	fprintf( stderr, "Malformed slurpd status file \"%s\"\n",
		sglob->slurpd_status_file, 0, 0 );
	exit( 1 );
    }

    /*
     * All readonly data should now be initialized. 
     * Check for any fatal error conditions before we get started
     */
     if ( sanity() < 0 ) {
	exit( 1 );
    }

    /*
     * Detach from the controlling terminal, if debug level = 0,
     * and if not in one-shot mode.
     */
#ifdef LDAP_DEBUG
    if (( ldap_debug == 0 )  && !sglob->one_shot_mode )
#else /* LDAP_DEBUG */
    if ( !sglob->one_shot_mode )
#endif /* LDAP_DEBUG */
	lutil_detach( 0, 0 );

	/* initialize thread package */
	ldap_pvt_thread_initialize();

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
	exit( 1 );

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
    Debug( LDAP_DEBUG_ANY, "slurpd: terminating normally\n", 0, 0, 0 );
    sglob->slurpd_shutdown = 1;

	return 0;
#endif /* !NO_THREADS */
}
