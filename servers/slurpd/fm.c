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
 * fm.c - file management routines.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/signal.h>

#include "slurp.h"
#include "globals.h"


/*
 * Externs
 */
extern RETSIGTYPE do_admin LDAP_P((int));
extern int file_nonempty LDAP_P(( char * ));
extern int acquire_lock LDAP_P((char *, FILE **, FILE ** ));
extern int relinquish_lock LDAP_P((char *, FILE *, FILE * ));

/*
 * Forward references
 */
static char *get_record LDAP_P(( FILE * ));
static void populate_queue LDAP_P(( char *f ));
static RETSIGTYPE set_shutdown LDAP_P((int));
RETSIGTYPE do_nothing LDAP_P((int));


/*
 * Main file manager routine.  Watches for new data to be appended to the
 * slapd replication log.  When new data is appended, fm does the following:
 *  - appends the data to slurpd's private copy of the replication log.
 *  - truncates the slapd replog
 *  - adds items to the internal queue of replication work to do
 *  - signals the replication threads to let them know new work has arrived.
 */
void
fm(
    void *arg
)
{
    int rc;

    /* Set up our signal handlers:
     * SIG{TERM,INT,HUP} causes a shutdown
     * SIG(STKFLT|USR1) - does nothing, used to wake up sleeping threads.
     * SIG(UNUSED|USR2) - causes slurpd to read its administrative interface file.
     *           (not yet implemented).
     */
#ifdef HAVE_LINUX_THREADS
    (void) SIGNAL( SIGSTKFLT, do_nothing );
    (void) SIGNAL( SIGUNUSED, do_admin );
#else
    (void) SIGNAL( SIGUSR1, do_nothing );
    (void) SIGNAL( SIGUSR2, do_admin );
#endif
    (void) SIGNAL( SIGTERM, set_shutdown );
    (void) SIGNAL( SIGINT, set_shutdown );
    (void) SIGNAL( SIGHUP, set_shutdown );

    if ( sglob->one_shot_mode ) {
	if ( file_nonempty( sglob->slapd_replogfile )) {
	    populate_queue( sglob->slapd_replogfile );
	}
	printf( "Processing in one-shot mode:\n" );
	printf( "%d total replication records in file,\n",
		sglob->rq->rq_getcount( sglob->rq, RQ_COUNT_ALL ));
	printf( "%d replication records to process.\n",
		sglob->rq->rq_getcount( sglob->rq, RQ_COUNT_NZRC ));
	return;
    }
    /*
     * There may be some leftover replication records in our own
     * copy of the replication log.  If any exist, add them to the
     * queue.
     */
    if ( file_nonempty( sglob->slurpd_replogfile )) {
	populate_queue( sglob->slurpd_replogfile );
    }


    while ( !sglob->slurpd_shutdown ) {
	if ( file_nonempty( sglob->slapd_replogfile )) {
	    /* New work found - copy to slurpd replog file */
	    Debug( LDAP_DEBUG_ARGS, "new work in %s\n",
		    sglob->slapd_replogfile, 0, 0 );
	    if (( rc = copy_replog( sglob->slapd_replogfile,
		    sglob->slurpd_replogfile )) == 0 )  {
		populate_queue( sglob->slurpd_replogfile );
	    } else {
		if ( rc < 0 ) {
		    Debug( LDAP_DEBUG_ANY,
			    "Fatal error while copying replication log\n",
			    0, 0, 0 );
		    sglob->slurpd_shutdown = 1;
		}
	    }
	} else {
	    tsleep( sglob->no_work_interval );
	}

	/* Garbage-collect queue */
	sglob->rq->rq_gc( sglob->rq );

	/* Trim replication log file, if needed */
	if ( sglob->rq->rq_needtrim( sglob->rq )) {
	    FILE *fp, *lfp;
	    if (( rc = acquire_lock( sglob->slurpd_replogfile, &fp,
		    &lfp )) < 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: cannot acquire lock on \"%s\" for trimming\n",
			sglob->slurpd_replogfile, 0, 0 );
	    } else {
		sglob->rq->rq_write( sglob->rq, fp );
		(void) relinquish_lock( sglob->slurpd_replogfile, fp, lfp );
	    }
	}
    }
    Debug( LDAP_DEBUG_ARGS, "fm: exiting\n", 0, 0, 0 );
}




/*
 * Set a global flag which signals that we're shutting down.
 */
static RETSIGTYPE
set_shutdown(int x)
{
    int	i;

    sglob->slurpd_shutdown = 1;				/* set flag */
#ifdef HAVE_LINUX_THREADS
    pthread_kill( sglob->fm_tid, SIGSTKFLT );	/* wake up file mgr */
#else
    pthread_kill( sglob->fm_tid, SIGUSR1 );		/* wake up file mgr */
#endif
    sglob->rq->rq_lock( sglob->rq );			/* lock queue */
    pthread_cond_broadcast( &(sglob->rq->rq_more) );	/* wake repl threads */
    for ( i = 0; i < sglob->num_replicas; i++ ) {
	(sglob->replicas[ i ])->ri_wake( sglob->replicas[ i ]);
    }
    sglob->rq->rq_unlock( sglob->rq );			/* unlock queue */
    (void) SIGNAL( SIGTERM, set_shutdown );	/* reinstall handlers */
    (void) SIGNAL( SIGINT, set_shutdown );
    (void) SIGNAL( SIGHUP, set_shutdown );
}




/*
 * A do-nothing signal handler.
 */
RETSIGTYPE
do_nothing(int i)
{
#ifdef HAVE_LINUX_THREADS
    (void) SIGNAL( SIGSTKFLT, do_nothing );
#else
    (void) SIGNAL( SIGUSR1, do_nothing );
#endif
}




/*
 * Open the slurpd replication log, seek to our last known position, and
 * process any pending replication entries.
 */
static void
populate_queue(
    char *f
)
{
    FILE	*fp, *lfp;
    Rq		*rq = sglob->rq;
    char	*p;

    if ( acquire_lock( f, &fp, &lfp ) < 0 ) {
	Debug( LDAP_DEBUG_ANY,
		"error: can't lock file \"%s\": %s\n",
		f, sys_errlist[ errno ], 0 );
	return;
    }

    /*
     * Read replication records from fp and append them the
     * the queue.
     */
    if ( fseek( fp, sglob->srpos, 0 ) < 0 ) {
	Debug( LDAP_DEBUG_ANY,
		"error: can't seek to offset %ld in file \"%s\"\n",
		sglob->srpos, f, 0 );
    } else {
    while (( p = get_record( fp )) != NULL ) {
	if ( sglob->rq->rq_add( sglob->rq, p ) < 0 ) {
	    char *t;
	    /* Print an error message.  Only print first line.  */
	    if (( t = strchr( p, '\n' )) != NULL ) {
		*t = '\0';
	    }
	    Debug( LDAP_DEBUG_ANY,
		    "error: malformed replog entry (begins with \"%s\")\n",
		    p, 0, 0 );
	}
	free( p );
	pthread_yield();
    }
    sglob->srpos = ftell( fp );
    }
    (void) relinquish_lock( f, fp, lfp );
}
    



/*
 * Get the next "record" from the file pointed to by fp.  A "record"
 * is delimited by two consecutive newlines.  Returns NULL on EOF.
 */
static char *
get_record(
    FILE *fp
)
{
    int		len;
    static char	line[BUFSIZ];
    char	*buf = NULL;
    static int	lcur, lmax;

    lcur = lmax = 0;

    while (( fgets( line, sizeof(line), fp ) != NULL ) &&
	    (( len = strlen( line )) > 1 )) {
	while ( lcur + len + 1 > lmax ) {
	    lmax += BUFSIZ;
	    buf = (char *) ch_realloc( buf, lmax );
	}
	strcpy( buf + lcur, line );
	lcur += len;
    }
    return( buf );
}

