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
 * globals.c - initialization code for global data
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>

#include "slurp.h"
#include "globals.h"

Globals		 *sglob;

int ldap_syslog = 0;
int ldap_syslog_level = LOG_DEBUG;
int ldap_debug = 0;


/*
 * Initialize the globals
 */
Globals *
init_globals( void )
{
    Globals *g;

    g = ( Globals * ) malloc( sizeof( Globals ));
    if ( g == NULL ) {
	return NULL;
    }

    g->slapd_configfile = SLAPD_DEFAULT_CONFIGFILE;
    g->no_work_interval = DEFAULT_NO_WORK_INTERVAL;
    g->slurpd_shutdown = 0;
    g->num_replicas = 0;
    g->replicas = NULL;
    g->slurpd_rdir = DEFAULT_SLURPD_REPLICA_DIR;
    strcpy( g->slurpd_status_file, DEFAULT_SLURPD_STATUS_FILE );
    g->slapd_replogfile[ 0 ] = '\0';
    g->slurpd_replogfile[ 0 ] = '\0';
    g->slurpd_status_file[ 0 ] = '\0';
    g->one_shot_mode = 0;
    g->no_detach = 0;
    g->myname = NULL;
    g->srpos = 0L;
    if ( St_init( &(g->st)) < 0 ) {
	fprintf( stderr, "Cannot initialize status data\n" );
	exit( EXIT_FAILURE );
    }
    ldap_pvt_thread_mutex_init( &(g->rej_mutex) );
    if ( Rq_init( &(g->rq)) < 0 ) {
	fprintf( stderr, "Cannot initialize queue\n" );
	exit( EXIT_FAILURE );
    }
#ifdef HAVE_KERBEROS
    g->default_srvtab = SRVTAB;
#endif /* HAVE_KERBEROS */

    return g;
}
