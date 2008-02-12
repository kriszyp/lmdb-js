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
 * (as part of U-MICH LDAP).
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
static Globals glob;

int ldap_syslog = 0;
#ifdef LOG_DEBUG
int ldap_syslog_level = LOG_DEBUG;
#else
int ldap_syslog_level = 0;
#endif
int ldap_debug = 0;

/*
 * Initialize the globals
 */
Globals *
init_globals( void )
{
    Globals *g;

    g = &glob;

	g->wake_sds[0] = -1;
	g->wake_sds[1] = -1;

#ifdef HAVE_NT_SERVICE_MANAGER
    g->slapd_configfile = ".\\slapd.conf";
    g->slurpd_rdir = ".\\replica";
#else
    g->slapd_configfile = SLAPD_DEFAULT_CONFIGFILE;
    g->slurpd_rdir = DEFAULT_SLURPD_REPLICA_DIR "/replica";
#endif

    g->no_work_interval = DEFAULT_NO_WORK_INTERVAL;
    g->slurpd_shutdown = 0;
    g->num_replicas = 0;
    g->replicas = NULL;
    g->slapd_replogfile[ 0 ] = '\0';
    g->slurpd_replogfile[ 0 ] = '\0';
    g->slurpd_status_file[ 0 ] = '\0';
    g->one_shot_mode = 0;
    g->no_detach = 0;
    g->myname = NULL;
    g->serverName = NULL;
    g->srpos = 0L;
    g->version = 0;
    if ( St_init( &(g->st)) < 0 ) {
	fprintf( stderr, "Cannot initialize status data\n" );
	exit( EXIT_FAILURE );
    }
    ldap_pvt_thread_mutex_init( &(g->rej_mutex) );
    if ( Rq_init( &(g->rq)) < 0 ) {
	fprintf( stderr, "Cannot initialize queue\n" );
	exit( EXIT_FAILURE );
    }
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
    g->default_srvtab = SRVTAB;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND */

    return g;
}
