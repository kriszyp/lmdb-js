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
 * args.c - process command-line arguments, and set appropriate globals.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap.h>
#include <lutil.h>

#include "slurp.h"
#include "globals.h"


static void
usage( char *name )
{
    fprintf( stderr, "usage: %s\t[-d debug-level] [-s syslog-level]\n", name );
    fprintf( stderr, "\t\t[-f slapd-config-file] [-r replication-log-file]\n" );
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
    fprintf( stderr, "\t\t[-t tmp-dir] [-o] [-k srvtab-file]\n" );
#else /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND */
    fprintf( stderr, "\t\t[-t tmp-dir] [-o]\n" );
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND */
    fprintf( stderr, "\t\t[-n service-name]\n" );
}



/*
 * Interpret argv, and fill in any appropriate globals.
 */
int
doargs(
    int		argc,
    char	**argv,
    Globals	*g
)
{
    int		i;
    int		rflag = 0;

    g->myname = strdup( lutil_progname( "slurpd", argc, argv ));

    while ( (i = getopt( argc, argv, "d:f:n:or:t:V" )) != EOF ) {
	switch ( i ) {
	case 'd': {	/* set debug level and 'do not detach' flag */
	    int level;
	    g->no_detach = 1;
	    if ( optarg[0] == '?' ) {
#ifdef LDAP_DEBUG
		printf( "Debug levels:\n" );
		printf( "\tLDAP_DEBUG_TRACE\t%d\n",
			LDAP_DEBUG_TRACE );
		printf( "\tLDAP_DEBUG_PACKETS\t%d\n",
			LDAP_DEBUG_PACKETS );
		printf( "\tLDAP_DEBUG_ARGS\t\t%d\n",
			LDAP_DEBUG_ARGS );
		printf( "\tLDAP_DEBUG_CONNS\t%d\n",
			LDAP_DEBUG_CONNS );
		printf( "\tLDAP_DEBUG_BER\t\t%d\n",
			LDAP_DEBUG_BER );
		printf( "\tLDAP_DEBUG_FILTER\t%d\n",
			LDAP_DEBUG_FILTER );
		printf( "\tLDAP_DEBUG_CONFIG\t%d\n",
			LDAP_DEBUG_CONFIG );
		printf( "\tLDAP_DEBUG_ACL\t\t%d\n",
			LDAP_DEBUG_ACL );
		printf( "\tLDAP_DEBUG_ANY\t\t%d\n",
			LDAP_DEBUG_ANY );
		puts( "\tThe -d flag also prevents slurpd from detaching." );
#endif /* LDAP_DEBUG */
		puts( "\tDebugging is disabled.  -d 0 prevents slurpd from detaching." );
		return( -1 );
	    }
#ifdef LDAP_DEBUG
	    if ( lutil_atoi( &level, optarg ) != 0 ) {
		fprintf( stderr, "unable to parse debug flag \"%s\".\n", optarg );
		usage( g->myname );
		return( -1 );
	    }
	    ldap_debug |= level;
#else /* !LDAP_DEBUG */
	    if ( lutil_atoi( &level, optarg ) != 0 || level != 0 )
		/* can't enable debugging - not built with debug code */
		fputs( "must compile with LDAP_DEBUG for debugging\n",
		       stderr );
#endif /* LDAP_DEBUG */
	    } break;
	case 'f':	/* slapd config file */
	    LUTIL_SLASHPATH( optarg );
	    g->slapd_configfile = strdup( optarg );
	    break;
	case 'n':	/* NT service name */
	    if ( g->serverName ) free( g->serverName );
	    g->serverName = strdup( optarg );
	    break;
	case 'o':
	    g->one_shot_mode = 1;
	    break;
	case 'r':	/* slapd replog file */
	    LUTIL_SLASHPATH( optarg );
		snprintf( g->slapd_replogfile, sizeof g->slapd_replogfile,
			"%s", optarg );
	    rflag++;
	    break;
	case 't': {	/* dir to use for our copies of replogs */
		size_t sz;
	    LUTIL_SLASHPATH( optarg );
	    g->slurpd_rdir = (char *)malloc (sz = (strlen(optarg) + sizeof(LDAP_DIRSEP "replica")));
	    snprintf(g->slurpd_rdir, sz,
			"%s" LDAP_DIRSEP "replica", optarg);
	    } break;
	case 'V':
	    (g->version)++;
	    break;
	default:
	    usage( g->myname );
	    return( -1 );
	}
    }

    if ( g->one_shot_mode && !rflag ) {
	fprintf( stderr, "If -o flag is given, -r flag must also be given.\n" );
	usage( g->myname );
	return( -1 );
    }

    /* Set location/name of our private copy of the slapd replog file */
    snprintf( g->slurpd_replogfile, sizeof g->slurpd_replogfile,
		"%s" LDAP_DIRSEP "%s", g->slurpd_rdir,
	    DEFAULT_SLURPD_REPLOGFILE );

    /* Set location/name of the slurpd status file */
    snprintf( g->slurpd_status_file, sizeof g->slurpd_status_file,
		"%s" LDAP_DIRSEP "%s", g->slurpd_rdir,
	    DEFAULT_SLURPD_STATUS_FILE );

	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldap_debug);
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldap_debug);
	ldif_debug = ldap_debug;

#ifdef LOG_LOCAL4
    openlog( g->myname, OPENLOG_OPTIONS, LOG_LOCAL4 );
#elif LOG_DEBUG
    openlog( g->myname, OPENLOG_OPTIONS );
#endif

    return 0;
}
