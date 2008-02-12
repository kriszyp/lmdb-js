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
 * sanity.c - perform sanity checks on the environment at startup time,
 * and report any errors before we disassociate from the controlling tty,
 * start up our threads, and do other stuff which makes it hard to give
 * feedback to the users.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/unistd.h>
#include <ac/string.h>

#include "slurp.h"
#include "globals.h"

#define FC_DIRBAD	1
#define FC_DIRUNREAD	2
#define FC_DIRUNWRITE	4
#define FC_FILEBAD	8
#define FC_FILEUNREAD	16
#define FC_FILEUNWRITE	32


/*
 * Forward declarations
 */
static unsigned int filecheck LDAP_P(( char * ));



/*
 * Take a look around to catch any fatal errors.  For example, make sure the
 * destination directory for our working files exists, check that all
 * pathnames make sense, and so on.  Returns 0 is everything's ok,
 # -1 if there's something wrong which will keep us from functioning
 * correctly.
 *
 * We do all these checks at startup so we can print a reasonable error
 * message on stderr before we disassociate from the controlling tty.  This
 * keeps some fatal error messages from "disappearing" into syslog.
 */

int
sanity( void )
{
    int	err = 0;
    int rc;

    /*
     * Are there any replicas listed in the slapd config file?
     */
    if ( sglob->replicas == NULL ) {
	fprintf( stderr, "No replicas in slapd.conf file \"%s\"!\n",
	    sglob->slapd_configfile );
	err++;
    }

    /*
     * Make sure the directory housing the slapd replogfile exists, and
     * that the slapd replogfile is readable, if it exists.
     */
    if ( sglob->slapd_replogfile == NULL ) {
	fprintf( stderr, "Fatal error: no \"replogfile\" "
		"slapd.conf directive given\n" );
	err++;
    } else {
	rc = filecheck( sglob->slapd_replogfile );
	if ( rc & FC_DIRBAD ) {
	    fprintf( stderr, "Error: %s: directory specified in "
			"\"replogfile\" slapd.conf directive does not exist\n", 
		    sglob->slapd_replogfile );
	    err++;
	} else if ( rc & FC_DIRUNREAD ) {
	    fprintf( stderr, "Error: %s: directory specified in "
			"\"replogfile\" slapd.conf directive is not readable\n", 
		    sglob->slapd_replogfile );
	    err++;
	} else if (!( rc & FC_FILEBAD) && ( rc & FC_FILEUNREAD )) {
	    fprintf( stderr, "Error: %s: file specified in "
			"\"replogfile\" slapd.conf directive is not readable\n", 
		    sglob->slapd_replogfile );
	    err++;
	}
    }

    /*
     * Make sure the directory for the slurpd replogfile is there, and
     * that the slurpd replogfile is readable and writable, if it exists.
     */
    if ( sglob->slurpd_replogfile == NULL ) {
	fprintf( stderr, "Fatal error: no \"replogfile\" directive given\n" );
	err++;
    } else {
	rc = filecheck( sglob->slurpd_replogfile );
	if ( rc & FC_DIRBAD ) {
	    fprintf( stderr, "Error: %s: slurpd \"replogfile\" "
			"directory does not exist\n", 
		    sglob->slurpd_replogfile );
	    err++;
	} else if ( rc & FC_DIRUNREAD ) {
	    fprintf( stderr, "Error: %s: slurpd \"replogfile\" "
			"directory not readable\n", 
		    sglob->slurpd_replogfile );
	    err++;
	} else if ( !( rc & FC_FILEBAD ) && ( rc & FC_FILEUNREAD )) {
	    fprintf( stderr, "Error: %s: slurpd \"replogfile\" not readable\n", 
		    sglob->slurpd_replogfile );
	    err++;
	} else if ( !( rc & FC_FILEBAD ) && ( rc & FC_FILEUNWRITE )) {
	    fprintf( stderr, "Error: %s: slurpd \"replogfile\" not writeable\n", 
		    sglob->slurpd_replogfile );
	    err++;
	}
    }

    /*
     * Make sure that the directory for the slurpd status file is there, and
     * that the slurpd status file is writable, if it exists.
     */
    rc = filecheck( sglob->slurpd_status_file );
    if ( rc & FC_DIRBAD ) {
	fprintf( stderr, "Error: %s: status directory does not exist\n", 
		sglob->slurpd_status_file );
	err++;
    } else if ( rc & FC_DIRUNREAD ) {
	fprintf( stderr, "Error: %s: status directory not readable\n", 
		sglob->slurpd_status_file );
	err++;
    } else if ( !( rc & FC_FILEBAD ) && ( rc & FC_FILEUNREAD )) {
	fprintf( stderr, "Error: %s: status file not readable\n", 
		sglob->slurpd_status_file );
	err++;
    } else if ( !( rc & FC_FILEBAD ) && ( rc & FC_FILEUNWRITE )) {
	fprintf( stderr, "Error: %s: status file not writeable\n", 
		sglob->slurpd_status_file );
	err++;
    }
    
    return ( err == 0 ? 0 : -1 );
}



/*
 * Check for the existence of the file and directory leading to the file.
 * Returns a bitmask which is the logical OR of the following flags:
 *
 *  FC_DIRBAD:		directory containing "f" does not exist.
 *  FC_DIRUNREAD:	directory containing "f" exists but is not readable.
 *  FC_DIRUNWRITE:	directory containing "f" exists but is not writable.
 *  FC_FILEBAD:		"f" does not exist.
 *  FC_FILEUNREAD:	"f" exists but is unreadable.
 *  FC_FILEUNWRITE:	"f" exists but is unwritable.
 *
 * The calling routine is responsible for determining which, if any, of
 * the returned flags is a problem for a particular file.
 */
static unsigned int
filecheck(
    char	*f
)
{
    char		dir[ MAXPATHLEN ];
    char		*p;
    unsigned int	ret = 0;

	snprintf( dir, sizeof dir, "%s", f );
    p = strrchr( dir, LDAP_DIRSEP[0] );
    if ( p != NULL ) {
	*p = '\0';
    }
    if ( access( dir, F_OK ) < 0 ) {
	ret |= FC_DIRBAD;
    }
    if ( access( dir, R_OK ) < 0 ) {
	ret |= FC_DIRUNREAD;
    }
    if ( access( dir, W_OK ) < 0 ) {
	ret |= FC_DIRUNWRITE;
    }
    if ( access( f, F_OK ) < 0 ) {
	ret |= FC_FILEBAD;
    }
    if ( access( f, R_OK ) < 0 ) {
	ret |= FC_FILEUNREAD;
    }
    if ( access( f, W_OK ) < 0 ) {
	ret |= FC_FILEUNWRITE;
    }

    return ret;
}
