/* $OpenLDAP$ */
/*
 * help.c: for rcpt500 (X.500 email query responder)
 *
 * 16 June 1992 by Mark C Smith
 * Copyright (c) 1992 The Regents of The University of Michigan
 * All Rights Reserved
 */

#include "portable.h"

#include <stdio.h>

#include <ac/syslog.h>
#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "ldap_defaults.h"
#include "rcpt500.h"


int
help_cmd(struct msginfo *msgp, char *reply)
{
    int		fd, len;

    if (( fd = open( RCPT500_HELPFILE, O_RDONLY )) == -1 ) {
	if ( dosyslog ) {
	    syslog( LOG_ERR, "open help file: %m" );
	}
	strcat( reply, "Unable to access the help file.  Sorry!\n" );
	return( 0 );
    }

    len = read( fd, reply + strlen( reply ), MAXSIZE );
    close( fd );

    if ( len == -1 ) {
	if ( dosyslog ) {
	    syslog( LOG_ERR, "read help file: %m" );
	}
	strcat( reply, "Unable to read the help file.  Sorry!\n" );
	return( 0 );
    }

    *(reply + len ) = '\0';
    return( 0 );
}
