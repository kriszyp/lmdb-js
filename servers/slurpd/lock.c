/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
 * lock.c - routines to open and apply an advisory lock to a file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/param.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "slurp.h"


FILE *
lock_fopen(
    const char	*fname,
    const char	*type,
    FILE	**lfp
)
{
	FILE	*fp;
	char	buf[MAXPATHLEN];

	/* open the lock file */
	snprintf( buf, sizeof buf, "%s.lock", fname );

	if ( (*lfp = fopen( buf, "w" )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( SLURPD, ERR, "lock_fopen: "
			"Error: could not open \"%s\"\n", buf, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"Error: could not open \"%s\"\n", buf, 0, 0 );
#endif
		return( NULL );
	}

	/* acquire the lock */
	ldap_lockf( fileno(*lfp) );

	/* open the log file */
	if ( (fp = fopen( fname, type )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( SLURPD, ERR, "lock_fopen: "
			"Error: could not open \"%s\"\n", fname, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"Error: could not open \"%s\"\n", fname, 0, 0 );
#endif
		ldap_unlockf( fileno(*lfp) );
		fclose( *lfp );
		*lfp = NULL;
		return( NULL );
	}

	return( fp );
}



int
lock_fclose(
    FILE	*fp,
    FILE	*lfp
)
{
	/* unlock */
	ldap_unlockf( fileno(lfp) );
	fclose( lfp );

	return( fclose( fp ) );
}



/*
 * Apply an advisory lock on a file.  Just calls lock_fopen()
 */
int
acquire_lock(
    const char	*file,
    FILE	**rfp,
    FILE	**lfp
)
{
    if (( *rfp = lock_fopen( file, "r+", lfp )) == NULL ) {
#ifdef NEW_LOGGING
	LDAP_LOG ( SLURPD, ERR, "acquire_lock: "
		"Error: acquire_lock(%ld): Could not acquire lock on \"%s\"\n",
		(long) getpid(), file, 0 );
#else
	Debug( LDAP_DEBUG_ANY,
		"Error: acquire_lock(%ld): Could not acquire lock on \"%s\"\n",
		(long) getpid(), file, 0);
#endif
	return( -1 );
    }
    return( 0 );
}



/*
 * Relinquish a lock on a file.  Calls lock_fclose() and also removes the
 * lock file.
 */
int
relinquish_lock(
    const char	*file,
    FILE	*rfp,
    FILE	*lfp
)
{
    if ( lock_fclose( rfp, lfp ) == EOF ) {
#ifdef NEW_LOGGING
	LDAP_LOG ( SLURPD, ERR, "relinguish_lock: "
		"Error: relinquish_lock (%ld): Error closing \"%s\"\n",
		(long) getpid(), file, 0 );
#else
	Debug( LDAP_DEBUG_ANY,
		"Error: relinquish_lock (%ld): Error closing \"%s\"\n",
		(long) getpid(), file, 0 );
#endif
	return( -1 );
    }
    return( 0 );
}
