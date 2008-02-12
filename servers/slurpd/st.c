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
 * st.c - routines for managing the status structure, and for reading and
 * writing status information to disk.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slurp.h"
#include "globals.h"
#include "lutil.h"

/*
 * Add information about replica host specified by Ri to list
 * of hosts.
 */
static Stel *
St_add(
    St	*st,
    Ri	*ri
)
{
    int	ind;

    if ( st == NULL || ri == NULL ) {
	return NULL;
    }

    /* Serialize access to the St struct */
    ldap_pvt_thread_mutex_lock( &(st->st_mutex ));

    st->st_nreplicas++;
    ind = st->st_nreplicas - 1;
    st->st_data = ( Stel ** ) ch_realloc( st->st_data, 
	    ( st->st_nreplicas * sizeof( Stel * )));
    if ( st->st_data == NULL ) {
	ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
	return NULL;
    }
    st->st_data[ ind ]  = ( Stel * ) ch_malloc( sizeof( Stel ) );
    if ( st->st_data[ ind ] == NULL ) {
	ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
	return NULL;
    }

    st->st_data[ ind ]->hostname = strdup( ri->ri_hostname );
    st->st_data[ ind ]->port = ri->ri_port;
    st->st_data[ ind ]->last = 0; 
    st->st_data[ ind ]->seq = 0;

    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
    return st->st_data[ ind ];
}



/*
 * Write the contents of an St to disk.
 */
static int
St_write (
    St	*st
)
{
    int		rc;
    Stel	*stel;
    int		i;

    if ( st == NULL ) {
	return -1;
    }
    ldap_pvt_thread_mutex_lock( &(st->st_mutex ));
    if ( st->st_fp == NULL ) {
	/* Open file */
	if (( rc = acquire_lock( sglob->slurpd_status_file, &(st->st_fp),
		&(st->st_lfp))) < 0 ) {
	    if ( !st->st_err_logged ) {
		Debug( LDAP_DEBUG_ANY,
			"Error: cannot open status file \"%s\": %s\n",
			sglob->slurpd_status_file, sys_errlist[ errno ], 0 );
		st->st_err_logged = 1;
		ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
		return -1;
	    }
	} else {
	    st->st_err_logged = 0;
	}
    }

    /* Write data to the file */
    truncate( sglob->slurpd_status_file, 0L );
    fseek( st->st_fp, 0L, 0 );
    for ( i = 0; i < st->st_nreplicas; i++ ) {
	stel = st->st_data[ i ];
	fprintf( st->st_fp, "%s:%d:%ld:%d\n",
		stel->hostname, stel->port,
		(long) stel->last, stel->seq );
    }
    fflush( st->st_fp );

    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));

    return 0;
}
    



/*
 * Update the entry for a given host.
 */
static int
St_update(
    St		*st,
    Stel	*stel,
    Re		*re
)
{
    if ( stel == NULL || re == NULL ) {
	return -1;
    }

    ldap_pvt_thread_mutex_lock( &(st->st_mutex ));
    stel->last = re->re_timestamp;
    stel->seq = re->re_seq;
    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
    return 0;
}




/*
 * Read status information from disk file.
 */
static int
St_read(
    St	*st
)
{
    FILE	*fp;
    FILE	*lfp;
    char	buf[ 255 ];
    int		i;
    int		rc;
    char	*hostname, *port, *timestamp, *seq, *p, *t;
    int		found;
    long	last;

    if ( st == NULL ) {
	return -1;
    }
    ldap_pvt_thread_mutex_lock( &(st->st_mutex ));
    if ( access( sglob->slurpd_status_file, F_OK ) < 0 ) {
	/*
	 * File doesn't exist, so create it and return.
	 */
	if (( fp = fopen( sglob->slurpd_status_file, "w" )) == NULL ) {
	    Debug( LDAP_DEBUG_ANY, "Error: cannot create status file \"%s\"\n",
		    sglob->slurpd_status_file, 0, 0 );
	    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
	    return -1;
	}
	(void) fclose( fp );
	ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
	Debug( LDAP_DEBUG_ARGS, "No status file found, defaulting values\n",
		0, 0, 0 );
	return 0;
    }
    if (( rc = acquire_lock( sglob->slurpd_status_file, &fp, &lfp)) < 0 ) {
	ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
	return 0;
    }
    while ( fgets( buf, sizeof( buf ), fp ) != NULL ) {
	p = buf;
	hostname = p;
	if (( t = strchr( p, ':' )) == NULL ) {
	    goto bad;
	}
	*t++ = '\0';
	p = t;
	port = p;
	if (( t = strchr( p, ':' )) == NULL ) {
	    goto bad;
	}
	*t++ = '\0';
	p = t;
	timestamp = p;
	if (( t = strchr( p, ':' )) == NULL ) {
	    goto bad;
	}
	*t++ = '\0';
	seq = t;
	if (( t = strchr( seq, '\n' )) != NULL ) {
	    *t = '\0';
	}

	found = 0;
	for ( i = 0; i < sglob->st->st_nreplicas; i++ ) {
	    int p;
	    if ( !strcmp( hostname, sglob->st->st_data[ i ]->hostname ) &&
		    lutil_atoi( &p, port ) == 0 && p == sglob->st->st_data[ i ]->port )
	    {
		found = (lutil_atol( &last, timestamp ) == 0);
		if ( found ) {
		    sglob->st->st_data[i]->last = last;
		    if ( lutil_atoi( &sglob->st->st_data[i]->seq, seq ) != 0 )
		        found = 0;
		}
		break;
	    }
	}
	if ( found ) {
	    char tbuf[ 255 ];
	    sprintf( tbuf, "%s.%s", timestamp, seq );
	    Debug( LDAP_DEBUG_ARGS,
		    "Retrieved state information for %s:%s (timestamp %s)\n", hostname, port, tbuf );
	} else {
	    Debug(  LDAP_DEBUG_ANY,
		    "Warning: saved state for %s:%s, not a known replica\n",
		    hostname, port, 0 );
	}
    }
    (void) relinquish_lock( sglob->slurpd_status_file, fp, lfp);
    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
    return 0;

bad:
    (void) relinquish_lock( sglob->slurpd_status_file, fp, lfp);
    ldap_pvt_thread_mutex_unlock( &(st->st_mutex ));
    return -1;
}
    



/*
 * Lock an St struct.
 */
static int
St_lock(
    St *st
)
{
    return( ldap_pvt_thread_mutex_lock( &st->st_mutex ));
}




/*
 * Lock an St struct.
 */
static int
St_unlock(
    St *st
)
{
    return( ldap_pvt_thread_mutex_unlock( &st->st_mutex ));
}




/*
 * Allocate and initialize an St struct.
 */
int
St_init(
    St **st
)
{
    if ( st == NULL ) {
	return -1;
    }

    (*st) = (St *) malloc( sizeof( St ));
    if ( *st == NULL ) {
	return -1;
    }

    ldap_pvt_thread_mutex_init( &((*st)->st_mutex) );
    (*st)->st_data = NULL;
    (*st)->st_fp = NULL;
    (*st)->st_lfp = NULL;
    (*st)->st_nreplicas = 0;
    (*st)->st_err_logged = 0;
    (*st)->st_update = St_update;
    (*st)->st_add = St_add;
    (*st)->st_write = St_write;
    (*st)->st_read = St_read;
    (*st)->st_lock = St_lock;
    (*st)->st_unlock = St_unlock;
    return 0;
}

