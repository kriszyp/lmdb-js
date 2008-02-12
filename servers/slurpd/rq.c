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
 * rq.c - routines used to manage the queue of replication entries.
 * An Rq (Replication queue) struct contains a linked list of Re
 * (Replication entry) structures.
 *
 * Routines wishing to access the replication queue should do so through
 * the Rq struct's member functions, e.g. rq->rq_gethead() and friends.
 * For example, Re structs should be added to the queue by calling 
 * the rq_add() member function.
 *
 * Access to the queue is serialized by a mutex.  Member functions which do
 * not do their own locking should only be called after locking the queue
 * using the rq_lock() member function.  The queue should be unlocked with
 * the rq_unlock() member function.
 *
 * Note that some member functions handle their own locking internally.
 * Callers should not lock the queue before calling these functions.
 * See the comment block for each function below.
 *
 */

#include "portable.h"

#include <stdio.h>
#include <sys/stat.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>		/* get ftruncate() */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "slurp.h"
#include "globals.h"

/*
 * Lock the replication queue.
 */
static int
Rq_lock(
    Rq	*rq
)
{
    return( ldap_pvt_thread_mutex_lock( &rq->rq_mutex ));
}


/*
 * Unlock the replication queue.
 */
static int
Rq_unlock(
    Rq	*rq
)
{
    return( ldap_pvt_thread_mutex_unlock( &rq->rq_mutex ));
}



/*
 * Return the head of the queue.  Callers should lock the queue before
 * calling this routine.
 */
static Re *
Rq_gethead(
    Rq	*rq
)
{
    return( rq == NULL ? NULL : rq->rq_head );
}


/*
 * Return the next item in the queue.  Callers should lock the queue before
 * calling this routine.
 */
static Re *
Rq_getnext(
    Re	*re
)
{
    if ( re == NULL ) {
	return NULL;
    } else {
	return( re->re_getnext( re ));
    }
}


/*
 * Delete the item at the head of the list.  The queue should be locked
 * by the caller before calling this routine.
 */
static int
Rq_delhead(
    Rq	*rq
)
{
    Re	*savedhead;
    int	rc;

    if ( rq == NULL ) {
	return( -1 );
    }

    savedhead = rq->rq_head;
    if ( savedhead == NULL ) {
	return( 0 );
    }

    if ( savedhead->re_getrefcnt( savedhead ) != 0 ) {
	Debug( LDAP_DEBUG_ANY, "Warning: attempt to delete when refcnt != 0\n",
		0, 0, 0 );
	return( -1 );
    }

    rq->rq_head = rq->rq_head->re_getnext( rq->rq_head );
    rc = savedhead->re_free( savedhead );
    rq->rq_nre--;	/* decrement count of Re's in queue */
    return( rc );
}


/* 
 * Add an entry to the tail of the replication queue.  Locking is handled
 * internally.  When items are added to the queue, this routine wakes
 * up any threads which are waiting for more work by signaling on the
 * rq->rq_more condition variable.
 */
static int
Rq_add(
    Rq		*rq,
    char	*buf
)
{
    Re	*re;
    int	wasempty = 0;

    /* Lock the queue */
    rq->rq_lock( rq );

    /* Create a new Re */
    if ( Re_init( &re ) < 0 ) {
	rq->rq_unlock( rq );
	return -1;
    }

    /* parse buf and fill in the re struct */
    if ( re->re_parse( re, buf ) < 0 ) {
	re->re_free( re );
	rq->rq_unlock( rq );
	return -1;
    }

    /* Insert into queue */
    if ( rq->rq_head == NULL ) {
	rq->rq_head = re;
	rq->rq_tail = re;
	wasempty = 1;
    } else {
	rq->rq_tail->re_next = re;
    }

    /* set the sequence number */
    re->re_seq = 0;
    if ( !wasempty && ( rq->rq_tail->re_timestamp == re->re_timestamp )) {
	/*
	 * Our new re has the same timestamp as the tail's timestamp.
	 * Increment the seq number in the tail and use it as our seq number.
	 */
	re->re_seq = rq->rq_tail->re_seq + 1;
    }
    rq->rq_tail = re;

    /* Increment count of items in queue */
    rq->rq_nre++;
    /* wake up any threads waiting for more work */
    ldap_pvt_thread_cond_broadcast( &rq->rq_more );

    /* ... and unlock the queue */
    rq->rq_unlock( rq );

    return 0;
}


/*
 * Garbage-collect the replication queue.  Locking is handled internally.
 */
static void
Rq_gc(
    Rq	*rq
)
{
    if ( rq == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Rq_gc: rq is NULL!\n", 0, 0, 0 );
	return;
    }
    rq->rq_lock( rq ); 
    while (( rq->rq_head != NULL ) &&
	    ( rq->rq_head->re_getrefcnt( rq->rq_head ) == 0 )) {
	rq->rq_delhead( rq );
	rq->rq_ndel++;	/* increment count of deleted entries */
    }
    rq->rq_unlock( rq ); 
    return;
}


/*
 * For debugging: dump the contents of the replication queue to a file.
 * Locking is handled internally.
 */
static void
Rq_dump(
    Rq	*rq
)
{
    Re		*re;
    FILE	*fp;
    int		tmpfd;

    if ( rq == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Rq_dump: rq is NULL!\n", 0, 0, 0 );
	return;
    }

    if (unlink(SLURPD_DUMPFILE) == -1 && errno != ENOENT) {
	Debug( LDAP_DEBUG_ANY, "Rq_dump: \"%s\" exists, and cannot unlink\n",
		SLURPD_DUMPFILE, 0, 0 );
	return;
    }
    if (( tmpfd = open(SLURPD_DUMPFILE, O_CREAT|O_RDWR|O_EXCL, 0600)) == -1) {
	Debug( LDAP_DEBUG_ANY, "Rq_dump: cannot open \"%s\" for write\n",
		SLURPD_DUMPFILE, 0, 0 );
	return;
    }
    if (( fp = fdopen( tmpfd, "w" )) == NULL ) {
	Debug( LDAP_DEBUG_ANY, "Rq_dump: cannot fdopen \"%s\" for write\n",
		SLURPD_DUMPFILE, 0, 0 );
	return;
    }

    rq->rq_lock( rq );
    for ( re = rq->rq_gethead( rq ); re != NULL; re = rq->rq_getnext( re )) {
	re->re_dump( re, fp );
    }
    rq->rq_unlock( rq );
    fclose( fp );
    return;
}


/*
 * Write the contents of a replication queue to a file.  Returns zero if
 * successful, -1 if not.  Handles queue locking internally.  Callers should
 * provide an open file pointer, which should refer to a locked file.
 */
static int
Rq_write(
    Rq		*rq,
    FILE 	*fp
)
{
    Re		*re;
    time_t	now;

    if ( rq == NULL ) {
	return -1;
    }

    Debug( LDAP_DEBUG_ARGS, "re-write on-disk replication log\n",
	    0, 0, 0 );
#ifndef SEEK_SET
#define SEEK_SET 0
#endif
    fseek( fp, 0L, SEEK_SET );	/* Go to beginning of file */
    rq->rq_lock( rq );

    for ( re = rq->rq_gethead( rq ); re != NULL; re = rq->rq_getnext( re )) {
	if ( re->re_write( NULL, re, fp ) < 0 ) {
	    fflush( fp );
	    rq->rq_unlock( rq );
	    return -1;
	}
    }
    fflush( fp );
    sglob->srpos = ftell( fp );	/* update replog file position */
    /* and truncate to correct len */
    if ( ftruncate( fileno( fp ), sglob->srpos ) < 0 ) {
	Debug( LDAP_DEBUG_ANY, "Error truncating replication log: %s\n",
		sys_errlist[ errno ], 0, 0 );
    }
    rq->rq_ndel = 0;	/* reset count of deleted re's */
    time( &now );
    rq->rq_lasttrim = now;	/* reset last trim time */
    rq->rq_unlock( rq );
    return 0;
}


/*
 * Check to see if the private slurpd replication log needs trimming.
 * The current criteria are:
 *  - The last trim was more than 5 minutes ago, *and*
 *  - We've finished with at least 50 replication log entries since the
 *    last time we re-wrote the replication log.
 *
 * Return 1 if replogfile should be trimmed, 0 if not.
 * Any different policy should be implemented by replacing this function.
 */
static int
Rq_needtrim(
    Rq	*rq
)
{
    int		rc = 0;
    time_t	now;

    if ( rq == NULL ) {
	return 0;
    }

    rq->rq_lock( rq );

    time( &now );

    if ( now > ( rq->rq_lasttrim + TRIMCHECK_INTERVAL )) {
	rc = ( rq->rq_ndel >= 50 );
    } else {
	rc = 0;
    }
    rq->rq_unlock( rq );
    return rc;
}


/*
 * Return counts of Re structs in the queue.
 */
static int
Rq_getcount(
    Rq	*rq,
    int	type
)
{
    int	count = 0;
    Re	*re;

    if ( rq == NULL ) {
	return 0;
    }

    rq->rq_lock( rq );
    if ( type == RQ_COUNT_ALL ) {
	count = rq->rq_nre;
    } else {
	for ( re = rq->rq_gethead( rq ); re != NULL;
		re = rq->rq_getnext( re )) {
	    if ( type == RQ_COUNT_NZRC ) {
		if ( re->re_getrefcnt( re ) > 0 ) {
		    count++;
		}
	    }
	}
    }
    rq->rq_unlock( rq );
    return count;
}


/* 
 * Allocate and initialize an Rq object.
 */
int
Rq_init(
    Rq	**rq
)
{
    /* Instantiate the struct */
    (*rq) = (Rq *) malloc( sizeof( Rq ));
    if ( *rq == NULL ) {
	return -1;
    }

    /* Fill in all the function pointers */
    (*rq)->rq_gethead = Rq_gethead;
    (*rq)->rq_getnext = Rq_getnext;
    (*rq)->rq_delhead = Rq_delhead;
    (*rq)->rq_add = Rq_add;
    (*rq)->rq_gc = Rq_gc;
    (*rq)->rq_lock = Rq_lock;
    (*rq)->rq_unlock = Rq_unlock;
    (*rq)->rq_dump = Rq_dump;
    (*rq)->rq_needtrim = Rq_needtrim;
    (*rq)->rq_write = Rq_write;
    (*rq)->rq_getcount = Rq_getcount;

    /* Initialize private data */
    ldap_pvt_thread_mutex_init( &((*rq)->rq_mutex) );
    ldap_pvt_thread_cond_init( &((*rq)->rq_more) );
    (*rq)->rq_head = NULL;
    (*rq)->rq_tail = NULL;
    (*rq)->rq_nre = 0;
    (*rq)->rq_ndel = 0;
    (*rq)->rq_lasttrim = (time_t) 0L;

    return 0;
}
