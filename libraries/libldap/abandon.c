/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  abandon.c
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>

#if !defined( MACOS ) && !defined( DOS )
#include <sys/types.h>
#include <sys/socket.h>
#endif

#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#endif /* DOS */

#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

#ifdef NEEDPROTOS
static int do_abandon( LDAP *ld, int origid, int msgid );
#else /* NEEDPROTOS */
static int do_abandon();
#endif /* NEEDPROTOS */
/*
 * ldap_abandon - perform an ldap (and X.500) abandon operation. Parameters:
 *
 *	ld		LDAP descriptor
 *	msgid		The message id of the operation to abandon
 *
 * ldap_abandon returns 0 if everything went ok, -1 otherwise.
 *
 * Example:
 *	ldap_abandon( ld, msgid );
 */
int
ldap_abandon( LDAP *ld, int msgid )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_abandon %d\n", msgid, 0, 0 );
	return( do_abandon( ld, msgid, msgid ));
}


static int
do_abandon( LDAP *ld, int origid, int msgid )
{
	BerElement	*ber;
	int		i, err, sendabandon;
	Sockbuf		*sb;
#ifdef LDAP_REFERRALS
	LDAPRequest	*lr;
#endif /* LDAP_REFERRALS */

	/*
	 * An abandon request looks like this:
	 *	AbandonRequest ::= MessageID
	 */

	Debug( LDAP_DEBUG_TRACE, "do_abandon origid %d, msgid %d\n",
		origid, msgid, 0 );

	sendabandon = 1;

#ifdef LDAP_REFERRALS
	/* find the request that we are abandoning */
	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( lr->lr_msgid == msgid ) {	/* this message */
			break;
		}
		if ( lr->lr_origid == msgid ) {	/* child:  abandon it */
			do_abandon( ld, msgid, lr->lr_msgid );
		}
	}

	if ( lr != NULL ) {
		if ( origid == msgid && lr->lr_parent != NULL ) {
			/* don't let caller abandon child requests! */
			ld->ld_errno = LDAP_PARAM_ERROR;
			return( -1 );
		}
		if ( lr->lr_status != LDAP_REQST_INPROGRESS ) {
			/* no need to send abandon message */
			sendabandon = 0;
		}
	}
#endif /* LDAP_REFERRALS */

	if ( ldap_msgdelete( ld, msgid ) == 0 ) {
		ld->ld_errno = LDAP_SUCCESS;
		return( 0 );
	}

	err = 0;
	if ( sendabandon ) {
		/* create a message to send */
		if ( (ber = alloc_ber_with_options( ld )) == NULLBER ) {
			err = -1;
			ld->ld_errno = LDAP_NO_MEMORY;
		} else {
#ifdef CLDAP
			if ( ld->ld_sb.sb_naddr > 0 ) {
				err = ber_printf( ber, "{isti}",
				    ++ld->ld_msgid, ld->ld_cldapdn,
				    LDAP_REQ_ABANDON, msgid );
			} else {
#endif /* CLDAP */
				err = ber_printf( ber, "{iti}", ++ld->ld_msgid,
				    LDAP_REQ_ABANDON, msgid );
#ifdef CLDAP
			}
#endif /* CLDAP */

			if ( err == -1 ) {
				ld->ld_errno = LDAP_ENCODING_ERROR;
				ber_free( ber, 1 );
			} else {
				/* send the message */
#ifdef LDAP_REFERRALS
				if ( lr != NULL ) {
					sb = lr->lr_conn->lconn_sb;
				} else {
					sb = &ld->ld_sb;
				}
#else /* LDAP_REFERRALS */
				sb = &ld->ld_sb;
#endif /* LDAP_REFERRALS */
				if ( ber_flush( sb, ber, 1 ) != 0 ) {
					ld->ld_errno = LDAP_SERVER_DOWN;
					err = -1;
				} else {
					err = 0;
				}
			}
		}
	}

#ifdef LDAP_REFERRALS
	if ( lr != NULL ) {
		if ( sendabandon ) {
			free_connection( ld, lr->lr_conn, 0, 1 );
		}
		if ( origid == msgid ) {
			free_request( ld, lr );
		}
	}
#endif /* LDAP_REFERRALS */


	if ( ld->ld_abandoned == NULL ) {
		if ( (ld->ld_abandoned = (int *) malloc( 2 * sizeof(int) ))
		    == NULL ) {
			ld->ld_errno = LDAP_NO_MEMORY;
			return( -1 );
		}
		i = 0;
	} else {
		for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
			;	/* NULL */
		if ( (ld->ld_abandoned = (int *) realloc( (char *)
		    ld->ld_abandoned, (i + 2) * sizeof(int) )) == NULL ) {
			ld->ld_errno = LDAP_NO_MEMORY;
			return( -1 );
		}
	}
	ld->ld_abandoned[i] = msgid;
	ld->ld_abandoned[i + 1] = -1;

	if ( err != -1 ) {
		ld->ld_errno = LDAP_SUCCESS;
	}
	return( err );
}
