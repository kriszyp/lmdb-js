/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  abandon.c
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

static int do_abandon LDAP_P(( LDAP *ld, int origid, int msgid ));

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
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	LDAPRequest	*lr;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	/*
	 * An abandon request looks like this:
	 *	AbandonRequest ::= MessageID
	 */

	Debug( LDAP_DEBUG_TRACE, "do_abandon origid %d, msgid %d\n",
		origid, msgid, 0 );

	sendabandon = 1;

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
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
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	if ( ldap_msgdelete( ld, msgid ) == 0 ) {
		ld->ld_errno = LDAP_SUCCESS;
		return( 0 );
	}

	err = 0;
	if ( sendabandon ) {
		/* create a message to send */
		if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
			err = -1;
			ld->ld_errno = LDAP_NO_MEMORY;
		} else {
#ifdef LDAP_CONNECTIONLESS
			if ( ld->ld_cldapnaddr > 0 ) {
				err = ber_printf( ber, "{isti}",
				    ++ld->ld_msgid, ld->ld_cldapdn,
				    LDAP_REQ_ABANDON, msgid );
			} else {
#endif /* LDAP_CONNECTIONLESS */
				err = ber_printf( ber, "{iti}", ++ld->ld_msgid,
				    LDAP_REQ_ABANDON, msgid );
#ifdef LDAP_CONNECTIONLESS
			}
#endif /* LDAP_CONNECTIONLESS */

			if ( err == -1 ) {
				ld->ld_errno = LDAP_ENCODING_ERROR;
				ber_free( ber, 1 );
			} else {
				/* send the message */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
				if ( lr != NULL ) {
					sb = lr->lr_conn->lconn_sb;
				} else {
					sb = &ld->ld_sb;
				}
#else /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
				sb = &ld->ld_sb;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
				if ( ber_flush( sb, ber, 1 ) != 0 ) {
					ld->ld_errno = LDAP_SERVER_DOWN;
					err = -1;
				} else {
					err = 0;
				}
			}
		}
	}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	if ( lr != NULL ) {
		if ( sendabandon ) {
			ldap_free_connection( ld, lr->lr_conn, 0, 1 );
		}
		if ( origid == msgid ) {
			ldap_free_request( ld, lr );
		}
	}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */


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
