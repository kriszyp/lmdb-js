/* abandon.c */
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
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions  Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 */
/* Portions Copyright (C) The Internet Society (1997).
 * ASN.1 fragments are from RFC 2251; see RFC for full legal notices.
 */

/*
 * An abandon request looks like this:
 *	AbandonRequest ::= MessageID
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

static int do_abandon LDAP_P((
	LDAP *ld,
	ber_int_t origid,
	ber_int_t msgid,
	LDAPControl **sctrls,
	LDAPControl **cctrls));

/*
 * ldap_abandon_ext - perform an ldap extended abandon operation.
 *
 * Parameters:
 *	ld			LDAP descriptor
 *	msgid		The message id of the operation to abandon
 *	scntrls		Server Controls
 *	ccntrls		Client Controls
 *
 * ldap_abandon_ext returns a LDAP error code.
 *		(LDAP_SUCCESS if everything went ok)
 *
 * Example:
 *	ldap_abandon_ext( ld, msgid, scntrls, ccntrls );
 */
int
ldap_abandon_ext(
	LDAP *ld,
	int msgid,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int rc;
	Debug( LDAP_DEBUG_TRACE, "ldap_abandon_ext %d\n", msgid, 0, 0 );

	/* check client controls */
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	rc = ldap_int_client_controls( ld, cctrls );
	if( rc == LDAP_SUCCESS )
		rc = do_abandon( ld, msgid, msgid, sctrls, cctrls );

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
	return rc;
}


/*
 * ldap_abandon - perform an ldap abandon operation. Parameters:
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
	return ldap_abandon_ext( ld, msgid, NULL, NULL ) == LDAP_SUCCESS
		? 0 : -1;
}


static int
do_abandon(
	LDAP *ld,
	ber_int_t origid,
	ber_int_t msgid,
	LDAPControl **sctrls,
	LDAPControl **cctrls)
{
	BerElement	*ber;
	int		i, err, sendabandon;
	ber_int_t *old_abandon;
	Sockbuf		*sb;
	LDAPRequest	*lr;

	Debug( LDAP_DEBUG_TRACE, "do_abandon origid %d, msgid %d\n",
		origid, msgid, 0 );

	sendabandon = 1;

	/* find the request that we are abandoning */
	for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
		if ( lr->lr_msgid == msgid ) {	/* this message */
			break;
		}
		if ( lr->lr_origid == msgid ) {/* child:  abandon it */
			(void) do_abandon( ld,
				lr->lr_origid, lr->lr_msgid, sctrls, cctrls );
		}
	}

	if ( lr != NULL ) {
		if ( origid == msgid && lr->lr_parent != NULL ) {
			/* don't let caller abandon child requests! */
			ld->ld_errno = LDAP_PARAM_ERROR;
			return( LDAP_PARAM_ERROR );
		}
		if ( lr->lr_status != LDAP_REQST_INPROGRESS ) {
			/* no need to send abandon message */
			sendabandon = 0;
		}
	}

/* ldap_msgdelete locks the res_mutex. Give up the req_mutex
 * while we're in there.
 */
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
	err = ldap_msgdelete( ld, msgid );
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	if ( err == 0 ) {
		ld->ld_errno = LDAP_SUCCESS;
		return LDAP_SUCCESS;
	}

	/* fetch again the request that we are abandoning */
	if ( lr != NULL ) {
		for ( lr = ld->ld_requests; lr != NULL; lr = lr->lr_next ) {
			if ( lr->lr_msgid == msgid ) {	/* this message */
				break;
			}
		}
	}

	err = 0;
	if ( sendabandon ) {
		if( ber_sockbuf_ctrl( ld->ld_sb, LBER_SB_OPT_GET_FD, NULL ) == -1 ) {
			/* not connected */
			err = -1;
			ld->ld_errno = LDAP_SERVER_DOWN;

		} else if ( (ber = ldap_alloc_ber_with_options( ld )) == NULL ) {
			/* BER element alocation failed */
			err = -1;
			ld->ld_errno = LDAP_NO_MEMORY;

		} else {
	/*
	 * We already have the mutex in LDAP_R_COMPILE, so
	 * don't try to get it again.
	 *		LDAP_NEXT_MSGID(ld, i);
	 */
			i = ++(ld)->ld_msgid;
#ifdef LDAP_CONNECTIONLESS
			if ( LDAP_IS_UDP(ld) ) {
				struct sockaddr sa = {0};
				/* dummy, filled with ldo_peer in request.c */
				err = ber_write( ber, &sa, sizeof( sa ), 0 );
			}
			if ( LDAP_IS_UDP(ld) && ld->ld_options.ldo_version ==
				LDAP_VERSION2) {
			    char *dn = ld->ld_options.ldo_cldapdn;
			    if (!dn) dn = "";
			    err = ber_printf( ber, "{isti",  /* '}' */
				i, dn,
				LDAP_REQ_ABANDON, msgid );
			} else
#endif
			{
			    /* create a message to send */
			    err = ber_printf( ber, "{iti",  /* '}' */
				i,
				LDAP_REQ_ABANDON, msgid );
			}

			if( err == -1 ) {
				/* encoding error */
				ld->ld_errno = LDAP_ENCODING_ERROR;

			} else {
				/* Put Server Controls */
				if ( ldap_int_put_controls( ld, sctrls, ber )
					!= LDAP_SUCCESS )
				{
					err = -1;

				} else {
					/* close '{' */
					err = ber_printf( ber, /*{*/ "N}" );

					if( err == -1 ) {
						/* encoding error */
						ld->ld_errno = LDAP_ENCODING_ERROR;
					}
				}
			}

			if ( err == -1 ) {
				ber_free( ber, 1 );

			} else {
				/* send the message */
				if ( lr != NULL ) {
					assert( lr->lr_conn != NULL );
					sb = lr->lr_conn->lconn_sb;
				} else {
					sb = ld->ld_sb;
				}

				if ( ber_flush( sb, ber, 1 ) != 0 ) {
					ld->ld_errno = LDAP_SERVER_DOWN;
					err = -1;
				} else {
					err = 0;
				}
			}
		}
	}

	if ( lr != NULL ) {
		if ( sendabandon || lr->lr_status == LDAP_REQST_WRITING ) {
			ldap_free_connection( ld, lr->lr_conn, 0, 1 );
		}
		if ( origid == msgid ) {
			ldap_free_request( ld, lr );
		}
	}

#ifdef LDAP_R_COMPILE
	/* ld_abandoned is actually protected by the ld_res_mutex;
	 * give up the ld_req_mutex and get the other */
	ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
	ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
#endif
	i = 0;
	if ( ld->ld_abandoned != NULL ) {
		for ( ; ld->ld_abandoned[i] != -1; i++ )
			;	/* NULL */
	}

	old_abandon = ld->ld_abandoned;

	ld->ld_abandoned = (ber_int_t *) LDAP_REALLOC( (char *)
		ld->ld_abandoned, (i + 2) * sizeof(ber_int_t) );
		
	if ( ld->ld_abandoned == NULL ) {
		ld->ld_abandoned = old_abandon;
		ld->ld_errno = LDAP_NO_MEMORY;
		goto done;
	}

	ld->ld_abandoned[i] = msgid;
	ld->ld_abandoned[i + 1] = -1;

	if ( err != -1 ) {
		ld->ld_errno = LDAP_SUCCESS;
	}

done:;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
	ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
	return( ld->ld_errno );
}
