/* result.c - wait for an ldap result */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 */
/* This notice applies to changes, created by or for Novell, Inc.,
 * to preexisting works for which notices appear elsewhere in this file.
 *
 * Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
 * USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT TO VERSION
 * 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS AVAILABLE AT
 * HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE" IN THE
 * TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION OF THIS
 * WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP PUBLIC
 * LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT THE
 * PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY. 
 *---
 * Modification to OpenLDAP source by Novell, Inc.
 * April 2000 sfs Add code to process V3 referrals and search results
 *---
 * Note: A verbatim copy of version 2.0.1 of the OpenLDAP Public License 
 * can be found in the file "build/LICENSE-2.0.1" in this distribution
 * of OpenLDAP Software.
 */
/* Portions Copyright (C) The Internet Society (1997)
 * ASN.1 fragments are from RFC 2251; see RFC for full legal notices.
 */

/*
 * LDAPv3 (RFC2251)
 *	LDAPResult ::= SEQUENCE {
 *		resultCode		ENUMERATED { ... },
 *		matchedDN		LDAPDN,
 *		errorMessage	LDAPString,
 *		referral		Referral OPTIONAL
 *	}
 *	Referral ::= SEQUENCE OF LDAPURL	(one or more)
 *	LDAPURL ::= LDAPString				(limited to URL chars)
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"
#include "ldap_log.h"

static int ldap_abandoned LDAP_P(( LDAP *ld, ber_int_t msgid ));
static int ldap_mark_abandoned LDAP_P(( LDAP *ld, ber_int_t msgid ));
static int wait4msg LDAP_P(( LDAP *ld, ber_int_t msgid, int all, struct timeval *timeout,
	LDAPMessage **result ));
static ber_tag_t try_read1msg LDAP_P(( LDAP *ld, ber_int_t msgid,
	int all, Sockbuf *sb, LDAPConn **lc, LDAPMessage **result ));
static ber_tag_t build_result_ber LDAP_P(( LDAP *ld, BerElement **bp, LDAPRequest *lr ));
static void merge_error_info LDAP_P(( LDAP *ld, LDAPRequest *parentr, LDAPRequest *lr ));
static LDAPMessage * chkResponseList LDAP_P(( LDAP *ld, int msgid, int all));


/*
 * ldap_result - wait for an ldap result response to a message from the
 * ldap server.  If msgid is LDAP_RES_ANY (-1), any message will be
 * accepted.  If msgid is LDAP_RES_UNSOLICITED (0), any unsolicited
 * message is accepted.  Otherwise ldap_result will wait for a response
 * with msgid.  If all is LDAP_MSG_ONE (0) the first message with id
 * msgid will be accepted, otherwise, ldap_result will wait for all
 * responses with id msgid and then return a pointer to the entire list
 * of messages.  In general, this is only useful for search responses,
 * which can be of three message types (zero or more entries, zero or
 * search references, followed by an ldap result).  An extension to
 * LDAPv3 allows partial extended responses to be returned in response
 * to any request.  The type of the first message received is returned.
 * When waiting, any messages that have been abandoned are discarded.
 *
 * Example:
 *	ldap_result( s, msgid, all, timeout, result )
 */
int
ldap_result(
	LDAP *ld,
	int msgid,
	int all,
	struct timeval *timeout,
	LDAPMessage **result )
{
	LDAPMessage	*lm;
	int	rc;

	assert( ld != NULL );
	assert( result != NULL );

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "ldap_result msgid %d\n", msgid, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_result msgid %d\n", msgid, 0, 0 );
#endif

#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
#endif
	lm = chkResponseList(ld, msgid, all);

	if ( lm == NULL ) {
		rc = wait4msg( ld, msgid, all, timeout, result );
	} else {
		*result = lm;
		ld->ld_errno = LDAP_SUCCESS;
		rc = lm->lm_msgtype;
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
#endif
	return( rc );
}

static LDAPMessage *
chkResponseList(
	LDAP *ld,
	int msgid,
	int all)
{
	LDAPMessage	*lm, *lastlm, *nextlm;
    /*
	 * Look through the list of responses we have received on
	 * this association and see if the response we're interested in
	 * is there.  If it is, return it.  If not, call wait4msg() to
	 * wait until it arrives or timeout occurs.
	 */

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "ldap_chkResponseList for msgid=%d, all=%d\n", 
		msgid, all, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldap_chkResponseList for msgid=%d, all=%d\n",
	    msgid, all, 0 );
#endif
	lastlm = NULL;
	for ( lm = ld->ld_responses; lm != NULL; lm = nextlm ) {
		nextlm = lm->lm_next;

		if ( ldap_abandoned( ld, lm->lm_msgid ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"ldap_chkResponseList msg abandoned, msgid %d\n", msgid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"ldap_chkResponseList msg abandoned, msgid %d\n",
			    msgid, 0, 0 );
#endif
			ldap_mark_abandoned( ld, lm->lm_msgid );

			if ( lastlm == NULL ) {
				/* Remove first entry in list */
				ld->ld_responses = lm->lm_next;
			} else {
				lastlm->lm_next = nextlm;
			}

			ldap_msgfree( lm );

			continue;
		}

		if ( msgid == LDAP_RES_ANY || lm->lm_msgid == msgid ) {
			LDAPMessage	*tmp;

			if ( all == LDAP_MSG_ONE || msgid == LDAP_RES_UNSOLICITED ) {
				break;
			}

			for ( tmp = lm; tmp != NULL; tmp = tmp->lm_chain ) {
				if ( tmp->lm_msgtype != LDAP_RES_SEARCH_ENTRY
				    && tmp->lm_msgtype != LDAP_RES_SEARCH_REFERENCE
					&& tmp->lm_msgtype != LDAP_RES_INTERMEDIATE )
				{
					break;
				}
			}

			if ( tmp == NULL ) {
				lm = NULL;
			}

			break;
		}
		lastlm = lm;
	}

    if ( lm != NULL ) {
		/* Found an entry, remove it from the list */
	    if ( lastlm == NULL ) {
		    ld->ld_responses = (all == LDAP_MSG_ONE && lm->lm_chain != NULL
		        ? lm->lm_chain : lm->lm_next);
	    } else {
		    lastlm->lm_next = (all == LDAP_MSG_ONE && lm->lm_chain != NULL
		        ? lm->lm_chain : lm->lm_next);
	    }
	    if ( all == LDAP_MSG_ONE && lm->lm_chain != NULL ) {
		    lm->lm_chain->lm_next = lm->lm_next;
		    lm->lm_chain = NULL;
	    }
	    lm->lm_next = NULL;
    }

#ifdef LDAP_DEBUG
	if( lm == NULL) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, "ldap_chkResponseList returns NULL\n",
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldap_chkResponseList returns NULL\n", 0, 0, 0);
#endif
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, RESULTS, 
			"ldap_chkResponseList returns msgid %d, type 0x%02lu\n",
			lm->lm_msgid, (unsigned long) lm->lm_msgtype, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"ldap_chkResponseList returns msgid %d, type 0x%02lu\n",
			lm->lm_msgid, (unsigned long) lm->lm_msgtype, 0);
#endif
	}
#endif
    return lm;
}

static int
wait4msg(
	LDAP *ld,
	ber_int_t msgid,
	int all,
	struct timeval *timeout,
	LDAPMessage **result )
{
	int		rc;
	struct timeval	tv, *tvp;
	time_t		start_time = 0;
	time_t		tmp_time;
	LDAPConn	*lc, *nextlc;

	assert( ld != NULL );
	assert( result != NULL );

#ifdef LDAP_DEBUG
	if ( timeout == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ARGS, 
			"wait4msg (infinite timeout), msgid %d\n", msgid, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "wait4msg (infinite timeout), msgid %d\n",
		    msgid, 0, 0 );
#endif
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ARGS, 
			"wait4msg (timeout %ld sec, %ld usec), msgid %d\n", 
			(long) timeout->tv_sec, (long) timeout->tv_usec, msgid );
#else
		Debug( LDAP_DEBUG_TRACE, "wait4msg (timeout %ld sec, %ld usec), msgid %d\n",
		       (long) timeout->tv_sec, (long) timeout->tv_usec, msgid );
#endif
	}
#endif /* LDAP_DEBUG */

	if ( timeout == NULL ) {
		tvp = NULL;
	} else {
		tv = *timeout;
		tvp = &tv;
		start_time = time( NULL );
	}
		    
	rc = -2;
	while ( rc == -2 ) {
#ifdef LDAP_DEBUG
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ARGS, 
			"wait4msg continue, msgid %d, all %d\n", msgid, all, 0 );
#else
		Debug( LDAP_DEBUG_TRACE, "wait4msg continue, msgid %d, all %d\n",
		    msgid, all, 0 );
#endif
		if ( ldap_debug & LDAP_DEBUG_TRACE ) {
			ldap_dump_connection( ld, ld->ld_conns, 1 );
			ldap_dump_requests_and_responses( ld );
		}
#endif /* LDAP_DEBUG */

        if( (*result = chkResponseList(ld, msgid, all)) != NULL ) {
            rc = (*result)->lm_msgtype;
        } else {
			int lc_ready = 0;

			for ( lc = ld->ld_conns; lc != NULL; lc = nextlc ) {
				nextlc = lc->lconn_next;
				if ( ber_sockbuf_ctrl( lc->lconn_sb,
						LBER_SB_OPT_DATA_READY, NULL ) ) {
					rc = try_read1msg( ld, msgid, all, lc->lconn_sb,
						&lc, result );
					lc_ready = 1;
				    break;
				}
	        }

		    if ( !lc_ready ) {
			    rc = ldap_int_select( ld, tvp );
#ifdef LDAP_DEBUG
			    if ( rc == -1 ) {
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, ARGS, 
						"wait4msg: ldap_int_select returned -1: errno %d\n", 
						errno, 0, 0 );
#else
			        Debug( LDAP_DEBUG_TRACE,
				        "ldap_int_select returned -1: errno %d\n",
				        errno, 0, 0 );
#endif
			    }
#endif

			    if ( rc == 0 || ( rc == -1 && (
				    !LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_RESTART)
				    || errno != EINTR )))
			    {
				    ld->ld_errno = (rc == -1 ? LDAP_SERVER_DOWN :
				        LDAP_TIMEOUT);
				    return( rc );
			    }

			    if ( rc == -1 ) {
				    rc = -2;	/* select interrupted: loop */
			    } else {
				    rc = -2;
#ifdef LDAP_R_COMPILE
				    ldap_pvt_thread_mutex_lock( &ld->ld_req_mutex );
#endif
				    if ( ld->ld_requests &&
						ld->ld_requests->lr_status == LDAP_REQST_WRITING &&
						ldap_is_write_ready( ld,
							ld->ld_requests->lr_conn->lconn_sb ) ) {
						ldap_int_flush_request( ld, ld->ld_requests );
					}
#ifdef LDAP_R_COMPILE
				    ldap_pvt_thread_mutex_unlock( &ld->ld_req_mutex );
#endif
				    for ( lc = ld->ld_conns; rc == -2 && lc != NULL;
				        lc = nextlc ) {
					    nextlc = lc->lconn_next;
					    if ( lc->lconn_status ==
					        LDAP_CONNST_CONNECTED &&
					        ldap_is_read_ready( ld,
					        lc->lconn_sb )) {
						    rc = try_read1msg( ld, msgid, all,
						        lc->lconn_sb, &lc, result );
							if ( lc == NULL ) lc = nextlc;
					    }
				    }
			    }
		    }
		}

		if ( rc == -2 && tvp != NULL ) {
			tmp_time = time( NULL );
			if (( tv.tv_sec -=  ( tmp_time - start_time )) <= 0 ) {
				rc = 0;	/* timed out */
				ld->ld_errno = LDAP_TIMEOUT;
				break;
			}

#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"wait4msg: %ld secs to go\n", (long) tv.tv_sec, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "wait4msg:  %ld secs to go\n",
			       (long) tv.tv_sec, 0, 0 );
#endif
			start_time = tmp_time;
		}
	}

	return( rc );
}


static ber_tag_t
try_read1msg(
	LDAP *ld,
	ber_int_t msgid,
	int all,
	Sockbuf *sb,
	LDAPConn **lcp,
	LDAPMessage **result )
{
	BerElement	*ber;
	LDAPMessage	*new, *l, *prev, *tmp;
	ber_int_t	id;
	ber_tag_t	tag;
	ber_len_t	len;
	int		foundit = 0;
	LDAPRequest	*lr, *tmplr;
	LDAPConn	*lc;
	BerElement	tmpber;
	int		rc, refer_cnt, hadref, simple_request;
	ber_int_t	lderr;
#ifdef LDAP_CONNECTIONLESS
	int		firstmsg = 1, moremsgs = 0, isv2 = 0;
#endif
	/*
	 * v3ref = flag for V3 referral / search reference
	 * 0 = not a ref, 1 = sucessfully chased ref, -1 = pass ref to application
	 */
	int     v3ref;

	assert( ld != NULL );
	assert( lcp != NULL );
	assert( *lcp != NULL );
	
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, "read1msg: msgid %d, all %d\n", msgid, all, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "read1msg: msgid %d, all %d\n", msgid, all, 0 );
#endif

	lc = *lcp;

retry:
	if ( lc->lconn_ber == NULL ) {
		lc->lconn_ber = ldap_alloc_ber_with_options(ld);

		if( lc->lconn_ber == NULL ) {
			return -1;
		}
	}

	ber = lc->lconn_ber;
	assert( LBER_VALID (ber) );

	/* get the next message */
	errno = 0;
#ifdef LDAP_CONNECTIONLESS
	if ( LDAP_IS_UDP(ld) ) {
		struct sockaddr from;
		ber_int_sb_read(sb, &from, sizeof(struct sockaddr));
		if (ld->ld_options.ldo_version == LDAP_VERSION2) isv2=1;
	}
nextresp3:
#endif
	tag = ber_get_next( sb, &len, ber );
	if ( tag == LDAP_TAG_MESSAGE ) {
		/*
	 	 * We read a complete message.
	 	 * The connection should no longer need this ber.
	 	 */
		lc->lconn_ber = NULL;
	}
	if ( tag != LDAP_TAG_MESSAGE ) {
		if ( tag == LBER_DEFAULT) {
#ifdef LDAP_DEBUG		   
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"read1msg: ber_get_next failed\n", 0, 0, 0 );
#else
			Debug( LDAP_DEBUG_CONNS,
			      "ber_get_next failed.\n", 0, 0, 0 );
#endif		   
#endif		   
#ifdef EWOULDBLOCK			
			if (errno==EWOULDBLOCK) return -2;
#endif
#ifdef EAGAIN
			if (errno == EAGAIN) return -2;
#endif
			ld->ld_errno = LDAP_SERVER_DOWN;
			return -1;
		}
		ld->ld_errno = LDAP_LOCAL_ERROR;
		return -1;
	}

	/* message id */
	if ( ber_get_int( ber, &id ) == LBER_ERROR ) {
		ber_free( ber, 1 );
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( -1 );
	}

	/* if it's been abandoned, toss it */
	if ( ldap_abandoned( ld, id ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "read1msg: abandoned\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "abandoned\n", 0, 0, 0);
#endif
retry_ber:
		ber_free( ber, 1 );
		if ( ber_sockbuf_ctrl( sb, LBER_SB_OPT_DATA_READY, NULL ) ) {
			goto retry;
		}
		return( -2 );	/* continue looking */
	}

	if (( lr = ldap_find_request_by_msgid( ld, id )) == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, 
			"read1msg: no request for response with msgid %ld (tossing)\n",
			(long) id, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "no request for response with msgid %ld (tossing)\n",
		    (long) id, 0, 0 );
#endif
		goto retry_ber;
	}
#ifdef LDAP_CONNECTIONLESS
	if (LDAP_IS_UDP(ld) && isv2) {
		ber_scanf(ber, "x{");
	}
nextresp2:
#endif
	/* the message type */
	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, 
		"read1msg: ldap_read: message type %s msgid %ld, original id %ld\n",
	    ldap_int_msgtype2str( tag ),
		(long) lr->lr_msgid, (long) lr->lr_origid );
#else
	Debug( LDAP_DEBUG_TRACE,
		"ldap_read: message type %s msgid %ld, original id %ld\n",
	    ldap_int_msgtype2str( tag ),
		(long) lr->lr_msgid, (long) lr->lr_origid );
#endif

	id = lr->lr_origid;
	refer_cnt = 0;
	hadref = simple_request = 0;
	rc = -2;	/* default is to keep looking (no response found) */
	lr->lr_res_msgtype = tag;

	/*
	 * This code figures out if we are going to chase a
	 * referral / search reference, or pass it back to the application
	 */
	v3ref = 0;	/* Assume not a V3 search reference or referral */
	if( (tag != LDAP_RES_SEARCH_ENTRY) && (ld->ld_version > LDAP_VERSION2) ) {
		BerElement	tmpber = *ber; 	/* struct copy */
		char **refs = NULL;

		if( tag == LDAP_RES_SEARCH_REFERENCE) {
			/* This is a V3 search reference */
			/* Assume we do not chase the reference, but pass it to application */
			v3ref = -1;
			if( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_REFERRALS) ||
					(lr->lr_parent != NULL) )
			{
				/* Get the referral list */
				if ( ber_scanf( &tmpber, "{v}", &refs ) == LBER_ERROR ) {
					rc = LDAP_DECODING_ERROR;
				} else {
					/* Note: refs arrary is freed by ldap_chase_v3referrals */
					refer_cnt = ldap_chase_v3referrals( ld, lr, refs,
					    1, &lr->lr_res_error, &hadref );
					if ( refer_cnt > 0 ) {	/* sucessfully chased reference */
						/* If haven't got end search, set chasing referrals */
						if( lr->lr_status != LDAP_REQST_COMPLETED) {
							lr->lr_status = LDAP_REQST_CHASINGREFS;
#ifdef NEW_LOGGING
							LDAP_LOG ( OPERATION, DETAIL1, 
								"read1msg: search ref chased,"
								"mark request chasing refs, id =	%d\n",
								lr->lr_msgid, 0, 0 );
#else
							Debug( LDAP_DEBUG_TRACE,
							    "read1msg:  search ref chased, mark request chasing refs, id = %d\n",
							    lr->lr_msgid, 0, 0);
#endif
						}
						v3ref = 1;	/* We sucessfully chased the reference */
					}
				}
			}
		} else {
			/* Check for V3 referral */
			ber_len_t len;
			if ( ber_scanf( &tmpber, "{iaa",/*}*/ &lderr,
				    &lr->lr_res_matched, &lr->lr_res_error )
				    != LBER_ERROR ) {
				/* Check if V3 referral */
				if( ber_peek_tag( &tmpber, &len) == LDAP_TAG_REFERRAL ) {
					/* We have a V3 referral, assume we cannot chase it */
					v3ref = -1;
					if( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_REFERRALS)
							 || (lr->lr_parent != NULL) )
					{
						v3ref = -1;  /* Assume referral not chased and return it to app */
						/* Get the referral list */
						if( ber_scanf( &tmpber, "{v}", &refs) == LBER_ERROR) {
							rc = LDAP_DECODING_ERROR;
							lr->lr_status = LDAP_REQST_COMPLETED;
#ifdef NEW_LOGGING
							LDAP_LOG ( OPERATION, DETAIL1, 
								"read1msg: referral decode error,"
								"mark request completed, id =	%d\n",
								lr->lr_msgid, 0, 0 );
#else
							Debug( LDAP_DEBUG_TRACE,
							    "read1msg: referral decode error, mark request completed, id = %d\n",
								    lr->lr_msgid, 0, 0);
#endif
						} else {
							/* Chase the referral 
							 * Note: refs arrary is freed by ldap_chase_v3referrals
							 */
							refer_cnt = ldap_chase_v3referrals( ld, lr, refs,
							    0, &lr->lr_res_error, &hadref );
							lr->lr_status = LDAP_REQST_COMPLETED;
#ifdef NEW_LOGGING
							LDAP_LOG ( OPERATION, DETAIL1, 
								"read1msg: referral chased,"
								"mark request completed, id =	%d\n",
								lr->lr_msgid, 0, 0 );
#else
							Debug( LDAP_DEBUG_TRACE,
							    "read1msg:  referral chased, mark request completed, id = %d\n",
							    lr->lr_msgid, 0, 0);
#endif
							if( refer_cnt > 0) {
								v3ref = 1;  /* Referral successfully chased */
							}
						}
					}
				}

				if( lr->lr_res_matched != NULL ) {
					LDAP_FREE( lr->lr_res_matched );
					lr->lr_res_matched = NULL;
				}
				if( lr->lr_res_error != NULL ) {
					LDAP_FREE( lr->lr_res_error );
					lr->lr_res_error = NULL;
				}
			}
		}
	}

	/* All results that just return a status, i.e. don't return data
	 * go through the following code.  This code also chases V2 referrals
	 * and checks if all referrals have been chased.
	 */
	if ( (tag != LDAP_RES_SEARCH_ENTRY) && (v3ref > -1) &&
		(tag != LDAP_RES_INTERMEDIATE ))
	{
		/* For a v3 search referral/reference, only come here if already chased it */
		if ( ld->ld_version >= LDAP_VERSION2 &&
			( lr->lr_parent != NULL ||
			LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_REFERRALS) ) )
		{
			tmpber = *ber;	/* struct copy */
			if ( v3ref == 1 ) {
				/* V3 search reference or V3 referral
				 * sucessfully chased. If this message
				 * is a search result, then it has no more
				 * outstanding referrals.
				 */
				if ( tag == LDAP_RES_SEARCH_RESULT )
					refer_cnt = 0;
			} else if ( ber_scanf( &tmpber, "{iaa}", &lderr,
			    &lr->lr_res_matched, &lr->lr_res_error )
			    != LBER_ERROR ) {
				if ( lderr != LDAP_SUCCESS ) {
					/* referrals are in error string */
					refer_cnt = ldap_chase_referrals( ld, lr,
						&lr->lr_res_error, -1, &hadref );
					lr->lr_status = LDAP_REQST_COMPLETED;
#ifdef NEW_LOGGING
					LDAP_LOG ( OPERATION, DETAIL1, 
						"read1msg: V2 referral chased,"
						"mark request completed, id =	%d\n",
						lr->lr_msgid, 0, 0 );
#else
					Debug( LDAP_DEBUG_TRACE,
					    "read1msg:  V2 referral chased, mark request completed, id = %d\n", lr->lr_msgid, 0, 0);
#endif
				}

				/* save errno, message, and matched string */
				if ( !hadref || lr->lr_res_error == NULL ) {
					lr->lr_res_errno = ( lderr ==
					LDAP_PARTIAL_RESULTS ) ? LDAP_SUCCESS
					: lderr;
				} else if ( ld->ld_errno != LDAP_SUCCESS ) {
					lr->lr_res_errno = ld->ld_errno;
				} else {
					lr->lr_res_errno = LDAP_PARTIAL_RESULTS;
				}
#ifdef NEW_LOGGING
LDAP_LOG ( OPERATION, DETAIL1, 
	"read1msg: new result: res_errno: %d, res_error: <%s>, res_matched: <%s>\n",
    lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
    lr->lr_res_matched ? lr->lr_res_matched : "" );
#else
Debug( LDAP_DEBUG_TRACE,
    "new result:  res_errno: %d, res_error: <%s>, res_matched: <%s>\n",
    lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
    lr->lr_res_matched ? lr->lr_res_matched : "" );
#endif
			}
		}

#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, DETAIL1, "read1msg: %d new referrals\n", 
			refer_cnt, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
		    "read1msg:  %d new referrals\n", refer_cnt, 0, 0 );
#endif

		if ( refer_cnt != 0 ) {	/* chasing referrals */
			ber_free( ber, 1 );
			ber = NULL;
			if ( refer_cnt < 0 ) {
				return( -1 );	/* fatal error */
			}
			lr->lr_res_errno = LDAP_SUCCESS; /* sucessfully chased referral */
		} else {
			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL ) {
				/* request without any referrals */
				simple_request = ( hadref ? 0 : 1 );
			} else {
				/* request with referrals or child request */
				ber_free( ber, 1 );
				ber = NULL;
			}

			lr->lr_status = LDAP_REQST_COMPLETED; /* declare this request done */
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"read1msg: mark request completed, id = %d\n", 
				lr->lr_msgid, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
			    "read1msg:  mark request completed, id = %d\n", lr->lr_msgid, 0, 0);
#endif
			while ( lr->lr_parent != NULL ) {
				merge_error_info( ld, lr->lr_parent, lr );

				lr = lr->lr_parent;
				if ( --lr->lr_outrefcnt > 0 ) {
					break;	/* not completely done yet */
				}
			}

			/* Check if all requests are finished, lr is now parent */
			tmplr = lr;
			if (tmplr->lr_status == LDAP_REQST_COMPLETED) {
				for(tmplr=lr->lr_child; tmplr != NULL; tmplr=tmplr->lr_refnext) {
				if( tmplr->lr_status != LDAP_REQST_COMPLETED) {
					break;
					}
				}
			}

			/* This is the parent request if the request has referrals */
			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL && tmplr == NULL ) {
				id = lr->lr_msgid;
				tag = lr->lr_res_msgtype;
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, DETAIL1, 
				"read1msg: request %ld done\n", (long) id, 0, 0 );
			LDAP_LOG ( OPERATION, DETAIL1, 
				"read1msg: res_errno: %d,res_error: <%s>, res_matched: <%s>\n",
				lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
				lr->lr_res_matched ? lr->lr_res_matched : "" );
#else
				Debug( LDAP_DEBUG_ANY, "request %ld done\n",
				    (long) id, 0, 0 );
Debug( LDAP_DEBUG_TRACE,
"res_errno: %d, res_error: <%s>, res_matched: <%s>\n",
lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
lr->lr_res_matched ? lr->lr_res_matched : "" );
#endif
				if ( !simple_request ) {
					ber_free( ber, 1 );
					ber = NULL;
					if ( build_result_ber( ld, &ber, lr )
					    == LBER_ERROR ) {
						rc = -1; /* fatal error */
					}
				}

				ldap_free_request( ld, lr );
			}

			if ( lc != NULL ) {
				ldap_free_connection( ld, lc, 0, 1 );
				*lcp = NULL;
			}
		}
	}

	if ( ber == NULL ) {
		return( rc );
	}

	/* make a new ldap message */
	if ( (new = (LDAPMessage *) LDAP_CALLOC( 1, sizeof(LDAPMessage) ))
	    == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}
	new->lm_msgid = (int)id;
	new->lm_msgtype = tag;
	new->lm_ber = ber;

#ifdef LDAP_CONNECTIONLESS
	/* CLDAP replies all fit in a single datagram. In LDAPv2 RFC1798
	 * the responses are all a sequence wrapped in one message. In
	 * LDAPv3 each response is in its own message. The datagram must
	 * end with a SearchResult. We can't just parse each response in
	 * separate calls to try_read1msg because the header info is only
	 * present at the beginning of the datagram, not at the beginning
	 * of each response. So parse all the responses at once and queue
	 * them up, then pull off the first response to return to the
	 * caller when all parsing is complete.
	 */
	if ( LDAP_IS_UDP(ld) ) {
		/* If not a result, look for more */
		if ( tag != LDAP_RES_SEARCH_RESULT ) {
			int ok = 0;
			moremsgs = 1;
			if (isv2) {
				/* LDAPv2: dup the current ber, skip past the current
				 * response, and see if there are any more after it.
				 */
				ber = ber_dup( ber );
				ber_scanf( ber, "x" );
				if (ber_peek_tag(ber, &len) != LBER_DEFAULT) {
					/* There's more - dup the ber buffer so they can all be
					 * individually freed by ldap_msgfree.
					 */
					struct berval bv;
					ber_get_option(ber, LBER_OPT_BER_REMAINING_BYTES, &len);
					bv.bv_val = LDAP_MALLOC(len);
					if (bv.bv_val) {
						ok=1;
						ber_read(ber, bv.bv_val, len);
						bv.bv_len = len;
						ber_init2(ber, &bv, ld->ld_lberoptions );
					}
				}
			} else {
				/* LDAPv3: Just allocate a new ber. Since this is a buffered
				 * datagram, if the sockbuf is readable we still have data
				 * to parse.
				 */
				ber = ldap_alloc_ber_with_options(ld);
				if (ber_sockbuf_ctrl(sb, LBER_SB_OPT_DATA_READY, NULL)) ok=1;
			}
			/* set up response chain */
			if ( firstmsg ) {
				firstmsg = 0;
				new->lm_next = ld->ld_responses;
				ld->ld_responses = new;
			} else {
				tmp->lm_chain = new;
			}
			tmp = new;
			/* "ok" means there's more to parse */
			if (ok) {
				if (isv2) goto nextresp2;
				else goto nextresp3;
			} else {
				/* got to end of datagram without a SearchResult. Free
				 * our dup'd ber, but leave any buffer alone. For v2 case,
				 * the previous response is still using this buffer. For v3,
				 * the new ber has no buffer to free yet.
				 */
				ber_free(ber, 0);
				return -1;
			}
		} else if ( moremsgs ) {
		/* got search result, and we had multiple responses in 1 datagram.
		 * stick the result onto the end of the chain, and then pull the
		 * first response off the head of the chain.
		 */
			tmp->lm_chain = new;
			*result = chkResponseList( ld, msgid, all );
			ld->ld_errno = LDAP_SUCCESS;
			return( (*result)->lm_msgtype );
		}
	}
#endif

	/* is this the one we're looking for? */
	if ( msgid == LDAP_RES_ANY || id == msgid ) {
		if ( all == LDAP_MSG_ONE
		    || (new->lm_msgtype != LDAP_RES_SEARCH_RESULT
		    && new->lm_msgtype != LDAP_RES_SEARCH_ENTRY
		    && new->lm_msgtype != LDAP_RES_SEARCH_REFERENCE) ) {
			*result = new;
			ld->ld_errno = LDAP_SUCCESS;
			return( tag );
		} else if ( new->lm_msgtype == LDAP_RES_SEARCH_RESULT) {
			foundit = 1;	/* return the chain later */
		}
	}

	/* 
	 * if not, we must add it to the list of responses.  if
	 * the msgid is already there, it must be part of an existing
	 * search response.
	 */

	prev = NULL;
	for ( l = ld->ld_responses; l != NULL; l = l->lm_next ) {
		if ( l->lm_msgid == new->lm_msgid )
			break;
		prev = l;
	}

	/* not part of an existing search response */
	if ( l == NULL ) {
		if ( foundit ) {
			*result = new;
			goto exit;
		}

		new->lm_next = ld->ld_responses;
		ld->ld_responses = new;
		goto exit;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, DETAIL1, 
		"read1msg: adding response id %ld type %ld\n",
		(long) new->lm_msgid, (long) new->lm_msgtype, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "adding response id %ld type %ld:\n",
	    (long) new->lm_msgid, (long) new->lm_msgtype, 0 );
#endif

	/* part of a search response - add to end of list of entries */
	for ( tmp = l; (tmp->lm_chain != NULL) &&
	    	((tmp->lm_chain->lm_msgtype == LDAP_RES_SEARCH_ENTRY) ||
	    	 (tmp->lm_chain->lm_msgtype == LDAP_RES_SEARCH_REFERENCE) ||
			 (tmp->lm_chain->lm_msgtype == LDAP_RES_INTERMEDIATE ));
	    tmp = tmp->lm_chain )
		;	/* NULL */
	tmp->lm_chain = new;

	/* return the whole chain if that's what we were looking for */
	if ( foundit ) {
		if ( prev == NULL )
			ld->ld_responses = l->lm_next;
		else
			prev->lm_next = l->lm_next;
		*result = l;
	}

exit:
	if ( foundit ) {
		ld->ld_errno = LDAP_SUCCESS;
		return( tag );
	}
	if ( ber_sockbuf_ctrl( sb, LBER_SB_OPT_DATA_READY, NULL ) ) {
		goto retry;
	}
	return( -2 );	/* continue looking */
}


static ber_tag_t
build_result_ber( LDAP *ld, BerElement **bp, LDAPRequest *lr )
{
	ber_len_t	len;
	ber_tag_t	tag;
	ber_int_t	along;
	BerElement *ber;

	*bp = NULL;
	ber = ldap_alloc_ber_with_options( ld );

	if( ber == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return LBER_ERROR;
	}

	if ( ber_printf( ber, "{it{ess}}", lr->lr_msgid,
	    lr->lr_res_msgtype, lr->lr_res_errno,
	    lr->lr_res_matched ? lr->lr_res_matched : "",
	    lr->lr_res_error ? lr->lr_res_error : "" ) == -1 ) {

		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free(ber, 1);
		return( LBER_ERROR );
	}

	ber_reset( ber, 1 );

	if ( ber_skip_tag( ber, &len ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free(ber, 1);
		return( LBER_ERROR );
	}

	if ( ber_get_int( ber, &along ) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free(ber, 1);
		return( LBER_ERROR );
	}

	tag = ber_peek_tag( ber, &len );

	if ( tag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		ber_free(ber, 1);
		return( LBER_ERROR );
	}

	*bp = ber;
	return tag;
}


static void
merge_error_info( LDAP *ld, LDAPRequest *parentr, LDAPRequest *lr )
{
/*
 * Merge error information in "lr" with "parentr" error code and string.
 */
	if ( lr->lr_res_errno == LDAP_PARTIAL_RESULTS ) {
		parentr->lr_res_errno = lr->lr_res_errno;
		if ( lr->lr_res_error != NULL ) {
			(void)ldap_append_referral( ld, &parentr->lr_res_error,
			    lr->lr_res_error );
		}
	} else if ( lr->lr_res_errno != LDAP_SUCCESS &&
	    parentr->lr_res_errno == LDAP_SUCCESS ) {
		parentr->lr_res_errno = lr->lr_res_errno;
		if ( parentr->lr_res_error != NULL ) {
			LDAP_FREE( parentr->lr_res_error );
		}
		parentr->lr_res_error = lr->lr_res_error;
		lr->lr_res_error = NULL;
		if ( LDAP_NAME_ERROR( lr->lr_res_errno )) {
			if ( parentr->lr_res_matched != NULL ) {
				LDAP_FREE( parentr->lr_res_matched );
			}
			parentr->lr_res_matched = lr->lr_res_matched;
			lr->lr_res_matched = NULL;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, DETAIL1, "merged parent (id %d) error info:  ",
	    parentr->lr_msgid, 0, 0 );
	LDAP_LOG( OPERATION, DETAIL1, "result errno %d, error <%s>, matched <%s>\n",
	    parentr->lr_res_errno, parentr->lr_res_error ?
	    parentr->lr_res_error : "", parentr->lr_res_matched ?
	    parentr->lr_res_matched : "" );
#else
	Debug( LDAP_DEBUG_TRACE, "merged parent (id %d) error info:  ",
	    parentr->lr_msgid, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "result errno %d, error <%s>, matched <%s>\n",
	    parentr->lr_res_errno, parentr->lr_res_error ?
	    parentr->lr_res_error : "", parentr->lr_res_matched ?
	    parentr->lr_res_matched : "" );
#endif
}



int
ldap_msgtype( LDAPMessage *lm )
{
	assert( lm != NULL );
	return ( lm != NULL ) ? lm->lm_msgtype : -1;
}


int
ldap_msgid( LDAPMessage *lm )
{
	assert( lm != NULL );

	return ( lm != NULL ) ? lm->lm_msgid : -1;
}


char * ldap_int_msgtype2str( ber_tag_t tag )
{
	switch( tag ) {
	case LDAP_RES_ADD: return "add";
	case LDAP_RES_BIND: return "bind";
	case LDAP_RES_COMPARE: return "compare";
	case LDAP_RES_DELETE: return "delete";
	case LDAP_RES_EXTENDED: return "extended-result";
	case LDAP_RES_INTERMEDIATE: return "intermediate";
	case LDAP_RES_MODIFY: return "modify";
	case LDAP_RES_RENAME: return "rename";
	case LDAP_RES_SEARCH_ENTRY: return "search-entry";
	case LDAP_RES_SEARCH_REFERENCE: return "search-reference";
	case LDAP_RES_SEARCH_RESULT: return "search-result";
	}
	return "unknown";
}

int
ldap_msgfree( LDAPMessage *lm )
{
	LDAPMessage	*next;
	int		type = 0;

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_msgfree\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_msgfree\n", 0, 0, 0 );
#endif

	for ( ; lm != NULL; lm = next ) {
		next = lm->lm_chain;
		type = lm->lm_msgtype;
		ber_free( lm->lm_ber, 1 );
		LDAP_FREE( (char *) lm );
	}

	return( type );
}

/*
 * ldap_msgdelete - delete a message.  It returns:
 *	0	if the entire message was deleted
 *	-1	if the message was not found, or only part of it was found
 */
int
ldap_msgdelete( LDAP *ld, int msgid )
{
	LDAPMessage	*lm, *prev;
	int rc = 0;

	assert( ld != NULL );

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ENTRY, "ldap_msgdelete\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "ldap_msgdelete\n", 0, 0, 0 );
#endif

	prev = NULL;
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_lock( &ld->ld_res_mutex );
#endif
	for ( lm = ld->ld_responses; lm != NULL; lm = lm->lm_next ) {
		if ( lm->lm_msgid == msgid )
			break;
		prev = lm;
	}

	if ( lm == NULL ) {
		rc = -1;
	} else {
		if ( prev == NULL )
			ld->ld_responses = lm->lm_next;
		else
			prev->lm_next = lm->lm_next;
	}
#ifdef LDAP_R_COMPILE
	ldap_pvt_thread_mutex_unlock( &ld->ld_res_mutex );
#endif
	if ( lm && ldap_msgfree( lm ) == LDAP_RES_SEARCH_ENTRY )
		rc = -1;

	return( rc );
}


/*
 * return 1 if message msgid is waiting to be abandoned, 0 otherwise
 */
static int
ldap_abandoned( LDAP *ld, ber_int_t msgid )
{
	int	i;

	if ( ld->ld_abandoned == NULL )
		return( 0 );

	for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
		if ( ld->ld_abandoned[i] == msgid )
			return( 1 );

	return( 0 );
}


static int
ldap_mark_abandoned( LDAP *ld, ber_int_t msgid )
{
	int	i;

	if ( ld->ld_abandoned == NULL )
		return( -1 );

	for ( i = 0; ld->ld_abandoned[i] != -1; i++ )
		if ( ld->ld_abandoned[i] == msgid )
			break;

	if ( ld->ld_abandoned[i] == -1 )
		return( -1 );

	for ( ; ld->ld_abandoned[i] != -1; i++ ) {
		ld->ld_abandoned[i] = ld->ld_abandoned[i + 1];
	}

	return( 0 );
}
