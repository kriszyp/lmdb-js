/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  result.c - wait for an ldap result
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"


static int ldap_abandoned LDAP_P(( LDAP *ld, int msgid ));
static int ldap_mark_abandoned LDAP_P(( LDAP *ld, int msgid ));
static int wait4msg LDAP_P(( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result ));
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
static int try_read1msg LDAP_P(( LDAP *ld, int msgid, int all, Sockbuf *sb, LDAPConn *lc,
	LDAPMessage **result ));
static unsigned long build_result_ber LDAP_P(( LDAP *ld, BerElement *ber, LDAPRequest *lr ));
static void merge_error_info LDAP_P(( LDAP *ld, LDAPRequest *parentr, LDAPRequest *lr ));
#else /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
static int try_read1msg LDAP_P(( LDAP *ld, int msgid, int all, Sockbuf *sb,
	LDAPMessage **result ));
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
#if defined( LDAP_CONNECTIONLESS ) || !defined( LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS )
static int ldap_select1 LDAP_P(( LDAP *ld, struct timeval *timeout ));
#endif


/*
 * ldap_result - wait for an ldap result response to a message from the
 * ldap server.  If msgid is -1, any message will be accepted, otherwise
 * ldap_result will wait for a response with msgid.  If all is 0 the
 * first message with id msgid will be accepted, otherwise, ldap_result
 * will wait for all responses with id msgid and then return a pointer to
 * the entire list of messages.  This is only useful for search responses,
 * which can be of two message types (zero or more entries, followed by an
 * ldap result).  The type of the first message received is returned.
 * When waiting, any messages that have been abandoned are discarded.
 *
 * Example:
 *	ldap_result( s, msgid, all, timeout, result )
 */
int
ldap_result( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result )
{
	LDAPMessage	*lm, *lastlm, *nextlm;

	/*
	 * First, look through the list of responses we have received on
	 * this association and see if the response we're interested in
	 * is there.  If it is, return it.  If not, call wait4msg() to
	 * wait until it arrives or timeout occurs.
	 */

	Debug( LDAP_DEBUG_TRACE, "ldap_result\n", 0, 0, 0 );

	*result = NULLMSG;
	lastlm = NULLMSG;
	for ( lm = ld->ld_responses; lm != NULLMSG; lm = nextlm ) {
		nextlm = lm->lm_next;

		if ( ldap_abandoned( ld, lm->lm_msgid ) ) {
			ldap_mark_abandoned( ld, lm->lm_msgid );

			if ( lastlm == NULLMSG ) {
				ld->ld_responses = lm->lm_next;
			} else {
				lastlm->lm_next = nextlm;
			}

			ldap_msgfree( lm );

			continue;
		}

		if ( msgid == LDAP_RES_ANY || lm->lm_msgid == msgid ) {
			LDAPMessage	*tmp;

			if ( all == 0
			    || (lm->lm_msgtype != LDAP_RES_SEARCH_RESULT
			    && lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE	/* LDAPv3 */
			    && lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY) )
				break;

			for ( tmp = lm; tmp != NULLMSG; tmp = tmp->lm_chain ) {
				if ( tmp->lm_msgtype == LDAP_RES_SEARCH_RESULT )
					break;
			}

			if ( tmp == NULLMSG ) {
				return( wait4msg( ld, msgid, all, timeout,
				    result ) );
			}

			break;
		}
		lastlm = lm;
	}
	if ( lm == NULLMSG ) {
		return( wait4msg( ld, msgid, all, timeout, result ) );
	}

	if ( lastlm == NULLMSG ) {
		ld->ld_responses = (all == 0 && lm->lm_chain != NULLMSG
		    ? lm->lm_chain : lm->lm_next);
	} else {
		lastlm->lm_next = (all == 0 && lm->lm_chain != NULLMSG
		    ? lm->lm_chain : lm->lm_next);
	}
	if ( all == 0 )
		lm->lm_chain = NULLMSG;
	lm->lm_next = NULLMSG;

	*result = lm;
	ld->ld_errno = LDAP_SUCCESS;
	return( lm->lm_msgtype );
}

static int
wait4msg( LDAP *ld, int msgid, int all, struct timeval *timeout,
	LDAPMessage **result )
{
	int		rc;
	struct timeval	tv, *tvp;
	time_t		start_time = 0;
	time_t		tmp_time;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	LDAPConn	*lc, *nextlc;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

#ifdef LDAP_DEBUG
	if ( timeout == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "wait4msg (infinite timeout)\n",
		    0, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "wait4msg (timeout %ld sec, %ld usec)\n",
		       (long) timeout->tv_sec, (long) timeout->tv_usec, 0 );
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
#ifndef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
		/* hack attack */
		if ( ! ber_pvt_sb_data_ready(&ld->ld_sb) ) {
			rc = ldap_select1( ld, tvp );

			if ( rc == 0 || ( rc == -1 && (
				( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_RESTART)
					== LDAP_OPT_OFF )
			    || errno != EINTR ))) {
				ld->ld_errno = (rc == -1 ? LDAP_SERVER_DOWN :
				    LDAP_TIMEOUT);
				return( rc );
			}

		}
		if ( rc == -1 ) {
			rc = -2;	/* select interrupted: loop */
		} else {
			rc = try_read1msg( ld, msgid, all, &ld->ld_sb, result );
		}
#else /* !LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_TRACE ) {
			ldap_dump_connection( ld, ld->ld_conns, 1 );
			ldap_dump_requests_and_responses( ld );
		}
#endif /* LDAP_DEBUG */
		for ( lc = ld->ld_conns; lc != NULL; lc = lc->lconn_next ) {
			if ( ber_pvt_sb_data_ready(lc->lconn_sb) ) {
				rc = try_read1msg( ld, msgid, all, lc->lconn_sb,
				    lc, result );
				break;
			}
		}

		if ( lc == NULL ) {
			rc = do_ldap_select( ld, tvp );


#ifdef LDAP_DEBUG
			if ( rc == -1 ) {
			    Debug( LDAP_DEBUG_TRACE,
				    "do_ldap_select returned -1: errno %d\n",
				    errno, 0, 0 );
			}
#endif

			if ( rc == 0 || ( rc == -1 && (
				( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_RESTART)
					== LDAP_OPT_OFF )
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
				for ( lc = ld->ld_conns; rc == -2 && lc != NULL;
				    lc = nextlc ) {
					nextlc = lc->lconn_next;
					if ( lc->lconn_status ==
					    LDAP_CONNST_CONNECTED &&
					    ldap_is_read_ready( ld,
					    lc->lconn_sb )) {
						rc = try_read1msg( ld, msgid, all,
						    lc->lconn_sb, lc, result );
					}
				}
			}
		}
#endif /* !LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

		if ( rc == -2 && tvp != NULL ) {
			tmp_time = time( NULL );
			if (( tv.tv_sec -=  ( tmp_time - start_time )) <= 0 ) {
				rc = 0;	/* timed out */
				ld->ld_errno = LDAP_TIMEOUT;
				break;
			}

			Debug( LDAP_DEBUG_TRACE, "wait4msg:  %ld secs to go\n",
			       (long) tv.tv_sec, 0, 0 );
			start_time = tmp_time;
		}
	}

	return( rc );
}


static int
try_read1msg( LDAP *ld, int msgid, int all, Sockbuf *sb,
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
    LDAPConn *lc,
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
    LDAPMessage **result )
{
	BerElement	*ber;
	LDAPMessage	*new, *l, *prev, *tmp;
	long		id;
	unsigned long	tag, len;
	int		foundit = 0;
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	LDAPRequest	*lr;
	BerElement	tmpber;
	int		rc, refer_cnt, hadref, simple_request;
	unsigned long	lderr;
	
	ber = &lc->lconn_ber;
#else
	ber = &ld->ld_ber;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	Debug( LDAP_DEBUG_TRACE, "read1msg\n", 0, 0, 0 );
#if 0
	ber_init_w_nullc( &ber, 0 );
	ldap_set_ber_options( ld, &ber );
#endif
	/* get the next message */
	if ( (tag = ber_get_next( sb, &len, ber ))
	    != LDAP_TAG_MESSAGE ) {
		if ( tag == LBER_DEFAULT) {
#ifdef LDAP_DEBUG		   
			Debug( LDAP_DEBUG_CONNS,
			      "ber_get_next failed.\n", 0, 0, 0 );
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
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( -1 );
	}

	/* if it's been abandoned, toss it */
	if ( ldap_abandoned( ld, (int)id ) ) {
		ber_clear( ber, 1 );	/* gack! */
		return( -2 );	/* continue looking */
	}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	if (( lr = ldap_find_request_by_msgid( ld, id )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "no request for response with msgid %ld (tossing)\n",
		    id, 0, 0 );
		ber_clear( ber, 1 );	/* gack! */
		return( -2 );	/* continue looking */
	}
	Debug( LDAP_DEBUG_TRACE, "ldap_read: %s msgid %ld, original id %d\n",
	    ( tag == LDAP_RES_SEARCH_ENTRY ) ? "entry" : 
		( tag == LDAP_RES_SEARCH_REFERENCE ) ? "reference" : "result",
		id, lr->lr_origid );
	id = lr->lr_origid;
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */

	/* the message type */
	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
		return( -1 );
	}

#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
	refer_cnt = 0;
	hadref = simple_request = 0;
	rc = -2;	/* default is to keep looking (no response found) */
	lr->lr_res_msgtype = tag;

	if ( tag != LDAP_RES_SEARCH_ENTRY ) {
		if ( ld->ld_version >= LDAP_VERSION2 &&
			( lr->lr_parent != NULL ||
			( LDAP_BOOL_GET(&ld->ld_options, LDAP_BOOL_REFERRALS)
				!= LDAP_OPT_OFF ) ) )
		{
			tmpber = *ber;	/* struct copy */
			if ( ber_scanf( &tmpber, "{iaa}", &lderr,
			    &lr->lr_res_matched, &lr->lr_res_error )
			    != LBER_ERROR ) {
				if ( lderr != LDAP_SUCCESS ) {
					/* referrals are in error string */
					refer_cnt = ldap_chase_referrals( ld, lr,
					    &lr->lr_res_error, &hadref );
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
Debug( LDAP_DEBUG_TRACE,
    "new result:  res_errno: %d, res_error: <%s>, res_matched: <%s>\n",
    lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
    lr->lr_res_matched ? lr->lr_res_matched : "" );
			}
		}

		Debug( LDAP_DEBUG_TRACE,
		    "read1msg:  %d new referrals\n", refer_cnt, 0, 0 );

		if ( refer_cnt != 0 ) {	/* chasing referrals */
			ber_clear( ber, 1 );	/* gack! */
			if ( refer_cnt < 0 ) {
				return( -1 );	/* fatal error */
			}
			lr->lr_status = LDAP_REQST_CHASINGREFS;
		} else {
			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL ) {
				/* request without any referrals */
				simple_request = ( hadref ? 0 : 1 );
			} else {
				/* request with referrals or child request */
				ber_clear( ber, 1 );	/* gack! */
			}

			while ( lr->lr_parent != NULL ) {
				merge_error_info( ld, lr->lr_parent, lr );

				lr = lr->lr_parent;
				if ( --lr->lr_outrefcnt > 0 ) {
					break;	/* not completely done yet */
				}
			}

			if ( lr->lr_outrefcnt <= 0 && lr->lr_parent == NULL ) {
				id = lr->lr_msgid;
				tag = lr->lr_res_msgtype;
				Debug( LDAP_DEBUG_ANY, "request %ld done\n",
				    id, 0, 0 );
Debug( LDAP_DEBUG_TRACE,
"res_errno: %d, res_error: <%s>, res_matched: <%s>\n",
lr->lr_res_errno, lr->lr_res_error ? lr->lr_res_error : "",
lr->lr_res_matched ? lr->lr_res_matched : "" );
				if ( !simple_request ) {
					ber_clear( ber, 1 ); /* gack! */
					if ( build_result_ber( ld, ber, lr )
					    == LBER_ERROR ) {
						ld->ld_errno = LDAP_NO_MEMORY;
						rc = -1; /* fatal error */
					}
				}

				ldap_free_request( ld, lr );
			}

			if ( lc != NULL ) {
				ldap_free_connection( ld, lc, 0, 1 );
			}
		}
	}

	if ( ber->ber_buf == NULL ) {
		return( rc );
	}

#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */
	/* make a new ldap message */
	if ( (new = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) ))
	    == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}
	new->lm_msgid = (int)id;
	new->lm_msgtype = tag;
	new->lm_ber = ber_dup( ber );
	ber_clear( ber, 0 ); /* don't kill buffer */

#ifndef LDAP_NOCACHE
		if ( ld->ld_cache != NULL ) {
			ldap_add_result_to_cache( ld, new );
		}
#endif /* LDAP_NOCACHE */

	/* is this the one we're looking for? */
	if ( msgid == LDAP_RES_ANY || id == msgid ) {
		if ( all == 0
		    || (new->lm_msgtype != LDAP_RES_SEARCH_RESULT
		    && new->lm_msgtype != LDAP_RES_SEARCH_ENTRY) ) {
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

	prev = NULLMSG;
	for ( l = ld->ld_responses; l != NULLMSG; l = l->lm_next ) {
		if ( l->lm_msgid == new->lm_msgid )
			break;
		prev = l;
	}

	/* not part of an existing search response */
	if ( l == NULLMSG ) {
		if ( foundit ) {
			*result = new;
			ld->ld_errno = LDAP_SUCCESS;
			return( tag );
		}

		new->lm_next = ld->ld_responses;
		ld->ld_responses = new;
		return( -2 );	/* continue looking */
	}

	Debug( LDAP_DEBUG_TRACE, "adding response id %d type %d:\n",
	    new->lm_msgid, new->lm_msgtype, 0 );

	/* part of a search response - add to end of list of entries */
	for ( tmp = l; tmp->lm_chain != NULLMSG &&
	    tmp->lm_chain->lm_msgtype == LDAP_RES_SEARCH_ENTRY;
	    tmp = tmp->lm_chain )
		;	/* NULL */
	tmp->lm_chain = new;

	/* return the whole chain if that's what we were looking for */
	if ( foundit ) {
		if ( prev == NULLMSG )
			ld->ld_responses = l->lm_next;
		else
			prev->lm_next = l->lm_next;
		*result = l;
		ld->ld_errno = LDAP_SUCCESS;
#ifdef LDAP_WORLD_P16
		/*
		 * XXX questionable fix; see text for [P16] on
		 * http://www.critical-angle.com/ldapworld/patch/
		 *
		 * inclusion of this patch causes searchs to hang on
		 * multiple platforms
		 */
		return( l->lm_msgtype );
#else	/* LDAP_WORLD_P16 */
		return( tag );
#endif	/* !LDAP_WORLD_P16 */
	}

	return( -2 );	/* continue looking */
}


#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS
static unsigned long
build_result_ber( LDAP *ld, BerElement *ber, LDAPRequest *lr )
{
	unsigned long	len;
	long		along;

	ber_init_w_nullc( ber, 0 );
	ldap_set_ber_options( ld, ber );
	if ( ber_printf( ber, "{it{ess}}", lr->lr_msgid,
	    (long)lr->lr_res_msgtype, lr->lr_res_errno,
	    lr->lr_res_matched ? lr->lr_res_matched : "",
	    lr->lr_res_error ? lr->lr_res_error : "" ) == -1 ) {
		return( LBER_ERROR );
	}

	ber_reset( ber, 1 );
	if ( ber_skip_tag( ber, &len ) == LBER_ERROR ) {
		return( LBER_ERROR );
	}

	if ( ber_get_int( ber, &along ) == LBER_ERROR ) {
		return( LBER_ERROR );
	}

	return( ber_peek_tag( ber, &len ));
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
			free( parentr->lr_res_error );
		}
		parentr->lr_res_error = lr->lr_res_error;
		lr->lr_res_error = NULL;
		if ( LDAP_NAME_ERROR( lr->lr_res_errno )) {
			if ( parentr->lr_res_matched != NULL ) {
				free( parentr->lr_res_matched );
			}
			parentr->lr_res_matched = lr->lr_res_matched;
			lr->lr_res_matched = NULL;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "merged parent (id %d) error info:  ",
	    parentr->lr_msgid, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "result errno %d, error <%s>, matched <%s>\n",
	    parentr->lr_res_errno, parentr->lr_res_error ?
	    parentr->lr_res_error : "", parentr->lr_res_matched ?
	    parentr->lr_res_matched : "" );
}
#endif /* LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */



#if defined( LDAP_CONNECTIONLESS ) || !defined( LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS )

static int
ldap_select1( LDAP *ld, struct timeval *timeout )
{
	fd_set		readfds;
	static int	tblsize;

	if ( tblsize == 0 ) {
#ifdef HAVE_SYSCONF
		tblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
		tblsize = getdtablesize();
#else
		tblsize = FD_SETSIZE;
#endif
#ifdef FD_SETSIZE
		if ( tblsize > FD_SETSIZE ) {
			tblsize = FD_SETSIZE;
		}
#endif	/* FD_SETSIZE */
	}

	FD_ZERO( &readfds );
	FD_SET( ber_pvt_sb_get_desc(&ld->ld_sb), &readfds );

	return( select( tblsize, &readfds, 0, 0, timeout ) );
}

#endif /* !LDAP_API_FEATURE_X_OPENLDAP_V2_REFERRALS */


int
ldap_msgtype( LDAPMessage *lm )
{
	return( lm ? lm->lm_msgtype : -1 );
}

int
ldap_msgid( LDAPMessage *lm )
{
	return( lm ? lm->lm_msgid : -1 );
}


int
ldap_msgfree( LDAPMessage *lm )
{
	LDAPMessage	*next;
	int		type = 0;

	Debug( LDAP_DEBUG_TRACE, "ldap_msgfree\n", 0, 0, 0 );

	for ( ; lm != NULLMSG; lm = next ) {
		next = lm->lm_chain;
		type = lm->lm_msgtype;
		ber_free( lm->lm_ber, 1 );
		free( (char *) lm );
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

	Debug( LDAP_DEBUG_TRACE, "ldap_msgdelete\n", 0, 0, 0 );

	prev = NULLMSG;
	for ( lm = ld->ld_responses; lm != NULLMSG; lm = lm->lm_next ) {
		if ( lm->lm_msgid == msgid )
			break;
		prev = lm;
	}

	if ( lm == NULLMSG )
		return( -1 );

	if ( prev == NULLMSG )
		ld->ld_responses = lm->lm_next;
	else
		prev->lm_next = lm->lm_next;

	if ( ldap_msgfree( lm ) == LDAP_RES_SEARCH_ENTRY )
		return( -1 );

	return( 0 );
}


/*
 * return 1 if message msgid is waiting to be abandoned, 0 otherwise
 */
static int
ldap_abandoned( LDAP *ld, int msgid )
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
ldap_mark_abandoned( LDAP *ld, int msgid )
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


#ifdef LDAP_CONNECTIONLESS
int
cldap_getmsg( LDAP *ld, struct timeval *timeout, BerElement *ber )
{
	int		rc;
	unsigned long	tag, len;

	if ( ! ber_pvt_sb_data_ready(&ld->ld_sb) ) {
		rc = ldap_select1( ld, timeout );
		if ( rc == -1 || rc == 0 ) {
			ld->ld_errno = (rc == -1 ? LDAP_SERVER_DOWN :
			    LDAP_TIMEOUT);
			return( rc );
		}
	}

	/* get the next message */
	if ( (tag = ber_get_next( &ld->ld_sb, &len, ber ))
	    != LDAP_TAG_MESSAGE ) {
		ld->ld_errno = (tag == LBER_DEFAULT ? LDAP_SERVER_DOWN :
		    LDAP_LOCAL_ERROR);
		return( -1 );
	}

	return( tag );
}
#endif /* LDAP_CONNECTIONLESS */
