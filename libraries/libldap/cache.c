/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1993 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  cache.c - local caching support for LDAP
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

#ifndef LDAP_NOCACHE

static int		cache_hash LDAP_P(( BerElement *ber ));
static LDAPMessage	*msg_dup LDAP_P(( LDAPMessage *msg ));
static int		request_cmp LDAP_P(( BerElement	*req1, BerElement *req2 ));
static int		chain_contains_dn LDAP_P(( LDAPMessage *msg, char *dn ));
static long		msg_size LDAP_P(( LDAPMessage *msg ));
static void		check_cache_memused LDAP_P(( LDAPCache *lc ));
static void		uncache_entry_or_req LDAP_P(( LDAP *ld, char *dn, int msgid ));

#endif

int
ldap_enable_cache( LDAP *ld, long timeout, long maxmem )
{
#ifndef LDAP_NOCACHE
	if ( ld->ld_cache == NULLLDCACHE ) {
		if (( ld->ld_cache = (LDAPCache *)malloc( sizeof( LDAPCache )))
		    == NULLLDCACHE ) {
			ld->ld_errno = LDAP_NO_MEMORY;
			return( -1 );
		}
		(void) memset( ld->ld_cache, 0, sizeof( LDAPCache ));
		ld->ld_cache->lc_memused = sizeof( LDAPCache );
	}

	ld->ld_cache->lc_timeout = timeout;
	ld->ld_cache->lc_maxmem = maxmem;
	check_cache_memused( ld->ld_cache );
	ld->ld_cache->lc_enabled = 1;
	return( 0 );
#else 
	return( -1 );
#endif
}


void
ldap_disable_cache( LDAP *ld )
{
#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULLLDCACHE ) {
		ld->ld_cache->lc_enabled = 0;
	}
#endif
}



void
ldap_set_cache_options( LDAP *ld, unsigned long opts )
{
#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULLLDCACHE ) {
		ld->ld_cache->lc_options = opts;
	}
#endif
}
	

void
ldap_destroy_cache( LDAP *ld )
{
#ifndef LDAP_NOCACHE
	if ( ld->ld_cache != NULLLDCACHE ) {
		ldap_flush_cache( ld );
		free( (char *)ld->ld_cache );
		ld->ld_cache = NULLLDCACHE;
	}
#endif
}


void
ldap_flush_cache( LDAP *ld )
{
#ifndef LDAP_NOCACHE
	int		i;
	LDAPMessage	*m, *next;

	Debug( LDAP_DEBUG_TRACE, "ldap_flush_cache\n", 0, 0, 0 );

	if ( ld->ld_cache != NULLLDCACHE ) {
		/* delete all requests in the queue */
		for ( m = ld->ld_cache->lc_requests; m != NULLMSG; m = next ) {
			next = m->lm_next;
			ldap_msgfree( m );
		}
		ld->ld_cache->lc_requests = NULLMSG;

		/* delete all messages in the cache */
		for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
			for ( m = ld->ld_cache->lc_buckets[ i ];
			    m != NULLMSG; m = next ) {
				next = m->lm_next;
				ldap_msgfree( m );
			}
			ld->ld_cache->lc_buckets[ i ] = NULLMSG;
		}
		ld->ld_cache->lc_memused = sizeof( LDAPCache );
	}
#endif
}


void
ldap_uncache_request( LDAP *ld, int msgid )
{
#ifndef LDAP_NOCACHE
	Debug( LDAP_DEBUG_TRACE, "ldap_uncache_request %d ld_cache %lx\n",
	    msgid, (long) ld->ld_cache, 0 );

	uncache_entry_or_req( ld, NULL, msgid );
#endif
}


void
ldap_uncache_entry( LDAP *ld, char *dn )
{
#ifndef LDAP_NOCACHE
	Debug( LDAP_DEBUG_TRACE, "ldap_uncache_entry %s ld_cache %lx\n",
	    dn, (long) ld->ld_cache, 0 );

	uncache_entry_or_req( ld, dn, 0 );
#endif
}


#ifndef LDAP_NOCACHE

static void
uncache_entry_or_req( LDAP *ld,
	char *dn,		/* if non-NULL, uncache entry */
	int msgid )		/* request to uncache (if dn == NULL) */
{
	int		i;
	LDAPMessage	*m, *prev, *next;

	Debug( LDAP_DEBUG_TRACE,
	    "ldap_uncache_entry_or_req  dn %s  msgid %d  ld_cache %lx\n",
	    dn, msgid, (long) ld->ld_cache );

	if ( ld->ld_cache == NULLLDCACHE ) {
	    return;
	}

	/* first check the request queue */
	prev = NULLMSG;
	for ( m = ld->ld_cache->lc_requests; m != NULLMSG; m = next ) {
		next = m->lm_next;
		if (( dn != NULL && chain_contains_dn( m, dn )) ||
			( dn == NULL && m->lm_msgid == msgid )) {
			if ( prev == NULLMSG ) {
				ld->ld_cache->lc_requests = next;
			} else {
				prev->lm_next = next;
			}
			ld->ld_cache->lc_memused -= msg_size( m );
			ldap_msgfree( m );
		} else {
			prev = m;
		}
	}

	/* now check the rest of the cache */
	for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
		prev = NULLMSG;
		for ( m = ld->ld_cache->lc_buckets[ i ]; m != NULLMSG;
		    m = next ) {
			next = m->lm_next;
			if (( dn != NULL && chain_contains_dn( m, dn )) ||
				( dn == NULL && m->lm_msgid == msgid )) {
				if ( prev == NULLMSG ) {
					ld->ld_cache->lc_buckets[ i ] = next;
				} else {
					prev->lm_next = next;
				}
				ld->ld_cache->lc_memused -= msg_size( m );
				ldap_msgfree( m );
			} else {
				prev = m;
			}
		}
	}
}

#endif

void
ldap_add_request_to_cache( LDAP *ld, unsigned long msgtype, BerElement *request )
{
#ifndef LDAP_NOCACHE
	LDAPMessage	*new;
	long		len;

	Debug( LDAP_DEBUG_TRACE, "ldap_add_request_to_cache\n", 0, 0, 0 );

	ld->ld_errno = LDAP_SUCCESS;
	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		return;
	}

	if (( new = (LDAPMessage *) calloc( 1, sizeof(LDAPMessage) ))
	    != NULL ) {
		if (( new->lm_ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
			free( (char *)new );
			return;
		}
		len = request->ber_ptr - request->ber_buf;
		if (( new->lm_ber->ber_buf = (char *) malloc( (size_t)len ))
		    == NULL ) {
			ber_free( new->lm_ber, 0 );
			free( (char *)new );
			ld->ld_errno = LDAP_NO_MEMORY;
			return;
		}
		SAFEMEMCPY( new->lm_ber->ber_buf, request->ber_buf,
		    (size_t)len );
		new->lm_ber->ber_ptr = new->lm_ber->ber_buf;
		new->lm_ber->ber_end = new->lm_ber->ber_buf + len;
		new->lm_msgid = ld->ld_msgid;
		new->lm_msgtype = msgtype;;
		new->lm_next = ld->ld_cache->lc_requests;
		ld->ld_cache->lc_requests = new;
	} else {
		ld->ld_errno = LDAP_NO_MEMORY;
	}
#endif
}


void
ldap_add_result_to_cache( LDAP *ld, LDAPMessage *result )
{
#ifndef LDAP_NOCACHE
	LDAPMessage	*m, **mp, *req, *new, *prev;
	int		err, keep;

	Debug( LDAP_DEBUG_TRACE, "ldap_add_result_to_cache: id %d, type %d\n", 
		result->lm_msgid, result->lm_msgtype, 0 );

	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		Debug( LDAP_DEBUG_TRACE, "artc: cache disabled\n", 0, 0, 0 );
		return;
	}

	if ( result->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
	    result->lm_msgtype != LDAP_RES_SEARCH_REFERENCE &&
	    result->lm_msgtype != LDAP_RES_SEARCH_RESULT &&
	    result->lm_msgtype != LDAP_RES_COMPARE ) {
		/*
		 * only cache search and compare operations
		 */
		Debug( LDAP_DEBUG_TRACE,
		    "artc: only caching search & compare operations\n", 0, 0, 0 );
		return;
	}

	/*
	 * if corresponding request is in the lc_requests list, add this
	 * result to it.  if this result completes the results for the
	 * request, add the request/result chain to the cache proper.
	 */
	prev = NULLMSG;
	for ( m = ld->ld_cache->lc_requests; m != NULL; m = m->lm_next ) {
		if ( m->lm_msgid == result->lm_msgid ) {
			break;
		}
		prev = m;
	}

	if ( m != NULLMSG ) {	/* found request; add to end of chain */
		req = m;
		for ( ; m->lm_chain != NULLMSG; m = m->lm_chain )
			;
		if (( new = msg_dup( result )) != NULLMSG ) {
			new->lm_chain = NULLMSG;
			m->lm_chain = new;
			Debug( LDAP_DEBUG_TRACE,
			    "artc: result added to cache request chain\n",
			    0, 0, 0 );
		}
		if ( result->lm_msgtype == LDAP_RES_SEARCH_RESULT ||
		    result->lm_msgtype == LDAP_RES_COMPARE ) {
			/*
			 * this result completes the chain of results
			 * add to cache proper if appropriate
			 */
			keep = 0;	/* pessimistic */
			err = ldap_result2error( ld, result, 0 );
			if ( err == LDAP_SUCCESS ||
			    ( result->lm_msgtype == LDAP_RES_COMPARE &&
			    ( err == LDAP_COMPARE_FALSE ||
			    err == LDAP_COMPARE_TRUE ||
			    err == LDAP_NO_SUCH_ATTRIBUTE ))) {
				keep = 1;
			}

			if ( ld->ld_cache->lc_options == 0 ) {
				if ( err == LDAP_SIZELIMIT_EXCEEDED ) {
				    keep = 1;
				}
			} else if (( ld->ld_cache->lc_options &
				LDAP_CACHE_OPT_CACHEALLERRS ) != 0 ) {
				keep = 1;
			}

			if ( prev == NULLMSG ) {
				ld->ld_cache->lc_requests = req->lm_next;
			} else {
				prev->lm_next = req->lm_next;
			}

			if ( !keep ) {
				Debug( LDAP_DEBUG_TRACE,
				    "artc: not caching result with error %d\n",
				    err, 0, 0 );
				ldap_msgfree( req );
			} else {
				mp = &ld->ld_cache->lc_buckets[
				    cache_hash( req->lm_ber ) ];
				req->lm_next = *mp;
				*mp = req;
				req->lm_time = (long) time( NULL );
				ld->ld_cache->lc_memused += msg_size( req );
				check_cache_memused( ld->ld_cache );
				Debug( LDAP_DEBUG_TRACE,
				    "artc: cached result with error %d\n",
				    err, 0, 0 );
			}
		}
	} else {
		Debug( LDAP_DEBUG_TRACE, "artc: msgid not in request list\n",
		    0, 0, 0 );
	}
#endif
}


/*
 * look in the cache for this request
 * return 0 if found, -1 if not
 * if found, the corresponding result messages are added to the incoming
 * queue with the correct (new) msgid so that subsequent ldap_result calls
 * will find them.
 */
int
ldap_check_cache( LDAP *ld, unsigned long msgtype, BerElement *request )
{
#ifndef LDAP_NOCACHE
	LDAPMessage	*m, *new, *prev, *next;
	BerElement	reqber;
	int		first, hash;
	unsigned long	validtime;

	Debug( LDAP_DEBUG_TRACE, "ldap_check_cache\n", 0, 0, 0 );

	if ( ld->ld_cache == NULLLDCACHE ||
	    ( ld->ld_cache->lc_enabled == 0 )) {
		return( -1 );
	}

	reqber.ber_buf = reqber.ber_ptr = request->ber_buf;
	reqber.ber_end = request->ber_ptr;

	validtime = (long)time( NULL ) - ld->ld_cache->lc_timeout;

	prev = NULLMSG;
	hash = cache_hash( &reqber );
	for ( m = ld->ld_cache->lc_buckets[ hash ]; m != NULLMSG; m = next ) {
		Debug( LDAP_DEBUG_TRACE,"cc: examining id %d,type %d\n",
		    m->lm_msgid, m->lm_msgtype, 0 );
		if ( m->lm_time < validtime ) {
			/* delete expired message */
			next = m->lm_next;
			if ( prev == NULL ) {
				ld->ld_cache->lc_buckets[ hash ] = next;
			} else {
				prev->lm_next = next;
			}
			Debug( LDAP_DEBUG_TRACE, "cc: expired id %d\n",
			    m->lm_msgid, 0, 0 );
			ld->ld_cache->lc_memused -= msg_size( m );
			ldap_msgfree( m );
		} else {
		    if ( m->lm_msgtype == (int)msgtype &&
			request_cmp( m->lm_ber, &reqber ) == 0 ) {
			    break;
		    }
		    next = m->lm_next;
		    prev = m;
		}
	}

	if ( m == NULLMSG ) {
		return( -1 );
	}

	/*
	 * add duplicates of responses to incoming queue
	 */
	first = 1;
	for ( m = m->lm_chain; m != NULLMSG; m = m->lm_chain ) {
		if (( new = msg_dup( m )) == NULLMSG ) {
			return( -1 );
		}

		new->lm_msgid = ld->ld_msgid;
		new->lm_chain = NULLMSG;
		if ( first ) {
			new->lm_next = ld->ld_responses;
			ld->ld_responses = new;
			first = 0;
		} else {
			prev->lm_chain = new;
		}
		prev = new;
		Debug( LDAP_DEBUG_TRACE, "cc: added type %d\n",
		    new->lm_msgtype, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "cc: result returned from cache\n", 0, 0, 0 );
	return( 0 );
#else
	return( -1 );
#endif
}

#ifndef LDAP_NOCACHE

static int
cache_hash( BerElement *ber )
{
	BerElement	bercpy;
	unsigned long	len;

	/*
         * just take the length of the packet and mod with # of buckets
	 */
	bercpy = *ber;
	if ( ber_skip_tag( &bercpy, &len ) == LBER_ERROR
		|| ber_scanf( &bercpy, "x" ) == LBER_ERROR ) {
	    len = 0;	/* punt: just return zero */
	} else {
	    len = bercpy.ber_end - bercpy.ber_ptr;
	}

	Debug( LDAP_DEBUG_TRACE, "cache_hash: len is %ld, returning %ld\n",
	    len, len % LDAP_CACHE_BUCKETS, 0 );
	return( (int) ( len % LDAP_CACHE_BUCKETS ));
}


static LDAPMessage *
msg_dup( LDAPMessage *msg )
{
	LDAPMessage	*new;
	long		len;

	if (( new = (LDAPMessage *)malloc( sizeof(LDAPMessage))) != NULL ) {
		*new = *msg;	/* struct copy */
		if (( new->lm_ber = ber_dup( msg->lm_ber )) == NULLBER ) {
			free( (char *)new );
			return( NULLMSG );
		}
		len = msg->lm_ber->ber_end - msg->lm_ber->ber_buf;
		if (( new->lm_ber->ber_buf = (char *) malloc(
		    (size_t)len )) == NULL ) {
			ber_free( new->lm_ber, 0 );
			free( (char *)new );
			return( NULLMSG );
		}
		SAFEMEMCPY( new->lm_ber->ber_buf, msg->lm_ber->ber_buf,
		    (size_t)len );
		new->lm_ber->ber_ptr = new->lm_ber->ber_buf +
			( msg->lm_ber->ber_ptr - msg->lm_ber->ber_buf );
		new->lm_ber->ber_end = new->lm_ber->ber_buf + len;
	}

	return( new );
}


static int
request_cmp( BerElement *req1, BerElement *req2 )
{
	unsigned long	len;
	BerElement	r1, r2;

	r1 = *req1;	/* struct copies */
	r2 = *req2;

	/*
	 * skip the enclosing tags (sequence markers) and the msg ids
	 */
	if ( ber_skip_tag( &r1, &len ) == LBER_ERROR || ber_scanf( &r1, "x" )
	    == LBER_ERROR ) {
	    return( -1 );
	}
	if ( ber_skip_tag( &r2, &len ) == LBER_ERROR || ber_scanf( &r2, "x" ) 
	    == LBER_ERROR ) {
	    return( -1 );
	}

	/*
	 * check remaining length and bytes if necessary
	 */
	if (( len = r1.ber_end - r1.ber_ptr ) !=
		(unsigned long) (r2.ber_end - r2.ber_ptr) )
	{
		return( -1 );	/* different lengths */
	}
	return( memcmp( r1.ber_ptr, r2.ber_ptr, (size_t)len ));
}	


static int
chain_contains_dn( LDAPMessage *msg, char *dn )
{
	LDAPMessage	*m;
	BerElement	ber;
	long		msgid;
	char		*s;
	int		rc;


	/*
	 * first check the base or dn of the request
	 */
	ber = *msg->lm_ber;	/* struct copy */
	if ( ber_scanf( &ber, "{i{a", &msgid, &s ) != LBER_ERROR ) {
	    rc = ( strcasecmp( dn, s ) == 0 ) ? 1 : 0;
	    free( s );
	    if ( rc != 0 ) {
		return( rc );
	    }
	}

	if ( msg->lm_msgtype == LDAP_REQ_COMPARE ) {
		return( 0 );
	}

	/*
	 * now check the dn of each search result
	 */
	rc = 0;
	for ( m = msg->lm_chain; m != NULLMSG && rc == 0 ; m = m->lm_chain ) {
		if ( m->lm_msgtype != LDAP_RES_SEARCH_ENTRY ) {
			continue;
		}
		ber = *m->lm_ber;	/* struct copy */
		if ( ber_scanf( &ber, "{a", &s ) != LBER_ERROR ) {
			rc = ( strcasecmp( dn, s ) == 0 ) ? 1 : 0;
			free( s );
		}
	}

	return( rc );
}


static long
msg_size( LDAPMessage *msg )
{
	LDAPMessage	*m;
	long		size;

	size = 0;
	for ( m = msg; m != NULLMSG; m = m->lm_chain ) {
		size += ( sizeof( LDAPMessage ) + m->lm_ber->ber_end -
		    m->lm_ber->ber_buf );
	}

	return( size );
}


#define THRESHOLD_FACTOR	3 / 4
#define SIZE_FACTOR		2 / 3

static void
check_cache_memused( LDAPCache *lc )
{
/*
 * this routine is called to check if the cache is too big (lc_maxmem >
 * minimum cache size and lc_memused > lc_maxmem).  If too big, it reduces
 * the cache size to < SIZE_FACTOR * lc_maxmem. The algorithm is as follows:
 *    remove_threshold = lc_timeout seconds;
 *    do {
 *        remove everything older than remove_threshold seconds;
 *        remove_threshold = remove_threshold * THRESHOLD_FACTOR;
 *    } while ( cache size is > SIZE_FACTOR * lc_maxmem )
 */
	int		i;
	unsigned long	remove_threshold, validtime;
	LDAPMessage	*m, *prev, *next;

	Debug( LDAP_DEBUG_TRACE, "check_cache_memused: %ld bytes in use (%ld max)\n",
	    lc->lc_memused, lc->lc_maxmem, 0 );

	if ( lc->lc_maxmem <= sizeof( LDAPCache )
	    || lc->lc_memused <= lc->lc_maxmem * SIZE_FACTOR ) {
		return;
	}

	remove_threshold = lc->lc_timeout;
	while ( lc->lc_memused > lc->lc_maxmem * SIZE_FACTOR ) {
		validtime = (long)time( NULL ) - remove_threshold;
		for ( i = 0; i < LDAP_CACHE_BUCKETS; ++i ) {
			prev = NULLMSG;
			for ( m = lc->lc_buckets[ i ]; m != NULLMSG;
			    m = next ) {
				next = m->lm_next;
				if ( m->lm_time < validtime ) {
					if ( prev == NULLMSG ) {
						lc->lc_buckets[ i ] = next;
					} else {
						prev->lm_next = next;
					}
					lc->lc_memused -= msg_size( m );
					Debug( LDAP_DEBUG_TRACE,
					    "ccm: removed %d\n",
					    m->lm_msgid, 0, 0 );
					ldap_msgfree( m );
				} else {
					prev = m;
				}
			}
		}
		remove_threshold *= THRESHOLD_FACTOR;
	}

	Debug( LDAP_DEBUG_TRACE, "ccm: reduced usage to %ld bytes\n",
	    lc->lc_memused, 0, 0 );
}

#endif /* !NO_CACHE */
