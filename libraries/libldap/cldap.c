/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990, 1994 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  cldap.c - synchronous, retrying interface to the cldap protocol
 */

#include "portable.h"

#ifdef LDAP_CONNECTIONLESS

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"

#define DEF_CLDAP_TIMEOUT	3
#define DEF_CLDAP_TRIES		4


struct cldap_retinfo {
	int		cri_maxtries;
	int		cri_try;
	int		cri_useaddr;
	long		cri_timeout;
};

static int add_addr LDAP_P((
	LDAP *ld, struct sockaddr *sap ));
static int cldap_result LDAP_P((
	LDAP *ld, int msgid, LDAPMessage **res,
	struct cldap_retinfo *crip, const char *base ));
static int cldap_parsemsg LDAP_P((
	LDAP *ld, int msgid, BerElement *ber,
	LDAPMessage **res, const char *base ));

/*
 * cldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 *
 * Example:
 *	LDAP	*ld;
 *	ld = cldap_open( hostname, port );
 */

LDAP *
cldap_open( LDAP_CONST char *host, int port )
{
    int 		s;
    unsigned long	address;
    struct sockaddr_in 	sock;
    struct hostent	*hp;
    LDAP		*ld;
    char		*p;
    int			i;

    /* buffers for ldap_pvt_gethostbyname_a ... */
    struct hostent      he_buf;
    int                 local_h_errno;
    char		*ha_buf=NULL;

#define DO_RETURN(x) if (ha_buf) LDAP_FREE(ha_buf); return (x);
   
    Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

    if ( (s = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ) {
	return( NULL );
    }

    sock.sin_addr.s_addr = 0;
    sock.sin_family = AF_INET;
    sock.sin_port = 0;
    if ( bind(s, (struct sockaddr *) &sock, sizeof(sock)) < 0)  {
	tcp_close( s );
	return( NULL );
    }
    if (( ld = ldap_init( host, port )) == NULL ) {
	tcp_close( s );
	return( NULL );
    }
	
    ld->ld_cldapnaddr = 0;
    ld->ld_cldapaddrs = NULL;

    if (ber_pvt_sb_set_io( &(ld->ld_sb), &ber_pvt_sb_io_udp, NULL )<0) {
       ldap_ld_free(ld, 1, NULL, NULL );
       return NULL;
    }
	
    ld->ld_version = LDAP_VERSION2;

    sock.sin_family = AF_INET;
    sock.sin_port = htons( port );

    /*
     * 'host' may be a space-separated list.
     */
    if ( host != NULL ) {
	char *host_dup = LDAP_STRDUP( host );
	host = host_dup;
	for ( ; host != NULL; host = p ) {
	    if (( p = strchr( host, ' ' )) != NULL ) {
		for (*p++ = '\0'; *p == ' '; p++) {
		    ;
		}
	    }

	    address = inet_addr( host );
	    /* This was just a test for -1 until OSF1 let inet_addr return
	       unsigned int, which is narrower than 'unsigned long address' */
	    if ( address == 0xffffffff || address == (unsigned long) -1 ) {
	        if ((ldap_pvt_gethostbyname_a( host, &he_buf, &ha_buf,
					      &hp,&local_h_errno)<0) || 
		    (hp==NULL)) {
		   errno = EHOSTUNREACH;
		   continue;
		}

		for ( i = 0; hp->h_addr_list[ i ] != 0; ++i ) {
		    SAFEMEMCPY( (char *)&sock.sin_addr,
			    (char *)hp->h_addr_list[ i ],
			    sizeof(sock.sin_addr));
		    if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
			ldap_ld_free( ld, 1, NULL, NULL );
			LDAP_FREE( host_dup );
			DO_RETURN( NULL );
		    }
		}

	    } else {
		sock.sin_addr.s_addr = address;
		if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
		    ldap_ld_free( ld, 1, NULL, NULL );
		    LDAP_FREE( host_dup );
		    DO_RETURN( NULL );
		}
	    }

	    if ( ld->ld_host == NULL ) {
		    ld->ld_host = LDAP_STRDUP( host );
	    }
	}
	LDAP_FREE( host_dup );
    } else {
	sock.sin_addr.s_addr = htonl( INADDR_LOOPBACK );
	if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
	    ldap_ld_free( ld, 1, NULL, NULL );
	    DO_RETURN( NULL );
	}
    }

    if ( ld->ld_cldapaddrs == NULL
	    || ( ld->ld_defconn = ldap_new_connection( ld, NULL, 1,0,0 )) == NULL
	    ) {
	ldap_ld_free( ld, 0, NULL, NULL );
	DO_RETURN( NULL );
    }

    ber_pvt_sb_udp_set_dst( &ld->ld_sb, ld->ld_cldapaddrs[0] );

    cldap_setretryinfo( ld, 0, 0 );

#ifdef LDAP_DEBUG
    putchar( '\n' );
    for ( i = 0; i < ld->ld_cldapnaddr; ++i ) {
	Debug( LDAP_DEBUG_TRACE, "end of cldap_open address %d is %s\n",
		i, inet_ntoa( ((struct sockaddr_in *)
		ld->ld_cldapaddrs[ i ])->sin_addr ), 0 );
    }
#endif

    DO_RETURN( ld );
}

#undef DO_RETURN

void
cldap_close( LDAP *ld )
{
	ldap_ld_free( ld, 0, NULL, NULL );
}


void
cldap_setretryinfo( LDAP *ld, int tries, int timeout )
{
    ld->ld_cldaptries = ( tries <= 0 ) ? DEF_CLDAP_TRIES : tries;
    ld->ld_cldaptimeout = ( timeout <= 0 ) ? DEF_CLDAP_TIMEOUT : timeout;
}


int
cldap_search_s( LDAP *ld,
	LDAP_CONST char *base,
	int scope,
	LDAP_CONST char *filter,
	char **attrs,
	int attrsonly,
	LDAPMessage **res,
	char *logdn )
{
    int				ret, msgid;
    struct cldap_retinfo	cri;

    *res = NULL;

    (void) memset( &cri, 0, sizeof( cri ));

    if ( logdn != NULL ) {
	ld->ld_cldapdn = logdn;
    } else if ( ld->ld_cldapdn == NULL ) {
	ld->ld_cldapdn = "";
    }

    do {
	if ( cri.cri_try != 0 ) {
		--ld->ld_msgid;	/* use same id as before */
	}
	    
	ber_pvt_sb_udp_set_dst( &(ld->ld_sb), 
			ld->ld_cldapaddrs[ cri.cri_useaddr ] );

	Debug( LDAP_DEBUG_TRACE, "cldap_search_s try %d (to %s)\n",
	    cri.cri_try, inet_ntoa( ((struct sockaddr_in *)
	    ld->ld_cldapaddrs[ cri.cri_useaddr ])->sin_addr), 0 );

	    if ( (msgid = ldap_search( ld, base, scope, filter, attrs,
		attrsonly )) == -1 ) {
		    return( ld->ld_errno );
	    }
#ifndef LDAP_NOCACHE
	    if ( ld->ld_cache != NULL && ld->ld_responses != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "cldap_search_s res from cache\n",
			0, 0, 0 );
		*res = ld->ld_responses;
		ld->ld_responses = ld->ld_responses->lm_next;
		return( ldap_result2error( ld, *res, 0 ));
	    }
#endif /* LDAP_NOCACHE */
	    ret = cldap_result( ld, msgid, res, &cri, base );
	} while (ret == -1);

	return( ret );
}


static int
add_addr( LDAP *ld, struct sockaddr *sap )
{
    struct sockaddr	*newsap, **addrs;

    if (( newsap = (struct sockaddr *)LDAP_MALLOC( sizeof( struct sockaddr )))
	    == NULL ) {
	ld->ld_errno = LDAP_NO_MEMORY;
	return( -1 );
    }
	
	addrs = (struct sockaddr **)LDAP_REALLOC( ld->ld_cldapaddrs,
		( ld->ld_cldapnaddr + 1 ) * sizeof(struct sockaddr *));

    if ( addrs == NULL ) {
	LDAP_FREE( newsap );
	ld->ld_errno = LDAP_NO_MEMORY;
	return( -1 );
    }

    SAFEMEMCPY( (char *)newsap, (char *)sap, sizeof( struct sockaddr ));
    addrs[ ld->ld_cldapnaddr++ ] = newsap;
    ld->ld_cldapaddrs = (void **)addrs;
    return( 0 );
}


static int
cldap_result( LDAP *ld, int msgid, LDAPMessage **res,
	struct cldap_retinfo *crip, const char *base )
{
    Sockbuf 		*sb = &ld->ld_sb;
    BerElement		ber;
    char		*logdn;
    int			ret, fromaddr, i;
	ber_int_t	id;
    struct timeval	tv;

    fromaddr = -1;

    if ( crip->cri_try == 0 ) {
	crip->cri_maxtries = ld->ld_cldaptries * ld->ld_cldapnaddr;
	crip->cri_timeout = ld->ld_cldaptimeout;
	crip->cri_useaddr = 0;
	Debug( LDAP_DEBUG_TRACE, "cldap_result tries %d timeout %d\n",
		ld->ld_cldaptries, ld->ld_cldaptimeout, 0 );
    }

    if ((tv.tv_sec = crip->cri_timeout / ld->ld_cldapnaddr) < 1 ) {
	tv.tv_sec = 1;
    }
    tv.tv_usec = 0;

    Debug( LDAP_DEBUG_TRACE,
	    "cldap_result waiting up to %ld seconds for a response\n",
	    (long) tv.tv_sec, 0, 0 );
    ber_init_w_nullc( &ber, 0 );
    ldap_set_ber_options( ld, &ber );

    if ( cldap_getmsg( ld, &tv, &ber ) == -1 ) {
	ret = ld->ld_errno;
	Debug( LDAP_DEBUG_TRACE, "cldap_getmsg returned -1 (%d)\n",
		ret, 0, 0 );
    } else if ( ld->ld_errno == LDAP_TIMEOUT ) {
	Debug( LDAP_DEBUG_TRACE,
	    "cldap_result timed out\n", 0, 0, 0 );
	/*
	 * It timed out; is it time to give up?
	 */
	if ( ++crip->cri_try >= crip->cri_maxtries ) {
	    ret = LDAP_TIMEOUT;
	    --crip->cri_try;
	} else {
	    if ( ++crip->cri_useaddr >= ld->ld_cldapnaddr ) {
		/*
		 * new round: reset address to first one and
		 * double the timeout
		 */
		crip->cri_useaddr = 0;
		crip->cri_timeout <<= 1;
	    }
	    ret = -1;
	}

    } else {
	/*
	 * Got a response.  It should look like:
	 * { msgid, logdn, { searchresponse...}}
	 */
	logdn = NULL;

	if ( ber_scanf( &ber, "ia", &id, &logdn ) == LBER_ERROR ) {
	    LDAP_FREE( ber.ber_buf );	/* gack! */
	    ret = LDAP_DECODING_ERROR;
	    Debug( LDAP_DEBUG_TRACE,
		    "cldap_result: ber_scanf returned LBER_ERROR (%d)\n",
		    ret, 0, 0 );
	} else if ( id != msgid ) {
	    LDAP_FREE( ber.ber_buf );	/* gack! */
	    Debug( LDAP_DEBUG_TRACE,
		    "cldap_result: looking for msgid %d; got %d\n",
		    msgid, id, 0 );
	    ret = -1;	/* ignore and keep looking */
	} else {
	    struct sockaddr_in * src;
	    /*
	     * got a result: determine which server it came from
	     * decode into ldap message chain
	     */
	    src = (struct sockaddr_in *) ber_pvt_sb_udp_get_src( sb );
		
	    for ( fromaddr = 0; fromaddr < ld->ld_cldapnaddr; ++fromaddr ) {
		    if ( memcmp( &((struct sockaddr_in *)
			    ld->ld_cldapaddrs[ fromaddr ])->sin_addr,
			    &(src->sin_addr),
			    sizeof( struct in_addr )) == 0 ) {
			break;
		    }
	    }
	    ret = cldap_parsemsg( ld, msgid, &ber, res, base );
	    LDAP_FREE( ber.ber_buf );	/* gack! */
	    Debug( LDAP_DEBUG_TRACE,
		"cldap_result got result (%d)\n", ret, 0, 0 );
	}

	if ( logdn != NULL ) {
		LDAP_FREE( logdn );
	}
    }
    

    /*
     * If we are giving up (successfully or otherwise) then 
     * abandon any outstanding requests.
     */
    if ( ret != -1 ) {
	i = crip->cri_try;
	if ( i >= ld->ld_cldapnaddr ) {
	    i = ld->ld_cldapnaddr - 1;
	}

	for ( ; i >= 0; --i ) {
	    if ( i == fromaddr ) {
		continue;
	    }
	    ber_pvt_sb_udp_set_dst( sb, ld->ld_cldapaddrs[i] );

	    Debug( LDAP_DEBUG_TRACE, "cldap_result abandoning id %d (to %s)\n",
		msgid, inet_ntoa( ((struct sockaddr_in *)
		ld->ld_cldapaddrs[i])->sin_addr ), 0 );
	    (void) ldap_abandon( ld, msgid );
	}
    }

    return( ld->ld_errno = ret );
}


static int
cldap_parsemsg( LDAP *ld, int msgid, BerElement *ber,
	LDAPMessage **res, const char *base )
{
    ber_tag_t	tag;
	ber_len_t	len;
    int			baselen, slen;
	ber_tag_t	rc;
    char		*dn, *p, *cookie;
    LDAPMessage		*chain, *prev, *ldm;
    struct berval	*bv;

    rc = LDAP_DECODING_ERROR;	/* pessimistic */
    ldm = chain = prev = NULL;
    baselen = ( base == NULL ) ? 0 : strlen( base );
    bv = NULL;

    for ( tag = ber_first_element( ber, &len, &cookie );
	    tag != LBER_DEFAULT && rc != LDAP_SUCCESS;
	    tag = ber_next_element( ber, &len, cookie )) {
	if (( ldm = (LDAPMessage *)LDAP_CALLOC( 1, sizeof(LDAPMessage)))
		== NULL || ( ldm->lm_ber = ldap_alloc_ber_with_options( ld ))
		== NULL ) {
	    rc = LDAP_NO_MEMORY;
	    break;	/* return w/error*/
	}
	ldm->lm_msgid = msgid;
	ldm->lm_msgtype = tag;

	if ( tag == LDAP_RES_SEARCH_RESULT ) {
	    Debug( LDAP_DEBUG_TRACE, "cldap_parsemsg got search result\n",
		    0, 0, 0 );

	    if ( ber_get_stringal( ber, &bv ) == LBER_DEFAULT ) {
		break;	/* return w/error */
	    }

	    if ( ber_printf( ldm->lm_ber, "tO", tag, bv ) == -1 ) {
		break;	/* return w/error */
	    }
	    ber_bvfree( bv );
	    bv = NULL;
	    rc = LDAP_SUCCESS;

	} else if ( tag == LDAP_RES_SEARCH_ENTRY ) {
	    if ( ber_scanf( ber, "{aO" /*}*/, &dn, &bv ) == LBER_ERROR ) {
		break;	/* return w/error */
	    }
	    Debug( LDAP_DEBUG_TRACE, "cldap_parsemsg entry %s\n", dn, 0, 0 );
	    if ( dn != NULL && *(dn + ( slen = strlen(dn)) - 1) == '*' &&
		    baselen > 0 ) {
		/*
		 * substitute original searchbase for trailing '*'
		 */
		if (( p = (char *)LDAP_MALLOC( slen + baselen )) == NULL ) {
		    rc = LDAP_NO_MEMORY;
		    LDAP_FREE( dn );
		    break;	/* return w/error */
		}
		strcpy( p, dn );
		strcpy( p + slen - 1, base );
		LDAP_FREE( dn );
		dn = p;
	    }

	    if ( ber_printf( ldm->lm_ber, "t{so}", tag, dn, bv->bv_val,
		    bv->bv_len ) == -1 ) {
		break;	/* return w/error */
	    }
	    LDAP_FREE( dn );
	    ber_bvfree( bv );
	    bv = NULL;
		
#ifdef notyet
	} else if ( tag == LDAP_RES_SEARCH_REFERENCE ) {
#endif
	} else {
	    Debug( LDAP_DEBUG_TRACE, "cldap_parsemsg got unknown tag %lu\n",
		    tag, 0, 0 );
	    rc = LDAP_DECODING_ERROR;
	    break;	/* return w/error */
	}

	/* Reset message ber so we can read from it later.  Gack! */
	ldm->lm_ber->ber_end = ldm->lm_ber->ber_ptr;
	ldm->lm_ber->ber_ptr = ldm->lm_ber->ber_buf;

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
	    fprintf( stderr, "cldap_parsemsg add message id %ld type %ld:\n",
		    (long) ldm->lm_msgid, (long) ldm->lm_msgtype  );
	    ber_log_dump( LDAP_DEBUG_BER, ldap_debug, ldm->lm_ber, 1 );
	}
#endif /* LDAP_DEBUG */

#ifndef LDAP_NOCACHE
	    if ( ld->ld_cache != NULL ) {
		ldap_add_result_to_cache( ld, ldm );
	    }
#endif /* LDAP_NOCACHE */

	if ( chain == NULL ) {
	    chain = ldm;
	} else {
	    prev->lm_chain = ldm;
	}
	prev = ldm;
	ldm = NULL;
    }

    /* dispose of any leftovers */
    if ( ldm != NULL ) {
	if ( ldm->lm_ber != NULL ) {
	    ber_free( ldm->lm_ber, 1 );
	}
	LDAP_FREE( ldm );
    }
    if ( bv != NULL ) {
	ber_bvfree( bv );
    }

    /* return chain, calling result2error if we got anything at all */
    *res = chain;
    return(( *res == NULL ) ? rc : ldap_result2error( ld, *res, 0 ));
}
#endif /* LDAP_CONNECTIONLESS */
