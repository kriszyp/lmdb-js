/*
 *  Copyright (c) 1990, 1994 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  cldap.c - synchronous, retrying interface to the cldap protocol
 */


#ifdef CLDAP

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990, 1994 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef MACOS
#include <stdlib.h>
#include "macos.h"
#else /* MACOS */
#ifdef DOS
#include "msdos.h"
#else /* DOS */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif /* DOS */
#endif /* MACOS */

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

#define DEF_CLDAP_TIMEOUT	3
#define DEF_CLDAP_TRIES		4

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK	((unsigned long) 0x7f000001)
#endif


struct cldap_retinfo {
	int		cri_maxtries;
	int		cri_try;
	int		cri_useaddr;
	long		cri_timeout;
};

#ifdef NEEDPROTOS
static int add_addr( LDAP *ld, struct sockaddr *sap );
static int cldap_result( LDAP *ld, int msgid, LDAPMessage **res,
	struct cldap_retinfo *crip, char *base );
static int cldap_parsemsg( LDAP *ld, int msgid, BerElement *ber,
	LDAPMessage **res, char *base );
#else /* NEEDPROTOS */
static int add_addr();
static int cldap_result();
static int cldap_parsemsg();
#endif /* NEEDPROTOS */

/*
 * cldap_open - initialize and connect to an ldap server.  A magic cookie to
 * be used for future communication is returned on success, NULL on failure.
 *
 * Example:
 *	LDAP	*ld;
 *	ld = cldap_open( hostname, port );
 */

LDAP *
cldap_open( char *host, int port )
{
    int 		s;
    unsigned long	address;
    struct sockaddr_in 	sock;
    struct hostent	*hp;
    LDAP		*ld;
    char		*p;
    int			i;

    Debug( LDAP_DEBUG_TRACE, "ldap_open\n", 0, 0, 0 );

    if ( port == 0 ) {
	    port = LDAP_PORT;
    }

    if ( (s = socket( AF_INET, SOCK_DGRAM, 0 )) < 0 ) {
	return( NULL );
    }

    sock.sin_addr.s_addr = 0;
    sock.sin_family = AF_INET;
    sock.sin_port = 0;
    if ( bind(s, (struct sockaddr *) &sock, sizeof(sock)) < 0)  {
	close( s );
	return( NULL );
    }

    if (( ld = ldap_init( host, port )) == NULL ) {
	close( s );
	return( NULL );
    }
    if ( (ld->ld_sb.sb_fromaddr = (void *) calloc( 1,
	    sizeof( struct sockaddr ))) == NULL ) {
	free( ld );
	close( s );
	return( NULL );
    }	
    ld->ld_sb.sb_sd = s;
    ld->ld_sb.sb_naddr = 0;
    ld->ld_version = LDAP_VERSION;

    sock.sin_family = AF_INET;
    sock.sin_port = htons( port );

    /*
     * 'host' may be a space-separated list.
     */
    if ( host != NULL ) {
	for ( ; host != NULL; host = p ) {
	    if (( p = strchr( host, ' ' )) != NULL ) {
		for (*p++ = '\0'; *p == ' '; p++) {
		    ;
		}
	    }

	    if ( (address = inet_addr( host )) == -1 ) {
		if ( (hp = gethostbyname( host )) == NULL ) {
		    errno = EHOSTUNREACH;
		    continue;
		}

		for ( i = 0; hp->h_addr_list[ i ] != 0; ++i ) {
		    SAFEMEMCPY( (char *)&sock.sin_addr.s_addr,
			    (char *)hp->h_addr_list[ i ],
			    sizeof(sock.sin_addr.s_addr));
		    if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
			close( s );
			free( ld );
			return( NULL );
		    }
		}

	    } else {
		sock.sin_addr.s_addr = address;
		if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
		    close( s );
		    free( ld );
		    return( NULL );
		}
	    }

	    if ( ld->ld_host == NULL ) {
		    ld->ld_host = strdup( host );
	    }
	}

    } else {
	address = INADDR_LOOPBACK;
	sock.sin_addr.s_addr = htonl( address );
	if ( add_addr( ld, (struct sockaddr *)&sock ) < 0 ) {
	    close( s );
	    free( ld );
	    return( NULL );
	}
    }

    if ( ld->ld_sb.sb_addrs == NULL
#ifdef LDAP_REFERRALS
	    || ( ld->ld_defconn = ldap_new_connection( ld, NULL, 1,0,0 )) == NULL
#endif /* LDAP_REFERRALS */
	    ) {
	free( ld );
	return( NULL );
    }

    ld->ld_sb.sb_useaddr = ld->ld_sb.sb_addrs[ 0 ];
    cldap_setretryinfo( ld, 0, 0 );

#ifdef LDAP_DEBUG
    putchar( '\n' );
    for ( i = 0; i < ld->ld_sb.sb_naddr; ++i ) {
	Debug( LDAP_DEBUG_TRACE, "end of cldap_open address %d is %s\n",
		i, inet_ntoa( ((struct sockaddr_in *)
		ld->ld_sb.sb_addrs[ i ])->sin_addr ), 0 );
    }
#endif

    return( ld );
}



void
cldap_close( LDAP *ld )
{
	ldap_ld_free( ld, 0 );
}


void
cldap_setretryinfo( LDAP *ld, int tries, int timeout )
{
    ld->ld_cldaptries = ( tries <= 0 ) ? DEF_CLDAP_TRIES : tries;
    ld->ld_cldaptimeout = ( timeout <= 0 ) ? DEF_CLDAP_TIMEOUT : timeout;
}


int
cldap_search_s( LDAP *ld, char *base, int scope, char *filter, char **attrs,
	int attrsonly, LDAPMessage **res, char *logdn )
{
    int				ret, msgid;
    struct cldap_retinfo	cri;

    *res = NULLMSG;

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
	ld->ld_sb.sb_useaddr = ld->ld_sb.sb_addrs[ cri.cri_useaddr ];

	Debug( LDAP_DEBUG_TRACE, "cldap_search_s try %d (to %s)\n",
	    cri.cri_try, inet_ntoa( ((struct sockaddr_in *)
	    ld->ld_sb.sb_useaddr)->sin_addr ), 0 );

	    if ( (msgid = ldap_search( ld, base, scope, filter, attrs,
		attrsonly )) == -1 ) {
		    return( ld->ld_errno );
	    }
#ifndef NO_CACHE
	    if ( ld->ld_cache != NULL && ld->ld_responses != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "cldap_search_s res from cache\n",
			0, 0, 0 );
		*res = ld->ld_responses;
		ld->ld_responses = ld->ld_responses->lm_next;
		return( ldap_result2error( ld, *res, 0 ));
	    }
#endif /* NO_CACHE */
	    ret = cldap_result( ld, msgid, res, &cri, base );
	} while (ret == -1);

	return( ret );
}


static int
add_addr( LDAP *ld, struct sockaddr *sap )
{
    struct sockaddr	*newsap, **addrs;

    if (( newsap = (struct sockaddr *)malloc( sizeof( struct sockaddr )))
	    == NULL ) {
	ld->ld_errno = LDAP_NO_MEMORY;
	return( -1 );
    }

    if ( ld->ld_sb.sb_naddr == 0 ) {
	addrs = (struct sockaddr **)malloc( sizeof(struct sockaddr *));
    } else {
	addrs = (struct sockaddr **)realloc( ld->ld_sb.sb_addrs,
		( ld->ld_sb.sb_naddr + 1 ) * sizeof(struct sockaddr *));
    }

    if ( addrs == NULL ) {
	free( newsap );
	ld->ld_errno = LDAP_NO_MEMORY;
	return( -1 );
    }

    SAFEMEMCPY( (char *)newsap, (char *)sap, sizeof( struct sockaddr ));
    addrs[ ld->ld_sb.sb_naddr++ ] = newsap;
    ld->ld_sb.sb_addrs = (void **)addrs;
    return( 0 );
}


static int
cldap_result( LDAP *ld, int msgid, LDAPMessage **res,
	struct cldap_retinfo *crip, char *base )
{
    Sockbuf 		*sb = &ld->ld_sb;
    BerElement		ber;
    char		*logdn;
    int			ret, id, fromaddr, i;
    struct timeval	tv;

    fromaddr = -1;

    if ( crip->cri_try == 0 ) {
	crip->cri_maxtries = ld->ld_cldaptries * sb->sb_naddr;
	crip->cri_timeout = ld->ld_cldaptimeout;
	crip->cri_useaddr = 0;
	Debug( LDAP_DEBUG_TRACE, "cldap_result tries %d timeout %d\n",
		ld->ld_cldaptries, ld->ld_cldaptimeout, 0 );
    }

    if ((tv.tv_sec = crip->cri_timeout / sb->sb_naddr) < 1 ) {
	tv.tv_sec = 1;
    }
    tv.tv_usec = 0;

    Debug( LDAP_DEBUG_TRACE,
	    "cldap_result waiting up to %d seconds for a response\n",
	    tv.tv_sec, 0, 0 );
    ber_init( &ber, 0 );
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
	    if ( ++crip->cri_useaddr >= sb->sb_naddr ) {
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
	    free( ber.ber_buf );	/* gack! */
	    ret = LDAP_DECODING_ERROR;
	    Debug( LDAP_DEBUG_TRACE,
		    "cldap_result: ber_scanf returned LBER_ERROR (%d)\n",
		    ret, 0, 0 );
	} else if ( id != msgid ) {
	    free( ber.ber_buf );	/* gack! */
	    Debug( LDAP_DEBUG_TRACE,
		    "cldap_result: looking for msgid %d; got %d\n",
		    msgid, id, 0 );
	    ret = -1;	/* ignore and keep looking */
	} else {
	    /*
	     * got a result: determine which server it came from
	     * decode into ldap message chain
	     */
	    for ( fromaddr = 0; fromaddr < sb->sb_naddr; ++fromaddr ) {
		    if ( memcmp( &((struct sockaddr_in *)
			    sb->sb_addrs[ fromaddr ])->sin_addr,
			    &((struct sockaddr_in *)sb->sb_fromaddr)->sin_addr,
			    sizeof( struct in_addr )) == 0 ) {
			break;
		    }
	    }
	    ret = cldap_parsemsg( ld, msgid, &ber, res, base );
	    free( ber.ber_buf );	/* gack! */
	    Debug( LDAP_DEBUG_TRACE,
		"cldap_result got result (%d)\n", ret, 0, 0 );
	}

	if ( logdn != NULL ) {
		free( logdn );
	}
    }
    

    /*
     * If we are giving up (successfully or otherwise) then 
     * abandon any outstanding requests.
     */
    if ( ret != -1 ) {
	i = crip->cri_try;
	if ( i >= sb->sb_naddr ) {
	    i = sb->sb_naddr - 1;
	}

	for ( ; i >= 0; --i ) {
	    if ( i == fromaddr ) {
		continue;
	    }
	    sb->sb_useaddr = sb->sb_addrs[ i ];
	    Debug( LDAP_DEBUG_TRACE, "cldap_result abandoning id %d (to %s)\n",
		msgid, inet_ntoa( ((struct sockaddr_in *)
		sb->sb_useaddr)->sin_addr ), 0 );
	    (void) ldap_abandon( ld, msgid );
	}
    }

    return( ld->ld_errno = ret );
}


static int
cldap_parsemsg( LDAP *ld, int msgid, BerElement *ber,
	LDAPMessage **res, char *base )
{
    unsigned long	tag, len;
    int			baselen, slen, rc;
    char		*dn, *p, *cookie;
    LDAPMessage		*chain, *prev, *ldm;
    struct berval	*bv;

    rc = LDAP_DECODING_ERROR;	/* pessimistic */
    ldm = chain = prev = NULLMSG;
    baselen = ( base == NULL ) ? 0 : strlen( base );
    bv = NULL;

    for ( tag = ber_first_element( ber, &len, &cookie );
	    tag != LBER_DEFAULT && rc != LDAP_SUCCESS;
	    tag = ber_next_element( ber, &len, cookie )) {
	if (( ldm = (LDAPMessage *)calloc( 1, sizeof(LDAPMessage)))
		== NULL || ( ldm->lm_ber = ldap_alloc_ber_with_options( ld ))
		== NULLBER ) {
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

	    if ( ber_printf( ldm->lm_ber, "to", tag, bv->bv_val,
		    bv->bv_len ) == -1 ) {
		break;	/* return w/error */
	    }
	    ber_bvfree( bv );
	    bv = NULL;
	    rc = LDAP_SUCCESS;

	} else if ( tag == LDAP_RES_SEARCH_ENTRY ) {
	    if ( ber_scanf( ber, "{aO", &dn, &bv ) == LBER_ERROR ) {
		break;	/* return w/error */
	    }
	    Debug( LDAP_DEBUG_TRACE, "cldap_parsemsg entry %s\n", dn, 0, 0 );
	    if ( dn != NULL && *(dn + ( slen = strlen(dn)) - 1) == '*' &&
		    baselen > 0 ) {
		/*
		 * substitute original searchbase for trailing '*'
		 */
		if (( p = (char *)malloc( slen + baselen )) == NULL ) {
		    rc = LDAP_NO_MEMORY;
		    free( dn );
		    break;	/* return w/error */
		}
		strcpy( p, dn );
		strcpy( p + slen - 1, base );
		free( dn );
		dn = p;
	    }

	    if ( ber_printf( ldm->lm_ber, "t{so}", tag, dn, bv->bv_val,
		    bv->bv_len ) == -1 ) {
		break;	/* return w/error */
	    }
	    free( dn );
	    ber_bvfree( bv );
	    bv = NULL;
		
	} else {
	    Debug( LDAP_DEBUG_TRACE, "cldap_parsemsg got unknown tag %d\n",
		    tag, 0, 0 );
	    rc = LDAP_PROTOCOL_ERROR;
	    break;	/* return w/error */
	}

	/* Reset message ber so we can read from it later.  Gack! */
	ldm->lm_ber->ber_end = ldm->lm_ber->ber_ptr;
	ldm->lm_ber->ber_ptr = ldm->lm_ber->ber_buf;

#ifdef LDAP_DEBUG
	if ( ldap_debug & LDAP_DEBUG_PACKETS ) {
	    fprintf( stderr, "cldap_parsemsg add message id %d type %d:\n",
		    ldm->lm_msgid, ldm->lm_msgtype  );
	    ber_dump( ldm->lm_ber, 1 );
	}
#endif /* LDAP_DEBUG */

#ifndef NO_CACHE
	    if ( ld->ld_cache != NULL ) {
		ldap_add_result_to_cache( ld, ldm );
	    }
#endif /* NO_CACHE */

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
	if ( ldm->lm_ber != NULLBER ) {
	    ber_free( ldm->lm_ber, 1 );
	}
	free( ldm );
    }
    if ( bv != NULL ) {
	ber_bvfree( bv );
    }

    /* return chain, calling result2error if we got anything at all */
    *res = chain;
    return(( *res == NULLMSG ) ? rc : ldap_result2error( ld, *res, 0 ));
}
#endif /* CLDAP */
