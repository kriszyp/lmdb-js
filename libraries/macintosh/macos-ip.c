/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  macos-ip.c -- Macintosh platform-specific TCP & UDP related code
 */

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1995 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Memory.h>
#include "macos.h"
#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

int
connect_to_host( Sockbuf *sb, char *host, unsigned long address,
	int port, int async )
/*
 * if host == NULL, connect using address
 * "address" and "port" must be in network byte order
 * zero is returned upon success, -1 if fatal error, -2 EINPROGRESS
 * async is only used ifndef NO_REFERRALS (non-0 means don't wait for connect)
 * XXX async is not used yet!
 */
{
	void			*tcps;
	short 			i;
#ifdef SUPPORT_OPENTRANSPORT
    InetHostInfo	hi;
#else /* SUPPORT_OPENTRANSPORT */
    struct hostInfo	hi;
#endif /* SUPPORT_OPENTRANSPORT */

	Debug( LDAP_DEBUG_TRACE, "connect_to_host: %s:%d\n",
	    ( host == NULL ) ? "(by address)" : host, ntohs( port ), 0 );

	if ( host != NULL && gethostinfobyname( host, &hi ) != noErr ) {
		return( -1 );
	}

	if (( tcps = tcpopen( NULL, TCP_BUFSIZ )) == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "tcpopen failed\n", 0, 0, 0 );
		return( -1 );
	}

#ifdef SUPPORT_OPENTRANSPORT
    for ( i = 0; host == NULL || hi.addrs[ i ] != 0; ++i ) {
    	if ( host != NULL ) {
			SAFEMEMCPY( (char *)&address, (char *)&hi.addrs[ i ], sizeof( long ));
		}
#else /* SUPPORT_OPENTRANSPORT */
    for ( i = 0; host == NULL || hi.addr[ i ] != 0; ++i ) {
    	if ( host != NULL ) {
			SAFEMEMCPY( (char *)&address, (char *)&hi.addr[ i ], sizeof( long ));
		}
#endif /* SUPPORT_OPENTRANSPORT */

		if ( tcpconnect( tcps, address, port ) > 0 ) {
			sb->sb_sd = (void *)tcps;
			return( 0 );
		}

		if ( host == NULL ) {	/* using single address -- not hi.addrs array */
			break;
		}
	}
	
	Debug( LDAP_DEBUG_TRACE, "tcpconnect failed\n", 0, 0, 0 );
	tcpclose( tcps );
	return( -1 );
}


void
close_connection( Sockbuf *sb )
{
	tcpclose( (tcpstream *)sb->sb_sd );
}


#ifdef KERBEROS
char *
host_connected_to( Sockbuf *sb )
{
	ip_addr addr;
	
#ifdef SUPPORT_OPENTRANSPORT
    InetHostInfo	hi;
#else /* SUPPORT_OPENTRANSPORT */
    struct hostInfo	hi;
#endif /* SUPPORT_OPENTRANSPORT */

	if ( tcpgetpeername( (tcpstream *)sb->sb_sd, &addr, NULL ) != noErr ) {
		return( NULL );
	}

#ifdef SUPPORT_OPENTRANSPORT
	if ( gethostinfobyaddr( addr, &hi ) == noErr ) {
		return( strdup( hi.name ));
	}
#else /* SUPPORT_OPENTRANSPORT */
	if ( gethostinfobyaddr( addr, &hi ) == noErr ) {
		return( strdup( hi.cname ));
	}
#endif /* SUPPORT_OPENTRANSPORT */

	return( NULL );
}
#endif /* KERBEROS */


#ifdef LDAP_REFERRALS
struct tcpstreaminfo {
	struct tcpstream	*tcpsi_stream;
	Boolean				tcpsi_check_read;
	Boolean				tcpsi_is_read_ready;
/*	Boolean				tcpsi_check_write;		/* no write select support needed yet */
/*	Boolean				tcpsi_is_write_ready;	/* ditto */
};

struct selectinfo {
	short					si_count;
	struct tcpstreaminfo	*si_streaminfo;
};


void
mark_select_read( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo		*sip;
	struct tcpstreaminfo	*tcpsip;
	short					i;
	
	Debug( LDAP_DEBUG_TRACE, "mark_select_read: stream %x\n", (tcpstream *)sb->sb_sd, 0, 0 );

	if (( sip = (struct selectinfo *)ld->ld_selectinfo ) == NULL ) {
		return;
	}
	
	for ( i = 0; i < sip->si_count; ++i ) {	/* make sure stream is not already in the list... */
		if ( sip->si_streaminfo[ i ].tcpsi_stream == (tcpstream *)sb->sb_sd ) {
			sip->si_streaminfo[ i ].tcpsi_check_read = true;
			sip->si_streaminfo[ i ].tcpsi_is_read_ready = false;
			return;
		}
	}

	/* add a new stream element to our array... */
	if ( sip->si_count <= 0 ) {
		tcpsip = (struct tcpstreaminfo *)malloc( sizeof( struct tcpstreaminfo ));
	} else {
		tcpsip = (struct tcpstreaminfo *)realloc( sip->si_streaminfo,
				( sip->si_count + 1 ) * sizeof( struct tcpstreaminfo ));
	}
	
	if ( tcpsip != NULL ) {
		tcpsip[ sip->si_count ].tcpsi_stream = (tcpstream *)sb->sb_sd;
		tcpsip[ sip->si_count ].tcpsi_check_read = true;
		tcpsip[ sip->si_count ].tcpsi_is_read_ready = false;
		sip->si_streaminfo = tcpsip;
		++sip->si_count;
	}
}


void
mark_select_clear( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	short				i;

	Debug( LDAP_DEBUG_TRACE, "mark_select_clear: stream %x\n", (tcpstream *)sb->sb_sd, 0, 0 );

	sip = (struct selectinfo *)ld->ld_selectinfo;
	if ( sip != NULL && sip->si_count > 0 && sip->si_streaminfo != NULL ) {
		for ( i = 0; i < sip->si_count; ++i ) {
			if ( sip->si_streaminfo[ i ].tcpsi_stream == (tcpstream *)sb->sb_sd ) {
				break;
			}
		}
		if ( i < sip->si_count ) {
			--sip->si_count;
			for ( ; i < sip->si_count; ++i ) {
				sip->si_streaminfo[ i ] = sip->si_streaminfo[ i + 1 ];
			}
			/* we don't bother to use realloc to make the si_streaminfo array smaller */
		}
	}
}


int
is_read_ready( LDAP *ld, Sockbuf *sb )
{
	struct selectinfo	*sip;
	short				i;
	
	sip = (struct selectinfo *)ld->ld_selectinfo;
	if ( sip != NULL && sip->si_count > 0 && sip->si_streaminfo != NULL ) {
		for ( i = 0; i < sip->si_count; ++i ) {
			if ( sip->si_streaminfo[ i ].tcpsi_stream == (tcpstream *)sb->sb_sd ) {
#ifdef LDAP_DEBUG
				if ( sip->si_streaminfo[ i ].tcpsi_is_read_ready ) {
					Debug( LDAP_DEBUG_TRACE, "is_read_ready: stream %x READY\n",
							(tcpstream *)sb->sb_sd, 0, 0 );
				} else {
					Debug( LDAP_DEBUG_TRACE, "is_read_ready: stream %x Not Ready\n",
							(tcpstream *)sb->sb_sd, 0, 0 );
				}
#endif /* LDAP_DEBUG */
				return( sip->si_streaminfo[ i ].tcpsi_is_read_ready ? 1 : 0 );
			}
		}
	}

	Debug( LDAP_DEBUG_TRACE, "is_read_ready: stream %x: NOT FOUND\n", (tcpstream *)sb->sb_sd, 0, 0 );
	return( 0 );
}


void *
new_select_info()
{
	return( (void *)calloc( 1, sizeof( struct selectinfo )));
}


void
free_select_info( void *sip )
{
	if ( sip != NULL ) {
		free( sip );
	}
}


int
do_ldap_select( LDAP *ld, struct timeval *timeout )
{
	struct selectinfo	*sip;
	Boolean				ready, gotselecterr;
	long				ticks, endticks;
	short				i, err;

	Debug( LDAP_DEBUG_TRACE, "do_ldap_select\n", 0, 0, 0 );

	if (( sip = (struct selectinfo *)ld->ld_selectinfo ) == NULL ) {
		return( -1 );
	}

	if ( sip->si_count == 0 ) {
		return( 1 );
	}

	if ( timeout != NULL ) {
		endticks = 60 * timeout->tv_sec + ( 60 * timeout->tv_usec ) / 1000000 + TickCount();
	}

	for ( i = 0; i < sip->si_count; ++i ) {
		if ( sip->si_streaminfo[ i ].tcpsi_check_read ) {
			sip->si_streaminfo[ i ].tcpsi_is_read_ready = false;
		}
	}

	ready = gotselecterr = false;
	do {
		for ( i = 0; i < sip->si_count; ++i ) {
			if ( sip->si_streaminfo[ i ].tcpsi_check_read && !sip->si_streaminfo[ i ].tcpsi_is_read_ready ) {
				if (( err = tcpreadready( sip->si_streaminfo[ i ].tcpsi_stream )) > 0 ) {
					sip->si_streaminfo[ i ].tcpsi_is_read_ready = ready = true;
				} else if ( err < 0 ) {
					gotselecterr = true;
				}
			}
		}
		if ( !ready && !gotselecterr ) {
			Delay( 2L, &ticks );
			SystemTask();
		}
	} while ( !ready && !gotselecterr && ( timeout == NULL || ticks < endticks ));

	Debug( LDAP_DEBUG_TRACE, "do_ldap_select returns %d\n", ready ? 1 : ( gotselecterr ? -1 : 0 ), 0, 0 );
	return( ready ? 1 : ( gotselecterr ? -1 : 0 ));
}
#endif /* LDAP_REFERRALS */
