/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright 2000, John E. Schimmel, All rights reserved.
 * This software is not subject to any license of Mirapoint, Inc.
 *
 * This is free software; you can redistribute and use it
 * under the same terms as OpenLDAP itself.
 */
/*
 * Sorry this file is so scary, but it needs to run on a wide range of
 * platforms.  The only exported routine is lutil_uuidstr() which is all
 * that LDAP cares about.  It generates a new uuid and returns it in
 * in string form.
 */
#include "portable.h"

#include <stdio.h>
#include <sys/types.h>

#include <ac/stdlib.h>

#ifdef HAVE_UUID_TO_STR
#  include <sys/uuid.h>
#elif defined( _WIN32 )
#  include <rpc.h>
#else
#  include <ac/socket.h>
#  include <ac/time.h>

	/* 100 usec intervals from 10/10/1582 to 1/1/1970 */
#	define UUID_TPLUS	0x01B21DD2138140LL

#  ifdef HAVE_SYS_SYSCTL_H
#    include <net/if.h>
#    include <sys/sysctl.h>
#    include <net/route.h>
#  endif
#endif

#include <lutil.h>

/* not needed for Windows */
#if !defined(HAVE_UUID_TO_STR) && !defined(_WIN32)
static unsigned char *
lutil_eaddr( void )
{
	static unsigned char zero[6];
	static unsigned char eaddr[6];

#ifdef HAVE_SYS_SYSCTL_H
	size_t needed;
	int mib[6];
	char *buf, *next, *lim;
	struct if_msghdr *ifm;
	struct sockaddr_dl *sdl;

	if (memcmp(eaddr, zero, sizeof(eaddr))) {
		return eaddr;
	}

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[3] = 0;
	mib[3] = 0;
	mib[4] = NET_RT_IFLIST;
	mib[5] = 0;

	if (sysctl(mib, sizeof(mib), NULL, &needed, NULL, 0) < 0) {
		return NULL;
	}

	buf = malloc(needed);
	if( buf == NULL ) return NULL;

	if (sysctl(mib, sizeof(mib), buf, &needed, NULL, 0) < 0) {
		free(buf);
		return NULL;
	}

	lim = buf + needed;
	for (next = buf; next < lim; next += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)next;
		sdl = (struct sockaddr_dl *)(ifm + 1);

		if ( sdl->sdl_family != AF_LINK || sdl->sdl_alen == 6 ) {
			AC_MEMCPY(eaddr,
				(unsigned char *)sdl->sdl_data + sdl->sdl_nlen,
				sizeof(eaddr));
			free(buf);
			return eaddr;
		}
	}

	free(buf);
	return NULL;

#elif defined (SIOCGIFADDR)
	char buf[sizeof(struct ifreq) * 32];
	struct ifconf ifc;
	struct ifreq *ifr;
	struct sockaddr *sa;
	struct sockaddr_dl *sdl;
	unsigned char *p;
	int s, i;

	if (memcmp(eaddr, zero, sizeof(eaddr))) {
		return eaddr;
	}

	s = socket( AF_INET, SOCK_DGRAM, 0 );
	if ( s < 0 ) {
		return NULL;
	}

	ifc.ifc_len = sizeof( buf );
	ifc.ifc_buf = buf;
	memset( buf, 0, sizeof( buf ) );

	i = ioctl( s, SIOCGIFCONF, (char *)&ifc );
	close( s );

	if( i < 0 ) {
		return NULL;
	}

	for ( i = 0; i < ifc.ifc_len; ) {
		ifr = (struct ifreq *)&ifc.ifc_buf[i];
		sa = &ifr->ifr_addr;

		if ( sa->sa_len > sizeof( ifr->ifr_addr ) ) {
			i += sizeof( ifr->ifr_name ) + sa->sa_len;
		} else {
			i += sizeof( *ifr );
		}

		if ( sa->sa_family != AF_LINK ) {
			continue;
		}

		sdl = (struct sockaddr_dl *)sa;

		if ( sdl->sdl_alen == 6 ) {
			AC_MEMCPY(eaddr,
				(unsigned char *)sdl->sdl_data + sdl->sdl_nlen,
				sizeof(eaddr));
			return eaddr;
		}
	}

	return NULL;

#else
	if (memcmp(eaddr, zero, sizeof(eaddr)) == 0) {
		/* XXX - who knows? */
		lutil_entropy( eaddr, sizeof(eaddr) );
		eaddr[0] |= 0x80; /* turn it into a mutlicast address */
	}

	return eaddr;
#endif
}
#endif

/*
** All we really care about is an ISO UUID string.  The format of a UUID is:
**	field			octet		note
**	time_low		0-3		low field of the timestamp
**	time_mid		4-5		middle field of timestamp
**	time_hi_and_version	6-7		high field of timestamp and
**						version number
**	clock_seq_hi_and_resv	8		high field of clock sequence
**						and variant
**	clock_seq_low		9		low field of clock sequence
**	node			10-15		spacially unique identifier
**
** We use DCE version one, and the DCE variant.  Our unique identifier is
** the first ethernet address on the system.
*/
size_t
lutil_uuidstr( char *buf, size_t len )
{
#ifdef HAVE_UUID_TO_STR
	uuid_t uu = {0};
	unsigned rc;
	char *s;
	size_t l;

	uuid_create( &uu, &rc );
	if ( rc != uuid_s_ok ) {
		return 0;
	}

	uuid_to_str( &uu, &s, &rc );
	if ( rc != uuid_s_ok ) {
		return 0;
	}

	l = strlen( s );
	if ( l >= len ) {
		free( s );
		return 0;
	}

	strncpy( buf, s, len );
	free( s );

	return l;

#elif defined( _WIN32 )
	UUID uuid;
	unsigned char *uuidstr;
	size_t uuidlen;

	if( UuidCreate( &uuid ) != RPC_S_OK ) {
		return 0;
	}
 
	if( UuidToString( &uuid, &uuidstr ) !=  RPC_S_OK ) {
		return 0;
	}

	uuidlen = strlen( uuidstr );
	if( uuidlen >= len ) {
		return 0;
	}

	strncpy( buf, uuidstr, len );
	free( uuidstr );

	return uuidlen;
 
#else
	struct timeval tv;
	unsigned long long tl;
	unsigned char *nl;
	unsigned short t2, t3, s1;
	unsigned int t1;

	/*
	 * Theoretically we should delay if seq wraps within 100usec but for now
	 * systems are not fast enough to worry about it.
	 */
	static int inited = 0;
	static unsigned short seq;
	
	if (!inited) {
		lutil_entropy( (unsigned char *) &seq, sizeof(seq) );
		inited++;
	}

#ifdef HAVE_GETTIMEOFDAY
	gettimeofday( &tv, 0 );
#else
	time( &tv.tv_sec );
	tv.tv_usec = 0;
#endif

	tl = ( tv.tv_sec * 10000000LL ) + ( tv.tv_usec * 10LL ) + UUID_TPLUS;
	nl = lutil_eaddr();

	t1 = tl & 0xffffffff;					/* time_low */
	t2 = ( tl >> 32 ) & 0xffff;				/* time_mid */
	t3 = ( ( tl >> 48 ) & 0x0fff ) | 0x1000;	/* time_hi_and_version */
	s1 = ( ++seq & 0x1fff ) | 0x8000;		/* clock_seq_and_reserved */

	t1 = snprintf( buf, len,
		"%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
	    t1, (unsigned) t2, (unsigned) t3, (unsigned) s1,
		(unsigned) nl[0], (unsigned) nl[1],
		(unsigned) nl[2], (unsigned) nl[3],
		(unsigned) nl[4], (unsigned) nl[5] );

	return (t1 < len) ? t1 : 0;
#endif
}

#ifdef TEST
int
main(int argc, char **argv)
{
	char buf1[8], buf2[64];

#ifndef HAVE_UUID_TO_STR
	unsigned char *p = lutil_eaddr();

	if( p ) {
		printf( "Ethernet Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned) p[0], (unsigned) p[1], (unsigned) p[2],
			(unsigned) p[3], (unsigned) p[4], (unsigned) p[5]);
	}
#endif

	if ( lutil_uuidstr( buf1, sizeof( buf1 ) ) ) {
		printf( "UUID: %s\n", buf1 );
	} else {
		fprintf( stderr, "too short: %ld\n", (long) sizeof( buf1 ) );
	}

	if ( lutil_uuidstr( buf2, sizeof( buf2 ) ) ) {
		printf( "UUID: %s\n", buf2 );
	} else {
		fprintf( stderr, "too short: %ld\n", (long) sizeof( buf2 ) );
	}

	if ( lutil_uuidstr( buf2, sizeof( buf2 ) ) ) {
		printf( "UUID: %s\n", buf2 );
	} else {
		fprintf( stderr, "too short: %ld\n", (long) sizeof( buf2 ) );
	}

	return 0;
}
#endif
