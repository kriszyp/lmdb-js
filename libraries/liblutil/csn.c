/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright 2000, John E. Schimmel, All rights reserved.
 * This software is not subject to any license of Mirapoint, Inc.
 *
 * This is free software; you can redistribute and use it
 * under the same terms as OpenLDAP itself.
 */
/* Adapted for incorporatation into OpenLDAP by Kurt Zeilenga */

/*
 * This file contains routines to generate a change sequence number.  Every
 * add delete, and modification is given a unique identifier for use in
 * resolving conflicts during replication operations.
 *
 * These routines are based upon draft-ietf-ldup-model-03.txt, and will
 * need to be revisited once standardized.
 *
 * The format of a CSN string is: yyyymmddhh:mm:ssz#0xSSSS#d#0xssss
 * where SSSS is a counter of operations within a timeslice, d is an
 * offset into a list of replica records, and ssss is a counter of
 * modifications within this operation.
 *
 * Calls to this routine MUST be serialized with other calls
 * to gmtime().
 */
#include "portable.h"

#include <stdio.h>
#include <ac/time.h>

#include <lutil.h>

size_t
lutil_csnstr(char *buf, size_t len, unsigned int replica, unsigned int mod)
{
	static time_t csntime;
	static unsigned int csnop;

	time_t t;
	unsigned int op;
	struct tm *ltm;
	int n;

	time( &t );
	if ( t > csntime ) {
		csntime = t;
		csnop = 0;
	}
	op = ++csnop;

	ltm = gmtime( &t );
	n = snprintf( buf, len, "%4d%02d%02d%02d:%02d:%02dZ#0x%04x#%d#%04x",
	    ltm->tm_year + 1900, ltm->tm_mon + 1, ltm->tm_mday, ltm->tm_hour,
	    ltm->tm_min, ltm->tm_sec, op, replica, mod );

	if( n < 0 ) return 0;
	return ( (size_t) n < len ) ? n : 0;
}

#ifdef TEST
int
main(int argc, char **argv)
{
	char buf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];

	if ( ! lutil_csnstr( buf, (size_t) 10, 0, 0 ) ) {
		fprintf(stderr, "failed lutil_csnstr\n");
	}
	if ( ! lutil_csnstr( buf, sizeof(buf), 0, 0 ) ) {
		fprintf(stderr, "failed lutil_csnstr\n");
	}
}
#endif
