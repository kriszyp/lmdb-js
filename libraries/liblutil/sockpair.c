/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"
#include <ac/socket.h>

#include <lutil.h>

/* Return a pair of socket descriptors that are connected to each other.
 * The returned descriptors are suitable for use with select(). The two
 * descriptors may or may not be identical; the function may return
 * the same descriptor number in both slots. It is guaranteed that
 * data written on sds[1] will be readable on sds[0]. The returned
 * descriptors may be datagram oriented, so data should be written
 * in reasonably small pieces and read all at once. On Unix systems
 * this function is best implemented using a single pipe() call.
 */

int lutil_pair( LBER_SOCKET_T sds[2] )
{
	struct sockaddr_in si;
	int rc, len = sizeof(si);
	LBER_SOCKET_T sd;

	sd = socket( AF_INET, SOCK_DGRAM, 0 );
	if (sd < 0)
		return sd;
	
	(void) memset( (void*) &si, 0, len );
	si.sin_family = AF_INET;
	si.sin_port = 0;
	si.sin_addr.s_addr = htonl( INADDR_LOOPBACK );

	if ( rc = bind( sd, (struct sockaddr *)&si, len ) ) {
		tcp_close(sd);
		return rc;
	}

	if ( rc = getsockname( sd, (struct sockaddr *)&si, &len ) ) {
		tcp_close(sd);
		return rc;
	}

	if ( rc = connect( sd, (struct sockaddr *)&si, len ) ) {
		tcp_close(sd);
		return rc;
	}

	sds[0] = sds[1] = sd;
	return 0;
}
