/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/socket.h>

/* Return a pair of descriptors that are connected to each other. The
 * returned descriptors are suitable for use with select(). The two
 * descriptors may or may not be identical; the function may return
 * the same descriptor number in both slots. It is guaranteed that
 * data written on fds[1] will be readable on fds[0]. The returned
 * descriptors may be datagram oriented, so data should be written
 * in reasonably small pieces and read all at once. On Unix systems
 * this function is best implemented using a single pipe() call.
 */
int lutil_pair( int fds[2] )
{
	struct sockaddr_in si;
	int rc, len = sizeof(si);
	int fd;

	fd = socket( AF_INET, SOCK_DGRAM, 0 );
	if (fd < 0)
		return fd;
	
	(void) memset( (void*) &si, 0, len );
	si.sin_family = AF_INET;
	si.sin_port = 0;
	si.sin_addr.s_addr = htonl( INADDR_LOOPBACK );

	if ( rc = bind( fd, (struct sockaddr *)&si, len ) )
	{
fail:		tcp_close(fd);
		return rc;
	}
	if ( rc = getsockname( fd, (struct sockaddr *)&si, &len ) )
		goto fail;
	if ( rc = connect( fd, (struct sockaddr *)&si, len ) )
		goto fail;
	fds[0] = fds[1] = fd;
	return 0;
}
