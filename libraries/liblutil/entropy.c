/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <fcntl.h>

#include <lutil.h>

/*
 * lutil_entropy() provides nbyptes of entropy in buf.
 * Quality offerred is suitable for one-time uses, such as "once" keys.
 */
int lutil_entropy( char *buf, int nbytes )
{
	if( nbytes < 0 ) return -1;
	if( nbytes == 0 ) return 0;

#ifdef URANDOM_DEVICE
	/* Linux and *BSD offer a urandom device */
	{
		int rc, fd;

		fd = open( URANDOM_DEVICE, O_RDONLY );

		if( fd < 0 ) return -1;

		rc = read( fd, buf, nbytes );
		close(fd);

		if( rc < nbytes ) return -1;

		return 0;
	}
#endif
	return -1;
}
