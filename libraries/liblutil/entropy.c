/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <fcntl.h>

#include <lutil.h>
#include <lutil_md5.h>

/*
 * lutil_entropy() provides nbytes of entropy in buf.
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

		/* should return nbytes */
		if( rc < nbytes ) return -1;

		return 0;
	}
#else
	{
		/* based upon Phil Karn's "practical randomness" idea
		 * but implementation 100% OpenLDAP.  So don't blame Phil. */
		/* worse case is this is a MD5 hash of a counter, if
		 *	MD5 is a strong cryptographic hash, this should
		 *	be fairly resistant to attack
		 */
		static int counter = 0;
		int n;

		struct rdata_s {
			int counter;

			char *buf;
			struct rdata_s *stack;

			pid_t	pid;

#ifdef HAVE_GETTIMEOFDAY
			struct timeval *tv;
#else
			time_t	time;
#endif
			unsigned long	junk;
		} rdata;

		/* make sure rdata differs for each process */
		rdata.pid = getpid();

		/* make sure rdata differs for each program */
		rdata.buf = buf;
		rdata.stack = &rdata;

		for( n = 0; n < nbytes; n += 16 ) {
			struct lutil_MD5Context ctx;
			char digest[16];

			/* hopefully has good resolution */
#ifdef HAVE_GETTIMEOFDAY
			(void) gettimeofday( &rdata.tv, sizeof( rdata.tv ) );
#else
			(void) time( &rdata.time );
#endif

			/* make sure rdata differs */
			rdata.counter = ++counter;
			rdata.pid++;
			rdata.junk++;

			lutil_MD5Init( &ctx );
			lutil_MD5Update( &ctx, (char *) &rdata, sizeof( rdata ) );
			lutil_MD5Final( digest, &ctx );

			memcpy( &buf[n], digest,
				nbytes - n > 16 ? 16 : nbytes - n );
		}

		return 0;
	}
#endif
	return -1;
}
