/*
 * Select uses bit masks of file descriptors in longs.  These macros
 * manipulate such bit fields.
 *
 * FD_SETSIZE is the number file descriptors select() is able to
 * deal with.  For DEC TCP/IP on VMS this is currently 32.
 */
#define	FD_SETSIZE	32
#define	NBBY	8		/* number of bits in a byte */

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#ifndef howmany
#define	howmany(x, y)	(((x)+((y)-1))/(y))
#endif

typedef	struct fd_set {
	fd_mask	fds_bits[howmany(FD_SETSIZE, NFDBITS)];
} fd_set;

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define	FD_ZERO(p)	memset((char *)(p), 0, sizeof(*(p)))

#define getdtablesize()	FD_SETSIZE

