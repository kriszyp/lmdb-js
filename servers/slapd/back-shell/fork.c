/* fork.c - fork and exec a process, connecting stdin/out w/pipes */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slap.h"
#include "shell.h"

#ifdef SHELL_SURROGATE_PARENT

#include <sys/uio.h>

/* Use several socketpairs to the surrogate parent, because   *
 * a single communication channel to it could be a bottleneck */
ldap_pvt_thread_mutex_t shell_surrogate_fd_mutex[2];
int                     shell_surrogate_fd[2] = { -1, -1 };
/* Index to shell_surrogate_fd, and its mutex */
ldap_pvt_thread_mutex_t shell_surrogate_index_mutex;
static int              shell_surrogate_index = 1;

pid_t                   shell_surrogate_pid = -1;

#define  nread( fd, buf, len ) n_rw( 0, fd, buf, len )
#define nwrite( fd, buf, len ) n_rw( 1, fd, buf, len )

static int
n_rw(
	int do_write,
	int fd,
	void *buf,
	int len
)
{
	int ret = 0, i;
	while( len ) {
		for(;;) {
			i = (do_write
			     ? write( fd, buf, len )
			     :  read( fd, buf, len ));
			if( i < 0 ) {
				if( errno == EINTR )
					continue;
				if( ret == 0 )
					ret = -1;
			}
			break;
		}
		if( i <= 0 )
			break;
		ret += i;
		buf = (char *)buf + i;
		len -= i;
	}
	return ret;
}

void
make_surrogate_parent( void )
{
	int pair[2][2], io[2], i, j, p, argc;
	ber_len_t len, buflen, offset;
	char *buf, **argv;
	pid_t pid;

	if( socketpair( AF_LOCAL, SOCK_STREAM, 0, pair[0] ) < 0 ||
	    socketpair( AF_LOCAL, SOCK_STREAM, 0, pair[1] ) < 0   ) {
		Debug( LDAP_DEBUG_ANY, "socketpair failed\n", 0, 0, 0 );
		exit( EXIT_FAILURE );
	}
	fflush( NULL );
	switch( fork() ) {
	case -1:
		Debug( LDAP_DEBUG_ANY, "fork failed\n", 0, 0, 0 );
		exit( EXIT_FAILURE );
	case 0:
		break;
	default:
		shell_surrogate_fd[0] = pair[0][0];
		shell_surrogate_fd[1] = pair[1][0];
		close( pair[0][1] );
		close( pair[1][1] );
		return;
	}

	/* Close unused file descriptors */
	for( i = 3, j = 32; j && i < 1024; i++ )
		if( i != pair[0][1] && i != pair[1][1] && close( i ) < 0 )
			--j;
		else if( j < 32 )
			j = 32;

	/* Surrogate parent running */

	buflen = 0;
	buf = NULL;
	argc = 0;
	argv = NULL;
	p = 0;

	for(;;) {
		/* Read file descriptors io[] from socket */ 
		static char dummy;
		static struct iovec iov = { &dummy, 1 };
		struct msghdr msg;
# ifdef CMSG_SPACE
		union {
			struct cmsghdr cm;
			char control[CMSG_SPACE(sizeof(io))];
		} control_un;
		struct cmsghdr *cmptr;
# endif

		/* clear msghdr */
		memset( &msg, 0, sizeof msg );

# ifdef CMSG_SPACE
		msg.msg_control = control_un.control;
		msg.msg_controllen = sizeof(control_un.control);
# else
		msg.msg_accrights = (caddr_t) io;
		msg.msg_accrightslen = sizeof(io);
# endif

		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		switch( recvmsg( pair[p][1], &msg, MSG_WAITALL ) ) {
		case -1:
			if( errno == EINTR )
				continue;
			_exit( EXIT_FAILURE );
		case 0:
			_exit( EXIT_SUCCESS );
		}
# ifdef CMSG_SPACE
		if( (cmptr = CMSG_FIRSTHDR(&msg)) == NULL   ||
		    cmptr->cmsg_len != CMSG_LEN(sizeof(io)) ||
		    cmptr->cmsg_level != SOL_SOCKET         ||
		    cmptr->cmsg_type != SCM_RIGHTS            ) {
			fputs( "bad descriptor message received\n", stderr );
			exit( EXIT_FAILURE );
		}
		memcpy( io, CMSG_DATA( cmptr ), sizeof(io) );
# else
		if( msg.msg_accrightslen != sizeof(io) ) {
			fputs( "bad descriptor message received\n", stderr );
			exit( EXIT_FAILURE );
		}
# endif

		/* Read length of arguments and then arguments from socket */
		if( nread( pair[p][1], &len, sizeof(len) ) != sizeof(len) ) {
			fputs( "bad descriptor message received\n", stderr );
			exit( EXIT_FAILURE );
		}
		if( buflen < len ) {
			buf = realloc( buf, buflen = len );
			if( buf == NULL ) {
				fputs( "realloc failed\n", stderr );
				exit( EXIT_FAILURE );
			}
		}
		if( nread( pair[p][1], buf, len ) != len ) {
			fputs( "bad descriptor message received\n", stderr );
			exit( EXIT_FAILURE );
		}
		i = 0;
		offset = 0;
		while( offset < len ) {
			if( i >= argc-1 ) {
				argc += i + 10;
				argv = realloc( argv, argc * sizeof(*argv) );
				if( argv == NULL ) {
					fputs( "realloc failed\n", stderr );
					exit( EXIT_FAILURE );
				}
			}
			argv[i++] = buf + offset;
			offset += strlen( buf + offset ) + 1;
		}
		argv[i] = NULL;

		/* Run program */
		pid = fork();
		switch( pid )
		{
		case 0:		/* child */
			if( dup2( io[0], 0 ) == -1 || dup2( io[1], 1 ) == -1 ) {
				fputs( "dup2 failed\n", stderr );
				exit( EXIT_FAILURE );
			}
			close( io[0] );
			close( io[1] );
			close( pair[0][1] );
			close( pair[1][1] );
			execv( argv[0], argv );

			fputs( "execv failed\n", stderr );
			exit( EXIT_FAILURE );

		case -1:	/* trouble */
			fputs( "fork failed\n", stderr );
			break;

		default:	/* parent */
			close( io[0] );
			close( io[1] );
			break;
		}
		if( nwrite( pair[p][1], &pid,
		            sizeof(pid_t) ) != sizeof(pid_t) )  {
			fputs( "could not send pid\n", stderr );
			exit( EXIT_FAILURE );
		}
		p ^= 1;
	}
}
#endif /* SHELL_SURROGATE_PARENT */

pid_t
forkandexec(
    Cmd_info  args,
    FILE	**rfp,
    FILE	**wfp
)
{
	int	p2c[2] = { -1, -1 }, c2p[2];
	pid_t	pid;

	if ( pipe( p2c ) != 0 || pipe( c2p ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "pipe failed\n", 0, 0, 0 );
		close( p2c[0] );
		close( p2c[1] );
		return( -1 );
	}

	/*
	 * what we're trying to set up looks like this:
	 *	parent *wfp -> p2c[1] | p2c[0] -> stdin child
	 *	parent *rfp <- c2p[0] | c2p[1] <- stdout child
	 */

#ifdef SHELL_SURROGATE_PARENT

	{
		int io[2] = { p2c[0], c2p[1] }, i, c;
		static char dummy = '\0';
		static struct iovec iov = { &dummy, 1 };
		struct msghdr msg;
# ifdef CMSG_SPACE
		union {
			struct cmsghdr cm;
			char control[CMSG_SPACE(sizeof(io))];
		} control_un;
		struct cmsghdr *cmptr;
# endif

		/* clear msghdr */
		memset( &msg, 0, sizeof msg );

# ifdef CMSG_SPACE
		msg.msg_control = control_un.control;
		msg.msg_controllen = sizeof(control_un.control);
		cmptr = CMSG_FIRSTHDR(&msg);
		cmptr->cmsg_len = CMSG_LEN(sizeof(io));
		cmptr->cmsg_level = SOL_SOCKET;
		cmptr->cmsg_type = SCM_RIGHTS;
		memcpy( CMSG_DATA(cmptr), io, sizeof(io) );
# else
		msg.msg_accrights = (caddr_t) io;
		msg.msg_accrightslen = sizeof(io);
# endif

		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;

		ldap_pvt_thread_mutex_lock( &shell_surrogate_index_mutex );
		i = shell_surrogate_index ^= 1;
		ldap_pvt_thread_mutex_unlock( &shell_surrogate_index_mutex );
		ldap_pvt_thread_mutex_lock( &shell_surrogate_fd_mutex[i] );
		c = (sendmsg( shell_surrogate_fd[i], &msg, 0 ) == 1 &&
			 nwrite( shell_surrogate_fd[i], &args.bv_len,
			         sizeof(args.bv_len) ) == sizeof(args.bv_len) &&
			 nwrite( shell_surrogate_fd[i], args.bv_val,
			         args.bv_len ) == args.bv_len &&
			 nread( shell_surrogate_fd[i], &pid,
			        sizeof(pid) ) == sizeof(pid));
		ldap_pvt_thread_mutex_unlock( &shell_surrogate_fd_mutex[i] );
		close( p2c[0] );
		close( c2p[1] );
		if ( !c ) {
			Debug( LDAP_DEBUG_ANY, "process creation failed\n", 0, 0, 0 );
			close( p2c[1] );
			close( c2p[0] );
			close( shell_surrogate_fd[0] );
			close( shell_surrogate_fd[1] );
			shell_surrogate_fd[0] =
				shell_surrogate_fd[1] = -1;
			return( -1 );
		}
	}

#else /* !SHELL_SURROGATE_PARENT */

	fflush( NULL );
# ifdef HAVE_THR
	pid = fork1();
# else
	pid = fork();
# endif
	if ( pid == 0 ) {		/* child */
		/*
		 * child could deadlock here due to resources locked
		 * by our parent
		 *
		 * If so, configure --without-threads.
		 */
		if ( dup2( p2c[0], 0 ) == -1 || dup2( c2p[1], 1 ) == -1 ) {
			Debug( LDAP_DEBUG_ANY, "dup2 failed\n", 0, 0, 0 );
			exit( EXIT_FAILURE );
		}
	}
	close( p2c[0] );
	close( c2p[1] );
	if ( pid <= 0 ) {
		close( p2c[1] );
		close( c2p[0] );
	}
	switch ( pid ) {
	case 0:
		execv( args[0], args );

		Debug( LDAP_DEBUG_ANY, "execv failed\n", 0, 0, 0 );
		exit( EXIT_FAILURE );

	case -1:	/* trouble */
		Debug( LDAP_DEBUG_ANY, "fork failed\n", 0, 0, 0 );
		return( -1 );
	}

#endif /* SHELL_SURROGATE_PARENT */

	/* parent */
	if ( (*rfp = fdopen( c2p[0], "r" )) == NULL || (*wfp = fdopen( p2c[1],
	    "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "fdopen failed\n", 0, 0, 0 );
		close( c2p[0] );
		close( p2c[1] );

		return( -1 );
	}

	return( pid );
}
