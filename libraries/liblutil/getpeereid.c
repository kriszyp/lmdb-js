/* getpeereid.c */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#ifndef HAVE_GETPEEREID

#include <sys/types.h>
#include <ac/unistd.h>

#include <ac/socket.h>
#include <ac/errno.h>

#if HAVE_SYS_UCRED_H
#include <sys/ucred.h>
#endif

#if !defined(SO_PEERCRED) && !defined(LOCAL_PEERCRED) && defined(HAVE_SENDMSG)
#define DO_SENDMSG
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <sys/stat.h>
#endif

int getpeereid( int s, uid_t *euid, gid_t *egid )
{
#ifdef LDAP_PF_LOCAL
#if defined( SO_PEERCRED )
	struct ucred peercred;
	size_t peercredlen = sizeof peercred;

	if(( getsockopt( s, SOL_SOCKET, SO_PEERCRED,
		(void *)&peercred, &peercredlen ) == 0 )
		&& ( peercredlen == sizeof peercred ))
	{
		*euid = peercred.uid;
		*egid = peercred.gid;
		return 0;
	}

#elif defined( LOCAL_PEERCRED )
	struct xucred peercred;
	socklen_t peercredlen = sizeof peercred;

	if(( getsockopt( s, LOCAL_PEERCRED, 1,
		(void *)&peercred, &peercredlen ) == 0 )
		&& ( peercred.cr_version == XUCRED_VERSION ))
	{
		*euid = peercred.cr_uid;
		*egid = peercred.cr_gid;
		return 0;
	}
#elif defined( DO_SENDMSG )
	int dummy, fd[2];
	struct iovec iov = {(char *)&dummy, 1};
	struct msghdr msg = {0};
	struct stat st;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_accrights = (char *)fd;
	msg.msg_accrightslen = sizeof(fd);
	if( recvmsg( s, &msg, MSG_PEEK) >= 0 && msg.msg_accrightslen == sizeof(int) )
	{
		/* We must receive a valid descriptor, it must be a pipe,
		 * and it must only be accessible by its owner.
		 */
		dummy = fstat( fd[0], &st );
		close(fd[0]);
		if( dummy == 0 && S_ISFIFO(st.st_mode) &&
			((st.st_mode & (S_IRWXG|S_IRWXO)) == 0))
		{
			*euid = st.st_uid;
			*egid = st.st_gid;
			return 0;
		}
	}
#endif
#endif /* LDAP_PF_LOCAL */

	return -1;
}

#endif /* HAVE_GETPEEREID */
