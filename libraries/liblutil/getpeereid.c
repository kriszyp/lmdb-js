/* getpeereid.c */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#ifndef HAVE_GETPEEREID

#include <sys/types.h>
#include <ac/unistd.h>

#include <ac/socket.h>
#include <ac/errno.h>

#if HAVE_SYS_UCRED_H
#if HAVE_GRP_H
#include <grp.h>	/* for NGROUPS on Tru64 5.1 */
#endif
#include <sys/ucred.h>
#endif

/* Disabled due to ITS#4893, will revisit in release 2.4 */
#if 0 /* !defined(SO_PEERCRED) && !defined(LOCAL_PEERCRED) && \
	defined(HAVE_SENDMSG) && (defined(HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTSLEN) || \
		defined(HAVE_STRUCT_MSGHDR_MSG_CONTROL)) */
#define DO_SENDMSG
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <sys/stat.h>
#endif

#include <stdlib.h>


int getpeereid( int s, uid_t *euid, gid_t *egid )
{
#ifdef LDAP_PF_LOCAL
#if defined( SO_PEERCRED )
	struct ucred peercred;
	ber_socklen_t peercredlen = sizeof peercred;

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
	ber_socklen_t peercredlen = sizeof peercred;

	if(( getsockopt( s, LOCAL_PEERCRED, 1,
		(void *)&peercred, &peercredlen ) == 0 )
		&& ( peercred.cr_version == XUCRED_VERSION ))
	{
		*euid = peercred.cr_uid;
		*egid = peercred.cr_gid;
		return 0;
	}
#elif defined( DO_SENDMSG )
	char dummy[8];
	int err, fd[2];
	struct iovec iov;
	struct msghdr msg = {0};
# ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
# ifndef CMSG_SPACE
# define CMSG_SPACE(len)	(_CMSG_ALIGN(sizeof(struct cmsghdr)) + _CMSG_ALIGN(len))
# endif
# ifndef CMSG_LEN
# define CMSG_LEN(len)		(_CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
# endif
	union {
		struct cmsghdr cm;
		unsigned char control[CMSG_SPACE(sizeof(int))];
	} control_un;
	struct cmsghdr *cmsg;
# endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	struct stat st;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	iov.iov_base = dummy;
	iov.iov_len = sizeof dummy;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
# ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = control_un.control;
	msg.msg_controllen = sizeof( control_un.control );

	cmsg = CMSG_FIRSTHDR( &msg );

	/*
	 * AIX returns a bogus file descriptor if recvmsg() is
	 * called with MSG_PEEK (is this a bug?). Hence we need
	 * to receive the Abandon PDU.
	 */
	if( recvmsg( s, &msg, MSG_WAITALL ) >= 0 &&
	    cmsg->cmsg_len == CMSG_LEN( sizeof(int) ) &&
	    cmsg->cmsg_level == SOL_SOCKET &&
	    cmsg->cmsg_type == SCM_RIGHTS )
# else
	msg.msg_accrights = (char *)fd;
	msg.msg_accrightslen = sizeof(fd);
	if( recvmsg( s, &msg, MSG_PEEK) >= 0 && msg.msg_accrightslen == sizeof(int) )
# endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL*/
	{
		/* We must receive a valid descriptor, it must be a pipe,
		 * and it must only be accessible by its owner.
		 */
# ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
		fd[0] = (*(int *)CMSG_DATA( cmsg ));
# endif
		err = fstat( fd[0], &st );
		close(fd[0]);
		if( err == 0 && S_ISFIFO(st.st_mode) &&
			((st.st_mode & (S_IRWXG|S_IRWXO)) == 0))
		{
			*euid = st.st_uid;
			*egid = st.st_gid;
			return 0;
		}
	}
#elif defined(SOCKCREDSIZE)
	struct msghdr msg;
	ber_socklen_t crmsgsize;
	void *crmsg;
	struct cmsghdr *cmp;
	struct sockcred *sc;

	memset(&msg, 0, sizeof msg);
	crmsgsize = CMSG_SPACE(SOCKCREDSIZE(NGROUPS));
	if (crmsgsize == 0) goto sc_err;
	crmsg = malloc(crmsgsize);
	if (crmsg == NULL) goto sc_err;
	memset(crmsg, 0, crmsgsize);
	
	msg.msg_control = crmsg;
	msg.msg_controllen = crmsgsize;
	
	if (recvmsg(s, &msg, 0) < 0) {
		free(crmsg);
		goto sc_err;
	}	

	if (msg.msg_controllen == 0 || (msg.msg_flags & MSG_CTRUNC) != 0) {
		free(crmsg);
		goto sc_err;
	}	
	
	cmp = CMSG_FIRSTHDR(&msg);
	if (cmp->cmsg_level != SOL_SOCKET || cmp->cmsg_type != SCM_CREDS) {
		printf("nocreds\n");
		goto sc_err;
	}	
	
	sc = (struct sockcred *)(void *)CMSG_DATA(cmp);
	
	*euid = sc->sc_euid;
	*egid = sc->sc_egid;

	free(crmsg);
	return 0;

sc_err:	
#endif
#endif /* LDAP_PF_LOCAL */

	return -1;
}

#endif /* HAVE_GETPEEREID */
