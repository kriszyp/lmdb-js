/* getpeereid.c */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#ifndef HAVE_GETPEEREID

#include <sys/types.h>
#include <ac/unistd.h>

#include <ac/socket.h>

#if HAVE_SYS_UCRED_H
#include <sys/ucred.h>
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
#endif
#endif

	return -1;
}

#endif
