/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/* File locking methods */

#include "portable.h"

#include <stdio.h>
#include <ac/unistd.h>

#if defined(NEED_FCNTL_LOCKING) && defined(HAVE_FCNTL_H)

#include <fcntl.h>

int lutil_ldap_lockf ( FILE *fs ) {
	struct flock file_lock;
	memset( &file_lock, 0, sizeof( file_lock ) );
	file_lock.l_type = F_WRLCK;
	file_lock.l_whence = SEEK_SET;
	file_lock.l_start = 0;
	file_lock.l_len = 0;
	return( fcntl( fileno( fs ), F_SETLKW, &file_lock ) );
}

int lutil_ldap_unlockf ( FILE *fs ) {
	struct flock file_lock;
	memset( &file_lock, 0, sizeof( file_lock ) );
	file_lock.l_type = F_UNLCK;
	file_lock.l_whence = SEEK_SET;
	file_lock.l_start = 0;
	file_lock.l_len = 0;
	return ( fcntl( fileno( fs ), F_SETLK, &file_lock ) );
}

#endif /* !HAVE_FILE_LOCKING */
