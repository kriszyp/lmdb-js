/* Generic queue.h */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */

#ifndef _AC_CRYPT_H
#define _AC_CRYPT_H

#if HAVE_SYS_QUEUE_H
#	include <sys/queue.h>
#else
#	include <queue-compat.h>
#endif

#endif /* _AC_CRYPT_H */
