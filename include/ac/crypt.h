/* Generic crypt.h */
/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_CRYPT_H
#define _AC_CRYPT_H

#include <ac/unistd.h>

/* crypt() may be defined in a separate include file */
#if HAVE_CRYPT_H
#	include <crypt.h>
#else
	extern char *(crypt)();
#endif

#endif /* _AC_CRYPT_H */
