/* Generic stdlib.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_STDLIB_H
#define _AC_STDLIB_H

#ifdef STDC_HEADERS
#	include <stdlib.h>

#else

#	ifdef HAVE_MALLOC_H
#		include <malloc.h>
#	endif

#endif

#endif /* _AC_STDLIB_H */
