/* Generic stdarg.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_STDARG_H
#define _AC_STDARG_H 1

#if defined( HAVE_STDARG ) || \
	( defined( HAVE_STDARG_H ) && defined( __STDC__ ) ) 

#	include <stdarg.h>

#	ifndef HAVE_STDARG
#		define HAVE_STDARG 1
#	endif

#else
#	include <varargs.h>
#endif

#endif /* _AC_STDARG_H */
