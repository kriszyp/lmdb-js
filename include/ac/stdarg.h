/* Generic stdarg.h */
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

#ifndef _AC_STDARG_H
#define _AC_STDARG_H 1

/* require STDC variable argument support */

#include <stdarg.h>

#ifndef HAVE_STDARG
#	define HAVE_STDARG 1
#endif

/*
 * These functions are not included amongst Mingw32 headers for some
 * reason even though they are supported in the library
 */

#if defined(__MINGW32__) && defined(HAVE_SNPRINTF)
LIBC_F (int) snprintf(char *, size_t, const char *, ...);
#endif

#if defined(__MINGW32__) && defined(HAVE_VSNPRINTF)
LIBC_F (int) vsnprintf(char *, size_t, const char *, va_list);
#endif

#endif /* _AC_STDARG_H */
