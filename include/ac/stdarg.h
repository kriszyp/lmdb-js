/* Generic stdarg.h */

#ifndef _AC_STDARG_H
#define _AC_STDARG_H

#if defined( HAVE_STDARG_H ) && \
		( defined( __STDC__) || defined( __WIN32 )
#	define HAVE_STDARG 1
#	include <stdarg.h>
#else
#	include <vararg.h>
#endif

#endif /* _AC_STDARG_H */
