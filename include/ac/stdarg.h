/* Generic stdarg.h */

#ifndef _AC_STDARG_H
#define _AC_STDARG_H 1

#if defined( HAVE_STDARG_H ) && \
	( defined( __STDC__ ) || defined( _WIN32 ) )
#	include <stdarg.h>
#	define HAVE_STDARG 1
#else
#	include <varargs.h>
#endif

#endif /* _AC_STDARG_H */
