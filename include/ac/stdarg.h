/* Generic stdarg.h */

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
