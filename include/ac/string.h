/* Generic string.h */

#ifndef _AC_STRING_H
#define _AC_STRING_H

#ifdef STDC_HEADERS
#	include <string.h>

#else
#	ifdef HAVE_STRING_H
#		include <string.h>
#	elif HAVE_STRINGS_H
#		include <strings.h>
#	endif

#	ifdef HAVE_MEMORY_H
#		include <memory.h>
#	endif

#	ifdef HAVE_MALLOC_H
#		include <malloc.h>
#	endif

#	ifndef HAVE_STRCHR
#		define strchr index
#		define strrchr rindex
#	endif

#	ifndef HAVE_MEMCPY
#		define memcpy(d, s, n)			bcopy ((s), (d), (n))
#		define memmove(d, s, n)			bcopy ((s), (d), (n))
#	endif
#endif

/*
 * provide prototypes for missing functions that we replace.
 * replacements can be found in -llutil
 */
#ifndef HAVE_STRDUP
	char *strdup( const char *s );
#endif

#ifndef SAFEMEMCPY
#	if defined( HAVE_MEMMOVE )
#		define SAFEMEMCPY( d, s, n ) 	memmove((d), (s), (n))
#	elif defined( HAVE_BCOPY )
#		define SAFEMEMCPY( d, s, n ) 	bcopy((s), (d), (n))
#	else
		/* nothing left but memcpy() */
#		define SAFEMEMCPY( d, s, n )	memcpy((d), (s), (n))
#	endif
#endif

#endif /* _AC_STRING_H */
