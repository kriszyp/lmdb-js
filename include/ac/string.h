/* Generic string.h */

#ifndef _AC_STRING_H
#define _AC_STRING_H

#if STDC_HEADERS
#	include <string.h>
#else
#	ifndef HAVE_STRCHR
#		define strchr index
#		define strrchr rindex
#	endif
	char *strchr (), *strrchr ();

#	ifndef HAVE_MEMCPY
#		define memcpy(d, s, n) bcopy ((s), (d), (n))
#		define memmove(d, s, n) bcopy ((s), (d), (n))
#	endif
#endif

#ifdef HAVE_MEMMOVE
#	define SAFEMEMCPY( d, s, n )		 	memmove((s), (d), (n))
#else
#	ifdef HAVE_BCOPY
#		define SAFEMEMCPY( d, s, n ) 		bcopy((s), (d), (n))
#	else
#		ifdef MACOS
#			define SAFEMEMCPY( d, s, n ) 	BlockMoveData((Ptr)(s), (Ptr)(d), (n))
#		else
#			define SAFEMEMCPY( d, s, n )	memmove((s), (d), (n))
#		endif
#	endif
#endif

#endif /* _AC_STRING_H */
