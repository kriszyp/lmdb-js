/* Generic string.h */

#ifndef _AC_STRING_H
#define _AC_STRING_H

#ifdef STDC_HEADERS
#	include <string.h>
#else
#	ifndef HAVE_STRCHR
#		define strchr index
#		define strrchr rindex
#	endif
	char *strchr (), *strrchr ();

#	ifndef HAVE_MEMCPY
#		define memcpy(d, s, n)			bcopy ((s), (d), (n))
#		define memmove(d, s, n)			bcopy ((s), (d), (n))
#	endif
#endif

#ifndef SAFEMEMCPY
#	if defined( HAVE_MEMMOVE )
#		define SAFEMEMCPY( d, s, n ) 	memmove((d), (s), (n))
#	elif defined( HAVE_BCOPY )
#		define SAFEMEMCPY( d, s, n ) 	bcopy((s), (d), (n))
#	elif defined( MACOS )
#		define SAFEMEMCPY( d, s, n ) 	BlockMoveData((Ptr)(s), (Ptr)(d), (n))
#	else
		/* nothing left but memcpy() */
#		define SAFEMEMCPY( d, s, n )	memcpy((d), (s), (n))
#	endif
#endif

#endif /* _AC_STRING_H */
