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

#	ifndef HAVE_STRCHR
#		define strchr index
#		define strrchr rindex
#	endif

#	ifndef HAVE_MEMCPY
#		define memcpy(d, s, n)			bcopy ((s), (d), (n))
#		define memmove(d, s, n)			bcopy ((s), (d), (n))
#	endif

#	if !defined(HAVE_STRING_H) && !defined(HAVE_STRINGS_H)
	/* define prototypes for string functions */
	/* this could cause problems on some odd ball systems */
	char	*strchr(), *strrchr();
	char	*strcpy(), *strncpy();
	char	*strcat (), *strncat ();
	int		strcmp(), strncmp();
	int		strcasecmp(), strncasecmp();
	char	*strdup();
	char	*strtok();
	char	*strpbrk();
	int		memcmp();
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
