/* @(#) stddef.h 1.1 92/02/15 17:25:46 */

#ifndef _stddef_h_
#define _stddef_h_

/* NULL is also defined in <stdio.h> */

#ifndef NULL
#define NULL 0
#endif

/* Structure member offset - some compilers barf on this. */

#define offsetof(type, member) ((size_t) &((type *)0)->member)

/* Some of the following types may already be defined in <sys/types.h>. */

/* #include <sys/types.h> */
/* typedef long ptrdiff_t;		/* type of pointer difference */
/* typedef unsigned short wchar_t;	/* wide character type */
/* typedef unsigned size_t;		/* type of sizeof */

#endif /* _stddef_h_ */
