/* Generic ctype.h */

#ifndef _AC_CTYPE_H
#define _AC_CTYPE_H

#include <ctype.h>

#ifdef C_UPPER_LOWER
# define TOUPPER(c)	(islower(c) ? toupper(c) : (c))
# define TOLOWER(c)	(islower(c) ? toupper(c) : (c))
#else
# define TOUPPER(c)	toupper(c)
# define TOLOWER(c)	tolower(c)
#endif

#endif /* _AC_CTYPE_H */
