/*
 * Generic Regex
 */
#ifndef _AC_REGEX_H_
#define _AC_REGEX_H_

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_REGEX_H
	/* have regex.h, assume it's POSIX compliant */
#	include <regex.h>
#else
	/* no regex.h, use compatibility library */
#	include <regex-compat.h>
#endif /* ! regex.h */

#endif /* _AC_REGEX_H_ */
