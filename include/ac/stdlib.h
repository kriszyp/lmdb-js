/* Generic stdlib.h */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.  A copy of this license is available at
 * http://www.OpenLDAP.org/license.html or in file LICENSE in the
 * top-level directory of the distribution.
 */

#ifndef _AC_STDLIB_H
#define _AC_STDLIB_H

#if defined( HAVE_CSRIMALLOC )
#include <stdio.h>
#define MALLOC_TRACE
#include <libmalloc.h>
#endif

#include <stdlib.h>

/* Ignore malloc.h if we have STDC_HEADERS */
#if defined(HAVE_MALLOC_H) && !defined(STDC_HEADERS)
#	include <malloc.h>
#endif

#ifndef EXIT_SUCCESS
#	define EXIT_SUCCESS 0
#	define EXIT_FAILURE 1
#endif

#ifdef HAVE_EBCDIC
#undef putchar
#undef putc
#define	putchar(c)	putc((c), stdout)
#define	putc(c, fp)	do { char x=(c); __atoe_l(&x,1); putc(x,fp);} while(0)
#endif

#endif /* _AC_STDLIB_H */
