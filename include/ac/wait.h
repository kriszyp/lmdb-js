/* Generic wait.h */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#ifndef _AC_WAIT_H
#define _AC_WAIT_H

#include <sys/types.h>

#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif

#ifdef WCONTINUED
# define WAIT_FLAGS ( WNOHANG | WUNTRACED | WCONTINUED )
#else
# define WAIT_FLAGS ( WNOHANG | WUNTRACED )
#endif

#endif /* _AC_WAIT_H */
