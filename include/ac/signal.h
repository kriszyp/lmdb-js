/* Generic signal.h */

#ifndef _AC_SIGNAL_H
#define _AC_SIGNAL_H

#include <signal.h>

#ifdef HAVE_SIGSET
#define SIGNAL sigset
#else
#define SIGNAL signal
#endif

#endif /* _AC_SIGNAL_H */
