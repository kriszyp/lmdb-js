/*
 * Generic syslog.h
 */
#ifndef _AC_SYSLOG_H_
#define _AC_SYSLOG_H_

#ifdef HAVE_SYSLOG_H
#include <syslog.h>

#if defined( LOG_NDELAY )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NDELAY )
#elif defined( LOG_NOWAIT )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NOWAIT )
#else
#	define OPENLOG_OPTIONS ( LOG_PID )
#endif

#endif /* syslog.h */

#endif /* _AC_SYSLOG_H_ */
