/*
 * Generic syslog.h
 */
#ifndef _AC_SYSLOG_H_
#define _AC_SYSLOG_H_

#if defined( HAVE_SYSLOG_H )
#include <syslog.h>
#elif defined ( HAVE_SYS_SYSLOG_H )
#include <sys/syslog.h>
#endif

#if defined( LOG_NDELAY ) && defined( LOG_NOWAIT )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NDELAY | LOG_NOWAIT )
#elif defined( LOG_NDELAY )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NDELAY )
#elif defined( LOG_NOWAIT )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NOWAIT )
#else
#	define OPENLOG_OPTIONS ( LOG_PID )
#endif

#endif /* _AC_SYSLOG_H_ */
