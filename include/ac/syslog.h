/*
 * Generic syslog.h
 */
#ifndef _AC_SYSLOG_H_
#define _AC_SYSLOG_H_

#if defined( HAVE_SYSLOG_H )
#  include <syslog.h>
#else
#  if defined ( HAVE_SYS_SYSLOG_H )
#    include <sys/syslog.h>
#  endif
#endif

#if defined( LOG_NDELAY ) && defined( LOG_NOWAIT )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NDELAY | LOG_NOWAIT )
#else
#  if defined( LOG_NDELAY )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NDELAY )
#  else
#    if defined( LOG_NOWAIT )
#	define OPENLOG_OPTIONS ( LOG_PID | LOG_NOWAIT )
#    else
#	define OPENLOG_OPTIONS ( LOG_PID )
#    endif
#  endif
#endif

#endif /* _AC_SYSLOG_H_ */
