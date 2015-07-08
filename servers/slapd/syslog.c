/*	$OpenBSD: syslog.c,v 1.29 2007/11/09 18:40:19 millert Exp $ */
/*
 * Copyright (c) 1983, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "portable.h"

#include <sys/types.h>
#include <ac/socket.h>
#include <ac/syslog.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netdb.h>

#include <ac/errno.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/stdarg.h>

#include "slap.h"

static int	LogType = SOCK_DGRAM;	/* type of socket connection */
static int	LogFile = -1;		/* fd for log */
static int	connected;		/* have done connect */
static int	LogStat;		/* status bits, set by openlog() */
static const char *LogTag;		/* string to tag the entry with */
static int	LogFacility = LOG_USER;	/* default facility code */
static int	LogMask = 0xff;		/* mask of priorities to be logged */

static void disconnectlog(void);
static void connectlog(void);

static void my_localtime(const time_t *t, struct tm *tm);

/*
 * syslog
 *	print message on log file; output is intended for syslogd(8).
 */
void
syslog(int pri, const char *fmt, ...)
{
	va_list ap;
	char *p, *t;
#define	TBUF_LEN	2048
#define	FMT_LEN		1024
	char *stdp, tbuf[TBUF_LEN], fmt_cpy[FMT_LEN];
	time_t now;
	int cnt;
	int fd, saved_errno, error;
	char ch;
	int tbuf_left, fmt_left, prlen;
	struct tm tm;

	va_start(ap, fmt);

	/* Check for invalid bits. */
	if (pri & ~(LOG_PRIMASK|LOG_FACMASK)) {
		if (LogTest(LOG_ERR))
			lutil_debug(slap_debug, LOG_ERR, 
			    "syslog: unknown facility/priority: %x", pri);
		pri &= LOG_PRIMASK|LOG_FACMASK;
	}

	saved_errno = errno;

	/* Set default facility if none specified. */
	if ((pri & LOG_FACMASK) == 0)
		pri |= LogFacility;

	(void)time(&now);

	p = tbuf;
	tbuf_left = TBUF_LEN;

#define	DEC()	\
	do {					\
		if (prlen < 0)			\
			prlen = 0;		\
		if (prlen >= tbuf_left)		\
			prlen = tbuf_left - 1;	\
		p += prlen;			\
		tbuf_left -= prlen;		\
	} while (0)

	prlen = snprintf(p, tbuf_left, "<%d>", pri);
	DEC();

	my_localtime(&now, &tm);
	prlen = strftime(p, tbuf_left, "%h %e %T ", &tm);
	DEC();

	if (LogTag != NULL) {
		prlen = snprintf(p, tbuf_left, "%s", LogTag);
		DEC();
	}
	if (LogStat & LOG_PID) {
		prlen = snprintf(p, tbuf_left, "[%ld]", (long)getpid());
		DEC();
	}
	if (LogTag != NULL) {
		if (tbuf_left > 1) {
			*p++ = ':';
			tbuf_left--;
		}
		if (tbuf_left > 1) {
			*p++ = ' ';
			tbuf_left--;
		}
	}

	/* strerror() is not reentrant */

	for (t = fmt_cpy, fmt_left = FMT_LEN; (ch = *fmt); ++fmt) {
		if (ch == '%' && fmt[1] == 'm') {
			++fmt;
			prlen = snprintf(t, fmt_left, "%s",
			    strerror(saved_errno)); 
			if (prlen < 0)
				prlen = 0;
			if (prlen >= fmt_left)
				prlen = fmt_left - 1;
			t += prlen;
			fmt_left -= prlen;
		} else if (ch == '%' && fmt[1] == '%' && fmt_left > 2) {
			*t++ = '%';
			*t++ = '%';
			fmt++;
			fmt_left -= 2;
		} else {
			if (fmt_left > 1) {
				*t++ = ch;
				fmt_left--;
			}
		}
	}
	*t = '\0';

	prlen = vsnprintf(p, tbuf_left, fmt_cpy, ap);
	DEC();
	cnt = p - tbuf;
	va_end(ap);

	/* Get connected, output the message to the local logger. */
	if (LogFile == -1)
		openlog(LogTag, LogStat, 0);
	connectlog();

	/*
	 * If the send() failed, there are two likely scenarios:
	 *  1) syslogd was restarted
	 *  2) /dev/log is out of socket buffer space
	 * We attempt to reconnect to /dev/log to take care of
	 * case #1 and keep send()ing data to cover case #2
	 * to give syslogd a chance to empty its socket buffer.
	 */
	if ((error = send(LogFile, tbuf, cnt, 0)) < 0) {
		if (errno != ENOBUFS) {
			disconnectlog();
			connectlog();
		}
		do {
			usleep(1);
			if ((error = send(LogFile, tbuf, cnt, 0)) >= 0)
				break;
		} while (errno == ENOBUFS);
	}
}

static void
disconnectlog(void)
{
	/*
	 * If the user closed the FD and opened another in the same slot,
	 * that's their problem.  They should close it before calling on
	 * system services.
	 */
	if (LogFile != -1) {
		close(LogFile);
		LogFile = -1;
	}
	connected = 0;		/* retry connect */
}

static void
connectlog(void)
{
	struct sockaddr_un SyslogAddr;	/* AF_UNIX address of local logger */

	if (LogFile == -1) {
		if ((LogFile = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
			return;
		(void)fcntl(LogFile, F_SETFD, FD_CLOEXEC);
	}
	if (LogFile != -1 && !connected) {
		memset(&SyslogAddr, '\0', sizeof(SyslogAddr));
#ifdef _BSD
		SyslogAddr.sun_len = sizeof(SyslogAddr);
#endif
		SyslogAddr.sun_family = AF_UNIX;
		strncpy(SyslogAddr.sun_path, _PATH_LOG,
		    sizeof(SyslogAddr.sun_path));
		if (connect(LogFile, (struct sockaddr *)&SyslogAddr,
		    sizeof(SyslogAddr)) == -1) {
			(void)close(LogFile);
			LogFile = -1;
		} else
			connected = 1;
	}
}

void
openlog(const char *ident, int logstat, int logfac)
{
	if (ident != NULL)
		LogTag = ident;
	LogStat = logstat;
	if (logfac != 0 && (logfac &~ LOG_FACMASK) == 0)
		LogFacility = logfac;

	if (LogStat & LOG_NDELAY)	/* open immediately */
		connectlog();
}

void
closelog()
{
	(void)close(LogFile);
	LogFile = -1;
	connected = 0;
	LogTag = NULL;
}

#define	SECS_PER_HOUR	(60 * 60)
#define	SECS_PER_DAY	(SECS_PER_HOUR * 24)

/* How many days come before each month (0-12).  */
static const unsigned short int __mon_yday[2][13] =
  {
    /* Normal years.  */
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    /* Leap years.  */
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 }
  };

/* Compute the `struct tm' representation of *T,
   and store year, yday, mon, mday, wday, hour, min, sec into *TP */
static void my_localtime(const time_t *t, struct tm *tm)
{
  time_t days, rem, y;
  const unsigned short int *ip;
  int leap;

  days = *t / SECS_PER_DAY;
  rem = *t % SECS_PER_DAY;
  rem -= timezone;
  while (rem < 0)
    {
      rem += SECS_PER_DAY;
      --days;
    }
  while (rem >= SECS_PER_DAY)
    {
      rem -= SECS_PER_DAY;
      ++days;
    }
  tm->tm_hour = rem / SECS_PER_HOUR;
  rem %= SECS_PER_HOUR;
  tm->tm_min = rem / 60;
  tm->tm_sec = rem % 60;
  /* January 1, 1970 was a Thursday.  */
  tm->tm_wday = (4 + days) % 7;
  if (tm->tm_wday < 0)
    tm->tm_wday += 7;
  y = 1970;

#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))
#define ISLEAP(y)	((y) % 4 == 0 && ((y) % 100 != 0 || (y) % 400 == 0))

  leap = ISLEAP(y);
  while (days < 0 || days >= (leap ? 366 : 365))
    {
      /* Guess a corrected year, assuming 365 days per year.  */
      time_t yg = y + days / 365 - (days % 365 < 0);

      /* Adjust DAYS and Y to match the guessed year.  */
      days -= ((yg - y) * 365
	       + LEAPS_THRU_END_OF (yg - 1)
	       - LEAPS_THRU_END_OF (y - 1));
      y = yg;
    }
  tm->tm_year = y - 1900;
  tm->tm_yday = days;
  ip = __mon_yday[leap];
  for (y = 11; days < (long int) ip[y]; --y)
    continue;
  days -= ip[y];
  tm->tm_mon = y;
  tm->tm_mday = days + 1;
}
