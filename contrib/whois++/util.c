#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			U T I L
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	November 1992
 * Version:	1.7
 * Description:
 *		Some routines that I use in most my LDAP playthings :-)
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Adelaide. The name of the University may not
 * be used to endorse or promote products derived from this software\
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "portable.h"

#include <stdio.h>
#include <signal.h>
#include <ctype.h>
#if defined(SYS5) || defined(XOS_2)
#include <termio.h>
#else
#include <sgtty.h>
#endif
#include <time.h>
#if defined(INTERNATIONAL)
#include <langinfo.h>
#include <locale.h>
#endif
#include <ac/unistd.h>

static void	handler(int sig);

char *
lowerCase( char *string )
{
	char	*s;

	for ( s = string; s != NULL && *s != '\0'; s++ )
		if ( isupper( (unsigned char) *s ) )
			*s = tolower( (unsigned char) *s );
	return string;
}

char *
convertTime( char *date, char *locale )
{
	/*
	 * A quick hack to convert the time from the format Quipu uses into
	 * a more normal representation.
	 */
	struct tm	*tm;
	time_t		time;
	static char	result[BUFSIZ];
	int		UTCOffset;

	/*
	 * Get local timezone information, we need to apply this to the 
	 * zulu time that Quipu uses later.
	 */
	time = 0;
	tm = localtime(&time);
	UTCOffset = tm->tm_gmtoff;
	sscanf( date, "%2d%2d%2d%2d%2d%2dZ",
		&tm->tm_year, &tm->tm_mon, &tm->tm_mday, 
		&tm->tm_hour, &tm->tm_min, &tm->tm_sec );
	tm->tm_mon--;
	tm->tm_isdst = 0;
	tm->tm_gmtoff = 0;
	time = mktime(tm);
	time += UTCOffset;
	tm = localtime(&time);
#if defined(INTERNATIONAL)
	setlocale(LC_TIME, locale);
	strftime(result, sizeof(result), nl_langinfo(D_T_FMT), tm);
#else
	strftime(result, sizeof(result), "%c", tm);
#endif
	return result;
}

static long	interrupt;

char *
getPassword( char *prompt )
{
#if defined(SYS5) || defined(XOS_2)
	struct termios	ttyb;
#else
	struct sgttyb	ttyb;
#endif
	FILE		*input;
	struct sigvec	ovec, vec;
	unsigned long	flags;
	int		c, idx;
	static char	buffer[BUFSIZ + 1];

	if ( ( input = fopen( "/dev/tty", "r" ) ) == NULL )
		input = stdin;
	else
		setbuf( input, (char *) NULL );
	vec.sv_handler = handler;
	vec.sv_mask = 0;
	vec.sv_flags = SV_INTERRUPT;
	sigvec( SIGINT, &vec, &ovec );
	interrupt = 0;
#if defined(SYS5) || defined(XOS_2)
	ioctl( fileno( input ), TCGETS, &ttyb );
	flags = ttyb.c_lflag;
	ttyb.c_lflags &= ~ ( ECHO | ECHOE | ECHOK | ECHONL );
	ioctl( fileno( input ), TCSETSF, &ttyb );
#else
	ioctl( fileno( input ), TIOCGETP, &ttyb );
	flags = ttyb.sg_flags;
	ttyb.sg_flags &= ~ ECHO;
	ioctl( fileno( input ), TIOCSETN, &ttyb );
#endif
	fputs( prompt, stderr );
	idx = 0;
	while ( !interrupt && ( c = getc( input ) ) != EOF ) {
		if ( c == '\n' || c == '\r' )
			break;
		if ( idx < BUFSIZ )
			buffer[idx++] = c;
	}
	if ( interrupt )
		buffer[0] = '\0';
	else
		buffer[idx] = '\0';
#if defined(SYS5) || defined(XOS_2)
	ttyb.c_lflag = flags;
	ioctl( fileno( input ), TCSETSW, &ttyb );
#else
	ttyb.sg_flags = flags;
	ioctl( fileno( input ), TIOCSETN, &ttyb );
#endif
	putc( '\n', stderr );
	sigvec( SIGINT, &ovec, (struct sigvec *) NULL );
	if ( input != stdin )
		fclose( input );
	if ( interrupt )
		kill( getpid(), SIGINT );
	return buffer;
}

static void
handler( int sig )
{
	++interrupt;
}
