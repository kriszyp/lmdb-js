/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <lber.h>
#include <lutil.h>
#include <ldap_defaults.h>

char* lutil_progname( const char* name, int argc, char *argv[] )
{
	char *progname;

	if(argc == 0) {
		return ber_strdup( name );
	}

	progname = strrchr ( argv[0], *LDAP_DIRSEP );
	progname = ber_strdup( progname ? &progname[1] : argv[0] );

	return progname;
}

#ifndef HAVE_MKSTEMP
int mkstemp( char * template )
{
#ifdef HAVE_MKTEMP
	return open ( mktemp ( template ), O_RDWR|O_CREAT|O_EXCL, 0600 );
#else
	return -1;
#endif
}
#endif

#ifndef HAVE_VSNPRINTF
#include <ac/stdarg.h>
#include <ac/signal.h>
#include <stdio.h>

/* Write at most n characters to the buffer in str, return the
 * number of chars written or -1 if the buffer would have been
 * overflowed.
 *
 * This is portable to any POSIX-compliant system. We use pipe()
 * to create a valid file descriptor, and then fdopen() it to get
 * a valid FILE pointer. The user's buffer and size are assigned
 * to the FILE pointer using setvbuf. Then we close the read side
 * of the pipe to invalidate the descriptor.
 *
 * If the write arguments all fit into size n, the write will
 * return successfully. If the write is too large, the stdio
 * buffer will need to be flushed to the underlying file descriptor.
 * The flush will fail because it is attempting to write to a
 * broken pipe, and the write will be terminated.
 *
 * Note: glibc's setvbuf is broken, so this code fails on glibc.
 * But that's no loss since glibc provides these functions itself.
 *
 * In practice, the main app will probably have ignored SIGPIPE
 * already, so catching it here is redundant, but harmless.
 *
 * -- hyc, 2002-07-19
 */
int vsnprintf( char *str, size_t n, const char *fmt, va_list ap )
{
	int fds[2], res;
	FILE *f;
#ifdef SIGPIPE
	RETSIGTYPE (*sig)();
#endif

	if (pipe( fds )) return -1;

	f = fdopen( fds[1], "w" );
	if ( !f ) {
		close( fds[1] );
		close( fds[0] );
		return -1;
	}
#ifdef SIGPIPE
	sig = SIGNAL( SIGPIPE, SIG_IGN );
#endif
	setvbuf( f, str, _IOFBF, n );
	close( fds[0] );

	res = vfprintf( f, fmt, ap );
	fclose( f );
#ifdef SIGPIPE
	SIGNAL( SIGPIPE, sig );
#endif
	return res;
}

int snprintf( char *str, size_t n, const char *fmt, ... )
{
	va_list ap;
	int res;

	va_start( ap, fmt );
	res = vsnprintf( str, n, fmt, ap );
	va_end( ap );
	return res;
}
#endif /* !HAVE_VSNPRINTF */
