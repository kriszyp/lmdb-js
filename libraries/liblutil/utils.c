/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/time.h>
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <lutil.h>
#include <ldap_defaults.h>

#ifdef HAVE_EBCDIC
int _trans_argv = 1;
#endif

char* lutil_progname( const char* name, int argc, char *argv[] )
{
	char *progname;

	if(argc == 0) {
		return (char *)name;
	}

#ifdef HAVE_EBCDIC
	if (_trans_argv) {
		int i;
		for (i=0; i<argc; i++) __etoa(argv[i]);
		_trans_argv = 0;
	}
#endif
	progname = strrchr ( argv[0], *LDAP_DIRSEP );
	progname = progname ? &progname[1] : argv[0];

	return progname;
}

#if 0
size_t lutil_gentime( char *s, size_t smax, const struct tm *tm )
{
	size_t ret;
#ifdef HAVE_EBCDIC
/* We've been compiling in ASCII so far, but we want EBCDIC now since
 * strftime only understands EBCDIC input.
 */
#pragma convlit(suspend)
#endif
	ret = strftime( s, smax, "%Y%m%d%H%M%SZ", tm );
#ifdef HAVE_EBCDIC
#pragma convlit(resume)
	__etoa( s );
#endif
	return ret;
}
#endif

size_t lutil_localtime( char *s, size_t smax, const struct tm *tm, long delta )
{
	size_t	ret;
	char	*p;

	if ( smax < 16 ) {	/* YYYYmmddHHMMSSZ */
		return 0;
	}

#ifdef HAVE_EBCDIC
/* We've been compiling in ASCII so far, but we want EBCDIC now since
 * strftime only understands EBCDIC input.
 */
#pragma convlit(suspend)
#endif
	ret = strftime( s, smax, "%Y%m%d%H%M%SZ", tm );
#ifdef HAVE_EBCDIC
#pragma convlit(resume)
	__etoa( s );
#endif
	if ( delta == 0 || ret == 0 ) {
		return ret;
	}

	if ( smax < 20 ) {	/* YYYYmmddHHMMSS+HHMM */
		return 0;
	}

	p = s + 14;

	if ( delta < 0 ) {
		p[ 0 ] = '-';
		delta = -delta;
	} else {
		p[ 0 ] = '+';
	}
	p++;

	snprintf( p, smax - 15, "%02ld%02ld", delta / 3600,
			( delta % 3600 ) / 60 );

	return ret + 5;
}


/* strcopy is like strcpy except it returns a pointer to the trailing NUL of
 * the result string. This allows fast construction of catenated strings
 * without the overhead of strlen/strcat.
 */
char *
lutil_strcopy(
	char *a,
	const char *b
)
{
	if (!a || !b)
		return a;
	
	while ((*a++ = *b++)) ;
	return a-1;
}

/* strncopy is like strcpy except it returns a pointer to the trailing NUL of
 * the result string. This allows fast construction of catenated strings
 * without the overhead of strlen/strcat.
 */
char *
lutil_strncopy(
	char *a,
	const char *b,
	size_t n
)
{
	if (!a || !b || n == 0)
		return a;
	
	while ((*a++ = *b++) && n-- > 0) ;
	return a-1;
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
