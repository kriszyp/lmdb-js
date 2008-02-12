/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
#include <ac/ctype.h>
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

#ifdef _WIN32
/* Some Windows versions accept both forward and backslashes in
 * directory paths, but we always use backslashes when generating
 * and parsing...
 */
void lutil_slashpath( char *path )
{
	char *c, *p;

	p = path;
	while (( c=strchr( p, '/' ))) {
		*c++ = '\\';
		p = c;
	}
}
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
	LUTIL_SLASHPATH( argv[0] );
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

int lutil_tm2time( struct lutil_tm *tm, struct lutil_timet *tt )
{
	static int moffset[12] = {
		0, 31, 59, 90, 120,
		151, 181, 212, 243,
		273, 304, 334 }; 
	int sec;

	tt->tt_usec = tm->tm_usec;

	/* special case 0000/01/01+00:00:00 is returned as zero */
	if ( tm->tm_year == -1900 && tm->tm_mon == 0 && tm->tm_mday == 1 &&
		tm->tm_hour == 0 && tm->tm_min == 0 && tm->tm_sec == 0 ) {
		tt->tt_sec = 0;
		tt->tt_gsec = 0;
		return 0;
	}

	/* tm->tm_year is years since 1900 */
	/* calculate days from years since 1970 (epoch) */ 
	tt->tt_sec = tm->tm_year - 70; 
	tt->tt_sec *= 365L; 

	/* count leap days in preceding years */ 
	tt->tt_sec += ((tm->tm_year -69) >> 2); 

	/* calculate days from months */ 
	tt->tt_sec += moffset[tm->tm_mon]; 

	/* add in this year's leap day, if any */ 
	if (((tm->tm_year & 3) == 0) && (tm->tm_mon > 1)) { 
		tt->tt_sec ++; 
	} 

	/* add in days in this month */ 
	tt->tt_sec += (tm->tm_mday - 1); 

	/* this function can handle a range of about 17408 years... */
	/* 86400 seconds in a day, divided by 128 = 675 */
	tt->tt_sec *= 675;

	/* move high 7 bits into tt_gsec */
	tt->tt_gsec = tt->tt_sec >> 25;
	tt->tt_sec -= tt->tt_gsec << 25;

	/* get hours */ 
	sec = tm->tm_hour; 

	/* convert to minutes */ 
	sec *= 60L; 
	sec += tm->tm_min; 

	/* convert to seconds */ 
	sec *= 60L; 
	sec += tm->tm_sec; 
	
	/* add remaining seconds */
	tt->tt_sec <<= 7;
	tt->tt_sec += sec;

	/* return success */
	return 0; 
}

int lutil_parsetime( char *atm, struct lutil_tm *tm )
{
	while (atm && tm) {
		char *ptr = atm;
		unsigned i, fracs;

		/* Is the stamp reasonably long? */
		for (i=0; isdigit((unsigned char) atm[i]); i++);
		if (i < sizeof("00000101000000")-1)
			break;

		/*
		 * parse the time into a struct tm
		 */
		/* 4 digit year to year - 1900 */
		tm->tm_year = *ptr++ - '0';
		tm->tm_year *= 10; tm->tm_year += *ptr++ - '0';
		tm->tm_year *= 10; tm->tm_year += *ptr++ - '0';
		tm->tm_year *= 10; tm->tm_year += *ptr++ - '0';
		tm->tm_year -= 1900;
		/* month 01-12 to 0-11 */
		tm->tm_mon = *ptr++ - '0';
		tm->tm_mon *=10; tm->tm_mon += *ptr++ - '0';
		if (tm->tm_mon < 1 || tm->tm_mon > 12) break;
		tm->tm_mon--;

		/* day of month 01-31 */
		tm->tm_mday = *ptr++ - '0';
		tm->tm_mday *=10; tm->tm_mday += *ptr++ - '0';
		if (tm->tm_mday < 1 || tm->tm_mday > 31) break;

		/* Hour 00-23 */
		tm->tm_hour = *ptr++ - '0';
		tm->tm_hour *=10; tm->tm_hour += *ptr++ - '0';
		if (tm->tm_hour < 0 || tm->tm_hour > 23) break;

		/* Minute 00-59 */
		tm->tm_min = *ptr++ - '0';
		tm->tm_min *=10; tm->tm_min += *ptr++ - '0';
		if (tm->tm_min < 0 || tm->tm_min > 59) break;

		/* Second 00-61 */
		tm->tm_sec = *ptr++ - '0';
		tm->tm_sec *=10; tm->tm_sec += *ptr++ - '0';
		if (tm->tm_sec < 0 || tm->tm_sec > 61) break;

		/* Fractions of seconds */
		if ( *ptr == '.' ) {
			ptr++;
			for (i = 0, fracs = 0; isdigit((unsigned char) *ptr); ) {
				i*=10; i+= *ptr++ - '0';
				fracs++;
			}
			tm->tm_usec = i;
			if (i) {
				for (i = fracs; i<6; i++)
					tm->tm_usec *= 10;
			}
		}

		/* Must be UTC */
		if (*ptr != 'Z') break;

		return 0;
	}
	return -1;
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

/*
 * Memory Reverse Search
 */
void *
lutil_memrchr(const void *b, int c, size_t n)
{
	if (n != 0) {
		const unsigned char *s, *bb = b, cc = c;

		for ( s = bb + n; s > bb; ) {
			if ( *--s == cc ) {
				return (void *) s;
			}
		}
	}

	return NULL;
}

int
lutil_atoix( int *v, const char *s, int x )
{
	char		*next;
	long		i;

	assert( s != NULL );
	assert( v != NULL );

	i = strtol( s, &next, x );
	if ( next == s || next[ 0 ] != '\0' ) {
		return -1;
	}

	if ( (long)(int)i != i ) {
		return 1;
	}

	*v = (int)i;

	return 0;
}

int
lutil_atoux( unsigned *v, const char *s, int x )
{
	char		*next;
	unsigned long	u;

	assert( s != NULL );
	assert( v != NULL );

	/* strtoul() has an odd interface */
	if ( s[ 0 ] == '-' ) {
		return -1;
	}

	u = strtoul( s, &next, x );
	if ( next == s || next[ 0 ] != '\0' ) {
		return -1;
	}

	if ( (unsigned long)(unsigned)u != u ) {
		return 1;
	}

	*v = u;

	return 0;
}

int
lutil_atolx( long *v, const char *s, int x )
{
	char		*next;
	long		l;

	assert( s != NULL );
	assert( v != NULL );

	l = strtol( s, &next, x );
	if ( next == s || next[ 0 ] != '\0' ) {
		return -1;
	}

	*v = l;

	return 0;
}

int
lutil_atoulx( unsigned long *v, const char *s, int x )
{
	char		*next;
	unsigned long	ul;

	assert( s != NULL );
	assert( v != NULL );

	/* strtoul() has an odd interface */
	if ( s[ 0 ] == '-' ) {
		return -1;
	}

	ul = strtoul( s, &next, x );
	if ( next == s || next[ 0 ] != '\0' ) {
		return -1;
	}

	*v = ul;

	return 0;
}

static	char		time_unit[] = "dhms";

int
lutil_parse_time(
	const char	*in,
	unsigned long	*tp )
{
	unsigned long	t = 0;
	char		*s,
			*next;
	int		sofar = -1,
			scale[] = { 86400, 3600, 60, 1 };

	*tp = 0;

	for ( s = (char *)in; s[ 0 ] != '\0'; ) {
		unsigned long	u;
		char		*what;

		/* strtoul() has an odd interface */
		if ( s[ 0 ] == '-' ) {
			return -1;
		}

		u = strtoul( s, &next, 10 );
		if ( next == s ) {
			return -1;
		}

		if ( next[ 0 ] == '\0' ) {
			/* assume seconds */
			t += u;
			break;
		}

		what = strchr( time_unit, next[ 0 ] );
		if ( what == NULL ) {
			return -1;
		}

		if ( what - time_unit <= sofar ) {
			return -1;
		}

		sofar = what - time_unit;
		t += u * scale[ sofar ];

		s = &next[ 1 ];
	}

	*tp = t;
	return 0;
}

int
lutil_unparse_time(
	char			*buf,
	size_t			buflen,
	unsigned long		t )
{
	int		len, i;
	unsigned long	v[ 4 ];

	v[ 0 ] = t/86400;
	v[ 1 ] = (t%86400)/3600;
	v[ 2 ] = (t%3600)/60;
	v[ 3 ] = t%60;

	for ( i = 0; i < 4; i++ ) {
		if ( v[i] > 0 || i == 3 ) {
			len = snprintf( buf, buflen, "%lu%c", v[ i ], time_unit[ i ] );
			if ( len < 0 || (unsigned)len >= buflen ) {
				return -1;
			}
			buflen -= len;
			buf += len;
		}
	}

	return 0;
}

