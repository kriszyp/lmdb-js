/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2007 The OpenLDAP Foundation.
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
#ifdef _WIN32
#include <windows.h>
#endif

#include "lutil.h"
#include "ldap_defaults.h"
#include "ldap_pvt.h"

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

/* return a broken out time, with microseconds
 * Must be mutex-protected.
 */
#ifdef _WIN32
/* Windows SYSTEMTIME only has 10 millisecond resolution, so we
 * also need to use a high resolution timer to get microseconds.
 * This is pretty clunky.
 */
void
lutil_gettime( struct lutil_tm *tm )
{
	static LARGE_INTEGER cFreq;
	static LARGE_INTEGER prevCount;
	static int subs;
	static int offset;
	LARGE_INTEGER count;
	SYSTEMTIME st;

	GetSystemTime( &st );
	QueryPerformanceCounter( &count );

	/* We assume Windows has at least a vague idea of
	 * when a second begins. So we align our microsecond count
	 * with the Windows millisecond count using this offset.
	 * We retain the submillisecond portion of our own count.
	 */
	if ( !cFreq.QuadPart ) {
		long long t;
		int usec;
		QueryPerformanceFrequency( &cFreq );

		t = count.QuadPart * 1000000;
		t /= cFreq.QuadPart;
		usec = t % 10000000;
		usec /= 1000;
		offset = ( usec - st.wMilliseconds ) * 1000;
	}

	/* It shouldn't ever go backwards, but multiple CPUs might
	 * be able to hit in the same tick.
	 */
	if ( count.QuadPart <= prevCount.QuadPart ) {
		subs++;
	} else {
		subs = 0;
		prevCount = count;
	}

	tm->tm_usub = subs;

	/* convert to microseconds */
	count.QuadPart *= 1000000;
	count.QuadPart /= cFreq.QuadPart;
	count.QuadPart -= offset;

	tm->tm_usec = count.QuadPart % 1000000;

	/* any difference larger than microseconds is
	 * already reflected in st
	 */

	tm->tm_sec = st.wSecond;
	tm->tm_min = st.wMinute;
	tm->tm_hour = st.wHour;
	tm->tm_mday = st.wDay;
	tm->tm_mon = st.wMonth - 1;
	tm->tm_year = st.wYear - 1900;
}
#else
void
lutil_gettime( struct lutil_tm *ltm )
{
	struct timeval tv;
	static struct timeval prevTv;
	static int subs;

#ifdef HAVE_GMTIME_R
	struct tm tm_buf;
#endif
	struct tm *tm;
	time_t t;

	gettimeofday( &tv, NULL );
	t = tv.tv_sec;

	if ( tv.tv_sec < prevTv.tv_sec
		|| ( tv.tv_sec == prevTv.tv_sec && tv.tv_usec == prevTv.tv_usec )) {
		subs++;
	} else {
		subs = 0;
		prevTv = tv;
	}

	ltm->tm_usub = subs;

#ifdef HAVE_GMTIME_R
	tm = gmtime_r( &t, &tm_buf );
#else
	tm = gmtime( &t );
#endif

	ltm->tm_sec = tm->tm_sec;
	ltm->tm_min = tm->tm_min;
	ltm->tm_hour = tm->tm_hour;
	ltm->tm_mday = tm->tm_mday;
	ltm->tm_mon = tm->tm_mon;
	ltm->tm_year = tm->tm_year;
	ltm->tm_usec = tv.tv_usec;
}
#endif

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

#ifdef _MSC_VER
struct dirent {
	char *d_name;
};
typedef struct DIR {
	HANDLE dir;
	struct dirent data;
	int first;
	char buf[MAX_PATH+1];
} DIR;
DIR *opendir( char *path )
{
	char tmp[32768];
	int len = strlen(path);
	DIR *d;
	HANDLE h;
	WIN32_FIND_DATA data;
	
	if (len+3 >= sizeof(tmp))
		return NULL;

	strcpy(tmp, path);
	tmp[len++] = '\\';
	tmp[len++] = '*';
	tmp[len] = '\0';

	h = FindFirstFile( tmp, &data );
	
	if ( h == INVALID_HANDLE_VALUE )
		return NULL;

	d = ber_memalloc( sizeof(DIR) );
	if ( !d )
		return NULL;
	d->dir = h;
	d->data.d_name = d->buf;
	d->first = 1;
	strcpy(d->data.d_name, data.cFileName);
	return d;
}
struct dirent *readdir(DIR *dir)
{
	WIN32_FIND_DATA data;

	if (dir->first) {
		dir->first = 0;
	} else {
		if (!FindNextFile(dir->dir, &data))
			return NULL;
		strcpy(dir->data.d_name, data.cFileName);
	}
	return &dir->data;
}
void closedir(DIR *dir)
{
	FindClose(dir->dir);
	ber_memfree(dir);
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

/* Used to parse and unparse time intervals, not timestamps */
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
	char		*ptr = buf;

	v[ 0 ] = t/86400;
	v[ 1 ] = (t%86400)/3600;
	v[ 2 ] = (t%3600)/60;
	v[ 3 ] = t%60;

	for ( i = 0; i < 4; i++ ) {
		if ( v[i] > 0 || ( i == 3 && ptr == buf ) ) {
			len = snprintf( ptr, buflen, "%lu%c", v[ i ], time_unit[ i ] );
			if ( len < 0 || (unsigned)len >= buflen ) {
				return -1;
			}
			buflen -= len;
			ptr += len;
		}
	}

	return 0;
}

