/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * util-int.c	Various functions to replace missing threadsafe ones.
 *				  Without the real *_r funcs, things will work, but won't be
 *				  threadsafe. 
 * 
 * Written by Bart Hartgers.
 *
 * Copyright 1998, A. Hartgers, All rights reserved.
 * This software is not subject to any license of Eindhoven University of
 * Technology, since it was written in my spare time.
 *			
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */ 

#include "portable.h"

#include <stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

static int int_strspn( const char *str, const char *delim )
{
#if defined( HAVE_STRSPN )
	return strspn( str, delim );
#else
	int pos;
	const char *p=delim;
	for( pos=0; (*str) ; pos++,str++) {
		if (*str!=*p)
			for( p=delim; (*p) ; p++ ) {
				if (*str==*p)
					break;
		  	}
		if (*p=='\0')
			return pos;
	}
	return pos;
#endif	
}

static char *int_strpbrk( const char *str, const char *accept )
{
#if defined( HAVE_STRPBRK )
	return strpbrk( str, accept );
#else
	const char *p;
	for( ; (*str) ; str++ ) {
		for( p=accept; (*p) ; p++) {
			if (*str==*p)
				return str;
		}
	}
	return NULL;
#endif
}

char *ldap_int_strtok( char *str, const char *delim, char **pos )
{
#ifdef HAVE_STRTOK_R
	return strtok_r(str, delim, pos);
#else
	char *p;

	if (pos==NULL)
		return NULL;
	if (str==NULL) {
		if (*pos==NULL)
			return NULL;
		str=*pos;
	}
	/* skip any initial delimiters */
	str += int_strspn( str, delim );
	if (*str == '\0')
		return NULL;
	p = int_strpbrk( str, delim );
	if (p==NULL) {
		*pos = NULL;
	} else {
		*p ='\0';
		*pos = p+1;
	}
	return str;
#endif
}

char *ldap_int_ctime( const time_t *tp, char *buf )
{
#if defined( HAVE_CTIME_R ) && defined( CTIME_R_NARGS )
# if (CTIME_R_NARGS > 3) || (CTIME_R_NARGS < 2)
	choke me!  nargs should have 2 or 3
# elif CTIME_R_NARGS > 2
	return ctime_r(tp,buf,26);
# else
	return ctime_r(tp,buf);
# endif	  
#else
	memcpy( buf, ctime(tp), 26 );
	return buf;
#endif	
}

#define BUFSTART 1024
#define BUFMAX (32*1024)

static char *safe_realloc( char **buf, int len )
{
	char *tmpbuf;
	tmpbuf = realloc( *buf, len );
	if (tmpbuf) {
		*buf=tmpbuf;
	} 
	return tmpbuf;
}

int ldap_int_gethostbyname_a(
	const char *name, 
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr )
{
#ifdef HAVE_GETHOSTBYNAME_R
	int r=-1;
	int buflen=BUFSTART;
	*buf = NULL;
	for(;buflen<BUFMAX;) {
		if (safe_realloc( buf, buflen )==NULL)
			return r;
		r = gethostbyname_r( name, resbuf, *buf,
			buflen, result, herrno_ptr );
#ifdef NETDB_INTERNAL
		if ((r<0) &&
			(*herrno_ptr==NETDB_INTERNAL) &&
			(errno==ERANGE))
		{
			buflen*=2;
			continue;
	 	}
#endif
		return r;
	}
	return -1;
#else	
	*result = gethostbyname( name );

	if (*result!=NULL) {
		return 0;
	}

	*herrno_ptr = h_errno;
	
	return -1;
#endif	
}
	 
int ldap_int_gethostbyaddr_a(
	const char *addr,
	int len,
	int type,
	struct hostent *resbuf,
	char **buf,
	struct hostent **result,
	int *herrno_ptr )
{
#ifdef HAVE_GETHOSTBYADDR_R
	int r=-1;
	int buflen=BUFSTART;
	*buf = NULL;   
	for(;buflen<BUFMAX;) {
		if (safe_realloc( buf, buflen )==NULL)
			return r;
		r = gethostbyaddr_r( addr, len, type,
			resbuf, *buf, buflen, 
			result, herrno_ptr );
#ifdef NETDB_INTERNAL
		if ((r<0) &&
			(*herrno_ptr==NETDB_INTERNAL) &&
			(errno==ERANGE))
		{
			buflen*=2;
			continue;
		}
#endif
		return r;
	}
	return -1;
#else /* gethostbyaddr() */
	*result = gethostbyaddr( addr, len, type );

	if (*result!=NULL) {
		return 0;
	}
	return -1;
#endif	
}
