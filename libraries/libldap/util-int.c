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

char *ldap_int_strtok( char *str, const char *delim, char **pos )
{
#ifdef HAVE_STRTOK_R
	return strtok_r(str, delim, pos);
#else
	return strtok(str, delim);
#endif
}

char *ldap_int_ctime( const time_t *tp, char *buf )
{
#ifdef HAVE_CTIME_R
# if defined( ARGS_CTIME_R_2 )
	return ctime_r(tp,buf);
# elif defined( ARGS_CTIME_R_3 )
	return ctime_r(tp,buf,26);
# else
	Do not know how many arguments ctime_r takes, so generating error
# endif	  
#else
	return ctime(tp);
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
	int r;
	int buflen=BUFSTART;

	if (safe_realloc( buf, buflen)) {
		for(;buflen<BUFMAX;) {
			r = gethostbyname_r( name, resbuf, *buf,
				buflen, result, herrno_ptr );
#ifdef NETDB_INTERNAL
			if ((r<0) &&
				(*herrno_ptr==NETDB_INTERNAL) &&
				(errno==ERANGE))
			{
				if (safe_realloc( buf, buflen*=2 )) {
						continue;
				}
	 		}
#endif
			return r;
		}
	}

#else /* gethostbyname() */
	*result = gethostbyname( name );

	if (*result!=NULL) {
		return 0;
	}

	*herrno_ptr = h_errno;
#endif	

	return -1;
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
	int r;
	int buflen=BUFSTART;
	if (safe_realloc( buf, buflen)) {
		for(;buflen<BUFMAX;) {
			r = gethostbyaddr_r( addr, len, type,
				resbuf, *buf, buflen, 
				result, herrno_ptr );
#ifdef NETDB_INTERNAL
			if ((r<0) &&
				(*herrno_ptr==NETDB_INTERNAL) &&
				(errno==ERANGE))
			{
				if (safe_realloc( buf, buflen*=2))
					continue;
	 		}
#endif
			return r;
		}
	}

#else /* gethostbyaddr() */
	*result = gethostbyaddr( addr, len, type );

	if (*result!=NULL) {
		return 0;
	}
#endif	

	return -1;
}
