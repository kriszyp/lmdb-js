/*
 * macos.h: bridge unix and Mac for  LBER/LDAP
 */
#define ntohl( l )	(l)
#define htonl( l )	(l)
#define ntohs( s )	(s)
#define htons( s )	(s)

#ifdef NO_GLOBALS

#ifdef macintosh	/* IUMagIDString declared in TextUtils.h under MPW */
#include <TextUtils.h>
#else /* macintosh */	/* IUMagIDString declared in Packages.h under ThinkC */
#include <Packages.h>
#endif /* macintosh */

#define strcasecmp( s1, s2 )	IUMagIDString( s1, s2, strlen( s1 ), \
					strlen( s2 ))
#else /* NO_GLOBALS */
int strcasecmp( char *s1, char *s2 );
int strncasecmp( char *s1, char *s2, long n );
#endif NO_GLOBALS

#include <Memory.h>	/* to get BlockMove() */

char *strdup( char *s );

#ifndef isascii
#define isascii(c)	((unsigned)(c)<=0177)	/* for those who don't have this in ctype.h */
#endif isascii

#include "tcp.h"
