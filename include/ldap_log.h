/* $OpenLDAP$ */
/*
 * Copyright 1998,1999 The OpenLDAP Foundation, Redwood City, California, USA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */
/* Portions
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LDAP_LOG_H
#define _LDAP_LOG_H

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

#define LDAP_DEBUG_TRACE	0x0001
#define LDAP_DEBUG_PACKETS	0x0002
#define LDAP_DEBUG_ARGS		0x0004
#define LDAP_DEBUG_CONNS	0x0008
#define LDAP_DEBUG_BER		0x0010
#define LDAP_DEBUG_FILTER	0x0020
#define LDAP_DEBUG_CONFIG	0x0040
#define LDAP_DEBUG_ACL		0x0080
#define LDAP_DEBUG_STATS	0x0100
#define LDAP_DEBUG_STATS2	0x0200
#define LDAP_DEBUG_SHELL	0x0400
#define LDAP_DEBUG_PARSE	0x0800

#define LDAP_DEBUG_DEPRECATED	0x1000
#define LDAP_DEBUG_NONE		0x8000
#define LDAP_DEBUG_ANY		-1

/* debugging stuff */
#ifdef LDAP_DEBUG

#ifndef ldap_debug
extern int	ldap_debug;
#endif /* !ldap_debug */

#ifdef LDAP_SYSLOG
extern int	ldap_syslog;
extern int	ldap_syslog_level;
#endif /* LDAP_SYSLOG */

/* this doesn't below as part of ldap.h */
#ifdef LDAP_SYSLOG
#define Debug( level, fmt, arg1, arg2, arg3 )	\
	do { \
		lutil_debug( ldap_debug, (level), (fmt), (arg1), (arg2), (arg3) ); \
		if ( ldap_syslog & (level) ) \
			syslog( ldap_syslog_level, (fmt), (arg1), (arg2), (arg3) ); \
	} while ( 0 )

#else
#define Debug( level, fmt, arg1, arg2, arg3 ) \
	lutil_debug( ldap_debug, (level), (fmt), (arg1), (arg2), (arg3) )
#endif

#else /* LDAP_DEBUG */
#define Debug( level, fmt, arg1, arg2, arg3 )
#endif /* LDAP_DEBUG */

#ifdef __MINGW32__
#   undef LDAP_F_PRE
#   ifdef LIBLUTIL_DECL
#	define LDAP_F_PRE	extern __declspec(LIBLUTIL_DECL)
#   else
#	define LDAP_F_PRE	extern
#   endif
#endif

LDAP_F(void) lutil_debug LDAP_P((
	int debug, int level,
	const char* fmt, ... )) LDAP_GCCATTR((format(printf, 3, 4)));

LDAP_END_DECL

#endif /* _LDAP_LOG_H */
