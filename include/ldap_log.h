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
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1990 Regents of the University of Michigan.
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

#include <stdio.h>
#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/*
 * debug reporting levels.
 *
 * They start with the syslog levels, and
 * go down in importance.  The normal
 * debugging levels begin with LDAP_LEVEL_ENTRY
 *
 */
#define LDAP_LEVEL_EMERG       0
#define LDAP_LEVEL_ALERT       1
#define LDAP_LEVEL_CRIT        2
#define LDAP_LEVEL_ERR         3
#define LDAP_LEVEL_WARNING     4
#define LDAP_LEVEL_NOTICE      5
#define LDAP_LEVEL_INFO        6
#define LDAP_LEVEL_ENTRY       7  /* log function entry points */
#define LDAP_LEVEL_ARGS        8  /* log function call parameters */
#define LDAP_LEVEL_RESULTS     9  /* Log function results */
#define LDAP_LEVEL_DETAIL1    10  /* log level 1 function operational details */
#define LDAP_LEVEL_DETAIL2    11  /* Log level 2 function operational details */

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
#define LDAP_DEBUG_CACHE    0x1000
#define LDAP_DEBUG_INDEX    0x2000
#define LDAP_DEBUG_SYNC		0x4000

#define LDAP_DEBUG_NONE		0x8000
#define LDAP_DEBUG_ANY		-1

/* debugging stuff */
#ifdef LDAP_DEBUG
    /*
     * This is a bogus extern declaration for the compiler. No need to ensure
     * a 'proper' dllimport.
     */
#   ifndef ldap_debug
     extern int	ldap_debug;
#   endif /* !ldap_debug */

#   ifdef LDAP_SYSLOG
    extern int	ldap_syslog;
    extern int	ldap_syslog_level;

#	ifdef HAVE_EBCDIC
#	define syslog	eb_syslog
	extern void eb_syslog(int pri, const char *fmt, ...);
#	endif

#   endif /* LDAP_SYSLOG */

/* this doesn't below as part of ldap.h */
#   ifdef LDAP_SYSLOG
#   define Debug( level, fmt, arg1, arg2, arg3 )	\
	do { \
		if ( ldap_debug & (level) ) \
			lutil_debug( ldap_debug, (level), (fmt), (arg1), (arg2), (arg3) ); \
		if ( ldap_syslog & (level) ) \
			syslog( ldap_syslog_level, (fmt), (arg1), (arg2), (arg3) ); \
	} while ( 0 )

#   else
#       define Debug( level, fmt, arg1, arg2, arg3 ) \
	do { \
		if ( ldap_debug & (level) ) \
	    		lutil_debug( ldap_debug, (level), (fmt), (arg1), (arg2), (arg3) ); \
	} while ( 0 )
#   endif

#else /* LDAP_DEBUG */
#   define Debug( level, fmt, arg1, arg2, arg3 )

#endif /* LDAP_DEBUG */

#ifndef LDAP_LOG
#define LDAP_LOG(a, b, fmt, arg1, arg2, arg3)
#define LDAP_LOGS_TEST(a, b) 0
#endif

LDAP_LUTIL_F(int) lutil_debug_file LDAP_P(( FILE *file ));

LDAP_LUTIL_F(void) lutil_debug LDAP_P((
	int debug, int level,
	const char* fmt, ... )) LDAP_GCCATTR((format(printf, 3, 4)));

LDAP_END_DECL

#endif /* _LDAP_LOG_H */
