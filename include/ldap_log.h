/*
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

/* debugging stuff */
#ifdef LDAP_DEBUG
extern int	ldap_debug;
#ifdef LDAP_SYSLOG
extern int	ldap_syslog;
extern int	ldap_syslog_level;
#endif /* LDAP_SYSLOG */

#define LDAP_DEBUG_TRACE	0x001
#define LDAP_DEBUG_PACKETS	0x002
#define LDAP_DEBUG_ARGS		0x004
#define LDAP_DEBUG_CONNS	0x008
#define LDAP_DEBUG_BER		0x010
#define LDAP_DEBUG_FILTER	0x020
#define LDAP_DEBUG_CONFIG	0x040
#define LDAP_DEBUG_ACL		0x080
#define LDAP_DEBUG_STATS	0x100
#define LDAP_DEBUG_STATS2	0x200
#define LDAP_DEBUG_SHELL	0x400
#define LDAP_DEBUG_PARSE	0x800
#define LDAP_DEBUG_ANY		0xffff

/* this doesn't below as part of ldap.h */
#ifdef LDAP_SYSLOG
#define Debug( level, fmt, arg1, arg2, arg3 )	\
	{ \
		if ( ldap_debug & (level) ) \
			fprintf( stderr, (fmt), (arg1), (arg2), (arg3) ); \
		if ( ldap_syslog & level ) \
			syslog( ldap_syslog_level, (fmt), (arg1), (arg2), (arg3) ); \
	}
#else /* LDAP_SYSLOG */
#ifndef WINSOCK
#define Debug( level, fmt, arg1, arg2, arg3 ) \
		if ( ldap_debug & (level) ) \
			fprintf( stderr, (fmt), (arg1), (arg2), (arg3) );
#else /* !WINSOCK */
extern void Debug( int level, char* fmt, ... );
#endif /* !WINSOCK */
#endif /* LDAP_SYSLOG */
#else /* LDAP_DEBUG */
#define Debug( level, fmt, arg1, arg2, arg3 )
#endif /* LDAP_DEBUG */

LDAP_END_DECL

#endif /* _LDAP_LOG_H */
