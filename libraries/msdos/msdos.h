/* ldapmsdos.h */
/*
 * Copyright (c) 1992 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifdef PCNFS
#include <sys/tk_types.h>
#include <sys/socket.h>
#include <sys/nfs_time.h>
#endif /* PCNFS */

#ifdef NCSA
#define NCSADOMAINFIX	1	/* see README.dos */

typedef unsigned short us;
typedef unsigned long ul;
#define ntohs(i) ((us)( (((us)i & 0xff) << 8)  + (((us)i & 0xff00) >> 8) ))
#define ntohl(i) ((ul)( (((ul)i & 0xff) << 24) + (((ul)i & 0xff00) << 8) + \
			(((ul)i & 0xff0000) >> 8) +  \
			(((ul)i & 0xff000000) >> 24) ))
#define htons(i) ntohs(i)
#define htonl(i) ntohl(i)

typedef unsigned long ip_addr;
typedef unsigned long u_long;
typedef unsigned short u_short;
typedef unsigned char u_char;

extern int ncsainit( void );
extern int ncsaopen( unsigned long addr, short port );
extern int nread(int connection_id, char *buff, int buff_size);
#endif /* NCSA */

#if defined( PCNFS ) || defined( NCSA )
#include <malloc.h>

struct timeval {
	long tv_sec;
	long tv_usec;
};
#endif /* PCNFS */

#define strcasecmp(a,b) stricmp(a,b)
#define strncasecmp(a,b,len) strnicmp(a,b,len)
