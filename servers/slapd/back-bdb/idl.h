/* back-bdb.h - ldap ldbm back-end header file */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _BDB_IDL_H_
#define _BDB_IDL_H_

#include <portable.h>

#include "slap.h"

#if 1
	/* larger IDL sizes (which blow thread stacks) */
#define BDB_IDL_DB_SIZE		(1<<16) /* 64K IDL on disk */
#define BDB_IDL_SIZE		(1<<17) /* 128K IDL in memory */
#else
	/* reduced IDL sizes for testing */
#define BDB_IDL_DB_SIZE		(1<<8) /* 256 IDL on disk */
#define BDB_IDL_SIZE		(1<<10) /* 1K IDL in memory */
#endif

#define BDB_IDL_DB_MAX		(BDB_IDL_DB_SIZE-32)
/* #define BDB_IDL_DB_ALLOC	(BDB_IDL_DB_SIZE * sizeof(ID)) */

#define BDB_IDL_MAX			(BDB_IDL_DB_SIZE-32)
/* #define BDB_IDL_DB_ALLOC	(BDB_IDL_DB_SIZE * sizeof(ID)) */

#define BDB_IDL_IS_RANGE(ids)	((ids)[0] == NOID)
#define BDB_IDL_RANGE_SIZE	(3 * sizeof(ID))
#define BDB_IDL_SIZEOF(ids) ( BDB_IDL_IS_RANGE(ids) \
	? BDB_IDL_RANGE_SIZE : ((ids)[0]+1) * sizeof(ID) )

#define BDB_IDL_RANGE( ids, f, l ) \
	do { \
		(ids)[0] = NOID; \
		(ids)[1] = (f);  \
		(ids)[2] = (l);  \
	} while(0)

#define BDB_IDL_ZERO(ids) \
	do { \
		(ids)[0] = 0; \
		(ids)[1] = 0; \
		(ids)[2] = 0; \
	} while(0);

#define BDB_IDL_IS_ZERO(ids) ( (ids)[0] == 0 )
#define BDB_IDL_IS_ALL( range, ids ) ( (ids)[0] == NOID \
	&& (ids)[1] <= (range)[1] && (range)[2] <= (ids)[2] )

#define BDB_IDL_CPY( dst, src ) (memcpy( dst, src, BDB_IDL_SIZEOF( src ) ))

#define BDB_IDL_ID( bdb, ids, id ) BDB_IDL_RANGE( ids, id, ((bdb)->bi_lastid) )
#define BDB_IDL_ALL( bdb, ids ) BDB_IDL_RANGE( ids, 1, ((bdb)->bi_lastid) )

#define BDB_IDL_FIRST( ids )	( ids[1] )
#define BDB_IDL_LAST( ids )		( BDB_IDL_IS_RANGE(ids) \
	? ids[2] : ids[ids[0]] )

#define BDB_IDL_N( ids )		( BDB_IDL_IS_RANGE(ids) \
	? (ids[2]-ids[1])+1 : ids[0] )

LDAP_BEGIN_DECL
LDAP_END_DECL

#endif
