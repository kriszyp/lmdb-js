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
/* ldbm.h - ldap dbm compatibility routine header file */

#ifndef _LDBM_H_
#define _LDBM_H_

#include <ldap_cdefs.h>

#if defined( LDBM_USE_DBBTREE ) || defined( LDBM_USE_DBHASH )

/*****************************************************************
 *                                                               *
 * use berkeley db btree or hash package                         *
 *                                                               *
 *****************************************************************/

#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>

#ifdef HAVE_DB_185_H
#	include <db_185.h>
#else
#	ifdef HAVE_DB1_DB_H
#		include <db1/db.h>
#	else
#		include <db.h>
#	endif
#	ifdef HAVE_BERKELEY_DB2
#		define R_NOOVERWRITE DB_NOOVERWRITE
#		ifndef DEFAULT_DB_PAGE_SIZE
#			define DEFAULT_DB_PAGE_SIZE 4096
#		endif
#	endif
#endif


LDAP_BEGIN_DECL

typedef DBT	Datum;
#define dsize	size
#define dptr	data

typedef DB	*LDBM;


/* for ldbm_open */
#ifdef HAVE_BERKELEY_DB2
typedef DBC	LDBMCursor;

#	define LDBM_READER	DB_RDONLY
#	define LDBM_WRITER	0x00000      /* hopefully */
# ifdef HAVE_BERKELEY_DB2_DB_THREAD
#	define LDBM_WRCREAT	(DB_NOMMAP|DB_CREATE|DB_THREAD)
#	define LDBM_NEWDB	(DB_TRUNCATE|DB_CREATE|DB_THREAD)
# else
#	define LDBM_WRCREAT	(DB_NOMMAP|DB_CREATE)
#	define LDBM_NEWDB	(DB_TRUNCATE|DB_CREATE)
# endif

#else
typedef void LDBMCursor;
#	define LDBM_READER	O_RDONLY
#	define LDBM_WRITER	O_RDWR
#	define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#	define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#endif

LDAP_END_DECL

/* for ldbm_open */
#define LDBM_NOSYNC	0
#define LDBM_SYNC	0
#define LDBM_LOCKING	0
#define LDBM_NOLOCKING	0

/* for ldbm_insert */
#define LDBM_INSERT	R_NOOVERWRITE
#define LDBM_REPLACE	0

#ifdef LDBM_USE_DBBTREE
#	define LDBM_ORDERED	1
#	define LDBM_SUFFIX	".dbb"
#	define DB_TYPE		DB_BTREE
#else
#	define LDBM_SUFFIX	".dbh"
#	define DB_TYPE		DB_HASH
#endif

#elif defined( HAVE_GDBM )

/*****************************************************************
 *                                                               *
 * use gdbm if possible                                          *
 *                                                               *
 *****************************************************************/

#include <gdbm.h>

LDAP_BEGIN_DECL

typedef datum		Datum;
typedef Datum LDBMCursor;
typedef GDBM_FILE	LDBM;

extern gdbm_error	gdbm_errno;

LDAP_END_DECL

/* for ldbm_open */
#define LDBM_READER	GDBM_READER
#define LDBM_WRITER	GDBM_WRITER
#define LDBM_WRCREAT	GDBM_WRCREAT
#define LDBM_NEWDB	GDBM_NEWDB

#ifdef GDBM_FAST
#define LDBM_NOSYNC	GDBM_FAST
#else
#define LDBM_NOSYNC	0
#endif

#ifdef GDBM_SYNC
#define LDBM_SYNC	GDBM_SYNC
#else
#define LDBM_SYNC	0
#endif

#define LDBM_LOCKING	0
#ifdef GDBM_NOLOCK
#define LDBM_NOLOCKING	GDBM_NOLOCK
#else
#define LDBM_NOLOCKING	0
#endif

#define LDBM_SUFFIX	".gdbm"

/* for ldbm_insert */
#define LDBM_INSERT	GDBM_INSERT
#define LDBM_REPLACE	GDBM_REPLACE

#elif defined( HAVE_MDBM )

/*****************************************************************
 *                                                               *
 * use mdbm if possible                                          *
 *                                                               *
 *****************************************************************/

#include <mdbm.h>

LDAP_BEGIN_DECL

typedef datum		Datum;
typedef int LDBMCursor;
typedef MDBM		*LDBM;

LDAP_END_DECL
    
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* for ldbm_open */
#define LDBM_READER	O_RDONLY
#define LDBM_WRITER	O_RDWR
#define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)

#define LDBM_SYNC	0
#define LDBM_NOSYNC	0
#define LDBM_LOCKING	0
#define LDBM_NOLOCKING	0

#define LDBM_SUFFIX	".mdbm"

/* for ldbm_insert */
#define LDBM_INSERT	MDBM_INSERT
#define LDBM_REPLACE	MDBM_REPLACE

#elif defined( HAVE_NDBM )

/*****************************************************************
 *                                                               *
 * if none of the above use ndbm, the standard unix thing        *
 *                                                               *
 *****************************************************************/

#include <ndbm.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

LDAP_BEGIN_DECL

typedef datum	Datum;
typedef int LDBMCursor;
typedef DBM	*LDBM;

LDAP_END_DECL

/* for ldbm_open */
#define LDBM_READER	O_RDONLY
#define LDBM_WRITER	O_WRONLY
#define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)

#define LDBM_NOSYNC	0
#define LDBM_SYNC	0
#define LDBM_NOLOCK	0
#define LDBM_SYNC	0

#define LDBM_SUFFIX	".ndbm"

/* for ldbm_insert */
#define LDBM_INSERT	DBM_INSERT
#define LDBM_REPLACE	DBM_REPLACE

#endif

LDAP_BEGIN_DECL

LIBLDBM_F (int) ldbm_initialize( void );
LIBLDBM_F (int) ldbm_shutdown( void );

LIBLDBM_F (int) ldbm_errno( LDBM ldbm );
LIBLDBM_F (LDBM) ldbm_open( char *name, int rw, int mode, int dbcachesize );
LIBLDBM_F (void) ldbm_close( LDBM ldbm );
LIBLDBM_F (void) ldbm_sync( LDBM ldbm );
LIBLDBM_F (void) ldbm_datum_free( LDBM ldbm, Datum data );
LIBLDBM_F (Datum) ldbm_datum_dup( LDBM ldbm, Datum data );
LIBLDBM_F (Datum) ldbm_fetch( LDBM ldbm, Datum key );
LIBLDBM_F (int) ldbm_store( LDBM ldbm, Datum key, Datum data, int flags );
LIBLDBM_F (int) ldbm_delete( LDBM ldbm, Datum key );

LIBLDBM_F (Datum) ldbm_firstkey( LDBM ldbm, LDBMCursor **cursor );
LIBLDBM_F (Datum) ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *cursor );

/* initialization of Datum structures */
#ifdef HAVE_BERKELEY_DB2
	LIBLDBM_F (void *) ldbm_malloc( size_t size );
#   define ldbm_datum_init(d) ((void)memset(&(d), 0, sizeof(Datum)))
#else
#   define ldbm_datum_init(d) ((void)0)
#endif  /* HAVE_BERKELEY_DB2 */

LDAP_END_DECL

#endif /* _ldbm_h_ */
