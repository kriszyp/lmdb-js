/* ldbm.h - ldap dbm compatibility routine header file */

#ifndef _LDBM_H_
#define _LDBM_H_

#ifdef LDBM_USE_DBBTREE

/*****************************************************************
 *                                                               *
 * use berkeley db btree package                                 *
 *                                                               *
 *****************************************************************/

#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>

#ifdef HAVE_DB185_H
#	include <db_185.h>
#else
#	include <db.h>
#	ifdef HAVE_BERKELEY_DB2
#		define R_NOOVERWRITE DB_NOOVERWRITE
#		define DEFAULT_DB_PAGE_SIZE 1024
#	endif
#endif


typedef DBT	Datum;
#define dsize	size
#define dptr	data

typedef DB	*LDBM;

#define DB_TYPE		DB_BTREE

/* for ldbm_open */
#ifdef HAVE_BERKELEY_DB2
#	define LDBM_READER	DB_RDONLY
#	define LDBM_WRITER	0x00000      /* hopefully */
#	define LDBM_WRCREAT	(DB_NOMMAP|DB_CREATE|DB_THREAD)
#	define LDBM_NEWDB	(DB_TRUNCATE|DB_CREATE|DB_THREAD)
#else
#	define LDBM_READER	O_RDONLY
#	define LDBM_WRITER	O_RDWR
#	define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#	define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#endif

#  define LDBM_FAST	0

#define LDBM_SUFFIX	".dbb"
#define LDBM_ORDERED	1

/* for ldbm_insert */
#define LDBM_INSERT	R_NOOVERWRITE
#define LDBM_REPLACE	0
#define LDBM_SYNC	0x80000000

/* Do not use #elif.  K&R does not support it. */
#else /* !LDBM_USE_DBBTREE */
#ifdef LDBM_USE_DBHASH

/*****************************************************************
 *                                                               *
 * use berkeley db hash package                                  *
 *                                                               *
 *****************************************************************/

#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>

#ifdef HAVE_DB185_H
#	include <db_185.h>
#else
#	include <db.h>
#	ifdef LDBM_USE_DB2
#		define R_NOOVERWRITE DB_NOOVERWRITE
#		define DEFAULT_DB_PAGE_SIZE 1024
#	endif
#endif

typedef DBT	Datum;
#define dsize	size
#define dptr	data

typedef DB	*LDBM;

#define DB_TYPE		DB_HASH

/* for ldbm_open */
#ifdef LDBM_USE_DB2
#	define LDBM_READER	DB_RDONLY
#	define LDBM_WRITER	0x00000      /* hopefully */
#	define LDBM_WRCREAT	(DB_NOMMAP|DB_CREATE|DB_THREAD)
#	define LDBM_NEWDB	(DB_TRUNCATE|DB_CREATE|DB_THREAD)
#else
#	define LDBM_READER	O_RDONLY
#	define LDBM_WRITER	O_RDWR
#	define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#	define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#	define LDBM_FAST	0
#endif

#define LDBM_SUFFIX	".dbh"

/* for ldbm_insert */
#define LDBM_INSERT	R_NOOVERWRITE
#define LDBM_REPLACE	0
#define LDBM_SYNC	0x80000000

#else /* !LDBM_USE_DBHASH */
#ifdef HAVE_GDBM

/*****************************************************************
 *                                                               *
 * use gdbm if possible                                          *
 *                                                               *
 *****************************************************************/

#include <gdbm.h>

typedef datum		Datum;

typedef GDBM_FILE	LDBM;

extern gdbm_error	gdbm_errno;

/* for ldbm_open */
#define LDBM_READER	GDBM_READER
#define LDBM_WRITER	GDBM_WRITER
#define LDBM_WRCREAT	GDBM_WRCREAT
#define LDBM_NEWDB	GDBM_NEWDB
#define LDBM_FAST	GDBM_FAST

#define LDBM_SUFFIX	".gdbm"

/* for ldbm_insert */
#define LDBM_INSERT	GDBM_INSERT
#define LDBM_REPLACE	GDBM_REPLACE
#define LDBM_SYNC	0x80000000


#else /* !HAVE_GDBM */
#ifdef HAVE_NDBM

/*****************************************************************
 *                                                               *
 * if none of the above use ndbm, the standard unix thing        *
 *                                                               *
 *****************************************************************/

#include <ndbm.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

typedef datum	Datum;

typedef DBM	*LDBM;

/* for ldbm_open */
#define LDBM_READER	O_RDONLY
#define LDBM_WRITER	O_WRONLY
#define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#define LDBM_FAST	0

#define LDBM_SUFFIX	".ndbm"

/* for ldbm_insert */
#define LDBM_INSERT	DBM_INSERT
#define LDBM_REPLACE	DBM_REPLACE
#define LDBM_SYNC	0

#endif /* HAVE_NDBM */
#endif /* HAVE_GDBM */
#endif /* LDBM_USE_DBHASH */
#endif /* LDBM_USE_DBBTREE */

int	ldbm_errno( LDBM ldbm );
LDBM	ldbm_open( char *name, int rw, int mode, int dbcachesize );
void	ldbm_close( LDBM ldbm );
void	ldbm_sync( LDBM ldbm );
void	ldbm_datum_free( LDBM ldbm, Datum data );
Datum	ldbm_datum_dup( LDBM ldbm, Datum data );
Datum	ldbm_fetch( LDBM ldbm, Datum key );
int	ldbm_store( LDBM ldbm, Datum key, Datum data, int flags );
int	ldbm_delete( LDBM ldbm, Datum key );

#if HAVE_BERKELEY_DB2
	void   *ldbm_malloc( size_t size );
	Datum	ldbm_firstkey( LDBM ldbm, DBC **dbch );
	Datum	ldbm_nextkey( LDBM ldbm, Datum key, DBC *dbcp );
#else
	Datum	ldbm_firstkey( LDBM ldbm );
	Datum	ldbm_nextkey( LDBM ldbm, Datum key );
#endif

#endif /* _ldbm_h_ */
