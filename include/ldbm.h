/* ldbm.h - ldap dbm compatibility routine header file */

#ifndef _LDBM_H_
#define _LDBM_H_

#ifdef LDBM_USE_GDBM

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

#else /* end of gdbm */

#ifdef LDBM_USE_DBHASH

/*****************************************************************
 *                                                               *
 * use berkeley db hash package                                  *
 *                                                               *
 *****************************************************************/

#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>
#include <db.h>

typedef DBT	Datum;
#define dsize	size
#define dptr	data

typedef DB	*LDBM;

#define DB_TYPE		DB_HASH

/* for ldbm_open */
#define LDBM_READER	O_RDONLY
#define LDBM_WRITER	O_RDWR
#define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#define LDBM_FAST	0

#define LDBM_SUFFIX	".dbh"

/* for ldbm_insert */
#define LDBM_INSERT	R_NOOVERWRITE
#define LDBM_REPLACE	0
#define LDBM_SYNC	0x80000000

extern int	errno;

#else /* end of db hash */

#ifdef LDBM_USE_DBBTREE

/*****************************************************************
 *                                                               *
 * use berkeley db btree package                                 *
 *                                                               *
 *****************************************************************/

#include <sys/types.h>
#include <limits.h>
#include <fcntl.h>
#include <db.h>

typedef DBT	Datum;
#define dsize	size
#define dptr	data

typedef DB	*LDBM;

#define DB_TYPE		DB_BTREE

/* for ldbm_open */
#define LDBM_READER	O_RDONLY
#define LDBM_WRITER	O_RDWR
#define LDBM_WRCREAT	(O_RDWR|O_CREAT)
#define LDBM_NEWDB	(O_RDWR|O_TRUNC|O_CREAT)
#define LDBM_FAST	0

#define LDBM_SUFFIX	".dbb"
#define LDBM_ORDERED	1

/* for ldbm_insert */
#define LDBM_INSERT	R_NOOVERWRITE
#define LDBM_REPLACE	0
#define LDBM_SYNC	0x80000000

extern int	errno;

#else /* end of db btree */

#ifdef LDBM_USE_NDBM

/*****************************************************************
 *                                                               *
 * if none of the above use ndbm, the standard unix thing        *
 *                                                               *
 *****************************************************************/

#include <ndbm.h>
#ifndef O_RDONLY
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

#endif /* ndbm */
#endif /* db hash */
#endif /* db btree */
#endif /* gdbm */

LDBM	ldbm_open( char *name, int rw, int mode, int dbcachesize );
void	ldbm_close( LDBM ldbm );
void	ldbm_sync( LDBM ldbm );
void	ldbm_datum_free( LDBM ldbm, Datum data );
Datum	ldbm_datum_dup( LDBM ldbm, Datum data );
Datum	ldbm_fetch( LDBM ldbm, Datum key );
int	ldbm_store( LDBM ldbm, Datum key, Datum data, int flags );
int	ldbm_delete( LDBM ldbm, Datum key );
Datum	ldbm_firstkey( LDBM ldbm );
Datum	ldbm_nextkey( LDBM ldbm, Datum key );
int	ldbm_errno( LDBM ldbm );

#endif /* _ldbm_h_ */
