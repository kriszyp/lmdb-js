/* ldbm.c - ldap dbm compatibility routines */

/* Patched for Berkeley DB version 2.0; /KSp; 98/02/23
 *
 *   - DB version 2.6.4b   ; 1998/12/28, /KSp
 *   - DB_DBT_MALLOC       ; 1998/03/22, /KSp
 *   - basic implementation; 1998/02/23, /KSp
 */

#include "portable.h"

#include "syslog.h"

#ifdef SLAPD_LDBM

#include <stdio.h>
#include <stdlib.h>
#include <ac/string.h>
#include <ac/errno.h>

#include "ldbm.h"
#include "ldap_pvt_thread.h"

#if defined( LDBM_USE_DBHASH ) || defined( LDBM_USE_DBBTREE )

/*****************************************************************
 *                                                               *
 * use berkeley db hash or btree package                         *
 *                                                               *
 *****************************************************************/

#ifdef HAVE_BERKELEY_DB2

/*  A malloc routine for use with DB_DBT_MALLOC  */
void *
ldbm_malloc( size_t size )
{
	return( calloc( 1, size ));
}

/* Berkeley DB 2.x is reentrant */
#define LDBM_LOCK   ((void)0)
#define LDBM_UNLOCK ((void)0)

#else

/* DB 1.85 is non-reentrant */
static ldap_pvt_thread_mutex_t ldbm_big_mutex;
#define LDBM_LOCK   (ldap_pvt_thread_mutex_lock(&ldbm_big_mutex))
#define LDBM_UNLOCK (ldap_pvt_thread_mutex_unlock(&ldbm_big_mutex))


/*  we need a dummy definition for pre-2.0 DB */
typedef  void  DB_ENV

#endif


/*  the old interface for tools and pre-2.0 DB  */
LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	return( ldbm_open_env( name, rw, mode, dbcachesize, NULL ));
}


/*  an enhanced interface for DB 2.0-slapd  */
LDBM
ldbm_open_env( char *name, int rw, int mode, int dbcachesize, DB_ENV *dbEnv )
{
	LDBM		ret = NULL;

#ifdef HAVE_BERKELEY_DB2
	DB_INFO  	dbinfo;

	memset( &dbinfo, 0, sizeof( dbinfo ));
	dbinfo.db_cachesize = dbcachesize;
	dbinfo.db_pagesize  = DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc    = ldbm_malloc;

	/*  use the environment, but only if initialized  */
    (void) db_open( name, DB_TYPE, rw, mode,
					dbEnv->db_errcall ? dbEnv : NULL, &dbinfo, &ret );

#else
	void		*info;
	BTREEINFO	binfo;
	HASHINFO	hinfo;

	if ( DB_TYPE == DB_HASH ) {
		memset( (char *) &hinfo, '\0', sizeof(hinfo) );
		hinfo.cachesize = dbcachesize;
		info = &hinfo;
	} else if ( DB_TYPE == DB_BTREE ) {
		memset( (char *) &binfo, '\0', sizeof(binfo) );
		binfo.cachesize = dbcachesize;
		info = &binfo;
	} else {
		info = NULL;
	}

	LDBM_LOCK;
	ret = dbopen( name, rw, mode, DB_TYPE, info );
	LDBM_UNLOCK;

#endif

	return( ret );
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_LOCK;
#ifdef HAVE_BERKELEY_DB2
	(*ldbm->close)( ldbm, 0 );
#else
	(*ldbm->close)( ldbm );
#endif
	LDBM_UNLOCK;
}

void
ldbm_sync( LDBM ldbm )
{
	LDBM_LOCK;
	(*ldbm->sync)( ldbm, 0 );
	LDBM_UNLOCK;
}

void
ldbm_datum_free( LDBM ldbm, Datum data )
{
	free( data.dptr );
}

Datum
ldbm_datum_dup( LDBM ldbm, Datum data )
{
	Datum	dup;

	ldbm_datum_init( dup );

	if ( data.dsize == 0 ) {
		return( dup );
	}
	dup.dsize = data.dsize;
	if ( dup.dptr = (char *) malloc( data.dsize ) )
		memcpy( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum	data;
	int	rc;

	LDBM_LOCK;

#ifdef HAVE_BERKELEY_DB2
	ldbm_datum_init( data );

	data.flags = DB_DBT_MALLOC;

	if ( (rc = (*ldbm->get)( ldbm, NULL, &key, &data, 0 )) != 0 ) {
		if ( data.dptr ) free( data.dptr );
#else
	if ( (rc = (*ldbm->get)( ldbm, &key, &data, 0 )) == 0 ) {
		data = ldbm_datum_dup( ldbm, data );
	} else {
#endif
		data.dptr = NULL;
		data.dsize = 0;
	}

	LDBM_UNLOCK;

	return( data );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	LDBM_LOCK;

#ifdef HAVE_BERKELEY_DB2
	rc = (*ldbm->put)( ldbm, NULL, &key, &data, flags & ~LDBM_SYNC );
	rc = (-1 ) * rc;
#else
	rc = (*ldbm->put)( ldbm, &key, &data, flags & ~LDBM_SYNC );
#endif

	if ( flags & LDBM_SYNC )
		(*ldbm->sync)( ldbm, 0 );

	LDBM_UNLOCK;

	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	LDBM_LOCK;

#ifdef HAVE_BERKELEY_DB2
	rc = (*ldbm->del)( ldbm, NULL, &key, 0 );
	rc = (-1 ) * rc;
#else
	rc = (*ldbm->del)( ldbm, &key, 0 );
#endif
	(*ldbm->sync)( ldbm, 0 );

	LDBM_UNLOCK;

	return( rc );
}

Datum
#ifdef HAVE_BERKELEY_DB2
ldbm_firstkey( LDBM ldbm, DBC **dbch )
#else
ldbm_firstkey( LDBM ldbm )
#endif
{
	Datum	key, data;
	int	rc;

#ifdef HAVE_BERKELEY_DB2
	DBC  *dbci;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.flags = data.flags = DB_DBT_MALLOC;

	LDBM_LOCK;

	/* acquire a cursor for the DB */

#  if defined( DB_VERSION_MAJOR ) && defined( DB_VERSION_MINOR ) && \
    DB_VERSION_MAJOR == 2 && DB_VERSION_MINOR < 6

	if ( (*ldbm->cursor)( ldbm, NULL, &dbci )) {

#  else

	if ( (*ldbm->cursor)( ldbm, NULL, &dbci, 0 )) {

#  endif

		return( key );
	} else {
		*dbch = dbci;
		if ( (*dbci->c_get)( dbci, &key, &data, DB_NEXT ) == 0 ) {
			if ( data.dptr ) free( data.dptr );
#else

	LDBM_LOCK;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_FIRST )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
#endif
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}

#ifdef HAVE_BERKELEY_DB2
	}
#endif

	LDBM_UNLOCK;

	return( key );
}

Datum
#ifdef HAVE_BERKELEY_DB2
ldbm_nextkey( LDBM ldbm, Datum key, DBC *dbcp )
#else
ldbm_nextkey( LDBM ldbm, Datum key )
#endif
{
	Datum	data;
	int	rc;

#ifdef HAVE_BERKELEY_DB2
	void *oldKey = key.dptr;

	ldbm_datum_init( data );

	data.flags = DB_DBT_MALLOC;

	LDBM_LOCK;

	if ( (*dbcp->c_get)( dbcp, &key, &data, DB_NEXT ) == 0 ) {
		if ( data.dptr ) free( data.dptr );
#else

	LDBM_LOCK;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_NEXT )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
#endif
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}

	LDBM_UNLOCK;

#ifdef HAVE_BERKELEY_DB2
	if ( oldKey ) free( oldKey );
#endif

	return( key );
}

int
ldbm_errno( LDBM ldbm )
{
	return( errno );
}

#elif defined( HAVE_GDBM )

#include <sys/stat.h>

/* GDBM is non-reentrant */
static ldap_pvt_thread_mutex_t ldbm_big_mutex;
#define LDBM_LOCK   (ldap_pvt_thread_mutex_lock(&ldbm_big_mutex))
#define LDBM_UNLOCK (ldap_pvt_thread_mutex_unlock(&ldbm_big_mutex))


/*****************************************************************
 *                                                               *
 * use gdbm                                                      *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;
	struct stat	st;

	LDBM_LOCK;

	if ( (db =  gdbm_open( name, 0, rw | GDBM_FAST, mode, 0 )) == NULL ) {
		return( NULL );
	}
	if ( dbcachesize > 0 && stat( name, &st ) == 0 ) {
		dbcachesize = (dbcachesize / st.st_blksize);
		gdbm_setopt( db, GDBM_CACHESIZE, &dbcachesize, sizeof(int) );
	}

	LDBM_UNLOCK;

	return( db );
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_LOCK;
	gdbm_close( ldbm );
	LDBM_UNLOCK;
}

void
ldbm_sync( LDBM ldbm )
{
	LDBM_LOCK;
	gdbm_sync( ldbm );
	LDBM_UNLOCK;
}

void
ldbm_datum_free( LDBM ldbm, Datum data )
{
	free( data.dptr );
}

Datum
ldbm_datum_dup( LDBM ldbm, Datum data )
{
	Datum	dup;

	if ( data.dsize == 0 ) {
		dup.dsize = 0;
		dup.dptr = NULL;

		return( dup );
	}
	dup.dsize = data.dsize;
	if ( (dup.dptr = (char *) malloc( data.dsize )) != NULL )
		memcpy( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum d;
	LDBM_LOCK;
	d = gdbm_fetch( ldbm, key );
	LDBM_UNLOCK;
	return d;
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	LDBM_LOCK;
	rc = gdbm_store( ldbm, key, data, flags & ~LDBM_SYNC );
	if ( flags & LDBM_SYNC )
		gdbm_sync( ldbm );
	LDBM_UNLOCK;

	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	LDBM_LOCK;
	rc = gdbm_delete( ldbm, key );
	gdbm_sync( ldbm );
	LDBM_UNLOCK;

	return( rc );
}

Datum
ldbm_firstkey( LDBM ldbm )
{
	Datum d;
	LDBM_LOCK;
	d = gdbm_firstkey( ldbm );
	LDBM_UNLOCK;
	return d;
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key )
{
	Datum d;
	LDBM_LOCK;
	d = gdbm_nextkey( ldbm, key );
	LDBM_UNLOCK;
	return d;
}

int
ldbm_errno( LDBM ldbm )
{
	int err;
	LDBM_LOCK;
	err = (int) gdbm_errno;
	LDBM_UNLOCK;
	return( err );
}

#elif defined( HAVE_NDBM )

/*****************************************************************
 *                                                               *
 * if no gdbm, fall back to using ndbm, the standard unix thing  *
 *                                                               *
 *****************************************************************/

/* NDBM is non-reentrant */
static ldap_pvt_thread_mutex_t ldbm_big_mutex;
#define LDBM_LOCK   (ldap_pvt_thread_mutex_lock(&ldbm_big_mutex))
#define LDBM_UNLOCK (ldap_pvt_thread_mutex_unlock(&ldbm_big_mutex))


/* ARGSUSED */
LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM ldbm;

	LDBM_LOCK;
	ldbm = dbm_open( name, rw, mode );
	LDBM_UNLOCK;

	return( ldbm );
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_LOCK;
	dbm_close( ldbm );
	LDBM_UNLOCK;
}

/* ARGSUSED */
void
ldbm_sync( LDBM ldbm )
{
	return;
}

void
ldbm_datum_free( LDBM ldbm, Datum data )
{
	return;
}

Datum
ldbm_datum_dup( LDBM ldbm, Datum data )
{
	Datum	dup;

	if ( data.dsize == 0 ) {
		dup.dsize = 0;
		dup.dptr = NULL;

		return( dup );
	}
	dup.dsize = data.dsize;
	dup.dptr = (char *) malloc( data.dsize );
	if ( dup.dptr )
		memcpy( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum d;

	LDBM_LOCK;
	d = ldbm_datum_dup( ldbm, dbm_fetch( ldbm, key ) );
	LDBM_UNLOCK;

	return d;
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int rc;

	LDBM_LOCK;
	rc = dbm_store( ldbm, key, data, flags );
	LDBM_UNLOCK;

	return rc;
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int rc;

	LDBM_LOCK;
	rc = dbm_delete( ldbm, key );
	LDBM_UNLOCK;

	return rc;
}

Datum
ldbm_firstkey( LDBM ldbm )
{
	Datum d;

	LDBM_LOCK;
	d = dbm_firstkey( ldbm );
	LDBM_UNLOCK;

	return d;
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key )
{
	Datum d;

	LDBM_LOCK;
	d = dbm_nextkey( ldbm );
	LDBM_UNLOCK;

	return d;
}

int
ldbm_errno( LDBM ldbm )
{
	int err;

	LDBM_LOCK;
	err = dbm_error( ldbm );
	LDBM_UNLOCK;

	return err;
}

#endif /* ndbm */
#endif /* ldbm */
