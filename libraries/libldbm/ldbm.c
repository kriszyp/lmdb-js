/* ldbm.c - ldap dbm compatibility routines */

/* Patched for Berkeley DB version 2.0; /KSp; 98/02/23
 *
 *   - basic implementation; 1998/02/23, /KSp
 *   - DB_DBT_MALLOC       ; 1998/03/22, /KSp
 */

#include "portable.h"

#ifdef SLAPD_LDBM

#include <stdio.h>
#include <ac/errno.h>

#include "ldbm.h"

#if defined( LDBM_USE_DBHASH ) || defined( LDBM_USE_DBBTREE )

/*****************************************************************
 *                                                               *
 * use berkeley db hash or btree package                         *
 *                                                               *
 *****************************************************************/

#ifdef HAVE_BERKELEY_DB2
/*************************************************
 *                                               *
 *  A malloc routine for use with DB_DBT_MALLOC  *
 *                                               *
 *************************************************/

void *
ldbm_malloc( size_t size )
{
	return( calloc( 1, size ));
}

#endif


LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		ret = NULL;

#ifdef HAVE_BERKELEY_DB2
	DB_INFO  	dbinfo;

	memset( &dbinfo, 0, sizeof( dbinfo ));
	dbinfo.db_cachesize = dbcachesize;
	dbinfo.db_pagesize  = DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc    = ldbm_malloc;

	db_open( name, DB_TYPE, rw, mode, NULL, &dbinfo, &ret );

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

	ret = dbopen( name, rw, mode, DB_TYPE, info );

#endif

	return( ret );
}

void
ldbm_close( LDBM ldbm )
{
#ifdef HAVE_BERKELEY_DB2
	(*ldbm->close)( ldbm, 0 );
#else
	(*ldbm->close)( ldbm );
#endif
}

void
ldbm_sync( LDBM ldbm )
{
	(*ldbm->sync)( ldbm, 0 );
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

#ifdef HAVE_BERKELEY_DB2
	memset( &dup, 0, sizeof( dup ));
#endif

	if ( data.dsize == 0 ) {
		dup.dsize = 0;
		dup.dptr = NULL;

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

#ifdef HAVE_BERKELEY_DB2
	memset( &data, 0, sizeof( data ));

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

	return( data );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

#ifdef HAVE_BERKELEY_DB2
	rc = (*ldbm->put)( ldbm, NULL, &key, &data, flags & ~LDBM_SYNC );
	rc = (-1 ) * rc;
#else
	rc = (*ldbm->put)( ldbm, &key, &data, flags & ~LDBM_SYNC );
#endif
	if ( flags & LDBM_SYNC )
		(*ldbm->sync)( ldbm, 0 );
	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

#ifdef HAVE_BERKELEY_DB2
	rc = (*ldbm->del)( ldbm, NULL, &key, 0 );
	rc = (-1 ) * rc;
#else
	rc = (*ldbm->del)( ldbm, &key, 0 );
#endif
	(*ldbm->sync)( ldbm, 0 );
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

	memset( &key, 0, sizeof( key ));
	memset( &data, 0, sizeof( data ));

	key.flags = data.flags = DB_DBT_MALLOC;

	/* acquire a cursor for the DB */
	if ( (*ldbm->cursor)( ldbm, NULL, &dbci )) {
		return( key );
	} else {
		*dbch = dbci;
		if ( (*dbci->c_get)( dbci, &key, &data, DB_NEXT ) == 0 ) {
			if ( data.dptr ) free( data.dptr );
#else
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

	memset( &data, 0, sizeof( data ));

	data.flags = DB_DBT_MALLOC;

	if ( (*dbcp->c_get)( dbcp, &key, &data, DB_NEXT ) == 0 ) {
		if ( data.dptr ) free( data.dptr );
#else
	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_NEXT )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
#endif
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}
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

/*****************************************************************
 *                                                               *
 * use gdbm							 *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;
	struct stat	st;

	if ( (db =  gdbm_open( name, 0, rw | GDBM_FAST, mode, 0 )) == NULL ) {
		return( NULL );
	}
	if ( dbcachesize > 0 && stat( name, &st ) == 0 ) {
		dbcachesize = (dbcachesize / st.st_blksize);
		gdbm_setopt( db, GDBM_CACHESIZE, &dbcachesize, sizeof(int) );
	}

	return( db );
}

void
ldbm_close( LDBM ldbm )
{
	gdbm_close( ldbm );
}

void
ldbm_sync( LDBM ldbm )
{
	gdbm_sync( ldbm );
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
	if ( dup.dptr = (char *) malloc( data.dsize ) )
		memcpy( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	return( gdbm_fetch( ldbm, key ) );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	rc = gdbm_store( ldbm, key, data, flags & ~LDBM_SYNC );
	if ( flags & LDBM_SYNC )
		gdbm_sync( ldbm );
	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	rc = gdbm_delete( ldbm, key );
	gdbm_sync( ldbm );
	return( rc );
}

Datum
ldbm_firstkey( LDBM ldbm )
{
	return( gdbm_firstkey( ldbm ) );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key )
{
	return( gdbm_nextkey( ldbm, key ) );
}

int
ldbm_errno( LDBM ldbm )
{
	return( (int) gdbm_errno );
}

#elif defined( HAVE_NDBM )

/*****************************************************************
 *                                                               *
 * if no gdbm, fall back to using ndbm, the standard unix thing  *
 *                                                               *
 *****************************************************************/

/* ARGSUSED */
LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	return( dbm_open( name, rw, mode ) );
}

void
ldbm_close( LDBM ldbm )
{
	dbm_close( ldbm );
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
	if ( dup.dptr = (char *) malloc( data.dsize ) )
		memcpy( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	return( ldbm_datum_dup( ldbm, dbm_fetch( ldbm, key ) ) );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	return( dbm_store( ldbm, key, data, flags ) );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	return( dbm_delete( ldbm, key ) );
}

Datum
ldbm_firstkey( LDBM ldbm )
{
	return( dbm_firstkey( ldbm ) );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key )
{
	return( dbm_nextkey( ldbm ) );
}

int
ldbm_errno( LDBM ldbm )
{
	return( dbm_error( ldbm ) );
}

#endif /* ndbm */
#endif /* ldbm */
