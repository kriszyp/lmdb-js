/* ldbm.c - ldap dbm compatibility routines */

#include <stdio.h>
#include "ldbm.h"

#ifdef LDBM_USE_GDBM

#include <sys/types.h>
#include <sys/stat.h>

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

#else
#if defined( LDBM_USE_DBHASH ) || defined( LDBM_USE_DBBTREE )

/*****************************************************************
 *                                                               *
 * use berkeley db hash or btree package                         *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		ret;
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
	return( ret );
}

void
ldbm_close( LDBM ldbm )
{
	(*ldbm->close)( ldbm );
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

	if ( (rc = (*ldbm->get)( ldbm, &key, &data, 0 )) == 0 ) {
		data = ldbm_datum_dup( ldbm, data );
	} else {
		data.dptr = NULL;
		data.dsize = 0;
	}

	return( data );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	rc = (*ldbm->put)( ldbm, &key, &data, flags & ~LDBM_SYNC );
	if ( flags & LDBM_SYNC )
		(*ldbm->sync)( ldbm, 0 );
	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	rc = (*ldbm->del)( ldbm, &key, 0 );
	(*ldbm->sync)( ldbm, 0 );
	return( rc );
}

Datum
ldbm_firstkey( LDBM ldbm )
{
	Datum	key, data;
	int	rc;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_FIRST )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}
	return( key );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key )
{
	Datum	data;
	int	rc;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_NEXT )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}
	return( key );
}

int
ldbm_errno( LDBM ldbm )
{
	return( errno );
}

#else

#ifdef LDBM_USE_NDBM

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
#endif /* db */
#endif /* gdbm */
