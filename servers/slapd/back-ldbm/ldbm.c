/* ldbm.c - ldap dbm compatibility routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
 * Portions Copyright 1998-2001 Net Boolean Incorporated.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *   Gary Williams
 *   Howard Chu
 *   Juan Gomez
 *   Kurt D. Zeilenga
 *   Kurt Spanier
 *   Mark Whitehouse
 *   Randy Kundee
 */

#include "portable.h"

#ifdef SLAPD_LDBM

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/errno.h>

#include "ldbm.h"
#include "ldap_pvt_thread.h"

void
ldbm_datum_free( LDBM ldbm, Datum data )
{
	if ( data.dptr ) {
		free( data.dptr );
		memset( &data, '\0', sizeof( Datum ));
		data.dptr = NULL;
	}
}

Datum
ldbm_datum_dup( LDBM ldbm, Datum data )
{
	Datum	dup;

	ldbm_datum_init( dup );

	if ( data.dsize == 0 ) {
		dup.dsize = 0;
		dup.dptr = NULL;

		return( dup );
	}
	dup.dsize = data.dsize;

	if ( (dup.dptr = (char *) malloc( data.dsize )) != NULL ) {
		AC_MEMCPY( dup.dptr, data.dptr, data.dsize );
	}

	return( dup );
}

static int ldbm_initialized = 0;

#if defined( USE_BERKELEY_CDB )
	/* not currently supported */
#define LDBM_RWLOCK_INIT  ((void) 0)
#define LDBM_RWLOCK_DESTROY ((void) 0)
#define LDBM_WLOCK		((void) 0)
#define LDBM_WUNLOCK	((void) 0)
#define LDBM_RLOCK		((void) 0)
#define LDBM_RUNLOCK	((void) 0)

#elif defined( HAVE_BERKELEY_DB_THREAD )
static ldap_pvt_thread_rdwr_t ldbm_big_rdwr;
#define LDBM_RWLOCK_INIT (ldap_pvt_thread_rdwr_init( &ldbm_big_rdwr ))
#define LDBM_RWLOCK_DESTROY (ldap_pvt_thread_rdwr_destroy( &ldbm_big_rdwr ))
#define LDBM_WLOCK		(ldap_pvt_thread_rdwr_wlock(&ldbm_big_rdwr))
#define LDBM_WUNLOCK	(ldap_pvt_thread_rdwr_wunlock(&ldbm_big_rdwr))
#define LDBM_RLOCK		(ldap_pvt_thread_rdwr_rlock(&ldbm_big_rdwr))
#define LDBM_RUNLOCK	(ldap_pvt_thread_rdwr_runlock(&ldbm_big_rdwr))

#else
static ldap_pvt_thread_mutex_t ldbm_big_mutex;
#define LDBM_RWLOCK_INIT (ldap_pvt_thread_mutex_init( &ldbm_big_mutex ))
#define LDBM_RWLOCK_DESTROY (ldap_pvt_thread_mutex_destroy( &ldbm_big_mutex ))
#define LDBM_WLOCK		(ldap_pvt_thread_mutex_lock(&ldbm_big_mutex))
#define LDBM_WUNLOCK	(ldap_pvt_thread_mutex_unlock(&ldbm_big_mutex))
#define LDBM_RLOCK		LDBM_WLOCK
#define LDBM_RUNLOCK	LDBM_WUNLOCK
#endif

#if !defined( HAVE_BERKELEY_DB ) || (DB_VERSION_MAJOR < 3)
	/*  a dbEnv for BERKELEYv2  */
DB_ENV *ldbm_Env = NULL;	/* real or fake, depending on db and version */
#endif

/* Let's make the version comparisons a little easier... */
#undef DB_VERSION_X
#ifdef HAVE_BERKELEY_DB
#define	DB_VERSION_X	((DB_VERSION_MAJOR<<16)|(DB_VERSION_MINOR<<8)|DB_VERSION_PATCH)
#endif

/*******************************************************************
 *                                                                 *
 *  Create some special functions to initialize Berkeley DB for    *
 *  versions greater than 2.                                       *
 *                                                                 *
 *******************************************************************/
#if defined( HAVE_BERKELEY_DB ) && (DB_VERSION_MAJOR >= 2)

void *
ldbm_malloc( size_t size )
{
	/* likely should use ber_mem* routines */
	return( calloc( 1, size ) );
}

#ifdef LDAP_SYSLOG
#include <ac/syslog.h>
#endif

static void
#if DB_VERSION_X < 0x040300
ldbm_db_errcall( const char *prefix, char *message )
#else
ldbm_db_errcall( const DB_ENV *env, const char *prefix, const char *message )
#endif
{
#ifdef LDAP_SYSLOG
	syslog( LOG_INFO, "ldbm: %s %s", prefix, message );
#endif
}

int ldbm_initialize( const char* home )
{
#if DB_VERSION_MAJOR < 3
	int	err;
	u_int32_t	envFlags;
#endif

	if(ldbm_initialized++) return 1;

	{
		char *version;
#ifdef HAVE_EBCDIC
		char v2[1024];
#endif
		int major, minor, patch;
		version = db_version( &major, &minor, &patch );
#ifdef HAVE_EBCDIC
		strcpy( v2, version );
		__etoa( v2 );
		version = v2;
#endif

		if( major != DB_VERSION_MAJOR ||
			minor < DB_VERSION_MINOR )
		{
#ifdef LDAP_SYSLOG
			syslog( LOG_INFO,
				"ldbm_initialize(): version mismatch\nexpected: %s\ngot: %s\n",
				DB_VERSION_STRING, version );
#endif
			return 1;
		}
	}

#if DB_VERSION_MAJOR < 3
	ldbm_Env = calloc( 1, sizeof( DB_ENV ));

	if( ldbm_Env == NULL ) return 1;

	ldbm_Env->db_errcall	= ldbm_db_errcall;
	ldbm_Env->db_errpfx		= "==>";

	envFlags = DB_CREATE | DB_USE_ENVIRON;

	/* add optional flags */
#ifdef DB_PRIVATE
	envFlags |= DB_PRIVATE;
#endif
#ifdef HAVE_BERKELEY_DB_THREAD
	envFlags |= DB_THREAD; 
#endif

	err = db_appinit( home, NULL, ldbm_Env, envFlags );

	if ( err ) {
#ifdef LDAP_SYSLOG
		syslog( LOG_INFO, "ldbm_initialize(): "
			"FATAL error (%d) in db_appinit()\n", err );
#endif
	 	return( 1 );
	}
#endif

	LDBM_RWLOCK_INIT;

	return 0;
}

int ldbm_shutdown( void )
{
	if( !ldbm_initialized ) return 1;

#if DB_VERSION_MAJOR < 3
	db_appexit( ldbm_Env );
#endif

	LDBM_RWLOCK_DESTROY;
	return 0;
}

#else  /* some DB other than Berkeley V2 or greater */

int ldbm_initialize( const char * home )
{
	if(ldbm_initialized++) return 1;

	LDBM_RWLOCK_INIT;

	return 0;
}

int ldbm_shutdown( void )
{
	if( !ldbm_initialized ) return 1;

	LDBM_RWLOCK_DESTROY;

	return 0;
}

#endif /* HAVE_BERKELEY_DB */

#if defined( HAVE_BERKELEY_DB ) && (DB_VERSION_MAJOR >= 3)

DB_ENV *ldbm_initialize_env(const char *home, int dbcachesize, int *envdirok)
{
	DB_ENV *env = NULL;    
	int     err;
	u_int32_t	envFlags;
#ifdef HAVE_EBCDIC
	char n2[2048];
#endif

	err = db_env_create( &env, 0 );

	if ( err ) {
#ifdef LDAP_SYSLOG
		syslog( LOG_INFO, "ldbm_initialize_env(): "
			"FATAL error in db_env_create() : %s (%d)\n",
			db_strerror( err ), err );
#endif
		return NULL;
	}

#if DB_VERSION_X >= 0x030300
	/* This interface appeared in 3.3 */
	env->set_alloc( env, ldbm_malloc, NULL, NULL );
#endif

	env->set_errcall( env, ldbm_db_errcall );
	env->set_errpfx( env, "==>" );
	if (dbcachesize) {
		env->set_cachesize( env, 0, dbcachesize, 0 );
	}

	envFlags = DB_CREATE | DB_INIT_MPOOL | DB_USE_ENVIRON;
#ifdef DB_PRIVATE
	envFlags |= DB_PRIVATE;
#endif
#ifdef DB_MPOOL_PRIVATE
	envFlags |= DB_MPOOL_PRIVATE;
#endif
#ifdef HAVE_BERKELEY_DB_THREAD
	envFlags |= DB_THREAD;
#endif

#ifdef HAVE_EBCDIC
	strncpy(n2, home, sizeof(n2)-1);
	n2[sizeof(n2)-1] = '\0';
	__atoe(n2);
	home = n2;
#endif
#if DB_VERSION_X >= 0x030100
	err = (env->open)( env, home, envFlags, 0 );
#else
	/* 3.0.x requires an extra argument */
	err = (env->open)( env, home, NULL, envFlags, 0 );
#endif

	if ( err != 0 ) {
#ifdef LDAP_SYSLOG
		syslog(	LOG_INFO, "ldbm_initialize_env(): "
			"FATAL error in dbEnv->open() : %s (%d)\n",
			db_strerror( err ), err );
#endif
		env->close( env, 0 );
		return NULL;
	}

	*envdirok = 1;
	return env;
}

void ldbm_shutdown_env(DB_ENV *env)
{
	env->close( env, 0 );
}

#else

DB_ENV *ldbm_initialize_env(const char *home, int dbcachesize, int *envdirok)
{
	return ldbm_Env;
}

void ldbm_shutdown_env(DB_ENV *env)
{
}

#endif

#if defined( LDBM_USE_DBHASH ) || defined( LDBM_USE_DBBTREE )

/*****************************************************************
 *                                                               *
 * use berkeley db hash or btree package                         *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( DB_ENV *env, char *name, int rw, int mode, int dbcachesize )
{
	LDBM		ret = NULL;
#ifdef HAVE_EBCDIC
	char n2[2048];
#endif

#if DB_VERSION_MAJOR >= 3
	int err;

	LDBM_WLOCK;

	err = db_create( &ret, env, 0 );
	if ( err != 0 ) {
		(void)ret->close(ret, 0);
		LDBM_WUNLOCK;

		return NULL;
	}

#if DB_VERSION_X < 0x030300
	ret->set_malloc( ret, ldbm_malloc );
#endif

	ret->set_pagesize( ret, DEFAULT_DB_PAGE_SIZE );

	/* likely should use ber_mem* routines */

#ifdef HAVE_EBCDIC
	strncpy(n2, name, sizeof(n2)-1);
	n2[sizeof(n2)-1] = '\0';
	__atoe(n2);
	name = n2;
#endif
#if DB_VERSION_X >= 0x040111
	err = (ret->open)( ret, NULL, name, NULL, DB_TYPE, rw, mode);
#else
	err = (ret->open)( ret, name, NULL, DB_TYPE, rw, mode);
#endif

	if ( err != 0 ) {
		int tmp = errno;
		(void)ret->close(ret, 0);
		errno = tmp;

		LDBM_WUNLOCK;
		return NULL;
	}

	LDBM_WUNLOCK;
 
#elif DB_VERSION_MAJOR >= 2
	DB_INFO dbinfo;

	memset( &dbinfo, '\0', sizeof( dbinfo ));

#if	DB_VERSION_MAJOR == 2 && DB_VERSION_MINOR == 4
	/*
	 * BerkeleyDB 2.4 do not allow db_cachesize
	 * to be specified if an DB_ENV is.
	 */
#else
	/* set db_cachesize of MPOOL is NOT being used. */
	if (( ldbm_Env == NULL ) || ( ldbm_Env->mp_info == NULL )) {
		dbinfo.db_cachesize = dbcachesize;
	}
#endif

	dbinfo.db_pagesize	= DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc	= ldbm_malloc;

	LDBM_WLOCK;
	(void) db_open( name, DB_TYPE, rw, mode, ldbm_Env, &dbinfo, &ret );
	LDBM_WUNLOCK;

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

	LDBM_WLOCK;
	ret = dbopen( name, rw, mode, DB_TYPE, info );
	LDBM_WUNLOCK;
#endif

	return ret;
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_WLOCK;
#if DB_VERSION_MAJOR >= 2
	ldbm->close( ldbm, 0 );
#else
	ldbm->close( ldbm );
#endif
	LDBM_WUNLOCK;
}

void
ldbm_sync( LDBM ldbm )
{
	LDBM_WLOCK;
	(*ldbm->sync)( ldbm, 0 );
	LDBM_WUNLOCK;
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum	data;
	int	rc;

	LDBM_RLOCK;

#if DB_VERSION_MAJOR >= 2
	ldbm_datum_init( data );

	data.flags = DB_DBT_MALLOC;

	if ( (rc = ldbm->get( ldbm, NULL, &key, &data, 0 )) != 0 ) {
		ldbm_datum_free( ldbm, data );
		data.dptr = NULL;
		data.dsize = 0;
	}
#else
	if ( (rc = ldbm->get( ldbm, &key, &data, 0 )) == 0 ) {
		/* Berkeley DB 1.85 don't malloc the data for us */
		/* duplicate it for to ensure reentrancy */
		data = ldbm_datum_dup( ldbm, data );
	} else {
		data.dptr = NULL;
		data.dsize = 0;
	}
#endif

	LDBM_RUNLOCK;

	return( data );
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	LDBM_WLOCK;

#if DB_VERSION_MAJOR >= 2
	rc = ldbm->put( ldbm, NULL, &key, &data, flags & ~LDBM_SYNC );
	rc = (-1) * rc;
#else
	rc = ldbm->put( ldbm, &key, &data, flags & ~LDBM_SYNC );
#endif

	if ( flags & LDBM_SYNC )
		ldbm->sync( ldbm, 0 );

	LDBM_WUNLOCK;

	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	LDBM_WLOCK;

#if DB_VERSION_MAJOR >= 2
	rc = ldbm->del( ldbm, NULL, &key, 0 );
	rc = (-1) * rc;
#else
	rc = ldbm->del( ldbm, &key, 0 );
#endif
	ldbm->sync( ldbm, 0 );

	LDBM_WUNLOCK;

	return( rc );
}

Datum
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbch )
{
	Datum	key, data;
	int	rc;

#if DB_VERSION_MAJOR >= 2
	LDBMCursor  *dbci;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.flags = data.flags = DB_DBT_MALLOC;

	LDBM_RLOCK;

	/* acquire a cursor for the DB */
# if DB_VERSION_X >= 0x020600
	rc = ldbm->cursor( ldbm, NULL, &dbci, 0 );
# else
	rc = ldbm->cursor( ldbm, NULL, &dbci );
# endif

	if( rc ) {
		key.dptr = NULL;
	} else {
		*dbch = dbci;
		if ( dbci->c_get( dbci, &key, &data, DB_NEXT ) == 0 ) {
			ldbm_datum_free( ldbm, data );
		} else {
			key.dptr = NULL;
			key.dsize = 0;
		}
	}

	LDBM_RUNLOCK;

#else
	LDBM_RLOCK;

	rc = ldbm->seq( ldbm, &key, &data, R_FIRST );

	if ( rc == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	} else {
		key.dptr = NULL;
		key.dsize = 0;
	}

	LDBM_RUNLOCK;
#endif

	return( key );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
{
	int	rc;
	Datum	data;

	LDBM_RLOCK;

#if DB_VERSION_MAJOR >= 2
	ldbm_datum_init( data );

	ldbm_datum_free( ldbm, key );
	key.flags = data.flags = DB_DBT_MALLOC;

	rc = dbcp->c_get( dbcp, &key, &data, DB_NEXT );
	if ( rc == 0 ) {
		ldbm_datum_free( ldbm, data );
	} else
#else
	rc = ldbm->seq( ldbm, &key, &data, R_NEXT );

	if ( rc == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	} else
#endif
	{
		key.dptr = NULL;
		key.dsize = 0;
	}

	LDBM_RUNLOCK;
	return( key );
}

int
ldbm_errno( LDBM ldbm )
{
	return( errno );
}

/******************************************************************
 *                                                                *
 *         END Berkeley section                                   *
 *                                                                *
 ******************************************************************/

#elif defined( HAVE_GDBM )

#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
#include <sys/stat.h>
#endif

/*****************************************************************
 *                                                               *
 * use gdbm                                                      *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( DB_ENV *env, char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
		struct stat	st;
#endif
#ifdef HAVE_EBCDIC
	char n2[2048];

	strncpy(n2, name, sizeof(n2)-1);
	n2[sizeof(n2)-1] = '\0';
	__atoe(n2);
	name = n2;
#endif

	LDBM_WLOCK;

	if ( (db = gdbm_open( name, 0, rw | GDBM_FAST, mode, 0 )) == NULL ) {
		LDBM_WUNLOCK;
		return( NULL );
	}

#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	if ( dbcachesize > 0 && stat( name, &st ) == 0 ) {
		dbcachesize /= st.st_blksize;
		if( dbcachesize == 0 ) dbcachesize = 1;
		gdbm_setopt( db, GDBM_CACHESIZE, &dbcachesize, sizeof(int) );
	}
#else
	if ( dbcachesize > 0 ) {
		dbcachesize /= 4096;
		if( dbcachesize == 0 ) dbcachesize = 1;
		gdbm_setopt( db, GDBM_CACHESIZE, &dbcachesize, sizeof(int) );
	}
#endif

	LDBM_WUNLOCK;

	return( db );
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_WLOCK;
	gdbm_close( ldbm );
	LDBM_WUNLOCK;
}

void
ldbm_sync( LDBM ldbm )
{
	LDBM_WLOCK;
	gdbm_sync( ldbm );
	LDBM_WUNLOCK;
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum d;

	LDBM_RLOCK;
	d = gdbm_fetch( ldbm, key );
	LDBM_RUNLOCK;

	return d;
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;

	LDBM_WLOCK;
	rc = gdbm_store( ldbm, key, data, flags & ~LDBM_SYNC );
	if ( flags & LDBM_SYNC )
		gdbm_sync( ldbm );
	LDBM_WUNLOCK;

	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;

	LDBM_WLOCK;
	rc = gdbm_delete( ldbm, key );
	gdbm_sync( ldbm );
	LDBM_WUNLOCK;

	return( rc );
}

Datum
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbcp )
{
	Datum d;

	LDBM_RLOCK;
	d = gdbm_firstkey( ldbm );
	LDBM_RUNLOCK;

	if ( d.dptr != NULL ) {
		*dbcp = (Datum *) malloc( sizeof( Datum ) );
		**dbcp = ldbm_datum_dup( ldbm, d );
	}

	return d;
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
{
	Datum d;

	LDBM_RLOCK;
	d = gdbm_nextkey( ldbm, *dbcp );
	LDBM_RUNLOCK;

	ldbm_datum_free( ldbm, *dbcp );

	if ( d.dptr != NULL ) {
		*dbcp = ldbm_datum_dup( ldbm, d );
	} else {
		free( dbcp );
	}

	return d;
}

int
ldbm_errno( LDBM ldbm )
{
	int err;

	LDBM_WLOCK;
	err = gdbm_errno;
	LDBM_WUNLOCK;

	return( err );
}

#elif HAVE_MDBM

/* MMAPED DBM HASHING DATABASE */

#include <ac/string.h>

/* #define MDBM_DEBUG */

#ifdef MDBM_DEBUG
#include <stdio.h>
#endif

#define NO_NULL_KEY
/* #define MDBM_CHAIN */

#ifdef MDBM_CHAIN

/* Use chaining */

#define mdbm_store	mdbm_chain_store
#define mdbm_fetch	mdbm_chain_fetch
#define mdbm_delete	mdbm_chain_delete
#define mdbm_first	mdbm_chain_first
#define mdbm_next	mdbm_chain_next

#endif

#define MDBM_PG_SZ	(4*1024)

/*****************************************************************
 *                                                               *
 * use mdbm                                                      *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( DB_ENV *env, char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;

#ifdef MDBM_DEBUG
	fprintf( stdout,
		 "==>(mdbm)ldbm_open(name=%s,rw=%x,mode=%x,cachesize=%d)\n",
		 name ? name : "NULL", rw, mode, dbcachesize );
	fflush( stdout );
#endif

	LDBM_WLOCK;	/* We need locking here, this is the only non-thread
		* safe function we have.  */

	if ( (db =  mdbm_open( name, rw, mode, MDBM_PG_SZ )) == NULL ) {
		LDBM_WUNLOCK;
#ifdef MDBM_DEBUG
		fprintf( stdout, "<==(mdbm)ldbm_open(db=NULL)\n" );
		fflush( stdout );
#endif
		return( NULL );
	}

#ifdef MDBM_CHAIN
	(void)mdbm_set_chain(db);
#endif

	LDBM_WUNLOCK;

#ifdef MDBM_DEBUG
	fprintf( stdout, "<==(mdbm)ldbm_open(db=%p)\n", db );
	fflush( stdout );
#endif

	return( db );
}

void
ldbm_close( LDBM ldbm )
{
	/* Open and close are not reentrant so we need to use locks here */

#ifdef MDBM_DEBUG
	fprintf( stdout,
		 "==>(mdbm)ldbm_close(db=%p)\n", ldbm );
	fflush( stdout );
#endif

	LDBM_WLOCK;
	mdbm_close( ldbm );
	LDBM_WUNLOCK;

#ifdef MDBM_DEBUG
	fprintf( stdout, "<==(mdbm)ldbm_close()\n" );
	fflush( stdout );
#endif
}

void
ldbm_sync( LDBM ldbm )
{
	/* XXX: Not sure if this is re-entrant need to check code, if so
	 * you can leave LOCKS out.
	 */

	LDBM_WLOCK;
	mdbm_sync( ldbm );
	LDBM_WUNLOCK;
}

#define MAX_MDBM_RETRY	5

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum	d;
	kvpair	k;
	int	retry = 0;

	/* This hack is needed because MDBM does not take keys
	 * which begin with NULL when working in the chaining
	 * mode.
	 */

#ifdef NO_NULL_KEY
	k.key.dsize = key.dsize + 1;			
	k.key.dptr = malloc(k.key.dsize);
	*(k.key.dptr) = 'l';
	AC_MEMCPY( (void *)(k.key.dptr + 1), key.dptr, key.dsize );	
#else
	k.key = key;
#endif	

	k.val.dptr = NULL;
	k.val.dsize = 0;

	/* LDBM_RLOCK; */
	do {
		d = mdbm_fetch( ldbm, k );

		if ( d.dsize > 0 ) {
			if ( k.val.dptr != NULL ) {
				free( k.val.dptr );
			}

			if ( (k.val.dptr = malloc( d.dsize )) != NULL ) {
				k.val.dsize = d.dsize;
				d = mdbm_fetch( ldbm, k );

			} else { 
				d.dsize = 0;
				break;
			}
		}/* if ( d.dsize > 0 ) */
	} while ((d.dsize > k.val.dsize) && (++retry < MAX_MDBM_RETRY));
	/* LDBM_RUNLOCK; */

#ifdef NO_NULL_KEY
	free(k.key.dptr);
#endif

	return d;
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int	rc;
	Datum	int_key;	/* Internal key */

#ifdef MDBM_DEBUG
	fprintf( stdout,
		 "==>(mdbm)ldbm_store(db=%p, key(dptr=%p,sz=%d), data(dptr=%p,sz=%d), flags=%x)\n",
		 ldbm, key.dptr, key.dsize, data.dptr, data.dsize, flags );
	fflush( stdout );
#endif

	/* LDBM_WLOCK; */

#ifdef NO_NULL_KEY
	int_key.dsize = key.dsize + 1;
	int_key.dptr = malloc( int_key.dsize );
	*(int_key.dptr) = 'l';	/* Must not be NULL !*/
	AC_MEMCPY( (void *)(int_key.dptr + 1), key.dptr, key.dsize );
#else
	int_key = key;
#endif

	rc = mdbm_store( ldbm, int_key, data, flags );
	if ( flags & LDBM_SYNC ) {
		mdbm_sync( ldbm );
	}

	/* LDBM_WUNLOCK; */

#ifdef MDBM_DEBUG
	fprintf( stdout, "<==(mdbm)ldbm_store(rc=%d)\n", rc );
	fflush( stdout );
#endif

#ifdef NO_NULL_KEY
	free(int_key.dptr);
#endif

	return( rc );
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int	rc;
	Datum	int_key;

	/* LDBM_WLOCK; */

#ifdef NO_NULL_KEY
	int_key.dsize = key.dsize + 1;
	int_key.dptr = malloc(int_key.dsize);
	*(int_key.dptr) = 'l';
	AC_MEMCPY( (void *)(int_key.dptr + 1), key.dptr, key.dsize );	
#else
	int_key = key;
#endif
	
	rc = mdbm_delete( ldbm, int_key );

	/* LDBM_WUNLOCK; */
#ifdef NO_NULL_KEY
	free(int_key.dptr);
#endif

	return( rc );
}

static Datum
ldbm_get_next( LDBM ldbm, kvpair (*fptr)(MDBM *, kvpair) ) 
{
	kvpair	out;
	kvpair	in;
	Datum	ret;
	size_t	sz = MDBM_PAGE_SIZE(ldbm);
#ifdef NO_NULL_KEY
	int	delta = 1;
#else
	int	delta = 0;
#endif

	/* LDBM_RLOCK; */

	in.key.dsize = sz;	/* Assume first key in one pg */
	in.key.dptr = malloc(sz);
	
	in.val.dptr = NULL;	/* Don't need data just key */ 
	in.val.dsize = 0;

	ret.dptr = NULL;
	ret.dsize = NULL;

	out = fptr( ldbm, in );

	if (out.key.dsize > 0) {
		ret.dsize = out.key.dsize - delta;

		if ((ret.dptr = (char *)malloc(ret.dsize)) == NULL) { 
			ret.dsize = 0;
			ret.dptr = NULL;

		} else {
			AC_MEMCPY(ret.dptr, (void *)(out.key.dptr + delta),
				ret.dsize );
	    }
	}

	/* LDBM_RUNLOCK; */
	
	free(in.key.dptr);
	return ret;
}

Datum
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbcp )
{
	return ldbm_get_next( ldbm, mdbm_first );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
{
	/* XXX:
	 * don't know if this will affect the LDAP server operation 
	 * but mdbm cannot take and input key.
	 */

	return ldbm_get_next( ldbm, mdbm_next );
}

int
ldbm_errno( LDBM ldbm )
{
	/* XXX: best we can do with current  mdbm interface */
	return( errno );
}

#elif defined( HAVE_NDBM )

/*****************************************************************
 *                                                               *
 * if no gdbm or mdbm, fall back to using ndbm, the standard unix thing  *
 *                                                               *
 *****************************************************************/

/* ARGSUSED */
LDBM
ldbm_open( DB_ENV *env, char *name, int rw, int mode, int dbcachesize )
{
	LDBM ldbm;

	LDBM_WLOCK;
	ldbm = dbm_open( name, rw, mode );
	LDBM_WUNLOCK;

	return( ldbm );
}

void
ldbm_close( LDBM ldbm )
{
	LDBM_WLOCK;
	dbm_close( ldbm );
	LDBM_WUNLOCK;
}

/* ARGSUSED */
void
ldbm_sync( LDBM ldbm )
{
	return;
}

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum d;

	LDBM_RLOCK;
	d = ldbm_datum_dup( ldbm, dbm_fetch( ldbm, key ) );
	LDBM_RUNLOCK;

	return d;
}

int
ldbm_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int rc;

	LDBM_WLOCK;
	rc = dbm_store( ldbm, key, data, flags );
	LDBM_WUNLOCK;

	return rc;
}

int
ldbm_delete( LDBM ldbm, Datum key )
{
	int rc;

	LDBM_WLOCK;
	rc = dbm_delete( ldbm, key );
	LDBM_WUNLOCK;

	return rc;
}

Datum
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbcp )
{
	Datum d;

	LDBM_RLOCK;
	d = dbm_firstkey( ldbm );
	LDBM_RUNLOCK;

	return d;
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
{
	Datum d;

	LDBM_RLOCK;
	d = dbm_nextkey( ldbm );
	LDBM_RUNLOCK;

	return d;
}

int
ldbm_errno( LDBM ldbm )
{
	int err;

	LDBM_WLOCK;
	err = dbm_error( ldbm );
	LDBM_WUNLOCK;

	return err;
}

#endif /* ndbm */
#endif /* ldbm */
