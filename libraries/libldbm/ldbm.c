/* ldbm.c - ldap dbm compatibility routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

/* Patched for Berkeley DB version 2.0; /KSp; 98/02/23
 *
 *   - DB version 2.6.4b   ; 1998/12/28, /KSp
 *   - DB_DBT_MALLOC       ; 1998/03/22, /KSp
 *   - basic implementation; 1998/02/23, /KSp
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
	if ( (dup.dptr = (char *) malloc( data.dsize )) != NULL )
		AC_MEMCPY( dup.dptr, data.dptr, data.dsize );

	return( dup );
}

static int ldbm_initialized = 0;

#ifdef HAVE_BERKELEY_DB_THREAD
#define LDBM_LOCK	((void)0)
#define LDBM_UNLOCK	((void)0)
#else

/* Only DB2 or DB3 with DB_THREAD is thread-free */
static ldap_pvt_thread_mutex_t ldbm_big_mutex;
#define LDBM_LOCK	(ldap_pvt_thread_mutex_lock(&ldbm_big_mutex))
#define LDBM_UNLOCK	(ldap_pvt_thread_mutex_unlock(&ldbm_big_mutex))

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
	return( calloc( 1, size ));
}

#ifdef LDAP_SYSLOG
#include <ac/syslog.h>
#endif

static void
ldbm_db_errcall( const char *prefix, char *message )
{
#ifdef LDAP_SYSLOG
	syslog( LOG_INFO, "ldbm_db_errcall(): %s %s", prefix, message );
#endif
}

/*  a dbEnv for BERKELEYv2  */
DB_ENV           *ldbm_Env = NULL;

int ldbm_initialize( const char* home )
{
	int     err;
	u_int32_t	envFlags;

	if(ldbm_initialized++) return 1;

#if DB_VERSION_MAJOR < 3
	ldbm_Env = calloc( 1, sizeof( DB_ENV ));

	if( ldbm_Env == NULL ) return 1;

	ldbm_Env->db_errcall   = ldbm_db_errcall;
	ldbm_Env->db_errpfx    = "==>";
#else
	ldbm_Env = NULL;
#endif

	envFlags = 
#if defined( DB_PRIVATE )
		DB_PRIVATE |
#endif
#if defined( HAVE_BERKELEY_DB_THREAD )
		DB_THREAD |
#endif
		DB_CREATE;

#if DB_VERSION_MAJOR >= 3
	err = db_env_create( &ldbm_Env, 0 );
#else
	envFlags |= DB_USE_ENVIRON;
	err = db_appinit( home, NULL, ldbm_Env, envFlags );
#endif

	if ( err ) {
		char error[BUFSIZ];

		sprintf( error, "%s (%d)\n", STRERROR( err ), err );

#ifdef LDAP_SYSLOG
		syslog( LOG_INFO,
#if DB_VERSION_MAJOR >= 3
			"ldbm_initialize(): FATAL error in db_env_create() : %s\n",
#else
			"ldbm_initialize(): FATAL error in db_appinit() : %s\n",
#endif
			error );
#endif
	 	return( 1 );
	}

#if DB_VERSION_MAJOR > 2
	ldbm_Env->set_errcall( ldbm_Env, ldbm_db_errcall );
	ldbm_Env->set_errpfx( ldbm_Env, "==>" );

	envFlags |= DB_INIT_MPOOL | DB_USE_ENVIRON;

#if (DB_VERSION_MAJOR > 3) || (DB_VERSION_MINOR >= 1)
        err = ldbm_Env->open( ldbm_Env, home, envFlags, 0 );
#else
        err = ldbm_Env->open( ldbm_Env, home, NULL, envFlags, 0 );
#endif
        if ( err != 0 )
        {
            char error[BUFSIZ];

            sprintf( error, "%s (%d)\n", STRERROR( err ), err );

#ifdef LDAP_SYSLOG
            syslog( LOG_INFO,
                    "ldbm_initialize(): FATAL error in dbEnv->open() : %s\n",
                    error );
#endif
		    ldbm_Env->close( ldbm_Env, 0 );
            return( 1 );
	}
#endif

	return 0;
}

int ldbm_shutdown( void )
{
	if( !ldbm_initialized ) return 1;

#if DB_VERSION_MAJOR >= 3
	ldbm_Env->close( ldbm_Env, 0 );
#else
	db_appexit( ldbm_Env );
#endif

	return 0;
}

#else  /* some DB other than Berkeley V2 or greater */

int ldbm_initialize( const char * home )
{
	if(ldbm_initialized++) return 1;

	ldap_pvt_thread_mutex_init( &ldbm_big_mutex );

	return 0;
}

int ldbm_shutdown( void )
{
	if( !ldbm_initialized ) return 1;

	ldap_pvt_thread_mutex_destroy( &ldbm_big_mutex );

	return 0;
}

#endif /* HAVE_BERKELEY_DB */


#if defined( LDBM_USE_DBHASH ) || defined( LDBM_USE_DBBTREE )

/*****************************************************************
 *                                                               *
 * use berkeley db hash or btree package                         *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		ret = NULL;

#if DB_VERSION_MAJOR >= 3
       int err;
       LDBM_LOCK;
       err = db_create( &ret, ldbm_Env, 0 );
       if ( err != 0 )
       {
           char error[BUFSIZ];

           sprintf( error, "%s (%d)\n", STRERROR( err ), err );

           (void)ret->close(ret, 0);
           return NULL;
       }

       ret->set_pagesize( ret, DEFAULT_DB_PAGE_SIZE );
       ret->set_malloc( ret, ldbm_malloc );
       ret->set_cachesize( ret, 0, dbcachesize, 0 );
       err = ret->open( ret, name, NULL, DB_TYPE, rw, mode);
       LDBM_UNLOCK;
       if ( err != 0 )
       {
           char error[BUFSIZ];

           sprintf( error, "%s (%d)\n", STRERROR( err ), err );

           (void)ret->close(ret, 0);
           return NULL;
       }
 
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
	if (( ldbm_Env == NULL ) || ( ldbm_Env->mp_info == NULL ))
		dbinfo.db_cachesize = dbcachesize;
#endif

	dbinfo.db_pagesize  = DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc    = ldbm_malloc;

	LDBM_LOCK;
    (void) db_open( name, DB_TYPE, rw, mode, ldbm_Env, &dbinfo, &ret );
	LDBM_UNLOCK;

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
#if DB_VERSION_MAJOR >= 3
        ldbm->close( ldbm, 0 );
#elif DB_VERSION_MAJOR >= 2
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

Datum
ldbm_fetch( LDBM ldbm, Datum key )
{
	Datum	data;
	int	rc;

	LDBM_LOCK;
#if DB_VERSION_MAJOR >= 3
        ldbm_datum_init( data );

        data.flags = DB_DBT_MALLOC;

        if ( (rc = ldbm->get( ldbm, NULL, &key, &data, 0 )) != 0 ) {
            ldbm_datum_free( ldbm, data );

#elif DB_VERSION_MAJOR >= 2
	ldbm_datum_init( data );

	data.flags = DB_DBT_MALLOC;

	if ( (rc = (*ldbm->get)( ldbm, NULL, &key, &data, 0 )) != 0 ) {
		ldbm_datum_free( ldbm, data );
#else
	if ( (rc = (*ldbm->get)( ldbm, &key, &data, 0 )) == 0 ) {
		/* Berkeley DB 1.85 don't malloc the data for us */
		/* duplicate it for to ensure reentrancy */
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

#if DB_VERSION_MAJOR >= 3
        rc = ldbm->put( ldbm, NULL, &key, &data, flags & ~LDBM_SYNC );
       if ( rc != 0 )
       {
           char error[BUFSIZ];

           sprintf( error, "%s (%d)\n", STRERROR( rc ), rc );
       }
       rc = (-1) * rc;

#elif DB_VERSION_MAJOR >= 2
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

#if DB_VERSION_MAJOR >= 3
	rc = ldbm->del( ldbm, NULL, &key, 0 );
	rc = (-1 ) * rc;
#elif DB_VERSION_MAJOR >= 2
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
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbch )
{
	Datum	key, data;

#if DB_VERSION_MAJOR >= 2
	LDBMCursor  *dbci;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.flags = data.flags = DB_DBT_MALLOC;

	LDBM_LOCK;

	/* acquire a cursor for the DB */
# if DB_VERSION_MAJOR >= 3
        if ( ldbm->cursor( ldbm, NULL, &dbci, 0 ) )
# elif defined( DB_VERSION_MAJOR ) && defined( DB_VERSION_MINOR ) && \
    (DB_VERSION_MAJOR == 2 && DB_VERSION_MINOR < 6)

	if ( (*ldbm->cursor)( ldbm, NULL, &dbci ))

#  else
	if ( (*ldbm->cursor)( ldbm, NULL, &dbci, 0 ))
#  endif
	{
		key.dptr = NULL;
		return( key );
	} else {
		*dbch = dbci;
		if ( (*dbci->c_get)( dbci, &key, &data, DB_NEXT ) == 0 ) {
			ldbm_datum_free( ldbm, data );
		}
	else {
#else
	int	rc;

	LDBM_LOCK;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_FIRST )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	}
	else {
#endif
		key.dptr = NULL;
		key.dsize = 0;
	}

#if DB_VERSION_MAJOR >= 2
	}
#endif

	LDBM_UNLOCK;

	return( key );
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
{
	Datum	data;

#if DB_VERSION_MAJOR >= 2
	ldbm_datum_init( data );

	ldbm_datum_free( ldbm, key );
	key.flags = data.flags = DB_DBT_MALLOC;

	LDBM_LOCK;

	if ( (*dbcp->c_get)( dbcp, &key, &data, DB_NEXT ) == 0 ) {
		ldbm_datum_free( ldbm, data );
	}
	else {
#else
	int	rc;

	LDBM_LOCK;

	if ( (rc = (*ldbm->seq)( ldbm, &key, &data, R_NEXT )) == 0 ) {
		key = ldbm_datum_dup( ldbm, key );
	}
	else {
#endif
		key.dptr = NULL;
		key.dsize = 0;
	}

	LDBM_UNLOCK;

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

#ifdef HAVE_ST_BLKSIZE
#include <sys/stat.h>
#endif

/*****************************************************************
 *                                                               *
 * use gdbm                                                      *
 *                                                               *
 *****************************************************************/

LDBM
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;
#ifdef HAVE_ST_BLKSIZE
		struct stat	st;
#endif

	LDBM_LOCK;

	if ( (db =  gdbm_open( name, 0, rw | GDBM_FAST, mode, 0 )) == NULL ) {
		LDBM_UNLOCK;
		return( NULL );
	}

#ifdef HAVE_ST_BLKSIZE
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
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbcp )
{
	Datum d;

	LDBM_LOCK;
	d = gdbm_firstkey( ldbm );
	LDBM_UNLOCK;

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

	LDBM_LOCK;
	d = gdbm_nextkey( ldbm, *dbcp );
	LDBM_UNLOCK;

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

	LDBM_LOCK;
	err = gdbm_errno;
	LDBM_UNLOCK;

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
ldbm_open( char *name, int rw, int mode, int dbcachesize )
{
	LDBM		db;

#ifdef MDBM_DEBUG
	fprintf( stdout,
		 "==>(mdbm)ldbm_open(name=%s,rw=%x,mode=%x,cachesize=%d)\n",
		 name ? name : "NULL", rw, mode, dbcachesize );
	fflush( stdout );
#endif

	LDBM_LOCK;	/* We need locking here, this is the only non-thread
			 * safe function we have.
			 */

	if ( (db =  mdbm_open( name, rw, mode, MDBM_PG_SZ )) == NULL ) {

		LDBM_UNLOCK;
#ifdef MDBM_DEBUG
		fprintf( stdout, "<==(mdbm)ldbm_open(db=NULL)\n" );
		fflush( stdout );
#endif
		return( NULL );

	}

#ifdef MDBM_CHAIN
	(void)mdbm_set_chain(db);
#endif

	LDBM_UNLOCK;

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

	LDBM_LOCK;
	mdbm_close( ldbm );
	LDBM_UNLOCK;

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

	LDBM_LOCK;
	mdbm_sync( ldbm );
        LDBM_UNLOCK;

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

	/* LDBM_LOCK; */

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

	/* LDBM_UNLOCK; */

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

	/* LDBM_LOCK; */

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

	/* LDBM_UNLOCK; */

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

	/* LDBM_LOCK; */

#ifdef NO_NULL_KEY
	int_key.dsize = key.dsize + 1;
	int_key.dptr = malloc(int_key.dsize);
	*(int_key.dptr) = 'l';
	AC_MEMCPY( (void *)(int_key.dptr + 1), key.dptr, key.dsize );	
#else
	int_key = key;
#endif
	
	rc = mdbm_delete( ldbm, int_key );

	/* LDBM_UNLOCK; */
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

	/* LDBM_LOCK; */

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

	/* LDBM_UNLOCK; */
	
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
	 * don't know if this will affect the LDAP server opertaion 
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
ldbm_firstkey( LDBM ldbm, LDBMCursor **dbcp )
{
	Datum d;

	LDBM_LOCK;
	d = dbm_firstkey( ldbm );
	LDBM_UNLOCK;

	return d;
}

Datum
ldbm_nextkey( LDBM ldbm, Datum key, LDBMCursor *dbcp )
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
