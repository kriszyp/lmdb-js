/* ldbmcache.c - maintain a cache of open ldbm files */

#define DISABLE_BRIDGE /* disable LDAP_BRIDGE code */
#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>

#include "slap.h"
#include "back-ldbm.h"
#include "ldapconfig.h"

#ifndef DECL_SYS_ERRLIST
extern int		sys_nerr;
extern char		*sys_errlist[];
#endif

extern time_t		currenttime;
extern pthread_mutex_t	currenttime_mutex;

struct dbcache *
ldbm_cache_open(
    Backend	*be,
    char	*name,
    char	*suffix,
    int		flags
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int		i, lru;
	time_t		oldtime, curtime;
	char		buf[MAXPATHLEN];
	LDBM		db;
	struct stat	st;

	sprintf( buf, "%s/%s%s", li->li_directory, name, suffix );

	Debug( LDAP_DEBUG_TRACE, "=> ldbm_cache_open( \"%s\", %d, %o )\n", buf,
	    flags, li->li_mode );

	lru = 0;
	pthread_mutex_lock( &currenttime_mutex );
	curtime = currenttime;
	pthread_mutex_unlock( &currenttime_mutex );
	oldtime = curtime;

	pthread_mutex_lock( &li->li_dbcache_mutex );
	for ( i = 0; i < MAXDBCACHE && li->li_dbcache[i].dbc_name != NULL;
	    i++ ) {
		/* already open - return it */
		if ( strcmp( li->li_dbcache[i].dbc_name, buf ) == 0 ) {
			li->li_dbcache[i].dbc_refcnt++;
			Debug( LDAP_DEBUG_TRACE,
			    "<= ldbm_cache_open (cache %d)\n", i, 0, 0 );
			pthread_mutex_unlock( &li->li_dbcache_mutex );
			return( &li->li_dbcache[i] );
		}

		/* keep track of lru db */
		if ( li->li_dbcache[i].dbc_lastref < oldtime &&
		    li->li_dbcache[i].dbc_refcnt == 0 ) {
			lru = i;
			oldtime = li->li_dbcache[i].dbc_lastref;
		}
	}

	/* no empty slots, not already open - close lru and use that slot */
	if ( i == MAXDBCACHE ) {
		i = lru;
		if ( li->li_dbcache[i].dbc_refcnt != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "ldbm_cache_open no unused db to close - waiting\n",
			    0, 0, 0 );
			lru = -1;
			while ( lru == -1 ) {
				pthread_cond_wait( &li->li_dbcache_cv,
				    &li->li_dbcache_mutex );
				for ( i = 0; i < MAXDBCACHE; i++ ) {
					if ( li->li_dbcache[i].dbc_refcnt
					    == 0 ) {
						lru = i;
						break;
					}
				}
			}
			i = lru;
		}
		ldbm_close( li->li_dbcache[i].dbc_db );
		free( li->li_dbcache[i].dbc_name );
		li->li_dbcache[i].dbc_name = NULL;
	}

	if ( (li->li_dbcache[i].dbc_db = ldbm_open( buf, flags, li->li_mode,
	    li->li_dbcachesize )) == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= ldbm_cache_open NULL \"%s\" errno %d reason \"%s\")\n",
		    buf, errno, errno > -1 && errno < sys_nerr ?
		    sys_errlist[errno] : "unknown" );
		pthread_mutex_unlock( &li->li_dbcache_mutex );
		return( NULL );
	}
	li->li_dbcache[i].dbc_name = strdup( buf );
	li->li_dbcache[i].dbc_refcnt = 1;
	li->li_dbcache[i].dbc_lastref = curtime;
	if ( stat( buf, &st ) == 0 ) {
		li->li_dbcache[i].dbc_blksize = st.st_blksize;
	} else {
		li->li_dbcache[i].dbc_blksize = DEFAULT_BLOCKSIZE;
	}
	li->li_dbcache[i].dbc_maxids = (li->li_dbcache[i].dbc_blksize /
	    sizeof(ID)) - 2;
	li->li_dbcache[i].dbc_maxindirect = (SLAPD_LDBM_MIN_MAXIDS /
	    li->li_dbcache[i].dbc_maxids) + 1;

	Debug( LDAP_DEBUG_ARGS,
	    "ldbm_cache_open (blksize %d) (maxids %d) (maxindirect %d)\n",
	    li->li_dbcache[i].dbc_blksize, li->li_dbcache[i].dbc_maxids,
	    li->li_dbcache[i].dbc_maxindirect );
	Debug( LDAP_DEBUG_TRACE, "<= ldbm_cache_open (opened %d)\n", i, 0, 0 );
	pthread_mutex_unlock( &li->li_dbcache_mutex );
	return( &li->li_dbcache[i] );
}

void
ldbm_cache_close( Backend *be, struct dbcache *db )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	pthread_mutex_lock( &li->li_dbcache_mutex );
	if ( --db->dbc_refcnt == 0 ) {
		pthread_cond_signal( &li->li_dbcache_cv );
	}
	pthread_mutex_unlock( &li->li_dbcache_mutex );
}

void
ldbm_cache_really_close( Backend *be, struct dbcache *db )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	pthread_mutex_lock( &li->li_dbcache_mutex );
	if ( --db->dbc_refcnt == 0 ) {
		pthread_cond_signal( &li->li_dbcache_cv );
		ldbm_close( db->dbc_db );
		free( db->dbc_name );
		db->dbc_name = NULL;
	}
	pthread_mutex_unlock( &li->li_dbcache_mutex );
}

void
ldbm_cache_flush_all( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int		i;

	pthread_mutex_lock( &li->li_dbcache_mutex );
	for ( i = 0; i < MAXDBCACHE; i++ ) {
		if ( li->li_dbcache[i].dbc_name != NULL ) {
			Debug( LDAP_DEBUG_TRACE, "ldbm flushing db (%s)\n",
			    li->li_dbcache[i].dbc_name, 0, 0 );
			pthread_mutex_lock( &li->li_dbcache[i].dbc_mutex );
			ldbm_sync( li->li_dbcache[i].dbc_db );
			pthread_mutex_unlock( &li->li_dbcache[i].dbc_mutex );
		}
	}
	pthread_mutex_unlock( &li->li_dbcache_mutex );
}

Datum
ldbm_cache_fetch(
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data;
#ifdef LDBM_USE_DB2
	memset( &data, 0, sizeof( data ) );
#endif

	pthread_mutex_lock( &db->dbc_mutex );
#ifdef reentrant_database
	/* increment reader count */
	db->dbc_readers++
	pthread_mutex_unlock( &db->dbc_mutex );
#endif

	data = ldbm_fetch( db->dbc_db, key );

#ifdef reentrant_database
	pthread_mutex_lock( &db->dbc_mutex );
	/* decrement reader count & signal any waiting writers */
	if ( --db->dbc_readers == 0 ) {
		pthread_cond_signal( &db->dbc_cv );
	}
#endif
	pthread_mutex_unlock( &db->dbc_mutex );

	return( data );
}

int
ldbm_cache_store(
    struct dbcache	*db,
    Datum		key,
    Datum		data,
    int			flags
)
{
	int	rc;

	pthread_mutex_lock( &db->dbc_mutex );
#ifdef reentrant_database
	/* wait for reader count to drop to zero */
	while ( db->dbc_readers > 0 ) {
		pthread_cond_wait( &db->dbc_cv, &db->dbc_mutex );
	}
#endif

#ifdef LDBM_DEBUG
	Statslog( LDAP_DEBUG_STATS,
		"=> ldbm_cache_store(): key.dptr=%s, key.dsize=%d\n",
		key.dptr, key.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> ldbm_cache_store(): key.dptr=0x%08x, data.dptr=0x%0 8x\n",
		key.dptr, data.dptr, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> ldbm_cache_store(): data.dptr=%s, data.dsize=%d\n",
		data.dptr, data.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> ldbm_cache_store(): flags=0x%08x\n",
		flags, 0, 0, 0, 0 );
#endif /* LDBM_DEBUG */

	rc = ldbm_store( db->dbc_db, key, data, flags );

	pthread_mutex_unlock( &db->dbc_mutex );

	return( rc );
}

int
ldbm_cache_delete(
    struct dbcache	*db,
    Datum		key
)
{
	int	rc;

	pthread_mutex_lock( &db->dbc_mutex );
#ifdef reentrant_database
	/* wait for reader count to drop to zero - then write */
	while ( db->dbc_readers > 0 ) {
		pthread_cond_wait( &db->dbc_cv, &db->dbc_mutex );
	}
#endif

	rc = ldbm_delete( db->dbc_db, key );

	pthread_mutex_unlock( &db->dbc_mutex );

	return( rc );
}
