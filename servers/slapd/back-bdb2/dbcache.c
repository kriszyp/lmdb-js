/* ldbmcache.c - maintain a cache of open bdb2 files */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/stat.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "ldapconfig.h"
#include "slap.h"
#include "back-bdb2.h"

struct dbcache *
bdb2i_cache_open(
    BackendDB	*be,
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

	/*  if in slapd, all files are open, so return handle from file cache  */
	if ( ( slapMode == SLAP_SERVER_MODE ) || ( slapMode == SLAP_TOOL_MODE ) ) {

		/*  use short name  */
		sprintf( buf, "%s%s", name, suffix );
		return( bdb2i_get_db_file_cache( li, buf ));

	}

	/*  use the absolute path  */
	sprintf( buf, "%s%s%s%s", li->li_directory, DEFAULT_DIRSEP, name, suffix );

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_cache_open( \"%s\", %d, %o )\n", buf,
	    flags, li->li_mode );

	lru = 0;
	ldap_pvt_thread_mutex_lock( &currenttime_mutex );
	curtime = currenttime;
	ldap_pvt_thread_mutex_unlock( &currenttime_mutex );
	oldtime = curtime;

	ldap_pvt_thread_mutex_lock( &li->li_dbcache_mutex );
	for ( i = 0; i < MAXDBCACHE && li->li_dbcache[i].dbc_name != NULL;
	    i++ ) {
		/* already open - return it */
		if ( strcmp( li->li_dbcache[i].dbc_name, buf ) == 0 ) {
			li->li_dbcache[i].dbc_refcnt++;
			Debug( LDAP_DEBUG_TRACE,
			    "<= bdb2i_cache_open (cache %d)\n", i, 0, 0 );
			ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
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
			    "bdb2i_cache_open no unused db to close - waiting\n",
			    0, 0, 0 );
			lru = -1;
			while ( lru == -1 ) {
				ldap_pvt_thread_cond_wait( &li->li_dbcache_cv,
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
	    0 )) == NULL ) {

		Debug( LDAP_DEBUG_TRACE,
		    "<= bdb2i_cache_open NULL \"%s\" errno %d reason \"%s\")\n",
		    buf, errno, errno > -1 && errno < sys_nerr ?
		    sys_errlist[errno] : "unknown" );
		ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
		return( NULL );
	}
	li->li_dbcache[i].dbc_name = ch_strdup( buf );
	li->li_dbcache[i].dbc_refcnt = 1;
	li->li_dbcache[i].dbc_lastref = curtime;
	if ( stat( buf, &st ) == 0 ) {
		li->li_dbcache[i].dbc_blksize = st.st_blksize;
	} else {
		li->li_dbcache[i].dbc_blksize = DEFAULT_BLOCKSIZE;
	}
	li->li_dbcache[i].dbc_maxids = (li->li_dbcache[i].dbc_blksize /
	    sizeof(ID)) - ID_BLOCK_IDS_OFFSET;
	li->li_dbcache[i].dbc_maxindirect = (SLAPD_LDBM_MIN_MAXIDS /
	    li->li_dbcache[i].dbc_maxids) + 1;

	Debug( LDAP_DEBUG_ARGS,
	    "bdb2i_cache_open (blksize %ld) (maxids %d) (maxindirect %d)\n",
	    li->li_dbcache[i].dbc_blksize, li->li_dbcache[i].dbc_maxids,
	    li->li_dbcache[i].dbc_maxindirect );
	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_cache_open (opened %d)\n", i, 0, 0 );
	ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
	return( &li->li_dbcache[i] );
}

void
bdb2i_cache_close( BackendDB *be, struct dbcache *db )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	/*  if in slapd, all files stay open and we have only
		readers or one writer  */
	if ( ( slapMode == SLAP_SERVER_MODE ) || ( slapMode == SLAP_TOOL_MODE ) )
			return;

	ldap_pvt_thread_mutex_lock( &li->li_dbcache_mutex );
	if ( --db->dbc_refcnt == 0 ) {
		ldap_pvt_thread_cond_signal( &li->li_dbcache_cv );
	}
	ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
}

void
bdb2i_cache_really_close( BackendDB *be, struct dbcache *db )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	/*  if in slapd, all files stay open and we have only
		readers or one writer  */
	if ( ( slapMode == SLAP_SERVER_MODE ) || ( slapMode == SLAP_TOOL_MODE ) )
			return;

	ldap_pvt_thread_mutex_lock( &li->li_dbcache_mutex );
	if ( --db->dbc_refcnt == 0 ) {
		ldap_pvt_thread_cond_signal( &li->li_dbcache_cv );
		ldbm_close( db->dbc_db );
		free( db->dbc_name );
		db->dbc_name = NULL;
	}
	ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
}

void
bdb2i_cache_flush_all( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int		i;

	/*  if in slapd, syncing is done by TP  */
	if ( ( slapMode == SLAP_SERVER_MODE ) || ( slapMode == SLAP_TOOL_MODE ) )
			return;

	ldap_pvt_thread_mutex_lock( &li->li_dbcache_mutex );
	for ( i = 0; i < MAXDBCACHE; i++ ) {
		if ( li->li_dbcache[i].dbc_name != NULL ) {
			Debug( LDAP_DEBUG_TRACE, "ldbm flushing db (%s)\n",
			    li->li_dbcache[i].dbc_name, 0, 0 );
			ldbm_sync( li->li_dbcache[i].dbc_db );
		}
	}
	ldap_pvt_thread_mutex_unlock( &li->li_dbcache_mutex );
}

Datum
bdb2i_cache_fetch(
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data;

	ldbm_datum_init( data );

	data = ldbm_fetch( db->dbc_db, key );

	return( data );
}

int
bdb2i_cache_store(
    struct dbcache	*db,
    Datum		key,
    Datum		data,
    int			flags
)
{
	int	rc;

#ifdef LDBM_DEBUG
	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): key.dptr=%s, key.dsize=%d\n",
		key.dptr, key.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): key.dptr=0x%08x, data.dptr=0x%0 8x\n",
		key.dptr, data.dptr, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): data.dptr=%s, data.dsize=%d\n",
		data.dptr, data.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): flags=0x%08x\n",
		flags, 0, 0, 0, 0 );
#endif /* LDBM_DEBUG */

	rc = ldbm_store( db->dbc_db, key, data, flags );

	return( rc );
}

int
bdb2i_cache_delete(
    struct dbcache	*db,
    Datum		key
)
{
	int	rc;

	rc = ldbm_delete( db->dbc_db, key );

	return( rc );
}
