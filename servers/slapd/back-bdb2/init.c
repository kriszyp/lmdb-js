/* init.c - initialize bdb2 backend */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

#ifdef SLAPD_BDB2_DYNAMIC

int back_bdb2_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, 0, sizeof(bi) );
    bi.bi_type = "bdb2";
    bi.bi_init = bdb2_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_BDB2_DYNAMIC */

static int
bdb2i_back_init_private(
    BackendInfo	*bi
)
{
	struct ldbtype  *bt;

	/*  allocate backend-type-specific stuff */
	bt = (struct ldbtype *) ch_calloc( 1, sizeof(struct ldbtype) );

	bt->lty_dbhome = DEFAULT_DB_HOME;
	bt->lty_mpsize = DEFAULT_DBCACHE_SIZE;

	if ( slapMode & SLAP_TIMED_MODE )
		bt->lty_betiming = 1;

	bi->bi_private = bt;

	return 0;
}


int
bdb2_back_initialize(
    BackendInfo	*bi
)
{
	int  ret;

	bi->bi_open = bdb2_back_open;
	bi->bi_config = bdb2_back_config;
	bi->bi_close = bdb2_back_close;
	bi->bi_destroy = bdb2_back_destroy;

	bi->bi_db_init = bdb2_back_db_init;
	bi->bi_db_config = bdb2_back_db_config;
	bi->bi_db_open = bdb2_back_db_open;
	bi->bi_db_close = bdb2_back_db_close;
	bi->bi_db_destroy = bdb2_back_db_destroy;

	bi->bi_op_bind = bdb2_back_bind;
	bi->bi_op_unbind = bdb2_back_unbind;
	bi->bi_op_search = bdb2_back_search;
	bi->bi_op_compare = bdb2_back_compare;
	bi->bi_op_modify = bdb2_back_modify;
	bi->bi_op_modrdn = bdb2_back_modrdn;
	bi->bi_op_add = bdb2_back_add;
	bi->bi_op_delete = bdb2_back_delete;
	bi->bi_op_abandon = bdb2_back_abandon;

	bi->bi_entry_release_rw = bdb2_back_entry_release_rw;
	bi->bi_acl_group = bdb2_back_group;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = bdb2_tool_entry_open;
	bi->bi_tool_entry_close = bdb2_tool_entry_close;
	bi->bi_tool_entry_first = bdb2_tool_entry_first;
	bi->bi_tool_entry_next = bdb2_tool_entry_next;
	bi->bi_tool_entry_get = bdb2_tool_entry_get;
	bi->bi_tool_entry_put = bdb2_tool_entry_put;
	bi->bi_tool_index_attr = bdb2_tool_index_attr;
	bi->bi_tool_index_change = bdb2_tool_index_change;
	bi->bi_tool_sync = bdb2_tool_sync;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	ret = bdb2i_back_init_private( bi );

	Debug( LDAP_DEBUG_TRACE, "bdb2_back_initialize: done (%d).\n", ret, 0, 0 );

	return( ret );
}

int
bdb2_back_destroy(
    BackendInfo	*bi
)
{
	return 0;
}

int
bdb2_back_open(
    BackendInfo	*bi
)
{
	static int initialized = 0;
	int rc;

	if ( initialized++ ) {

		Debug( LDAP_DEBUG_TRACE,
				"bdb2_back_open: backend already initialized.\n", 0, 0, 0 );
		return 0;

	}

	/* initialize the underlying database system */
	rc = bdb2i_back_startup( bi );

	return rc;
}

int
bdb2_back_close(
    BackendInfo	*bi
)
{
	int  rc;

	/* close the underlying database system */
	rc = bdb2i_back_shutdown( bi );

	return rc;
}

/*  BDB2 changed  */
static int
bdb2i_back_db_init_internal(
    BackendDB	*be
)
{
	struct ldbminfo	*li;
	char		*argv[ 4 ];

	/* allocate backend-database-specific stuff */
	li = (struct ldbminfo *) ch_calloc( 1, sizeof(struct ldbminfo) );

	/* arrange to read nextid later (on first request for it) */
	li->li_nextid = NOID;
#if	SLAPD_NEXTID_CHUNK > 1
	li->li_nextid_wrote = NOID;
#endif

	/* default cache size */
	li->li_cache.c_maxsize = DEFAULT_CACHE_SIZE;

	/* default database cache size */
	li->li_dbcachesize = DEFAULT_DBCACHE_SIZE;

	/* default cache mode is sync on write */
	li->li_dbcachewsync = 1;

	/* default file creation mode */
	li->li_mode = DEFAULT_MODE;

	/* default database directory */
	li->li_directory = DEFAULT_DB_DIRECTORY;

	argv[ 0 ] = "objectclass";
	argv[ 1 ] = "pres,eq";
	argv[ 2 ] = NULL;
	bdb2i_attr_index_config( li, "ldbm objectclass initialization",
		0, 2, argv, 1 );

	/*  initialize the cache mutex */
	ldap_pvt_thread_mutex_init( &li->li_cache.c_mutex );

	/*  initialize the TP file head  */
	if ( bdb2i_txn_head_init( &li->li_txn_head ) != 0 )
		return 1;

	be->be_private = li;

	return 0;
}


int
bdb2_back_db_init(
    BackendDB	*be
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	ret = bdb2i_back_db_init_internal( be );
	bdb2i_stop_timing( be->bd_info, time1, "DB-INIT", NULL, NULL );

	return( ret );
}


int
bdb2_back_db_open(
    BackendDB	*be
)
{
	int  rc;

	rc = bdb2_back_db_startup( be );

	return( rc );
}

int
bdb2_back_db_destroy(
    BackendDB	*be
)
{
	/* should free/destroy every in be_private */
	free( be->be_private );
	be->be_private = NULL;
	return 0;
}


