/* init.c - initialize bdb2 backend */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"


int
bdb2_back_initialize(
    BackendInfo	*bi
)
{
	bi->bi_open = bdb2_back_open;
	bi->bi_config = NULL;
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

	bi->bi_acl_group = bdb2_back_group;

	return 0;
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
	int rc;

	/* initialize the underlying database system */
	rc = bdb2_initialize();

	return rc;
}

int
bdb2_back_close(
    BackendInfo	*bi
)
{
	/* close the underlying database system */
	bdb2_shutdown();

	return 0;
}

/*  BDB2 changed  */
static int
bdb2i_back_db_init_internal(
    Backend	*be
)
{
	struct ldbminfo	*li;
	char		*argv[ 4 ];
	int		i;

	/* allocate backend-specific stuff */
	li = (struct ldbminfo *) ch_calloc( 1, sizeof(struct ldbminfo) );

	/* arrange to read nextid later (on first request for it) */
	li->li_nextid = NOID;
#if	SLAPD_NEXTID_CHUNCK > 1
	li->li_nextid_wrote = NOID
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

	/* always index dn, id2children, objectclass (used in some searches) */
	argv[ 0 ] = "dn";
	argv[ 1 ] = "dn";
	argv[ 2 ] = NULL;
	attr_syntax_config( "ldbm dn initialization", 0, 2, argv );
	argv[ 0 ] = "dn";
	argv[ 1 ] = "sub";
	argv[ 2 ] = "eq";
	argv[ 3 ] = NULL;
	bdb2i_attr_index_config( li, "ldbm dn initialization", 0, 3, argv, 1 );
	argv[ 0 ] = "id2children";
	argv[ 1 ] = "eq";
	argv[ 2 ] = NULL;
	bdb2i_attr_index_config( li, "ldbm id2children initialization", 0, 2, argv,
	    1 );
	argv[ 0 ] = "objectclass";
	argv[ 1 ] = ch_strdup( "pres,eq" );
	argv[ 2 ] = NULL;
	bdb2i_attr_index_config( li, "ldbm objectclass initialization", 0, 2, argv,
	    1 );
	free( argv[ 1 ] );

	/* initialize various mutex locks & condition variables */
	ldap_pvt_thread_mutex_init( &li->li_root_mutex );
	ldap_pvt_thread_mutex_init( &li->li_add_mutex );
	ldap_pvt_thread_mutex_init( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_init( &li->li_nextid_mutex );
	ldap_pvt_thread_mutex_init( &li->li_dbcache_mutex );
	ldap_pvt_thread_cond_init( &li->li_dbcache_cv );

	/*  initialize the TP file head  */
	bdb2i_txn_head_init( &li->li_txn_head );

	be->be_private = li;

	return 0;
}


int
bdb2_back_db_init(
    Backend	*be
)
{
	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	ret = bdb2i_back_db_init_internal( be );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "INIT elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}

	return( ret );
}


int
bdb2_back_db_open(
    BackendDB	*be
)
{
	return 0;
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


