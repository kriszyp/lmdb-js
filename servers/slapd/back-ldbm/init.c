/* init.c - initialize ldbm backend */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

void
ldbm_back_init(
    Backend	*be
)
{
	struct ldbminfo	*li;
	char		*argv[ 4 ];
	int		i;

	/* initialize the underlying database system */
	ldbm_initialize();

	/* allocate backend-specific stuff */
	li = (struct ldbminfo *) ch_calloc( 1, sizeof(struct ldbminfo) );

	/* arrange to read nextid later (on first request for it) */
	li->li_nextid = NOID;

#if SLAPD_NEXTID_CHUNK > 1
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
	li->li_nextid_file = DEFAULT_DB_DIRECTORY "/NEXTID";

	/* always index dn, id2children, objectclass (used in some searches) */
	argv[ 0 ] = "dn";
	argv[ 1 ] = "dn";
	argv[ 2 ] = NULL;
	attr_syntax_config( "ldbm dn initialization", 0, 2, argv );
	argv[ 0 ] = "dn";
#ifdef SLAPD_DN_SUBSTRING_INDEX
	/*
	 * this is generally too expensive on larger servers and not
	 * effective on small servers.
	 */
	argv[ 1 ] = ch_strdup( "sub,eq" );
#else
	argv[ 1 ] = ch_strdup( "eq" );
#endif
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm dn initialization", 0, 2, argv, 1 );
	free( argv[ 1 ] );
	argv[ 0 ] = "id2children";
	argv[ 1 ] = "eq";
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm id2children initialization", 0, 2, argv,
	    1 );
	argv[ 0 ] = "objectclass";
	argv[ 1 ] = ch_strdup( "eq" );
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm objectclass initialization", 0, 2, argv,
	    1 );
	free( argv[ 1 ] );

	/* initialize various mutex locks & condition variables */
	ldap_pvt_thread_mutex_init( &li->li_root_mutex );
	ldap_pvt_thread_mutex_init( &li->li_add_mutex );
	ldap_pvt_thread_mutex_init( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_init( &li->li_nextid_mutex );
	ldap_pvt_thread_mutex_init( &li->li_dbcache_mutex );
	ldap_pvt_thread_cond_init( &li->li_dbcache_cv );

	be->be_private = li;
}
