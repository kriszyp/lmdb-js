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

#ifdef SLAPD_CRYPT
	extern pthread_mutex_t crypt_mutex;
#endif /* SLAPD_CRYPT */

	/* allocate backend-specific stuff */
	li = (struct ldbminfo *) ch_calloc( 1, sizeof(struct ldbminfo) );

	/* arrange to read nextid later (on first request for it) */
	li->li_nextid = -1;

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
	attr_index_config( li, "ldbm dn initialization", 0, 3, argv, 1 );
	argv[ 0 ] = "id2children";
	argv[ 1 ] = "eq";
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm id2children initialization", 0, 2, argv,
	    1 );
	argv[ 0 ] = "objectclass";
	argv[ 1 ] = strdup( "pres,eq" );
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm objectclass initialization", 0, 2, argv,
	    1 );
	free( argv[ 1 ] );

	/* initialize various mutex locks & condition variables */
	pthread_mutex_init( &li->li_cache.c_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &li->li_nextid_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &li->li_dbcache_mutex, pthread_mutexattr_default );
#ifdef SLAPD_CRYPT
	pthread_mutex_init( &crypt_mutex, pthread_mutexattr_default );
#endif /* SLAPD_CRYPT */
	pthread_cond_init( &li->li_dbcache_cv, pthread_condattr_default );
	for ( i = 0; i < MAXDBCACHE; i++ ) {
		pthread_mutex_init( &li->li_dbcache[i].dbc_mutex,
		    pthread_mutexattr_default );
		pthread_cond_init( &li->li_dbcache[i].dbc_cv,
		    pthread_condattr_default );
	}

	be->be_private = li;
}
