/* init.c - initialize ldbm backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "external.h"

#if SLAPD_LDBM == SLAPD_MOD_DYNAMIC

int init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "ldbm";
    bi.bi_init = ldbm_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_LDBM */

int
ldbm_back_initialize(
    BackendInfo	*bi
)
{
	static char *controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		LDAP_CONTROL_VALUESRETURNFILTER,
		NULL
	};

	bi->bi_controls = controls;

	bi->bi_flags |= 
		SLAP_BFLAG_INCREMENT |
#ifdef LDBM_SUBENTRIES
		SLAP_BFLAG_SUBENTRIES |
#endif
		SLAP_BFLAG_ALIASES |
		SLAP_BFLAG_REFERRALS;

	bi->bi_open = ldbm_back_open;
	bi->bi_config = NULL;
	bi->bi_close = ldbm_back_close;
	bi->bi_destroy = ldbm_back_destroy;

	bi->bi_db_init = ldbm_back_db_init;
	bi->bi_db_config = ldbm_back_db_config;
	bi->bi_db_open = ldbm_back_db_open;
	bi->bi_db_close = ldbm_back_db_close;
	bi->bi_db_destroy = ldbm_back_db_destroy;

	bi->bi_op_bind = ldbm_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = ldbm_back_search;
	bi->bi_op_compare = ldbm_back_compare;
	bi->bi_op_modify = ldbm_back_modify;
	bi->bi_op_modrdn = ldbm_back_modrdn;
	bi->bi_op_add = ldbm_back_add;
	bi->bi_op_delete = ldbm_back_delete;
	bi->bi_op_abandon = 0;

	bi->bi_extended = ldbm_back_extended;

	bi->bi_entry_release_rw = ldbm_back_entry_release_rw;
	bi->bi_entry_get_rw = ldbm_back_entry_get;
	bi->bi_chk_referrals = ldbm_back_referrals;
	bi->bi_operational = ldbm_back_operational;
	bi->bi_has_subordinates = ldbm_back_hasSubordinates;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = ldbm_tool_entry_open;
	bi->bi_tool_entry_close = ldbm_tool_entry_close;
	bi->bi_tool_entry_first = ldbm_tool_entry_first;
	bi->bi_tool_entry_next = ldbm_tool_entry_next;
	bi->bi_tool_entry_get = ldbm_tool_entry_get;
	bi->bi_tool_entry_put = ldbm_tool_entry_put;
	bi->bi_tool_entry_reindex = ldbm_tool_entry_reindex;
	bi->bi_tool_sync = ldbm_tool_sync;

	bi->bi_tool_dn2id_get = 0;
	bi->bi_tool_id2entry_get = 0;
	bi->bi_tool_entry_modify = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

int
ldbm_back_destroy(
    BackendInfo	*bi
)
{
	return 0;
}

int
ldbm_back_open(
    BackendInfo	*bi
)
{
	int rc;

	/* initialize the underlying database system */
	rc = ldbm_initialize( NULL );
	return rc;
}

int
ldbm_back_close(
    BackendInfo	*bi
)
{
	/* terminate the underlying database system */
	ldbm_shutdown();
	return 0;
}

int
ldbm_back_db_init(
    Backend	*be
)
{
	struct ldbminfo	*li;

	/* allocate backend-database-specific stuff */
	li = (struct ldbminfo *) ch_calloc( 1, sizeof(struct ldbminfo) );

	/* arrange to read nextid later (on first request for it) */
	li->li_nextid = NOID;

	/* default cache size */
	li->li_cache.c_maxsize = DEFAULT_CACHE_SIZE;

	/* default database cache size */
	li->li_dbcachesize = DEFAULT_DBCACHE_SIZE;

	/* default db mode is with locking */ 
	li->li_dblocking = 1;

	/* default db mode is with write synchronization */ 
	li->li_dbwritesync = 1;

	/* default file creation mode */
	li->li_mode = SLAPD_DEFAULT_DB_MODE;

	/* default database directory */
	li->li_directory = ch_strdup( SLAPD_DEFAULT_DB_DIR );

	/* DB_ENV environment pointer for DB3 */
	li->li_dbenv = 0;

	/* envdirok is turned on by ldbm_initialize_env if DB3 */
	li->li_envdirok = 0;

	/* syncfreq is 0 if disabled, or # seconds */
	li->li_dbsyncfreq = 0;

	/* wait up to dbsyncwaitn times if server is busy */
	li->li_dbsyncwaitn = 12;

	/* delay interval */
	li->li_dbsyncwaitinterval = 5;

	/* flag to notify ldbm_cache_sync_daemon to shut down */
	li->li_dbshutdown = 0;

	/* initialize various mutex locks & condition variables */
	ldap_pvt_thread_rdwr_init( &li->li_giant_rwlock );
	ldap_pvt_thread_mutex_init( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_init( &li->li_dbcache_mutex );
	ldap_pvt_thread_cond_init( &li->li_dbcache_cv );

	be->be_private = li;

	return 0;
}

int
ldbm_back_db_open(
    BackendDB	*be
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	li->li_dbenv = ldbm_initialize_env( li->li_directory,
		li->li_dbcachesize, &li->li_envdirok );

	/* sync thread */
	if ( li->li_dbsyncfreq > 0 )
	{
		int rc;
		rc = ldap_pvt_thread_create( &li->li_dbsynctid,
			0, ldbm_cache_sync_daemon, (void*)be );

		if ( rc != 0 )
		{
			Debug(	LDAP_DEBUG_ANY,
				"sync ldap_pvt_thread_create failed (%d)\n", rc, 0, 0 );
			return 1;
		}
	}

	return 0;
}

int
ldbm_back_db_destroy(
    BackendDB	*be
)
{
	/* should free/destroy every in be_private */
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	if (li->li_dbenv)
	    ldbm_shutdown_env(li->li_dbenv);

	free( li->li_directory );
	attr_index_destroy( li->li_attrs );

	ldap_pvt_thread_rdwr_destroy( &li->li_giant_rwlock );
	ldap_pvt_thread_mutex_destroy( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_destroy( &li->li_dbcache_mutex );
	ldap_pvt_thread_cond_destroy( &li->li_dbcache_cv );

	free( be->be_private );
	be->be_private = NULL;

	return 0;
}
