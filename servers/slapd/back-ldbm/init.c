/* init.c - initialize ldbm backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

#ifdef SLAPD_LDBM_DYNAMIC

int back_ldbm_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, 0, sizeof(bi) );
    bi.bi_type = "ldbm";
    bi.bi_init = ldbm_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_LDBM_DYNAMIC */

int
ldbm_back_initialize(
    BackendInfo	*bi
)
{
	static char *controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
	/*	LDAP_CONTROL_X_CHANGE_PASSWD, */
		NULL
	};

	bi->bi_controls = controls;

	bi->bi_open = ldbm_back_open;
	bi->bi_config = 0;
	bi->bi_close = ldbm_back_close;
	bi->bi_destroy = ldbm_back_destroy;

	bi->bi_db_init = ldbm_back_db_init;
	bi->bi_db_config = ldbm_back_db_config;
	bi->bi_db_open = ldbm_back_db_open;
	bi->bi_db_close = ldbm_back_db_close;
	bi->bi_db_destroy = ldbm_back_db_destroy;

	bi->bi_op_bind = ldbm_back_bind;
	bi->bi_op_unbind = ldbm_back_unbind;
	bi->bi_op_search = ldbm_back_search;
	bi->bi_op_compare = ldbm_back_compare;
	bi->bi_op_modify = ldbm_back_modify;
	bi->bi_op_modrdn = ldbm_back_modrdn;
	bi->bi_op_add = ldbm_back_add;
	bi->bi_op_delete = ldbm_back_delete;
	bi->bi_op_abandon = ldbm_back_abandon;

	bi->bi_extended = ldbm_back_extended;

	bi->bi_entry_release_rw = ldbm_back_entry_release_rw;
	bi->bi_acl_group = ldbm_back_group;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = ldbm_tool_entry_open;
	bi->bi_tool_entry_close = ldbm_tool_entry_close;
	bi->bi_tool_entry_first = ldbm_tool_entry_first;
	bi->bi_tool_entry_next = ldbm_tool_entry_next;
	bi->bi_tool_entry_get = ldbm_tool_entry_get;
	bi->bi_tool_entry_put = ldbm_tool_entry_put;
	bi->bi_tool_index_attr = ldbm_tool_index_attr;
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	bi->bi_tool_index_change = ldbm_tool_index_change;
#endif
	bi->bi_tool_sync = ldbm_tool_sync;

#ifdef HAVE_CYRUS_SASL
	bi->bi_sasl_authorize = 0;
	bi->bi_sasl_getsecret = 0;
	bi->bi_sasl_putsecret = 0;
#endif /* HAVE_CYRUS_SASL */

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
	rc = ldbm_initialize();

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
	li->li_mode = DEFAULT_MODE;

	/* default database directory */
	li->li_directory = ch_strdup( DEFAULT_DB_DIRECTORY );

	/* initialize various mutex locks & condition variables */
	ldap_pvt_thread_mutex_init( &li->li_root_mutex );
	ldap_pvt_thread_mutex_init( &li->li_add_mutex );
	ldap_pvt_thread_mutex_init( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_init( &li->li_nextid_mutex );
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
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		*argv[ 4 ];

	/* allocate backend-database-specific stuff */

	argv[ 0 ] = "objectclass";
	argv[ 1 ] = "eq";
	argv[ 2 ] = NULL;
	attr_index_config( li, "ldbm objectclass initialization",
		0, 2, argv, 1 );

	return 0;
}

int
ldbm_back_db_destroy(
    BackendDB	*be
)
{
	/* should free/destroy every in be_private */
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	free( li->li_directory );
	attr_index_destroy( li->li_attrs );

	ldap_pvt_thread_mutex_destroy( &li->li_root_mutex );
	ldap_pvt_thread_mutex_destroy( &li->li_add_mutex );
	ldap_pvt_thread_mutex_destroy( &li->li_cache.c_mutex );
	ldap_pvt_thread_mutex_destroy( &li->li_nextid_mutex );
	ldap_pvt_thread_mutex_destroy( &li->li_dbcache_mutex );
	ldap_pvt_thread_cond_destroy( &li->li_dbcache_cv );

	free( be->be_private );
	be->be_private = NULL;

	return 0;
}
