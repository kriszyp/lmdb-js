/* init.c - initialize bdb backend */
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
#include "back-bdb.h"

#ifdef SLAPD_BDB_DYNAMIC

int back_bdb_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "bdb";
    bi.bi_init = bdb_back_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_BDB_DYNAMIC */

int
bdb_back_initialize(
    BackendInfo	*bi
)
{
	static char *controls[] = {
		LDAP_CONTROL_MANAGEDSAIT,
		NULL
	};

	{	/* version check */
		int major, minor, patch;
		char *version = db_version( &major, &minor, &patch );

		if( major != DB_VERSION_MAJOR || minor != DB_VERSION_MINOR ||
			patch < DB_VERSION_PATCH )
		{
			Debug( LDAP_DEBUG_ANY,
				"bdb_back_initialize: version mismatch\n"
				"\texpected: " DB_VERSION_STRING "\n"
				"\tgot: %s \n", version, 0, 0 );
		}

		Debug( LDAP_DEBUG_ANY, "bdb_back_initialize: %s\n",
			version, 0, 0 );
	}

#if 0
	bi->bi_controls = controls;

	bi->bi_open = bdb_back_open;
	bi->bi_config = 0;
	bi->bi_close = bdb_back_close;
	bi->bi_destroy = bdb_back_destroy;

	bi->bi_db_init = bdb_back_db_init;
	bi->bi_db_config = bdb_back_db_config;
	bi->bi_db_open = bdb_back_db_open;
	bi->bi_db_close = bdb_back_db_close;
	bi->bi_db_destroy = bdb_back_db_destroy;

	bi->bi_op_bind = bdb_back_bind;
	bi->bi_op_unbind = bdb_back_unbind;
	bi->bi_op_search = bdb_back_search;
	bi->bi_op_compare = bdb_back_compare;
	bi->bi_op_modify = bdb_back_modify;
	bi->bi_op_modrdn = bdb_back_modrdn;
	bi->bi_op_add = bdb_back_add;
	bi->bi_op_delete = bdb_back_delete;
	bi->bi_op_abandon = bdb_back_abandon;

	bi->bi_extended = bdb_back_extended;

	bi->bi_entry_release_rw = bdb_back_entry_release_rw;
	bi->bi_acl_group = bdb_back_group;
	bi->bi_acl_attribute = bdb_back_attribute;
	bi->bi_chk_referrals = bdb_back_referrals;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = bdb_tool_entry_open;
	bi->bi_tool_entry_close = bdb_tool_entry_close;
	bi->bi_tool_entry_first = bdb_tool_entry_first;
	bi->bi_tool_entry_next = bdb_tool_entry_next;
	bi->bi_tool_entry_get = bdb_tool_entry_get;
	bi->bi_tool_entry_put = bdb_tool_entry_put;
	bi->bi_tool_entry_reindex = bdb_tool_entry_reindex;
	bi->bi_tool_sync = bdb_tool_sync;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;
#endif

	return 0;
}

int
bdb_back_destroy(
    BackendInfo	*bi
)
{
	return 0;
}

int
bdb_back_open(
    BackendInfo	*bi
)
{
	/* initialize the underlying database system */
	return 0;
}

int
bdb_back_close(
    BackendInfo	*bi
)
{
	/* terminate the underlying database system */
	return 0;
}

int
bdb_back_db_init(
    Backend	*be
)
{
	struct bdb_dbinfo	*bdi;

	/* allocate backend-database-specific stuff */
	bdi = (struct bdb_dbinfo *) ch_calloc( 1, sizeof(struct bdb_dbinfo) );

	/* DBEnv parameters */
	bdi->bdi_dbenv_home = ch_strdup( DEFAULT_DBENV_HOME );
	bdi->bdi_dbenv_xflags = 0;
	bdi->bdi_dbenv_mode = DEFAULT_MODE;

	/* default database directories */
	bdi->bdi_db_tmp_dir = ch_strdup( DEFAULT_DB_TMP_DIR );
	bdi->bdi_db_lg_dir = ch_strdup( DEFAULT_DB_LG_DIR );
	bdi->bdi_db_data_dir = ch_strdup( DEFAULT_DB_DATA_DIR );

	be->be_private = bdi;
	return 0;
}

int
bdb_back_db_open(
    BackendDB	*be
)
{
	int rc;
	struct bdb_dbinfo *bdi = (struct bdb_dbinfo *) be->be_private;
	u_int32_t flags;

	/* we should check existance of dbenv_home and db_directory */

	rc = db_env_create( &bdi->bdi_dbenv, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: db_env_create failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	flags = DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_TXN |
		DB_CREATE | DB_RECOVER | DB_THREAD;

#ifdef SLAPD_BDB_PRIVATE
	flags |= DB_PRIVATE;
#else
	flags |= DB_INIT_MPOOL;
#endif

	rc = bdi->bdi_dbenv->set_tmp_dir( bdi->bdi_dbenv,
		bdi->bdi_db_tmp_dir );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: set_tmp_dir(%s) failed: %s (%d)\n",
			bdi->bdi_db_tmp_dir, db_strerror(rc), rc );
		return rc;
	}

	rc = bdi->bdi_dbenv->set_lg_dir( bdi->bdi_dbenv,
		bdi->bdi_db_lg_dir );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: set_lg_dir(%s) failed: %s (%d)\n",
			bdi->bdi_db_lg_dir, db_strerror(rc), rc );
		return rc;
	}

	rc = bdi->bdi_dbenv->set_data_dir( bdi->bdi_dbenv,
		bdi->bdi_db_data_dir );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: set_data_dir(%s) failed: %s (%d)\n",
			bdi->bdi_db_data_dir, db_strerror(rc), rc );
		return rc;
	}

	rc = bdi->bdi_dbenv->open( bdi->bdi_dbenv,
		bdi->bdi_dbenv_home,
		flags | bdi->bdi_dbenv_xflags,
		bdi->bdi_dbenv_mode );

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: db_open(%s) failed: %s (%d)\n",
			bdi->bdi_dbenv_home, db_strerror(rc), rc );
		return rc;
	}

	return 0;
}

int
bdb_back_db_destroy(
    BackendDB	*be
)
{
	int rc;
	struct bdb_dbinfo *bdi = (struct bdb_dbinfo *) be->be_private;

	rc = bdi->bdi_dbenv->close( bdi->bdi_dbenv, 0 );
	bdi->bdi_dbenv = NULL;

	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_back_db_open: db_open failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	return 0;
}
