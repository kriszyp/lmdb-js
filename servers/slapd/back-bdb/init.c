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

#include "back-bdb.h"

static int
bi_back_destroy( BackendInfo *bi )
{
	return 0;
}

static int
bi_back_open( BackendInfo *bi )
{
	/* initialize the underlying database system */
	return 0;
}

static int
bi_back_close( BackendInfo *bi )
{
	/* terminate the underlying database system */
	return 0;
}

static int
bi_back_db_init( Backend *be )
{
	struct bdb_info	*bdb;

	/* allocate backend-database-specific stuff */
	bdb = (struct bdb_info *) ch_calloc( 1, sizeof(struct bdb_info) );

	/* DBEnv parameters */
	bdb->bi_dbenv_home = ch_strdup( BDB_DBENV_HOME );
	bdb->bi_dbenv_xflags = 0;
	bdb->bi_dbenv_mode = DEFAULT_MODE;

	be->be_private = bdb;
	return 0;
}

static int
bi_back_db_open( BackendDB *be )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	u_int32_t flags;
	/* we should check existance of dbenv_home and db_directory */

	rc = db_env_create( &bdb->bi_dbenv, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bi_back_db_open: db_env_create failed: %s (%d)\n",
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

	bdb->bi_dbenv->set_errpfx( bdb->bi_dbenv, be->be_suffix[0] );
	bdb->bi_dbenv->set_errcall( bdb->bi_dbenv, bdb_errcall );

	{
		char dir[MAXPATHLEN];
		size_t len = strlen( bdb->bi_dbenv_home );

		strcpy( dir, bdb->bi_dbenv_home );
		strcat( &dir[len], BDB_TMP_SUBDIR );
		
		rc = bdb->bi_dbenv->set_tmp_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bi_back_db_open: set_tmp_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}

		strcat( &dir[len], BDB_LG_SUBDIR );

		rc = bdb->bi_dbenv->set_lg_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bi_back_db_open: set_lg_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}

		strcat( &dir[len], BDB_DATA_SUBDIR );

		rc = bdb->bi_dbenv->set_data_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bi_back_db_open: set_data_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}
	}

	rc = bdb->bi_dbenv->open( bdb->bi_dbenv,
		bdb->bi_dbenv_home,
		flags | bdb->bi_dbenv_xflags,
		bdb->bi_dbenv_mode );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bi_back_db_open: db_open(%s) failed: %s (%d)\n",
			bdb->bi_dbenv_home, db_strerror(rc), rc );
		return rc;
	}

	/* we now need to open (and create) all database */

	return 0;
}

static int
bi_back_db_destroy( BackendDB *be )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	/* force a checkpoint */
	rc = txn_checkpoint( bdb->bi_dbenv, 0, 0, DB_FORCE );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bi_back_db_destroy: txn_checkpoint failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	/* close db environment */
	rc = bdb->bi_dbenv->close( bdb->bi_dbenv, 0 );
	bdb->bi_dbenv = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bi_back_db_destroy: close failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	return 0;
}

#ifdef SLAPD_BDB_DYNAMIC
int back_bdb_LTX_init_module( int argc, char *argv[] ) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "bdb";
    bi.bi_init = bi_back_initialize;

    backend_add( &bi );
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

		if( major != DB_VERSION_MAJOR ||
			minor != DB_VERSION_MINOR ||
			patch < DB_VERSION_PATCH )
		{
			Debug( LDAP_DEBUG_ANY,
				"bi_back_initialize: version mismatch\n"
				"\texpected: " DB_VERSION_STRING "\n"
				"\tgot: %s \n", version, 0, 0 );
		}

		Debug( LDAP_DEBUG_ANY, "bi_back_initialize: %s\n",
			version, 0, 0 );
	}

	bi->bi_controls = controls;

	bi->bi_open = bi_back_open;
	bi->bi_close = bi_back_close;
	bi->bi_config = 0;
	bi->bi_destroy = bi_back_destroy;

#if 0
	bi->bi_db_init = bi_back_db_init;
	bi->bi_db_config = bi_back_db_config;
	bi->bi_db_open = bi_back_db_open;
	bi->bi_db_close = bi_back_db_close;
	bi->bi_db_destroy = bi_back_db_destroy;

	bi->bi_op_bind = bi_back_bind;
	bi->bi_op_unbind = bi_back_unbind;
	bi->bi_op_search = bi_back_search;
	bi->bi_op_compare = bi_back_compare;
	bi->bi_op_modify = bi_back_modify;
	bi->bi_op_modrdn = bi_back_modrdn;
	bi->bi_op_add = bi_back_add;
	bi->bi_op_delete = bi_back_delete;
	bi->bi_op_abandon = bi_back_abandon;

	bi->bi_extended = bi_back_extended;

	bi->bi_entry_release_rw = bi_back_entry_release_rw;
	bi->bi_acl_group = bi_back_group;
	bi->bi_acl_attribute = bi_back_attribute;
	bi->bi_chk_referrals = bi_back_referrals;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = bi_tool_entry_open;
	bi->bi_tool_entry_close = bi_tool_entry_close;
	bi->bi_tool_entry_first = bi_tool_entry_first;
	bi->bi_tool_entry_next = bi_tool_entry_next;
	bi->bi_tool_entry_get = bi_tool_entry_get;
	bi->bi_tool_entry_put = bi_tool_entry_put;
	bi->bi_tool_entry_reindex = bi_tool_entry_reindex;
	bi->bi_tool_sync = bi_tool_sync;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;
#endif

	return 0;
}
