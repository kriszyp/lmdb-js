/* init.c - initialize bdb backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"
#include "external.h"

static struct bdbi_database {
	char *file;
	char *name;
	int type;
	int flags;
} bdbi_databases[BDB_INDICES] = {
	{ "nextid" BDB_SUFFIX, "nextid", DB_BTREE, 0 },
	{ "dn2entry" BDB_SUFFIX, "dn2entry", DB_BTREE, 0 },
	{ "id2entry" BDB_SUFFIX, "id2entry", DB_BTREE, 0 },
};

#if 0
static int
bdb_destroy( BackendInfo *bi )
{
	return 0;
}

static int
bdb_open( BackendInfo *bi )
{
	/* initialize the underlying database system */
	Debug( LDAP_DEBUG_TRACE, "bdb_open: initialize BDB backend\n",
		0, 0, 0 );

	return 0;
}

static int
bdb_close( BackendInfo *bi )
{
	/* terminate the underlying database system */
	return 0;
}
#endif

static int
bdb_db_init( BackendDB *be )
{
	struct bdb_info	*bdb;

	Debug( LDAP_DEBUG_ANY,
		"bdb_db_init: Initializing BDB database\n",
		0, 0, 0 );

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
bdb_db_open( BackendDB *be )
{
	int rc, i;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	u_int32_t flags;

	Debug( LDAP_DEBUG_ARGS,
		"bdb_db_open: %s\n",
		be->be_suffix[0], 0, 0 );

	/* we should check existance of dbenv_home and db_directory */

	rc = db_env_create( &bdb->bi_dbenv, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_open: db_env_create failed: %s (%d)\n",
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

#ifdef BDB_SUBDIRS
	{
		char dir[MAXPATHLEN];
		size_t len = strlen( bdb->bi_dbenv_home );

		strcpy( dir, bdb->bi_dbenv_home );
		strcat( &dir[len], BDB_TMP_SUBDIR );
		
		rc = bdb->bi_dbenv->set_tmp_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_db_open: set_tmp_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}

		strcat( &dir[len], BDB_LG_SUBDIR );

		rc = bdb->bi_dbenv->set_lg_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_db_open: set_lg_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}

		strcat( &dir[len], BDB_DATA_SUBDIR );

		rc = bdb->bi_dbenv->set_data_dir( bdb->bi_dbenv, dir );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_db_open: set_data_dir(%s) failed: %s (%d)\n",
				dir, db_strerror(rc), rc );
			return rc;
		}
	}
#endif

	Debug( LDAP_DEBUG_TRACE,
		"bdb_db_open: dbenv_open(%s)\n",
		bdb->bi_dbenv_home, 0, 0);

	rc = bdb->bi_dbenv->open( bdb->bi_dbenv,
		bdb->bi_dbenv_home,
		flags | bdb->bi_dbenv_xflags,
		bdb->bi_dbenv_mode );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_open: dbenv_open failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	flags = DB_THREAD | DB_CREATE;

	bdb->bi_databases = (struct bdb_db_info **) ch_malloc(
		BDB_INDICES * sizeof(struct bdb_db_info *) );

	/* open (and create) main database */
	for( i = 0; i < BDB_INDICES; i++ ) {
		struct bdb_db_info *db;

		db = (struct bdb_db_info *) ch_calloc(1, sizeof(struct bdb_db_info));

		rc = db_create( &db->bdi_db, bdb->bi_dbenv, 0 );
		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_db_open: db_create(%s) failed: %s (%d)\n",
				bdb->bi_dbenv_home, db_strerror(rc), rc );
			return rc;
		}

		rc = db->bdi_db->open( db->bdi_db,
			bdbi_databases[i].file,
			bdbi_databases[i].name,
			bdbi_databases[i].type,
			bdbi_databases[i].flags | flags,
			bdb->bi_dbenv_mode );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"bdb_db_open: db_open(%s) failed: %s (%d)\n",
				bdb->bi_dbenv_home, db_strerror(rc), rc );
			return rc;
		}

		bdb->bi_databases[i] = db;
	}

	/* <insert> open (and create) index databases */


	return 0;
}

static int
bdb_db_close( BackendDB *be )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	/* force a checkpoint */
	rc = txn_checkpoint( bdb->bi_dbenv, 0, 0, DB_FORCE );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_destroy: txn_checkpoint failed: %s (%d)\n",
			db_strerror(rc), rc, 0 );
		return rc;
	}

	while( bdb->bi_ndatabases-- ) {
		rc = bdb->bi_databases[bdb->bi_ndatabases]->bdi_db->close(
			bdb->bi_databases[bdb->bi_ndatabases]->bdi_db, 0 );
	}

	return 0;
}

static int
bdb_db_destroy( BackendDB *be )
{
	int rc;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;

	/* close db environment */
	rc = bdb->bi_dbenv->close( bdb->bi_dbenv, 0 );
	bdb->bi_dbenv = NULL;
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb_db_destroy: close failed: %s (%d)\n",
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
	bi.bi_init = bdb_initialize;

	backend_add( &bi );
	return 0;
}
#endif /* SLAPD_BDB_DYNAMIC */

int
bdb_initialize(
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

		Debug( LDAP_DEBUG_ANY, "bdb_initialize: %s\n",
			version, 0, 0 );
	}

#if 0
	db_env_set_func_malloc( ch_malloc );
	db_env_set_func_realloc( ch_realloc );
	db_env_set_func_free( ch_free );
#endif
	db_env_set_func_yield( ldap_pvt_thread_yield );

	bi->bi_controls = controls;

	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = bdb_db_init;
	bi->bi_db_config = bdb_db_config;
	bi->bi_db_open = bdb_db_open;
	bi->bi_db_close = bdb_db_close;
	bi->bi_db_destroy = bdb_db_destroy;

	bi->bi_op_add = bdb_add;
	bi->bi_op_bind = bdb_bind;
	bi->bi_op_compare = bdb_compare;
	bi->bi_op_delete = bdb_delete;
	bi->bi_op_modify = bdb_modify;
	bi->bi_op_modrdn = bdb_modrdn;
	bi->bi_op_search = bdb_search;

#if 0
	bi->bi_op_unbind = bdb_unbind;
	bi->bi_op_abandon = bdb_abandon;

	bi->bi_extended = bdb_extended;

	bi->bi_acl_group = bdb_group;
	bi->bi_acl_attribute = bdb_attribute;

#endif
	bi->bi_chk_referrals = bdb_referrals;

	bi->bi_entry_release_rw = 0;

	/*
	 * hooks for slap tools
	 */
	bi->bi_tool_entry_open = bdb_tool_entry_open;
	bi->bi_tool_entry_close = bdb_tool_entry_close;
	bi->bi_tool_entry_first = bdb_tool_entry_next;
	bi->bi_tool_entry_next = bdb_tool_entry_next;
	bi->bi_tool_entry_get = bdb_tool_entry_get;
	bi->bi_tool_entry_put = bdb_tool_entry_put;
	bi->bi_tool_entry_reindex = 0;
	bi->bi_tool_sync = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}
