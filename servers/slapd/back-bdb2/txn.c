/* txn.c - TP support functions of the bdb2 backend */
/* $OpenLDAP$ */

#include "portable.h"

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include "txn.h"

/*  default DB files  */
char  *bdb2i_fixed_filenames[] = {
	"id2entry",
	"dn2id",
	"objectclass",
	NULL
};


int
bdb2i_txn_head_init( BDB2_TXN_HEAD *head )
{
	int             dbFile;
	BDB2_TXN_FILES  **fileNodeH;

	/*  for each fixed DB file allocate a file descriptor node and
        initialize the file's name  */
	fileNodeH = &head->dbFiles;

	for ( dbFile = 0; bdb2i_fixed_filenames[dbFile] != NULL; dbFile++ ) {
		char fileName[MAXPATHLEN];

		*fileNodeH = (BDB2_TXN_FILES *) ch_calloc( 1, sizeof( BDB2_TXN_FILES ));

		if ( *fileNodeH == NULL ) {
			Debug( LDAP_DEBUG_ANY, "bdb2i_txn_head_init(): out of memory!\n",
					0, 0, 0 );
			return( 1 );
		}

		sprintf( fileName, "%s" BDB2_SUFFIX, bdb2i_fixed_filenames[dbFile] );
		(*fileNodeH)->dbc_name = ch_strdup( fileName );

		fileNodeH = &(*fileNodeH)->next;

	}

	/*  set defaults for checkpointing  */
	head->txn_log  = BDB2_TXN_CHKP_MAX_LOG;
	head->txn_time = BDB2_TXN_CHKP_MAX_TIME;

	/*  initialize the txn_dirty_mutex  */
	ldap_pvt_thread_mutex_init( &txn_dirty_mutex );

	return 0;
}


static void
bdb2i_init_db_file_cache( struct ldbminfo *li, BDB2_TXN_FILES *fileinfo )
{
	struct stat st;
	char        buf[MAXPATHLEN];

	fileinfo->dbc_refcnt = 1;

	sprintf( buf, "%s" LDAP_DIRSEP "%s",
		li->li_directory, fileinfo->dbc_name );

	if ( stat( buf, &st ) == 0 ) {
		fileinfo->dbc_blksize = st.st_blksize;
	} else {
		fileinfo->dbc_blksize = DEFAULT_BLOCKSIZE;
	}

	fileinfo->dbc_maxids = ( fileinfo->dbc_blksize / sizeof( ID )) -
			ID_BLOCK_IDS_OFFSET;
	fileinfo->dbc_maxindirect = ( SLAPD_LDBM_MIN_MAXIDS /
		fileinfo->dbc_maxids ) + 1;

}


/*  create a DB file cache entry for a specified index attribute
	(if not already done); the function is called during config
	file read for all index'ed attributes; if "default" index with
	a non-none selection is given, this is remembered for run-time
	extension of the list of index files; the function is also
	called before add or modify operations to check for putative
	new "default" index files; at that time, files are also opened
*/
void
bdb2i_txn_attr_config(
	struct ldbminfo  *li,
	char             *attr,
	int              open )
{
	BDB2_TXN_HEAD  *head = &li->li_txn_head;

	/*  the "attribute" 'default' is special  */
	if ( strcasecmp( attr, "default" )) {

		/*  create a new index file node, if the index is not known  already  */
		BDB2_TXN_FILES  **fileNodeH;
		char            fileName[MAXPATHLEN];

		sprintf( fileName, "%s%s", attr,  BDB2_SUFFIX );

		/*  search for the end of the list or a node describing
			the current attribute  */
		for ( fileNodeH = &head->dbFiles;
				( *fileNodeH && strcasecmp( (*fileNodeH)->dbc_name, fileName ));
				fileNodeH = &(*fileNodeH)->next ) {

		}

		/*  unless we have that attribute already...  */
		if ( *fileNodeH == NULL ) {
			BDB2_TXN_FILES *p;

			Debug( LDAP_DEBUG_TRACE,
					"bdb2i_txn_attr_config(): adding node for \"%s\"\n",
					fileName, 0, 0 );

			/*  if we're out of memory, we have to see, how to exit...  */
			if ( ( *fileNodeH = p = (BDB2_TXN_FILES *)
					ch_calloc( 1, sizeof( BDB2_TXN_FILES )) ) == NULL ) {

				Debug( LDAP_DEBUG_ANY,
						"bdb2i_txn_attr_config(): out of memory -- FATAL.\n",
						0, 0, 0 );

				/*  during configuration (no files are opened)
					we can just exit, otherwise we kill ourself and
					hope to shutdown cleanly...  */
				if ( open ) {
					pthread_kill( pthread_self(), LDAP_SIGUSR1 );
				} else {
					exit( EXIT_FAILURE );
				}
			}

			p->dbc_name = ch_strdup( fileName );

			/*  if requested for, we have to open the DB file  */
			/*  BUT NOT "objectclass", 'cause that's a default index !  */
			if ( open && strcasecmp( fileName, "objectclass" )) {

				/*  re-use filename to get the complete path  */
				sprintf( fileName, "%s" LDAP_DIRSEP "%s",
							li->li_directory, p->dbc_name );

				/*  since we have an mpool, we should not define a cache size */
				p->dbc_db = bdb2i_db_open( fileName, DB_TYPE,
									LDBM_WRCREAT, li->li_mode, 0 );

				/*  if the files could not be opened, something is wrong;
					complain  */
				if ( p->dbc_db == NULL ) {

					Debug( LDAP_DEBUG_ANY,
				"bdb2i_txn_open_files(): couldn't open file \"%s\" -- FATAL.\n",
						p->dbc_name, 0, 0 );
					pthread_kill( pthread_self(), LDAP_SIGUSR1 );

				}

				bdb2i_init_db_file_cache( li, p );

				Debug( LDAP_DEBUG_TRACE,
					"bdb2i_txn_attr_config(): NEW INDEX FILE \"%s\"\n",
					p->dbc_name, 0, 0 );

			}
		}

	} else {  /*  it is "attribute" 'default'  */

		head->withDefIDX = BDB2_WITH_DEF_IDX;

	}
}


/*  open the NEXTID file for read/write; if it does not exist,
	create it (access to the file must be preceeded by a rewind)
*/
static int
bdb2i_open_nextid( BackendDB *be )
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	LDBM            db = NULL;
	DB_INFO			dbinfo;
	char            fileName[MAXPATHLEN];

	sprintf( fileName, "%s" LDAP_DIRSEP "%s",
				li->li_directory, NEXTID_NAME );

	/*  try to open the file for read and write  */
	memset( &dbinfo, 0, sizeof( dbinfo ));
	dbinfo.db_pagesize  = DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc    = ldbm_malloc;

	(void) db_open( fileName, DB_RECNO, DB_CREATE | DB_THREAD,
					li->li_mode, &bdb2i_dbEnv, &dbinfo, &db );

	if ( db == NULL ) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_open_nextid: could not open \"%s\"\n",
				NEXTID_NAME, 0, 0 );
			return( -1 );

	}

	/*  the file is open for read/write  */
	head->nextidFile = db;

	return( 0 );
}


/*  open all DB during startup of the backend (necessary due to TP)
	additional files may be opened during slapd life-time due to
	default indexes (must be configured in slapd.conf;
	see bdb2i_txn_attr_config)
	also, set the counter and timer for TP checkpointing
*/
int
bdb2i_txn_open_files( BackendDB *be )
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	BDB2_TXN_FILES  *dbFile;
	int             rc;

	for ( dbFile = head->dbFiles; dbFile; dbFile = dbFile->next ) {
		char   fileName[MAXPATHLEN];

		sprintf( fileName, "%s" LDAP_DIRSEP "%s",
					li->li_directory, dbFile->dbc_name );

		/*  since we have an mpool, we should not define a cache size */
		dbFile->dbc_db = bdb2i_db_open( fileName, DB_TYPE,
							LDBM_WRCREAT, li->li_mode, 0 );

		/*  if the files could not be opened, something is wrong; complain  */
		if ( dbFile->dbc_db == NULL ) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_txn_open_files(): couldn't open file \"%s\" -- FATAL.\n",
				dbFile->dbc_name, 0, 0 );
			return( -1 );

		}

		/*  initialize the file info  */
		bdb2i_init_db_file_cache( li, dbFile );

		Debug( LDAP_DEBUG_TRACE, "bdb2i_txn_open_files(): OPEN INDEX \"%s\"\n",
				dbFile->dbc_name, 0, 0 );

	}

	rc = bdb2i_open_nextid( be );

	txn_max_pending_log  = head->txn_log;
	txn_max_pending_time = head->txn_time;

	return rc;
}


/*  close all DB files during shutdown of the backend  */
void
bdb2i_txn_close_files( BackendDB *be )
{
	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD    *head = &li->li_txn_head;
	BDB2_TXN_FILES   *dbFile;

	for ( dbFile = head->dbFiles; dbFile; dbFile = dbFile->next ) {

		ldbm_close( dbFile->dbc_db );

	}

	if ( head->nextidFile )
		ldbm_close( head->nextidFile );

}


/*  get the db_cache structure associated with a specified
	DB file (replaces the on-the-fly opening of files in cache_open()
*/
BDB2_TXN_FILES *
bdb2i_get_db_file_cache( struct ldbminfo *li, char *name )
{
	BDB2_TXN_HEAD  *head = &li->li_txn_head;
	BDB2_TXN_FILES *dbFile;
	int            dbFileNum;

	Debug( LDAP_DEBUG_TRACE, "bdb2i_get_db_file_cache(): looking for file %s\n",
			name, 0, 0 );

	for ( dbFile = head->dbFiles; dbFile; dbFile = dbFile->next ) {

		/*  we've got it  */
		if ( !strcasecmp( dbFile->dbc_name, name )) return( dbFile );

	}

	Debug( LDAP_DEBUG_ANY,
		"bdb2i_get_db_file_cache(): UPS, could't find \"%s\" \n", name, 0, 0 );

	/*  ups, we couldn't find the file  */
	return( NULL );

}


/*  check for new attribute indexes, that might have been created
    during former runs of slapd  */
/*  this is called during startup of the slapd server  */
int
bdb2i_check_additional_attr_index( struct ldbminfo *li )
{
	DIR            *datadir;
	struct dirent  *file;

	if ( ( datadir = opendir( li->li_directory ) ) == NULL ) {
		int err = errno;

		Debug( LDAP_DEBUG_ANY,
	"bdb2i_check_additional_attr_index(): ERROR while opening datadir: %s\n",
				strerror( err ), 0, 0 );
		return( 1 );

	}

	for ( file = readdir( datadir ); file; file = readdir( datadir )) {
		char  filename[MAXPATHLEN];
		int   namelen;

		strcpy( filename, file->d_name );
		namelen = strlen( filename );

		if ( namelen > strlen( BDB2_SUFFIX )) {

			if ( !strcasecmp( filename + namelen - strlen( BDB2_SUFFIX ),
							BDB2_SUFFIX )) {

				*(filename + namelen - strlen( BDB2_SUFFIX )) = '\0';
				bdb2i_txn_attr_config( li, filename, 0 );

				Debug( LDAP_DEBUG_TRACE, "INDEX FILE: %s\n", filename, 0, 0 );

			}

		}

	}

	closedir( datadir );

	return 0;
}


/*  check for the addition of new attribute indexes during add  */
/*  this is called after startup of the slapd server  */
/*  DON'T WORRY ABOUT ACCESS RIGHTS, THAT MIGHT PREVENT US
	FROM ADDING ATTRIBUTES LATER ON  */
void
bdb2i_check_default_attr_index_add( struct ldbminfo *li, Entry *e )
{
	BDB2_TXN_HEAD  *head = &li->li_txn_head;

	if ( head->withDefIDX == BDB2_WITH_DEF_IDX ) {
		Attribute   *ap;

		for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
			if ( strcasecmp( ap->a_type, "objectclass" ))
				bdb2i_txn_attr_config( li, ap->a_type, 1 );
		}
	}
}


/*  check for the addition of new attribute indexes during modify  */
/*  this is called after startup of the slapd server  */
/*  DON'T WORRY ABOUT ACCESS RIGHTS, THAT MIGHT PREVENT US
	FROM ADDING ATTRIBUTES LATER ON  */
void
bdb2i_check_default_attr_index_mod( struct ldbminfo *li, LDAPModList *modlist )
{
	BDB2_TXN_HEAD  *head = &li->li_txn_head;

	if ( head->withDefIDX == BDB2_WITH_DEF_IDX ) {
		LDAPModList *ml;
		char  *default_attrs[] = { "modifytimestamp", "modifiersname", NULL };
		int   attr;

		for ( ml = modlist; ml != NULL; ml = ml->ml_next ) {
			LDAPMod *mod = &ml->ml_mod;

			if (( mod->mod_op & ~LDAP_MOD_BVALUES ) == LDAP_MOD_ADD )
				if ( strcasecmp( mod->mod_type, "objectclass" ))
					bdb2i_txn_attr_config( li, mod->mod_type, 1 );
		}

		/*  these attributes are default when modifying  */
		for ( attr = 0; default_attrs[attr]; attr++ ) {
			bdb2i_txn_attr_config( li, default_attrs[attr], 1 );
		}
	}
}


/*  get the next ID from the NEXTID file  */
ID
bdb2i_get_nextid( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD	*head = &li->li_txn_head;
	ID				id;
	Datum			key;
	Datum			data;
	db_recno_t		rec = NEXTID_RECNO;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.data = &rec;
	key.size = sizeof( rec );

	data = bdb2i_db_fetch( head->nextidFile, key );
	if ( data.data == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"next_id_read: could not get nextid from \"%s\"\n",
			NEXTID_NAME, 0, 0 );
		return NOID;
	}

	id = atol( data.data );
	ldbm_datum_free( head->nextidFile, data );

	if ( id < 1 ) {
		Debug( LDAP_DEBUG_ANY,
			"next_id_read %ld: return non-positive integer\n",
			id, 0, 0 );
		return NOID;
	}

	return( id );
}


int
bdb2i_put_nextid( BackendDB *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD	*head = &li->li_txn_head;
	int				rc, flags;
	Datum			key;
	Datum			data;
	db_recno_t		rec = NEXTID_RECNO;
	char			buf[20];

	sprintf( buf, "%ld\n", id );

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.data = &rec;
	key.size = sizeof( rec );

	data.data = &buf;
	data.size = sizeof( buf );

	flags = LDBM_REPLACE;
	if (( rc = bdb2i_db_store( head->nextidFile, key, data, flags )) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "next_id_write(%ld): store failed (%d)\n",
			id, rc, 0 );
		return( -1 );
	}

	return( rc );
}


/*  BDB2 backend-private functions of libldbm  */
LDBM
bdb2i_db_open(
	char *name,
	int type,
	int rw,
	int mode,
	int dbcachesize )
{
	LDBM		ret = NULL;
	DB_INFO		dbinfo;

	memset( &dbinfo, 0, sizeof( dbinfo ));
	if ( bdb2i_dbEnv.mp_info == NULL )
		dbinfo.db_cachesize = dbcachesize;
	dbinfo.db_pagesize  = DEFAULT_DB_PAGE_SIZE;
	dbinfo.db_malloc    = ldbm_malloc;

	(void) db_open( name, type, rw, mode, &bdb2i_dbEnv, &dbinfo, &ret );

	return( ret );
}


int
bdb2i_db_store( LDBM ldbm, Datum key, Datum data, int flags )
{
	int     rc;

	rc = (*ldbm->put)( ldbm, txnid, &key, &data, flags );
	rc = (-1 ) * rc;

	if ( txnid != NULL ) {

		/*  if the store was OK, set the dirty flag,
			otherwise set the abort flag  */
		if ( rc == 0 ) {

			txn_dirty = 1;

		} else {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_db_store: transaction failed: aborted.\n",
				0, 0, 0 );
			txn_do_abort = 1;

		}
	}

	return( rc );
}


int
bdb2i_db_delete( LDBM ldbm, Datum key )
{
	int     rc;

	rc = (*ldbm->del)( ldbm, txnid, &key, 0 );
	rc = (-1 ) * rc;

	if ( txnid != NULL ) {

		/*  if the delete was OK, set the dirty flag,
			otherwise set the abort flag  */
		if ( rc == 0 ) {

			txn_dirty = 1;

		} else {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_db_delete: transaction failed: aborted.\n",
				0, 0, 0 );
			txn_do_abort = 1;

		}
	}

	return( rc );
}


Datum
bdb2i_db_fetch( LDBM ldbm, Datum key )
{
	Datum   data;
	int     rc;

	ldbm_datum_init( data );
	data.flags = DB_DBT_MALLOC;

	if ( (rc = (*ldbm->get)( ldbm, txnid, &key, &data, 0 )) != 0 ) {
		if (( txnid != NULL ) && ( rc != DB_NOTFOUND )) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_db_fetch: transaction failed: aborted.\n",
				0, 0, 0 );
			txn_do_abort = 1;

		}
		if ( data.dptr ) free( data.dptr );
		data.dptr = NULL;
		data.dsize = 0;
	}

	return( data );
}


Datum
bdb2i_db_firstkey( LDBM ldbm, DBC **dbch )
{
	Datum	key, data;
	int		rc;
	DBC		*dbci;

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.flags = data.flags = DB_DBT_MALLOC;

#if defined( DB_VERSION_MAJOR ) && defined( DB_VERSION_MINOR ) && \
   DB_VERSION_MAJOR == 2 && DB_VERSION_MINOR < 6

	if ( (*ldbm->cursor)( ldbm, txnid, &dbci ))

#else

	if ( (*ldbm->cursor)( ldbm, txnid, &dbci, 0 ))

#endif
	{
		if ( txnid != NULL ) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_db_firstkey: transaction failed: aborted.\n",
				0, 0, 0 );
			txn_do_abort = 1;

		}
		key.flags = 0;
		return( key );
	} else {
		*dbch = dbci;
		if ( (*dbci->c_get)( dbci, &key, &data, DB_NEXT ) == 0 ) {
			ldbm_datum_free( ldbm, data );
		} else {
			if ( txnid != NULL ) {

				Debug( LDAP_DEBUG_ANY,
					"bdb2i_db_firstkey: transaction failed: aborted.\n",
					0, 0, 0 );
				txn_do_abort = 1;

			}
			ldbm_datum_free( ldbm, key );
			key.flags = 0;
			key.dptr = NULL;
			key.dsize = 0;
		}
	}

	return( key );
}


Datum
bdb2i_db_nextkey( LDBM ldbm, Datum key, DBC *dbcp )
{
	Datum	data;
	int		rc;

	ldbm_datum_init( data );
	ldbm_datum_free( ldbm, key );
	key.flags = data.flags = DB_DBT_MALLOC;

	if ( (*dbcp->c_get)( dbcp, &key, &data, DB_NEXT ) == 0 ) {
		ldbm_datum_free( ldbm, data );
	} else {
		if ( txnid != NULL ) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_db_nextkey: transaction failed: aborted.\n",
				0, 0, 0 );
			txn_do_abort = 1;

		}
		key.flags = 0;
		key.dptr = NULL;
		key.dsize = 0;
	}

	return( key );
}


/*  Transaction control of write access  */
/*  Since these functions are only used by one writer at a time,
	we do not have any concurrency (locking) problem  */

/*  initialize a new transaction  */
int
bdb2i_start_transction( DB_TXNMGR *txmgr )
{
	int		rc;

	txnid        = NULL;
	txn_do_abort = 0;

	if (( rc = txn_begin( txmgr, NULL, &txnid )) != 0 ) {
		int err = errno;
		Debug( LDAP_DEBUG_ANY, "bdb2i_start_transction failed: %d: errno=%s\n",
					rc, strerror( err ), 0 );

		if ( txnid != NULL )
			(void) txn_abort( txnid );
		return( -1 );
	}

	Debug( LDAP_DEBUG_TRACE,
			"bdb2i_start_transaction: transaction started.\n",
			0, 0, 0 );

	return( 0 );
}


/*  finish the transaction  */
int
bdb2i_finish_transaction()
{
	int		rc = 0;

	/*  if transaction was NOT selected, just return  */
	if ( txnid == NULL ) return( 0 );

	/*  if nothing was wrong so far, we can try to commit the transaction  */
	/*  complain, if the commit fails  */
	if (( txn_do_abort == 0 ) && ( txn_commit( txnid )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb2i_finish_transaction: transaction commit failed: aborted.\n",
			0, 0, 0 );
		txn_do_abort = 1;
	}

	/*  if anything went wrong, we have to abort the transaction  */
	if ( txn_do_abort ) {
		Debug( LDAP_DEBUG_ANY,
			"bdb2i_finish_transaction: transaction aborted.\n",
			0, 0, 0 );
		(void) txn_abort( txnid );
		rc = -1;
	} else {
		Debug( LDAP_DEBUG_TRACE,
			"bdb2i_finish_transaction: transaction commited.\n",
			0, 0, 0 );
	}

	/*  XXX do NOT free the txnid memory !!!  */
	txnid        = NULL;
	txn_do_abort = 0;

	return( rc );
}


/*  set a checkpoint
	either forced (during shutdown) or when logsize or time are exceeded
	(is called by reader and writer, so protect txn_dirty)
*/
int
bdb2i_set_txn_checkpoint( DB_TXNMGR *txmgr, int forced )
{
	int   rc = 0;

	/*  set dirty mutex  */
	ldap_pvt_thread_mutex_lock( &txn_dirty_mutex );

	if ( txn_dirty ) {
		int  rc;
		u_int32_t   logsize;
		u_int32_t   mins;
		time_t      now;

		logsize = forced ? (u_int32_t) 0 : txn_max_pending_log;
		mins    = forced ? (u_int32_t) 0 : txn_max_pending_time;

		now = slap_get_time();

		rc = txn_checkpoint( txmgr, logsize, mins );

		/*  if checkpointing was successful, reset txn_dirty  */
		if ( rc == 0 ) {
			DB_TXN_STAT  *statp = NULL;

			/*  check whether the checkpoint was actually written;
				if so, unset the txn_dirty flag  */
			if (( rc = txn_stat( txmgr, &statp, ldbm_malloc )) == 0 ) {

				if ( statp && ( statp->st_time_ckp >= now )) {

					Debug( LDAP_DEBUG_TRACE,
						"bdb2i_set_txn_checkpoint succeded.\n",
						0, 0, 0 );
					txn_dirty = 0;

				}

				if ( statp ) free( statp );

			} else {
				Debug( LDAP_DEBUG_ANY,
						"bdb2i_set_txn_checkpoint: txn_stat failed: %d\n",
						rc, 0, 0 );
			}
		} else {
			Debug( LDAP_DEBUG_ANY, "bdb2i_set_txn_checkpoint failed: %d\n",
					rc, 0, 0 );
		}
	}

	/*  release dirty mutex  */
	ldap_pvt_thread_mutex_unlock( &txn_dirty_mutex );

	return( rc );
}


