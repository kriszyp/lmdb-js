/* txn.c - TP support functions of the bdb2 backend */

#include "txn.h"


int
bdb2i_txn_head_init( BDB2_TXN_HEAD *head )
{
	int             dbFile;
	BDB2_TXN_FILES  **fileNodeH;

	/*  for each fixed DB file allocate a file descriptor node and
        initialize the file's name  */
	fileNodeH = &head->dbFiles;
	for ( dbFile = BDB2_DB_DN_FILE; dbFile <= BDB2_DB_OC_IDX_FILE; dbFile++ ) {

		char fileName[MAXPATHLEN];

		*fileNodeH = (BDB2_TXN_FILES *) ch_calloc( 1, sizeof( BDB2_TXN_FILES ));
		if ( *fileNodeH == NULL ) {

			Debug( LDAP_DEBUG_ANY, "bdb2i_txn_head_init(): out of memory!\n",
					0, 0, 0 );
			return( 1 );

		}

		sprintf( fileName, "%s%s", bdb2i_fixed_filenames[dbFile], BDB2_SUFFIX );
		(*fileNodeH)->dbc_name = strdup( fileName );

		fileNodeH = &(*fileNodeH)->next;

	}

	return 0;
}


static void
bdb2i_init_db_file_cache( struct ldbminfo *li, BDB2_TXN_FILES *fileinfo )
{
	struct stat st;
	char        buf[MAXPATHLEN];

	fileinfo->dbc_refcnt = 1;

	sprintf( buf, "%s%s%s", li->li_directory, DEFAULT_DIRSEP,
					fileinfo->dbc_name );
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
					exit( 1 );
				}
			}

			p->dbc_name = strdup( fileName );

			/*  if requested for, we have to open the DB file  */
			/*  BUT NOT "objectclass", 'cause that's a default index !  */
			if ( open && strcasecmp( fileName, "objectclass" )) {

				/*  re-use filename to get the complete path  */
				sprintf( fileName, "%s%s%s",
							li->li_directory, DEFAULT_DIRSEP, p->dbc_name );

				/*  since we have an mpool, we should not define a cache size */
				p->dbc_db = ldbm_open( fileName, LDBM_WRCREAT, li->li_mode, 0 );

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
bdb2i_open_nextid( struct ldbminfo *li )
{
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	FILE            *fp = NULL;
	char            *file = li->li_nextid_file;

	/*  try to open the file for read and write  */
	if ((( fp = fopen( file, "r+" )) == NULL ) &&
		(( fp = fopen( file, "w+" )) == NULL )) {

			Debug( LDAP_DEBUG_ANY,
				"bdb2i_open_nextid: could not open \"%s\"\n",
				file, 0, 0 );
			return( -1 );

	}

	/*  the file is open for read/write  */
	head->nextidFP = fp;

	return( 0 );
}


/*  open all DB during startup of the backend (necessary due to TP)
	additional files may be opened during slapd life-time due to
	default indexes (must be configured in slapd.conf;
	see bdb2i_txn_attr_config)
*/
int
bdb2i_txn_open_files( struct ldbminfo *li )
{
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	BDB2_TXN_FILES  *dbFile;
	int             rc;

	for ( dbFile = head->dbFiles; dbFile; dbFile = dbFile->next ) {
		char   fileName[MAXPATHLEN];

		sprintf( fileName, "%s%s%s",
					li->li_directory, DEFAULT_DIRSEP, dbFile->dbc_name );

		/*  since we have an mpool, we should not define a cache size */
		dbFile->dbc_db = ldbm_open( fileName, LDBM_WRCREAT, li->li_mode, 0 );

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

	rc = bdb2i_open_nextid( li );

	return rc;
}


/*  close the NEXTID file  */
static void
bdb2i_close_nextid( BDB2_TXN_HEAD *head )
{
	fclose( head->nextidFP );
	head->nextidFP = NULL;
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

	bdb2i_close_nextid( head );

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

		Debug( LDAP_DEBUG_ANY,
	"bdb2i_check_additional_attr_index(): ERROR while opening datadir: %s\n",
				strerror( errno ), 0, 0 );
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


