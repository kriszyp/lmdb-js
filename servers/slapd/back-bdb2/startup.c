/* startup.c - startup bdb2 backend */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldapconfig.h"
#include "slap.h"
#include "back-bdb2.h"

#include "db.h"

static void remove_old_locks( char *home );


static void
bdb2i_db_errcall( char *prefix, char *message )
{
	Debug( LDAP_DEBUG_ANY, "dbd2_db_errcall(): %s %s", prefix, message, 0 );
}


void
bdb2i_back_startup_internal(
    Backend	*be
)
{
	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;
	DB_ENV           *dbEnv = &li->li_db_env;
	int    envFlags = DB_CREATE | DB_THREAD | DB_INIT_LOCK | DB_INIT_MPOOL;
	int    err      = 0;
	char   *home;
	char   datadir[MAXPATHLEN];
	char   *config[2] = { datadir, NULL };

	/*  if the data directory is not an absolute path, have it relative
        to the current working directory (which should not be configured !)  */
	if ( *li->li_directory != *DEFAULT_DIRSEP ) {
		char   cwd[MAXPATHLEN];

		(void) getcwd( cwd, MAXPATHLEN );
		sprintf( cwd, "%s%s%s", cwd, DEFAULT_DIRSEP, li->li_directory );
		free( li->li_directory );
		li->li_directory = strdup( cwd );

	}

	/*  set the DB home directory to the configured one, or the data dir  */
	if ( li->li_dbhome ) {

		if ( *li->li_dbhome != *DEFAULT_DIRSEP ) {
			char   cwd[MAXPATHLEN];

			(void) getcwd( cwd, MAXPATHLEN );
			sprintf( cwd, "%s%s%s", cwd, DEFAULT_DIRSEP, li->li_dbhome );
			free( li->li_dbhome );
			li->li_dbhome = strdup( cwd );

		}
		home = li->li_dbhome;

	} else {

		home = li->li_directory;

	}

	/*  set the DATA_DIR  */
	sprintf( datadir, "DB_DATA_DIR %s", li->li_directory );

	/*  general initialization of the environment  */
	memset( dbEnv, 0, sizeof( DB_ENV ));
	dbEnv->db_errcall = bdb2i_db_errcall;
	dbEnv->db_errpfx  = "==>";

	/*  initialize the lock subsystem  */
	dbEnv->lk_max     = 0;

	/*  remove old locking tables  */
	remove_old_locks( home );

	/*  initialize the mpool subsystem  */
	dbEnv->mp_size   = (size_t) li->li_dbcachesize;

	/*  now do the db_appinit  */
	if ( ( err = db_appinit( home, config, dbEnv, envFlags )) ) {
		char  error[BUFSIZ];

		if ( err < 0 ) sprintf( error, "%ld\n", (long) err );
		else           sprintf( error, "%s\n", strerror( err ));

		fprintf( stderr,
				"bdb2i_back_startup(): FATAL error in db_appinit() : %s\n",
				error );
	 	exit( 1 );

	}

	bdb2i_with_dbenv = 1;

	/*  if there are more index files, add them to the DB file list  */
	bdb2i_check_additional_attr_index( li );

	/*  now open all DB files  */
	bdb2i_txn_open_files( li );

}


static void
bdb2i_back_shutdown_internal(
    Backend	*be
)
{
	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;
	DB_ENV           *dbEnv = &li->li_db_env;
	int              err;

	/*  close all DB files  */
	bdb2i_txn_close_files( &li->li_txn_head );

	/*  remove old locking tables  */
	dbEnv->db_errpfx  = "bdb2i_back_shutdown(): lock_unlink:";
	if ( ( err = lock_unlink( NULL, 1, dbEnv )) != 0 )
		Debug( LDAP_DEBUG_ANY, "bdb2i_back_shutdown(): lock_unlink: %s\n",
					strerror( err ), 0, 0);

	/*  remove old memory pool  */
	dbEnv->db_errpfx  = "bdb2i_back_shutdown(): memp_unlink:";
	if ( ( err = memp_unlink( NULL, 1, dbEnv )) != 0 )
		Debug( LDAP_DEBUG_ANY, "bdb2i_back_shutdown(): memp_unlink: %s\n",
					strerror( err ), 0, 0);

	(void) db_appexit( &li->li_db_env );

}


void
bdb2_back_startup(
    Backend	*be
)
{
	struct timeval  time1, time2;
	char   *elapsed_time;

	gettimeofday( &time1, NULL );

	bdb2i_back_startup_internal( be );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "START elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}
}


void
bdb2_back_shutdown(
    Backend	*be
)
{
	struct timeval  time1, time2;
	char   *elapsed_time;

	gettimeofday( &time1, NULL );

	bdb2i_back_shutdown_internal( be );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "SHUTDOWN elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}
}


static void
remove_old_locks( char *home )
{
	DB_ENV  dbEnv;
	int     err;

	memset( &dbEnv, 0, sizeof( DB_ENV ));
	dbEnv.db_errcall = stderr;
	dbEnv.db_errpfx  = "remove_old_locks(): db_appinit:";
	dbEnv.lk_max     = 0;

	if ( ( err = db_appinit( home, NULL, &dbEnv, 0 )) != 0 )
		Debug( LDAP_DEBUG_ANY, "remove_old_locks(): db_appinit: %s\n",
					strerror( err ), 0, 0);

	dbEnv.db_errpfx  = "remove_old_locks(): lock_unlink:";
	if ( ( err = lock_unlink( NULL, 1, &dbEnv )) != 0 )
		Debug( LDAP_DEBUG_ANY, "remove_old_locks(): lock_unlink: %s\n",
					strerror( err ), 0, 0);

	dbEnv.db_errpfx  = "remove_old_locks(): db_appexit:";
	if ( ( err = db_appexit( &dbEnv )) != 0 )
		Debug( LDAP_DEBUG_ANY, "remove_old_locks(): db_appexit: %s\n",
					strerror( err ), 0, 0);

}


