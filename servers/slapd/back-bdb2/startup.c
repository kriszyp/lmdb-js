/* startup.c - startup/shutdown bdb2 backend */

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


/*  startup/shutdown per backend type  */

static int
bdb2i_back_startup_internal(
    BackendInfo	*bi
)
{
	struct ldbtype  *lty = (struct ldbtype *) bi->bi_private;
	DB_ENV           *dbEnv = lty->lty_dbenv;
	int    envFlags = DB_CREATE | DB_THREAD | DB_INIT_LOCK | DB_INIT_MPOOL;
	int    err      = 0;
	char   *home;

	/*  make sure, dbhome is an absolute path  */
	if ( *lty->lty_dbhome != *DEFAULT_DIRSEP ) {
		char   cwd[MAXPATHLEN];

		(void) getcwd( cwd, MAXPATHLEN );
		sprintf( cwd, "%s%s%s", cwd, DEFAULT_DIRSEP, lty->lty_dbhome );
		free( lty->lty_dbhome );
		lty->lty_dbhome = strdup( cwd );

	}
	home = lty->lty_dbhome;

	/*  general initialization of the environment  */
	memset( dbEnv, 0, sizeof( DB_ENV ));
	dbEnv->db_errcall = bdb2i_db_errcall;
	dbEnv->db_errpfx  = "==>";

	/*  initialize the lock subsystem  */
	dbEnv->lk_max     = 0;

	/*  remove old locking tables  */
	remove_old_locks( home );

	/*  initialize the mpool subsystem  */
	dbEnv->mp_size   = lty->lty_mpsize;

	/*  now do the db_appinit  */
	if ( ( err = db_appinit( home, NULL, dbEnv, envFlags )) ) {
		char  error[BUFSIZ];

		if ( err < 0 ) sprintf( error, "%ld\n", (long) err );
		else           sprintf( error, "%s\n", strerror( err ));

		Debug( LDAP_DEBUG_ANY,
				"bdb2i_back_startup(): FATAL error in db_appinit() : %s\n",
				error, 0, 0 );
	 	return( 1 );

	}

	return 0;
}


static int
bdb2i_back_shutdown_internal(
    BackendInfo	*bi
)
{
	struct ldbtype  *lty = (struct ldbtype *) bi->bi_private;
	DB_ENV           *dbEnv = lty->lty_dbenv;
	int              err;

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

	(void) db_appexit( dbEnv );

	return( 0 );
}


int
bdb2i_back_startup(
    BackendInfo	*bi
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( bi, &time1 );

	ret = bdb2i_back_startup_internal( bi );
	bdb2i_stop_timing( bi, time1, "BE-START", NULL, NULL );

	return( ret );
}


int
bdb2i_back_shutdown(
    BackendInfo	*bi
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( bi, &time1 );

	ret = bdb2i_back_shutdown_internal( bi );
	bdb2i_stop_timing( bi, time1, "BE-SHUTDOWN", NULL, NULL );

	return( ret );
}


/*  startup/shutdown per backend database  */

static int
bdb2i_back_db_startup_internal(
    BackendDB	*be
)
{
	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;

	/*  if the data directory is not an absolute path, have it relative
        to the current working directory (which should not be configured !)  */
	if ( *li->li_directory != *DEFAULT_DIRSEP ) {
		char   cwd[MAXPATHLEN];

		(void) getcwd( cwd, MAXPATHLEN );
		sprintf( cwd, "%s%s%s", cwd, DEFAULT_DIRSEP, li->li_directory );
		free( li->li_directory );
		li->li_directory = strdup( cwd );

	}

	/*  if there are more index files, add them to the DB file list  */
	if ( bdb2i_check_additional_attr_index( li ) != 0 )
		return 1;

	/*  now open all DB files  */
	if ( bdb2i_txn_open_files( li ) != 0 )
		return 1;

	return 0;
}


static int
bdb2i_back_db_shutdown_internal(
    BackendDB	*be
)
{
	return 0;
}


int
bdb2_back_db_startup(
    BackendDB	*be
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->be_private, &time1 );

	ret = bdb2i_back_db_startup_internal( be );
	bdb2i_stop_timing( be->be_private, time1, "DB-START", NULL, NULL );

	return( ret );
}


int
bdb2_back_db_shutdown(
    BackendDB	*be
)
{
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->be_private, &time1 );

	ret = bdb2i_back_db_shutdown_internal( be );
	bdb2i_stop_timing( be->be_private, time1, "DB-SHUTDOWN", NULL, NULL );

	return( ret );
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


