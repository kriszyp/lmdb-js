/* startup.c - startup ldbm backend */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldapconfig.h"
#include "slap.h"
#include "back-ldbm.h"

#include "db.h"


void
ldbm_back_startup(
    Backend	*be
)
{
#ifndef HAVE_BERKELEY_DB2

		ldap_pvt_thread_mutex_init( &ldbm_big_mutex );

#else

	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;
	DB_ENV           *dbEnv = &li->li_db_env;
	int    envFlags = DB_CREATE | DB_THREAD;
	int    err      = 0;
	char   *home;

	/*  if the data directory is not an absolute path, have it relative
        to the current working directory (which should not be configured !)  */
	if ( *li->li_directory != *DEFAULT_DIRSEP ) {
		char   cwd[MAXPATHLEN];

		(void) getcwd( cwd, MAXPATHLEN );
		sprintf( cwd, "%s%s%s", cwd, DEFAULT_DIRSEP, li->li_directory );
		free( li->li_directory );
		li->li_directory = strdup( cwd );

	}

	/*  set the DB home directory to the data dir  */
	home = li->li_directory;

	/*  general initialization of the environment  */
	memset( dbEnv, 0, sizeof( DB_ENV ));
	dbEnv->db_errcall = ldbm_db_errcall;
	dbEnv->db_errpfx  = "==>";


	/*  now do the db_appinit  */
	if ( ( err = db_appinit( home, NULL, dbEnv, envFlags )) ) {
		char  error[BUFSIZ];

		if ( err < 0 ) sprintf( error, "%ld\n", (long) err );
		else           sprintf( error, "%s\n", strerror( err ));

		fprintf( stderr,
				"ldbm_back_startup(): FATAL error in db_appinit() : %s\n",
				error );
	 	exit( 1 );

	}

#endif
}


void
ldbm_back_shutdown(
    Backend	*be
)
{
#ifdef HAVE_BERKELEY_DB2

	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;

	(void) db_appexit( &li->li_db_env );

#endif
}


#ifdef HAVE_BERKELEY_DB2

void
ldbm_db_errcall( char *prefix, char *message )
{
	Debug( LDAP_DEBUG_ANY, "ldbm_db_errcall(): %s %s", prefix, message, 0 );
}


#endif  /*  HAVE_BERKELEY_DB2  */

