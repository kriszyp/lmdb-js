/* startup.c - startup ldbm backend */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <direct.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

#ifdef HAVE_DB1_DB_H
#	include <db1/db.h>
#else
#	include <db.h>
#endif

#ifdef HAVE_BERKELEY_DB2

void
ldbm_db_errcall( const char *prefix, const char *message )
{
	Debug( LDAP_DEBUG_ANY, "ldbm_db_errcall(): %s %s", prefix, message, 0 );
}

#endif  /*  HAVE_BERKELEY_DB2  */


void
ldbm_back_startup(
    Backend	*be
)
{
#ifndef HAVE_BERKELEY_DB2
	/* make sure we have one and only one big mutex */
	static int protect = 0;

	if(!protect++) {
		ldap_pvt_thread_mutex_init( &ldbm_big_mutex );
	}

#else
	struct ldbminfo  *li = (struct ldbminfo *) be->be_private;
	DB_ENV           *dbEnv = &li->li_db_env;
	u_int32_t    envFlags = DB_CREATE
#ifdef HAVE_BERKELEY_DB2_DB_THREAD
		| DB_THREAD
#endif
		;
	int    err      = 0;
	char   *home;

	/*  if the data directory is not an absolute path, have it relative
        to the current working directory (which should not be configured !)  */
	if ( *li->li_directory != *LDAP_DIRSEP ) {
		char   cwd[MAXPATHLEN];

		(void) getcwd( cwd, MAXPATHLEN );
		sprintf( cwd, "%s" LDAP_DIRSEP "%s", cwd, li->li_directory );
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
	 	exit( EXIT_FAILURE );

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
