/* close.c - close bdb2 backend database */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

static int
bdb2i_back_db_close_internal( BackendDB *be )
{
	Debug( LDAP_DEBUG_TRACE, "bdb2 backend saving nextid\n", 0, 0, 0 );
	if ( bdb2i_next_id_save( be ) < 0 ) {
		Debug( LDAP_DEBUG_ANY, "bdb2 backend nextid save failed!\n", 0, 0, 0 );
	}

	/*  close all DB files  */
	Debug( LDAP_DEBUG_TRACE, "bdb2 backend closing DB files\n", 0, 0, 0 );
	bdb2i_txn_close_files( be );
	Debug( LDAP_DEBUG_TRACE, "bdb2 backend done closing DB files\n", 0, 0, 0 );

	return 0;
}


int
bdb2_back_db_close( BackendDB *be )
{
	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	ret = bdb2i_back_db_close_internal( be );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "CLOSE elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}

	return( ret );
}


