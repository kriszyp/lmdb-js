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
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	ret = bdb2i_back_db_close_internal( be );

	bdb2i_stop_timing( be->bd_info, time1, "CLOSE", NULL, NULL );

	return( ret );
}


