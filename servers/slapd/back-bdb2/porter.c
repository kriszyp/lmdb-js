/* porter.c - port functions of the bdb2 backend */

#include "portable.h"

#include <stdio.h>
#include <errno.h>

#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"

#define  PORTER_OBJ   "bdb2_backend"


static int
bdb2i_enter_backend( DB_ENV *dbEnv, DB_LOCK *lock, int writer )
{
	u_int32_t      locker;
	db_lockmode_t  lock_type;
	DBT            lock_dbt;
	int            ret;

	if ( ( slapMode != SLAP_SERVER_MODE ) && ( slapMode != SLAP_TOOL_MODE ) )
			return( 0 );

	if ( ( ret = lock_id( dbEnv->lk_info, &locker )) != 0 ) {

		Debug( LDAP_DEBUG_ANY,
				"bdb2i_enter_backend(): unable to get locker id -- %s\n",
				strerror( ret ), 0, 0 );
		return( ret );

	}

	lock_type     = writer ? DB_LOCK_WRITE : DB_LOCK_READ;
	lock_dbt.data = PORTER_OBJ;
	lock_dbt.size = strlen( PORTER_OBJ );

	switch ( ( ret = lock_get( dbEnv->lk_info, locker, 0, &lock_dbt,
					lock_type, lock ))) {

		case 0:
			Debug( LDAP_DEBUG_TRACE, "bdb2i_enter_backend() -- %s lock granted\n",
						writer ? "write" : "read", 0, 0 );
			break;

		case DB_LOCK_NOTGRANTED:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_enter_backend() -- %s lock NOT granted\n",
						writer ? "write" : "read", 0, 0 );
			break;

		case DB_LOCK_DEADLOCK:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_enter_backend() -- %s lock returned DEADLOCK\n",
						writer ? "write" : "read", 0, 0 );
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_enter_backend() -- %s lock returned ERROR: %s\n",
						writer ? "write" : "read", strerror( errno ), 0 );
			ret = errno;
			break;
			
	}

	return( ret );
}


int
bdb2i_enter_backend_r( DB_ENV *dbEnv, DB_LOCK *lock )
{
	return( bdb2i_enter_backend( dbEnv, lock, 0 ));
}


int
bdb2i_enter_backend_w( DB_ENV *dbEnv, DB_LOCK *lock )
{
	return( bdb2i_enter_backend( dbEnv, lock, 1 ));
}


int
bdb2i_leave_backend( DB_ENV *dbEnv, DB_LOCK lock )
{
	int   ret;

	if ( ( slapMode != SLAP_SERVER_MODE ) && ( slapMode != SLAP_TOOL_MODE ) )
			return( 0 );

	switch( ( ret = lock_put( dbEnv->lk_info, lock ))) {

		case 0:
			Debug( LDAP_DEBUG_TRACE, "bdb2i_leave_backend() -- lock released\n",
						0, 0, 0 );
			break;

		case DB_LOCK_NOTHELD:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- lock NOT held\n",
						0, 0, 0 );
			break;

		case DB_LOCK_DEADLOCK:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- lock returned DEADLOCK\n",
						0, 0, 0 );
			break;

		default:
			Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- lock returned ERROR: %s\n",
						strerror( errno ), 0, 0 );
			ret = errno;
			break;
			
	}

	return( ret );

}


