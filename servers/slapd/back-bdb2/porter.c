/* porter.c - port functions of the bdb2 backend */

#include "portable.h"

#include <stdio.h>
#include <errno.h>

#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"

#define  PORTER_OBJ   "bdb2_backend"


int
bdb2i_enter_backend_rw( DB_ENV *dbEnv, DB_LOCK *lock, int writer )
{
	u_int32_t      locker;
	db_lockmode_t  lock_type;
	DBT            lock_dbt;
	int            ret = 0;

	switch ( slapMode ) {

		case SLAP_SERVER_MODE:
		case SLAP_TIMEDSERVER_MODE:
		case SLAP_TOOL_MODE:
		case SLAP_TOOLID_MODE:
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
					Debug( LDAP_DEBUG_TRACE,
						"bdb2i_enter_backend() -- %s lock granted\n",
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
			break;
	}

	/*  if we are a writer and we have the backend lock,
		start transaction control  */
	if ( writer && ( ret == 0 )) {

		ret = bdb2i_start_transction( dbEnv->tx_info );

	}

	return( ret );
}


int
bdb2i_leave_backend_rw( DB_ENV *dbEnv, DB_LOCK lock, int writer )
{
	/*  since one or more error can occure,
		we must have several return codes that are or'ed at the end  */
	int   ret_transaction = 0;
	int   ret_lock        = 0;
	int   ret_chkp        = 0;

	/*  if we are a writer, finish the transaction  */
	if ( writer ) {

		ret_transaction = bdb2i_finish_transaction();

	}

	/*  check whether checkpointing is needed  */
	ret_transaction |= bdb2i_set_txn_checkpoint( dbEnv->tx_info, 0 );

	/*  now release the lock  */
	switch ( slapMode ) {

		case SLAP_SERVER_MODE:
		case SLAP_TIMEDSERVER_MODE:
		case SLAP_TOOL_MODE:
		case SLAP_TOOLID_MODE:
			switch( ( ret_lock = lock_put( dbEnv->lk_info, lock ))) {

				case 0:
					Debug( LDAP_DEBUG_TRACE,
						"bdb2i_leave_backend() -- %s lock released\n",
						writer ? "write" : "read", 0, 0 );
					break;

				case DB_LOCK_NOTHELD:
					Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- %s lock NOT held\n",
						writer ? "write" : "read", 0, 0 );
					break;

				case DB_LOCK_DEADLOCK:
					Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- %s lock returned DEADLOCK\n",
						writer ? "write" : "read", 0, 0 );
					break;

				default:
					Debug( LDAP_DEBUG_ANY,
						"bdb2i_leave_backend() -- %s lock returned ERROR: %s\n",
						writer ? "write" : "read", strerror( errno ), 0 );
					ret_lock = errno;
					break;
			
			}
			break;
	}

	return( ret_transaction | ret_lock );
}


