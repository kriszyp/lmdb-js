/* ldbmcache.c - maintain a cache of open bdb2 files */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/stat.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-bdb2.h"

struct dbcache *
bdb2i_cache_open(
    BackendDB	*be,
    char	*name,
    char	*suffix,
    int		flags
)
{
	/*  all files are open, so return handle from file cache  */
	switch ( slapMode & SLAP_MODE ) {

		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
			{
				struct	ldbminfo	*li = (struct ldbminfo *) be->be_private;
				char	buf[MAXPATHLEN];

				/*  use short name  */
				sprintf( buf, "%s%s", name, suffix );
				return( bdb2i_get_db_file_cache( li, buf ));

			}
			break;

		default:
			/*  if not SERVER or TOOL, who else would ask?
				NO ONE, so return error  */

			Debug( LDAP_DEBUG_ANY,
	"bdb2i_cache_open: database user (%d) unknown -- cannot open \"%s%s\".\n",
					slapMode, name, suffix );
			return( NULL );
	}
}

void
bdb2i_cache_close( BackendDB *be, struct dbcache *db )
{
	/*  all files stay open until SERVER or TOOL shut down  */
	switch ( slapMode & SLAP_MODE ) {
		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
			return;

		default:
			/*  if unknown user, complain  */
			Debug( LDAP_DEBUG_ANY,
				"bdb2i_cache_close: database user (%d) unknown -- ignored.\n",
				slapMode, 0, 0 );
			return;
	}
}

void
bdb2i_cache_really_close( BackendDB *be, struct dbcache *db )
{
	/*  all files stay open until SERVER or TOOL shut down  */
	switch ( slapMode & SLAP_MODE ) {
		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
			return;

		default:
			/*  if unknown user, complain  */
			Debug( LDAP_DEBUG_ANY,
		"bdb2i_cache_really_close: database user (%d) unknown -- ignored.\n",
				slapMode, 0, 0 );
			return;
	}
}

void
bdb2i_cache_flush_all( BackendDB *be )
{
	/*  if SERVER or TOOL, syncing is done by TP, or during shutdown  */
	switch ( slapMode & SLAP_MODE ) {

		case SLAP_SERVER_MODE:
		case SLAP_TOOL_MODE:
			return;

		default:
			/*  if unknown user, complain  */
			Debug( LDAP_DEBUG_ANY,
		"bdb2i_cache_flush_all: database user (%d) unknown -- ignored.\n",
				slapMode, 0, 0 );
			return;
	}
}

Datum
bdb2i_cache_fetch(
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data;

	ldbm_datum_init( data );

	data = bdb2i_db_fetch( db->dbc_db, key );

	return( data );
}

int
bdb2i_cache_store(
    struct dbcache	*db,
    Datum		key,
    Datum		data,
    int			flags
)
{
	int	rc;
	struct timeval  time1;

#ifdef LDBM_DEBUG
	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): key.dptr=%s, key.dsize=%d\n",
		key.dptr, key.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): key.dptr=0x%08x, data.dptr=0x%0 8x\n",
		key.dptr, data.dptr, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): data.dptr=%s, data.dsize=%d\n",
		data.dptr, data.dsize, 0, 0, 0 );

	Statslog( LDAP_DEBUG_STATS,
		"=> bdb2i_cache_store(): flags=0x%08x\n",
		flags, 0, 0, 0, 0 );
#endif /* LDBM_DEBUG */

	if ( slapMode & SLAP_TIMED_MODE )
		bdb2i_uncond_start_timing( &time1 );

	rc = bdb2i_db_store( db->dbc_db, key, data, flags );

	if ( slapMode & SLAP_TIMED_MODE ) {
		char buf[BUFSIZ];
		char buf2[BUFSIZ];

		*buf2 = '\0';
		if ( !( strcasecmp( db->dbc_name, "dn.bdb2" )))
			sprintf( buf2, " [%s]", key.dptr );
		sprintf( buf, "ADD-BDB2( %s%s )", db->dbc_name, buf2 );
		bdb2i_uncond_stop_timing( time1, buf,
					NULL, NULL, LDAP_DEBUG_TRACE );
	}

	return( rc );
}

int
bdb2i_cache_delete(
    struct dbcache	*db,
    Datum		key
)
{
	int	rc;

	rc = bdb2i_db_delete( db->dbc_db, key );

	return( rc );
}
