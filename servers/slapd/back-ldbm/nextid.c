/* id.c - keep track of the next id to be given out */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-ldbm.h"

static ID
next_id_read( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID  	id;
	char	buf[20];
	char*	file = li->li_nextid_file; 
	FILE*	fp;

	if ( (fp = fopen( file, "r" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "next_id_read: could not open \"%s\"\n",
		    file, 0, 0 );
		return NOID;
	}

	if ( fgets( buf, sizeof(buf), fp ) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		   "next_id_read: could not fgets nextid from \"%s\"\n",
		    file, 0, 0 );
		fclose( fp );
		return NOID;
	}

	id = atol( buf );
	fclose( fp );

	if(id < 1) {
		Debug( LDAP_DEBUG_ANY,
			"next_id_read %lu: atol(%s) return non-positive integer\n",
			id, buf, 0 );
		return NOID;
	}

	return id;
}

static int
next_id_write( Backend *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char	buf[20];
	char*	file = li->li_nextid_file; 
	FILE*	fp;
	int		rc;

	if ( (fp = fopen( file, "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "next_id_write(%lu): could not open \"%s\"\n",
		    id, file, 0 );
		return -1;
	} 

	rc = 0;

	if ( fprintf( fp, "%ld\n", id ) == EOF ) {
		Debug( LDAP_DEBUG_ANY, "next_id_write(%lu): cannot fprintf\n",
		    id, 0, 0 );
		rc = -1;
	}

	if( fclose( fp ) != 0 ) {
		Debug( LDAP_DEBUG_ANY, "next_id_write %lu: cannot fclose\n",
		    id, 0, 0 );
		rc = -1;
	}

	return rc;
}

ID
next_id( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID		id;

	pthread_mutex_lock( &li->li_nextid_mutex );

	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );

		if ( li->li_nextid == NOID ) {
			li->li_nextid = 1;
		}
	}

	id = li->li_nextid++;
	(void) next_id_write( be, li->li_nextid );

	pthread_mutex_unlock( &li->li_nextid_mutex );
	return( id );
}

void
next_id_return( Backend *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	pthread_mutex_lock( &li->li_nextid_mutex );

	if ( id != li->li_nextid - 1 ) {
		pthread_mutex_unlock( &li->li_nextid_mutex );
		return;
	}

	li->li_nextid--;
	(void) next_id_write( be, li->li_nextid );

	pthread_mutex_unlock( &li->li_nextid_mutex );
}

ID
next_id_get( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID		id;

	pthread_mutex_lock( &li->li_nextid_mutex );

	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );

		if ( li->li_nextid == NOID ) {
			li->li_nextid = 1;
		}
	}

	id = li->li_nextid;

	pthread_mutex_unlock( &li->li_nextid_mutex );

	return( id );
}
