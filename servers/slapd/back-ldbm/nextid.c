/* id.c - keep track of the next id to be given out */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-ldbm.h"

ID
next_id( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		buf[MAXPATHLEN];
	char		buf2[20];
	FILE		*fp;
	ID		id;

	sprintf( buf, "%s/NEXTID", li->li_directory );

	pthread_mutex_lock( &li->li_nextid_mutex );
	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == -1 ) {
		if ( (fp = fopen( buf, "r" )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			    "next_id %d: could not open \"%s\"\n",
			    li->li_nextid, buf, 0 );
			li->li_nextid = 1;
		} else {
			if ( fgets( buf2, sizeof(buf2), fp ) != NULL ) {
				li->li_nextid = atol( buf2 );
			} else {
				Debug( LDAP_DEBUG_ANY,
			    "next_id %d: could not fgets nextid from \"%s\"\n",
				    li->li_nextid, buf2, 0 );
				li->li_nextid = 1;
			}
			fclose( fp );
		}
	}

	li->li_nextid++;
	if ( (fp = fopen( buf, "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "next_id %d: could not open \"%s\"\n",
		    li->li_nextid, buf, 0 );
	} else {
		if ( fprintf( fp, "%ld\n", li->li_nextid ) == EOF ) {
			Debug( LDAP_DEBUG_ANY, "next_id %d: cannot fprintf\n",
			    li->li_nextid, 0, 0 );
		}
		if( fclose( fp ) != 0 ) {
			Debug( LDAP_DEBUG_ANY, "next_id %d: cannot fclose\n",
			    li->li_nextid, 0, 0 );
		}
	}
	id = li->li_nextid - 1;
	pthread_mutex_unlock( &li->li_nextid_mutex );

	return( id );
}

void
next_id_return( Backend *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		buf[MAXPATHLEN];
	FILE		*fp;

	pthread_mutex_lock( &li->li_nextid_mutex );
	if ( id != li->li_nextid - 1 ) {
		pthread_mutex_unlock( &li->li_nextid_mutex );
		return;
	}

	sprintf( buf, "%s/NEXTID", li->li_directory );

	li->li_nextid--;
	if ( (fp = fopen( buf, "w" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "next_id_return of %d: could not open \"%s\" next id %d\n",
		    id, buf, li->li_nextid );
	} else {
		if ( fprintf( fp, "%ld\n", li->li_nextid ) == EOF ) {
			Debug( LDAP_DEBUG_ANY,
		    "next_id_return of %d: cannot fprintf \"%s\" next id %d\n",
			    id, buf, li->li_nextid );
		}
		if( fclose( fp ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
		    "next_id_return of %d: cannot fclose \"%s\" next id %d\n",
			    id, buf, li->li_nextid );
		}
	}
	pthread_mutex_unlock( &li->li_nextid_mutex );
}

ID
next_id_get( Backend *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	char		buf[MAXPATHLEN];
	char		buf2[20];
	FILE		*fp;
	ID		id;

	sprintf( buf, "%s/NEXTID", li->li_directory );

	pthread_mutex_lock( &li->li_nextid_mutex );
	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == -1 ) {
		if ( (fp = fopen( buf, "r" )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			    "next_id %d: could not open \"%s\"\n",
			    li->li_nextid, buf, 0 );
			li->li_nextid = 1;
		} else {
			if ( fgets( buf2, sizeof(buf2), fp ) != NULL ) {
				li->li_nextid = atol( buf2 );
			} else {
				Debug( LDAP_DEBUG_ANY,
			    "next_id %d: cannot fgets nextid from \"%s\"\n",
				    li->li_nextid, buf2, 0 );
				li->li_nextid = 1;
			}
			fclose( fp );
		}
	}
	id = li->li_nextid;
	pthread_mutex_unlock( &li->li_nextid_mutex );

	return( id );
}
