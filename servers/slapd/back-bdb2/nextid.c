/* id.c - keep track of the next id to be given out */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-bdb2.h"

static ID
next_id_read( BackendDB *be )
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
next_id_write( BackendDB *be, ID id )
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

int
bdb2i_next_id_save( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID id = bdb2i_next_id_get( be );
	int rc = next_id_write( be, id );

	if (rc == 0) {
		li->li_nextid_wrote = id;
	}

	return rc;
}

ID
bdb2i_next_id( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID		id;

	ldap_pvt_thread_mutex_lock( &li->li_nextid_mutex );

	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );

		if ( li->li_nextid == NOID ) {
			li->li_nextid = 1;
		}

#if SLAPD_NEXTID_CHUNK > 1
		li->li_nextid_wrote = li->li_nextid;
#endif
	}

	id = li->li_nextid++;

#if SLAPD_NEXTID_CHUNK > 1
	if ( li->li_nextid > li->li_nextid_wrote ) {
		li->li_nextid_wrote += SLAPD_NEXTID_CHUNK;
		(void) next_id_write( be, li->li_nextid_wrote );
	}
#else
	(void) next_id_write( be, li->li_nextid );
#endif

	ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );
	return( id );
}

void
bdb2i_next_id_return( BackendDB *be, ID id )
{
#ifdef SLAPD_NEXTID_RETURN
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	ldap_pvt_thread_mutex_lock( &li->li_nextid_mutex );

	if ( id != li->li_nextid - 1 ) {
		ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );
		return;
	}

	li->li_nextid--;

#if !( SLAPD_NEXTID_CHUCK > 1 )
	(void) next_id_write( be, li->li_nextid );
#endif

	ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );
#endif
}

ID
bdb2i_next_id_get( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID		id;

	ldap_pvt_thread_mutex_lock( &li->li_nextid_mutex );

	/* first time in here since startup - try to read the nexid */
	if ( li->li_nextid == NOID ) {
		li->li_nextid = next_id_read( be );

		if ( li->li_nextid == NOID ) {
			li->li_nextid = 1;
		}

#if SLAPD_NEXTID_CHUNK > 1
		li->li_nextid_wrote = li->li_nextid;
#endif
	}

	id = li->li_nextid;

	ldap_pvt_thread_mutex_unlock( &li->li_nextid_mutex );

	return( id );
}
