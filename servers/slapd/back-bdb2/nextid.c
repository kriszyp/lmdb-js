/* id.c - keep track of the next id to be given out */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-bdb2.h"

/*  XXX the separate handling of the NEXTID file is in contrast to TP  */
/*  the NEXTID file is beeing opened during database start-up  */
static ID
next_id_read( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	FILE*	fp = head->nextidFP;
	ID  	id;
	char	buf[20];

	/*  set the file pointer to the beginnig of the file  */
	rewind( fp );

	/*  read the nextid  */
	if ( fgets( buf, sizeof(buf), fp ) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		   "next_id_read: could not fgets nextid from \"%s\"\n",
		    li->li_nextid_file, 0, 0 );
		return NOID;
	}

	id = atol( buf );

	if(id < 1) {
		Debug( LDAP_DEBUG_ANY,
			"next_id_read %ld: atol(%s) return non-positive integer\n",
			id, buf, 0 );
		return NOID;
	}

	return id;
}

/*  XXX the separate handling of the NEXTID file is in contrast to TP  */
/*  the NEXTID file is beeing opened during database start-up  */
static int
next_id_write( BackendDB *be, ID id )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	BDB2_TXN_HEAD   *head = &li->li_txn_head;
	FILE*	fp = head->nextidFP;
	char	buf[20];
	int		rc = 0;

	/*  set the file pointer to the beginnig of the file  */
	rewind( fp );

	/*  write the nextid  */
	if ( fprintf( fp, "%ld\n", id ) == EOF ) {
		Debug( LDAP_DEBUG_ANY, "next_id_write(%ld): cannot fprintf\n",
		    id, 0, 0 );
		rc = -1;
	}

	/*  if forced flushing of files is in effect, do so  */
	if( li->li_dbcachewsync && ( fflush( fp ) != 0 )) {
		Debug( LDAP_DEBUG_ANY, "next_id_write %ld: cannot fflush\n",
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

	return( id );
}

void
bdb2i_next_id_return( BackendDB *be, ID id )
{
#ifdef SLAPD_NEXTID_RETURN
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	if ( id != li->li_nextid - 1 ) {
		return;
	}

	li->li_nextid--;

#if !( SLAPD_NEXTID_CHUCK > 1 )
	(void) next_id_write( be, li->li_nextid );
#endif
#endif
}

ID
bdb2i_next_id_get( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID		id;

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

	return( id );
}
