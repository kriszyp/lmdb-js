/* id.c - keep track of the next id to be given out */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "slap.h"
#include "back-bdb2.h"

/*  reading and writing NEXTID is handled in txn.c  */
#define next_id_read(be)  bdb2i_get_nextid( (be) )
#define next_id_write(be,id)  bdb2i_put_nextid( (be), (id) )


int
bdb2i_next_id_save( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	ID id = bdb2i_next_id_get( be );
	int rc;

	rc = next_id_write( be, id );
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
