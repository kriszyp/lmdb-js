/* id.c - keep track of the next id to be given out */
/* $OpenLDAP$ */

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
	}

	id = li->li_nextid++;

	(void) next_id_write( be, li->li_nextid );

	return( id );
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
	}

	id = li->li_nextid;

	return( id );
}
