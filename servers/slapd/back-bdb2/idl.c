/* idl.c - ldap id list handling routines */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

static ID_BLOCK* idl_dup( ID_BLOCK *idl );

/* Allocate an ID_BLOCK with room for nids ids */
ID_BLOCK *
bdb2i_idl_alloc( unsigned int nids )
{
	ID_BLOCK	*new;

	/* nmax + nids + space for the ids */
	new = (ID_BLOCK *) ch_calloc( (ID_BLOCK_IDS_OFFSET + nids), sizeof(ID) );
	ID_BLOCK_NMAX(new) = nids;
	ID_BLOCK_NIDS(new) = 0;

	return( new );
}


/* Allocate an empty ALLIDS ID_BLOCK */
ID_BLOCK	*
bdb2i_idl_allids( BackendDB *be )
{
	ID_BLOCK	*idl;

	idl = bdb2i_idl_alloc( 0 );
	ID_BLOCK_NMAX(idl) = ID_BLOCK_ALLIDS_VALUE;
	ID_BLOCK_NIDS(idl) = bdb2i_next_id_get( be );

	return( idl );
}


/* Free an ID_BLOCK */
void
bdb2i_idl_free( ID_BLOCK *idl )
{
	if ( idl == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"bdb2i_idl_free: called with NULL pointer\n",
			0, 0, 0 );
		return;
	}

	free( (char *) idl );
}


/* Fetch an single ID_BLOCK from the cache */
static ID_BLOCK *
idl_fetch_one(
    BackendDB		*be,
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data;
	ID_BLOCK	*idl;

	ldbm_datum_init( data );

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_fetch_one\n", 0, 0, 0 ); */

	data = bdb2i_cache_fetch( db, key );

	if( data.dptr == NULL ) {
		return NULL;
	}

	idl = idl_dup( (ID_BLOCK *) data.dptr);
	ldbm_datum_free( db->dbc_db, data );

	return( idl );
}


/* Fetch a set of ID_BLOCKs from the cache
 *	if not INDIRECT
 * 		if block return is an ALLIDS block,
 *			return an new ALLIDS block
 * 		otherwise
 *			return block
 *	construct super block from all blocks referenced by INDIRECT block
 *	return super block
 */
ID_BLOCK *
bdb2i_idl_fetch(
    BackendDB		*be,
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data;
	ID_BLOCK	*idl;
	ID_BLOCK	**tmp;
	char	*kstr;
	int	i, nids;

	idl = idl_fetch_one( be, db, key );

	if ( idl == NULL ) { 
		return NULL;
	}

	if ( ID_BLOCK_ALLIDS(idl) ) {
		/* all ids block */
		/* make sure we have the current value of highest id */
		bdb2i_idl_free( idl );
		idl = bdb2i_idl_allids( be );

		return( idl );
	}

	if ( ! ID_BLOCK_INDIRECT( idl ) ) {
		/* regular block */
		return( idl );
	}

	/*
	 * this is an indirect block which points to other blocks.
	 * we need to read in all the blocks it points to and construct
	 * a big id list containing all the ids, which we will return.
	 */

	/* count the number of blocks & allocate space for pointers to them */
	for ( i = 0; !ID_BLOCK_NOID(idl, i); i++ )
		;	/* NULL */
	tmp = (ID_BLOCK **) ch_malloc( (i + 1) * sizeof(ID_BLOCK *) );

	/* read in all the blocks */
	kstr = (char *) ch_malloc( key.dsize + CONT_SIZE );
	nids = 0;
	for ( i = 0; !ID_BLOCK_NOID(idl, i); i++ ) {
		ldbm_datum_init( data );

		sprintf( kstr, "%c%ld%s", CONT_PREFIX,
			ID_BLOCK_ID(idl, i), key.dptr );
		data.dptr = kstr;
		data.dsize = strlen( kstr ) + 1;

		if ( (tmp[i] = idl_fetch_one( be, db, data )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			    "bdb2i_idl_fetch of (%s) returns NULL\n", data.dptr, 0, 0 );
			continue;
		}

		nids += ID_BLOCK_NIDS(tmp[i]);
	}
	tmp[i] = NULL;
	free( kstr );
	bdb2i_idl_free( idl );

	/* allocate space for the big block */
	idl = bdb2i_idl_alloc( nids );
	ID_BLOCK_NIDS(idl) = nids;
	nids = 0;

	/* copy in all the ids from the component blocks */
	for ( i = 0; tmp[i] != NULL; i++ ) {
		if ( tmp[i] == NULL ) {
			continue;
		}

		SAFEMEMCPY(
			(char *) &ID_BLOCK_ID(idl, nids),
			(char *) &ID_BLOCK_ID(tmp[i], 0),
		    ID_BLOCK_NIDS(tmp[i]) * sizeof(ID) );
		nids += ID_BLOCK_NIDS(tmp[i]);

		bdb2i_idl_free( tmp[i] );
	}
	free( (char *) tmp );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_idl_fetch %ld ids (%ld max)\n",
	       ID_BLOCK_NIDS(idl), ID_BLOCK_NMAX(idl), 0 );
	return( idl );
}


/* store a single block */
static int
idl_store(
    BackendDB		*be,
    struct dbcache	*db,
    Datum		key, 
    ID_BLOCK		*idl
)
{
	int	rc, flags;
	Datum	data;
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;

	ldbm_datum_init( data );

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_store\n", 0, 0, 0 ); */

	data.dptr = (char *) idl;
	data.dsize = (ID_BLOCK_IDS_OFFSET + ID_BLOCK_NMAX(idl)) * sizeof(ID);
	
#ifdef LDBM_DEBUG
	Statslog( LDAP_DEBUG_STATS, "<= idl_store(): rc=%d\n",
		rc, 0, 0, 0, 0 );
#endif

	flags = LDBM_REPLACE;
	if( li->li_dbcachewsync ) flags |= LDBM_SYNC;
	rc = bdb2i_cache_store( db, key, data, flags );

	/* Debug( LDAP_DEBUG_TRACE, "<= idl_store %d\n", rc, 0, 0 ); */
	return( rc );
}


/* split the block at id
 *    locate ID greater than or equal to id.
 */
static void
idl_split_block(
    ID_BLOCK	*b,
    ID		id,
    ID_BLOCK	**right,
    ID_BLOCK	**left
)
{
	unsigned int	nr, nl;

	/* find where to split the block *//* XXX linear search XXX */
	for ( nr = 0; nr < ID_BLOCK_NIDS(b) && id > ID_BLOCK_ID(b, nr); nr++ )
		;	/* NULL */

	nl = ID_BLOCK_NIDS(b) - nr;

	*right = bdb2i_idl_alloc( nr == 0 ? 1 : nr );
	*left = bdb2i_idl_alloc( nl + (nr == 0 ? 0 : 1));

	/*
	 * everything before the id being inserted in the first block
	 * unless there is nothing, in which case the id being inserted
	 * goes there.
	 */
	if ( nr == 0 ) {
		ID_BLOCK_NIDS(*right) = 1;
		ID_BLOCK_ID(*right, 0) = id;
	} else {
		SAFEMEMCPY(
			(char *) &ID_BLOCK_ID(*right, 0),
			(char *) &ID_BLOCK_ID(b, 0),
			nr * sizeof(ID) );
		ID_BLOCK_NIDS(*right) = nr;
		ID_BLOCK_ID(*left, 0) = id;
	}

	/* the id being inserted & everything after in the second block */
	SAFEMEMCPY(
		(char *) &ID_BLOCK_ID(*left, (nr == 0 ? 0 : 1)),
	    (char *) &ID_BLOCK_ID(b, nr),
		nl * sizeof(ID) );
	ID_BLOCK_NIDS(*left) = nl + (nr == 0 ? 0 : 1);
}


/*
 * idl_change_first - called when an indirect block's first key has
 * changed, meaning it needs to be stored under a new key, and the
 * header block pointing to it needs updating.
 */
static int
idl_change_first(
    BackendDB		*be,
    struct dbcache	*db,
    Datum		hkey,		/* header block key	*/
    ID_BLOCK		*h,		/* header block 	*/
    int			pos,		/* pos in h to update	*/
    Datum		bkey,		/* data block key	*/
    ID_BLOCK		*b		/* data block 		*/
)
{
	int	rc;

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_change_first\n", 0, 0, 0 ); */

	/* delete old key block */
	if ( (rc = bdb2i_cache_delete( db, bkey )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "bdb2i_db_delete of (%s) returns %d\n", bkey.dptr, rc,
		    0 );
		return( rc );
	}

	/* write block with new key */
	sprintf( bkey.dptr, "%c%ld%s", CONT_PREFIX,
			ID_BLOCK_ID(b, 0), hkey.dptr );
	bkey.dsize = strlen( bkey.dptr ) + 1;
	if ( (rc = idl_store( be, db, bkey, b )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "idl_store of (%s) returns %d\n", bkey.dptr, rc, 0 );
		return( rc );
	}

	/* update + write indirect header block */
	ID_BLOCK_ID(h, pos) = ID_BLOCK_ID(b, 0);
	if ( (rc = idl_store( be, db, hkey, h )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "idl_store of (%s) returns %d\n", hkey.dptr, rc, 0 );
		return( rc );
	}

	return( 0 );
}


int
bdb2i_idl_insert_key(
    BackendDB		*be,
    struct dbcache	*db,
    Datum		key,
    ID			id
)
{
	int	i, j, first, rc;
	ID_BLOCK	*idl, *tmp, *tmp2, *tmp3;
	char	*kstr;
	Datum	k2;

	ldbm_datum_init( k2 );

	if ( (idl = idl_fetch_one( be, db, key )) == NULL ) {
#ifdef LDBM_DEBUG
		Statslog( LDAP_DEBUG_STATS, "=> bdb2i_idl_insert_key(): no key yet\n",
			0, 0, 0, 0, 0 );
#endif

		idl = bdb2i_idl_alloc( 1 );
		ID_BLOCK_ID(idl, ID_BLOCK_NIDS(idl)++) = id;
		rc = idl_store( be, db, key, idl );

		bdb2i_idl_free( idl );
		return( rc );
	}

	if ( ID_BLOCK_ALLIDS( idl ) ) {
		/* ALLIDS */
		bdb2i_idl_free( idl );
		return 0;
	}

	if ( ! ID_BLOCK_INDIRECT( idl ) ) {
		/* regular block */
		switch ( bdb2i_idl_insert( &idl, id, db->dbc_maxids ) ) {
		case 0:		/* id inserted - store the updated block */
		case 1:
			rc = idl_store( be, db, key, idl );
			break;

		case 2:		/* id already there - nothing to do */
			rc = 0;
			break;

		case 3:		/* id not inserted - block must be split */
			/* check threshold for marking this an all-id block */
			if ( db->dbc_maxindirect < 2 ) {
				bdb2i_idl_free( idl );
				idl = bdb2i_idl_allids( be );
				rc = idl_store( be, db, key, idl );
				break;
			}

			idl_split_block( idl, id, &tmp, &tmp2 );
			bdb2i_idl_free( idl );

			/* create the header indirect block */
			idl = bdb2i_idl_alloc( 3 );
			ID_BLOCK_NMAX(idl) = 3;
			ID_BLOCK_NIDS(idl) = ID_BLOCK_INDIRECT_VALUE;
			ID_BLOCK_ID(idl, 0) = ID_BLOCK_ID(tmp, 0);
			ID_BLOCK_ID(idl, 1) = ID_BLOCK_ID(tmp2, 0);
			ID_BLOCK_ID(idl, 2) = NOID;

			/* store it */
			rc = idl_store( be, db, key, idl );

			/* store the first id block */
			kstr = (char *) ch_malloc( key.dsize + CONT_SIZE );
			sprintf( kstr, "%c%ld%s", CONT_PREFIX,
			    ID_BLOCK_ID(tmp, 0), key.dptr );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			rc = idl_store( be, db, k2, tmp );

			/* store the second id block */
			sprintf( kstr, "%c%ld%s", CONT_PREFIX,
			    ID_BLOCK_ID(tmp2, 0), key.dptr );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			rc = idl_store( be, db, k2, tmp2 );

			free( kstr );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
			break;
		}

		bdb2i_idl_free( idl );
		return( rc );
	}

	/*
	 * this is an indirect block which points to other blocks.
	 * we need to read in the block into which the id should be
	 * inserted, then insert the id and store the block.  we might
	 * have to split the block if it is full, which means we also
	 * need to write a new "header" block.
	 */

	/* select the block to try inserting into *//* XXX linear search XXX */
	for ( i = 0; !ID_BLOCK_NOID(idl, i) && id > ID_BLOCK_ID(idl, i); i++ )
		;	/* NULL */
	if ( i != 0 ) {
		i--;
		first = 0;
	} else {
		first = 1;
	}

	/* get the block */
	kstr = (char *) ch_malloc( key.dsize + CONT_SIZE );
	sprintf( kstr, "%c%ld%s", CONT_PREFIX,
		ID_BLOCK_ID(idl, i), key.dptr );
	k2.dptr = kstr;
	k2.dsize = strlen( kstr ) + 1;
	if ( (tmp = idl_fetch_one( be, db, k2 )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "nonexistent continuation block (%s)\n",
		    k2.dptr, 0, 0 );
		free( kstr );
		bdb2i_idl_free( idl );
		return( -1 );
	}

	/* insert the id */
	switch ( bdb2i_idl_insert( &tmp, id, db->dbc_maxids ) ) {
	case 0:		/* id inserted ok */
		if ( (rc = idl_store( be, db, k2, tmp )) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "idl_store of (%s) returns %d\n", k2.dptr, rc, 0 );
		}
		break;

	case 1:		/* id inserted - first id in block has changed */
		/*
		 * key for this block has changed, so we have to
		 * write the block under the new key, delete the
		 * old key block + update and write the indirect
		 * header block.
		 */

		rc = idl_change_first( be, db, key, idl, i, k2, tmp );
		break;

	case 2:		/* id not inserted - already there, do nothing */
		rc = 0;
		break;

	case 3:		/* id not inserted - block is full */
		/*
		 * first, see if it will fit in the next block,
		 * without splitting, unless we're trying to insert
		 * into the beginning of the first block.
		 */

		/* is there a next block? */
		if ( !first && !ID_BLOCK_NOID(idl, i + 1) ) {
			/* read it in */
			sprintf( kstr, "%c%ld%s", CONT_PREFIX,
			    ID_BLOCK_ID(idl, i + 1), key.dptr );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			if ( (tmp2 = idl_fetch_one( be, db, k2 )) == NULL ) {
				Debug( LDAP_DEBUG_ANY,
				    "idl_fetch_one (%s) returns NULL\n",
				    k2.dptr, 0, 0 );
				/* split the original block */
				goto split;
			}

			switch ( (rc = bdb2i_idl_insert( &tmp2, id,
			    db->dbc_maxids )) ) {
			case 1:		/* id inserted first in block */
				rc = idl_change_first( be, db, key, idl,
				    i + 1, k2, tmp2 );
				/* FALL */

			case 2:		/* id already there - how? */
			case 0:		/* id inserted */
				if ( rc == 2 ) {
					Debug( LDAP_DEBUG_ANY,
					    "id %ld already in next block\n",
					    id, 0, 0 );
				}
				free( kstr );
				bdb2i_idl_free( tmp );
				bdb2i_idl_free( tmp2 );
				bdb2i_idl_free( idl );
				return( 0 );

			case 3:		/* split the original block */
				break;
			}

			bdb2i_idl_free( tmp2 );
		}

split:
		/*
		 * must split the block, write both new blocks + update
		 * and write the indirect header block.
		 */

		rc = 0;	/* optimistic */


		/* count how many indirect blocks *//* XXX linear count XXX */
		for ( j = 0; !ID_BLOCK_NOID(idl, j); j++ )
			;	/* NULL */

		/* check it against all-id thresholed */
		if ( j + 1 > db->dbc_maxindirect ) {
			/*
			 * we've passed the all-id threshold, meaning
			 * that this set of blocks should be replaced
			 * by a single "all-id" block.  our job: delete
			 * all the indirect blocks, and replace the header
			 * block by an all-id block.
			 */

			/* delete all indirect blocks */
			for ( j = 0; !ID_BLOCK_NOID(idl, j); j++ ) {
				sprintf( kstr, "%c%ld%s", CONT_PREFIX,
				    ID_BLOCK_ID(idl, j), key.dptr );
				k2.dptr = kstr;
				k2.dsize = strlen( kstr ) + 1;

				rc = bdb2i_cache_delete( db, k2 );
			}

			/* store allid block in place of header block */
			bdb2i_idl_free( idl );
			idl = bdb2i_idl_allids( be );
			rc = idl_store( be, db, key, idl );

			free( kstr );
			bdb2i_idl_free( idl );
			bdb2i_idl_free( tmp );
			return( rc );
		}

		idl_split_block( tmp, id, &tmp2, &tmp3 );
		bdb2i_idl_free( tmp );

		/* create a new updated indirect header block */
		tmp = bdb2i_idl_alloc( ID_BLOCK_NMAX(idl) + 1 );
		ID_BLOCK_NIDS(tmp) = ID_BLOCK_INDIRECT_VALUE;
		/* everything up to the split block */
		SAFEMEMCPY(
			(char *) &ID_BLOCK_ID(tmp, 0),
			(char *) &ID_BLOCK_ID(idl, 0),
		    i * sizeof(ID) );
		/* the two new blocks */
		ID_BLOCK_ID(tmp, i) = ID_BLOCK_ID(tmp2, 0);
		ID_BLOCK_ID(tmp, i + 1) = ID_BLOCK_ID(tmp3, 0);
		/* everything after the split block */
		SAFEMEMCPY(
			(char *) &ID_BLOCK_ID(tmp, i + 2),
			(char *) &ID_BLOCK_ID(idl, i + 1),
		    (ID_BLOCK_NMAX(idl) - i - 1) * sizeof(ID) );

		/* store the header block */
		rc = idl_store( be, db, key, tmp );

		/* store the first id block */
		sprintf( kstr, "%c%ld%s", CONT_PREFIX,
		    ID_BLOCK_ID(tmp2, 0), key.dptr );
		k2.dptr = kstr;
		k2.dsize = strlen( kstr ) + 1;
		rc = idl_store( be, db, k2, tmp2 );

		/* store the second id block */
		sprintf( kstr, "%c%ld%s", CONT_PREFIX,
		    ID_BLOCK_ID(tmp3, 0), key.dptr );
		k2.dptr = kstr;
		k2.dsize = strlen( kstr ) + 1;
		rc = idl_store( be, db, k2, tmp3 );

		bdb2i_idl_free( tmp2 );
		bdb2i_idl_free( tmp3 );
		break;
	}

	free( kstr );
	bdb2i_idl_free( tmp );
	bdb2i_idl_free( idl );
	return( rc );
}


/*
 * bdb2i_idl_insert - insert an id into an id list.
 *
 * returns
 *		0	id inserted
 *		1	id inserted, first id in block has changed
 *		2	id not inserted, already there
 *		3	id not inserted, block must be split
 */
int
bdb2i_idl_insert( ID_BLOCK **idl, ID id, unsigned int maxids )
{
	unsigned int	i;

	if ( ID_BLOCK_ALLIDS( *idl ) ) {
		return( 2 );	/* already there */
	}

	/* is it already there? *//* XXX linear search XXX */
	for ( i = 0; i < ID_BLOCK_NIDS(*idl) && id > ID_BLOCK_ID(*idl, i); i++ ) {
		;	/* NULL */
	}
	if ( i < ID_BLOCK_NIDS(*idl) && ID_BLOCK_ID(*idl, i) == id ) {
		return( 2 );	/* already there */
	}

	/* do we need to make room for it? */
	if ( ID_BLOCK_NIDS(*idl) == ID_BLOCK_NMAX(*idl) ) {
		/* make room or indicate block needs splitting */
		if ( ID_BLOCK_NMAX(*idl) >= maxids ) {
			return( 3 );	/* block needs splitting */
		}

		ID_BLOCK_NMAX(*idl) *= 2;
		if ( ID_BLOCK_NMAX(*idl) > maxids ) {
			ID_BLOCK_NMAX(*idl) = maxids;
		}
		*idl = (ID_BLOCK *) ch_realloc( (char *) *idl,
		    (ID_BLOCK_NMAX(*idl) + ID_BLOCK_IDS_OFFSET) * sizeof(ID) );
	}

	/* make a slot for the new id */
	SAFEMEMCPY( &ID_BLOCK_ID(*idl, i+1), &ID_BLOCK_ID(*idl, i),
	            (ID_BLOCK_NIDS(*idl) - i) * sizeof(ID) );

	ID_BLOCK_ID(*idl, i) = id;
	ID_BLOCK_NIDS(*idl)++;
	(void) memset(
		(char *) &ID_BLOCK_ID((*idl), ID_BLOCK_NIDS(*idl)),
		'\0',
	    (ID_BLOCK_NMAX(*idl) - ID_BLOCK_NIDS(*idl)) * sizeof(ID) );

	return( i == 0 ? 1 : 0 );	/* inserted - first id changed or not */
}


int
bdb2i_idl_delete_key (
	BackendDB         *be,
	struct dbcache  *db,
	Datum           key,
	ID              id
)
{
	Datum  data;
	ID_BLOCK *idl, *tmp;
	unsigned i;
	int j, nids;
	char	*kstr;

	if ( (idl = idl_fetch_one( be, db, key ) ) == NULL )
	{
		/* It wasn't found.  Hmm... */
		return -1;
	}

	if ( ID_BLOCK_ALLIDS( idl ) ) {
		bdb2i_idl_free( idl );
		return 0;
	}

	if ( ! ID_BLOCK_INDIRECT( idl ) ) {
		for ( i=0; i < ID_BLOCK_NIDS(idl); i++ ) {
			if ( ID_BLOCK_ID(idl, i) == id ) {
				if( --ID_BLOCK_NIDS(idl) == 0 ) {
					bdb2i_cache_delete( db, key );

				} else {
					SAFEMEMCPY (
						&ID_BLOCK_ID(idl, i),
						&ID_BLOCK_ID(idl, i+1),
						(ID_BLOCK_NIDS(idl)-i) * sizeof(ID) );

					ID_BLOCK_ID(idl, ID_BLOCK_NIDS(idl)) = NOID;

					idl_store( be, db, key, idl );
				}

				bdb2i_idl_free( idl );
				return 0;
			}
			/*  We didn't find the ID.  Hmmm... */
		}
		bdb2i_idl_free( idl );
		return -1;
	}
	
	/* We have to go through an indirect block and find the ID
	   in the list of IDL's
	   */
	for ( nids = 0; !ID_BLOCK_NOID(idl, nids); nids++ )
		;	/* NULL */
	kstr = (char *) ch_malloc( key.dsize + CONT_SIZE );
	for ( j = 0; !ID_BLOCK_NOID(idl, j); j++ )
	{
		ldbm_datum_init( data );
		sprintf( kstr, "%c%ld%s", CONT_PREFIX, ID_BLOCK_ID(idl, j), key.dptr );
		data.dptr = kstr;
		data.dsize = strlen( kstr ) + 1;

		if ( (tmp = idl_fetch_one( be, db, data )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			    "bdb2i_idl_fetch of (%s) returns NULL\n", data.dptr, 0, 0 );
			continue;
		}
		/*
		   Now try to find the ID in tmp
		*/
		for ( i=0; i < ID_BLOCK_NIDS(tmp); i++ )
		{
			if ( ID_BLOCK_ID(tmp, i) == id )
			{
				SAFEMEMCPY(
					&ID_BLOCK_ID(tmp, i),
					&ID_BLOCK_ID(tmp, i+1),
					(ID_BLOCK_NIDS(tmp)-(i+1)) * sizeof(ID));
				ID_BLOCK_ID(tmp, ID_BLOCK_NIDS(tmp)-1 ) = NOID;
				ID_BLOCK_NIDS(tmp)--;

				if ( ID_BLOCK_NIDS(tmp) ) {
					idl_store ( be, db, data, tmp );

				} else {
					bdb2i_cache_delete( db, data );
					SAFEMEMCPY(
						&ID_BLOCK_ID(idl, j),
						&ID_BLOCK_ID(idl, j+1),
						(nids-(j+1)) * sizeof(ID));
					ID_BLOCK_ID(idl, nids-1) = NOID;
					nids--;
					if ( ! nids )
						bdb2i_cache_delete( db, key );
					else
						idl_store( be, db, key, idl );
				}
				bdb2i_idl_free( tmp );
				free( kstr );
				bdb2i_idl_free( idl );
				return 0;
			}
		}
		bdb2i_idl_free( tmp );
	}
	free( kstr );
	bdb2i_idl_free( idl );
	return -1;
}


/* return a duplicate of a single ID_BLOCK */
static ID_BLOCK *
idl_dup( ID_BLOCK *idl )
{
	ID_BLOCK	*new;

	if ( idl == NULL ) {
		return( NULL );
	}

	new = bdb2i_idl_alloc( ID_BLOCK_NMAX(idl) );
	SAFEMEMCPY(
		(char *) new,
		(char *) idl,
		(ID_BLOCK_NMAX(idl) + ID_BLOCK_IDS_OFFSET) * sizeof(ID) );

	return( new );
}


/* return the smaller ID_BLOCK */
static ID_BLOCK *
idl_min( ID_BLOCK *a, ID_BLOCK *b )
{
	return( ID_BLOCK_NIDS(a) > ID_BLOCK_NIDS(b) ? b : a );
}


/*
 * bdb2i_idl_intersection - return a intersection b
 */
ID_BLOCK *
bdb2i_idl_intersection(
    BackendDB	*be,
    ID_BLOCK	*a,
    ID_BLOCK	*b
)
{
	unsigned int	ai, bi, ni;
	ID_BLOCK		*n;

	if ( a == NULL || b == NULL ) {
		return( NULL );
	}
	if ( ID_BLOCK_ALLIDS( a ) ) {
		return( idl_dup( b ) );
	}
	if ( ID_BLOCK_ALLIDS( b ) ) {
		return( idl_dup( a ) );
	}

	n = idl_dup( idl_min( a, b ) );

	for ( ni = 0, ai = 0, bi = 0; ai < ID_BLOCK_NIDS(a); ai++ ) {
		for ( ;
			bi < ID_BLOCK_NIDS(b) && ID_BLOCK_ID(b, bi) < ID_BLOCK_ID(a, ai);
			bi++ )
		{
			;	/* NULL */
		}

		if ( bi == ID_BLOCK_NIDS(b) ) {
			break;
		}

		if ( ID_BLOCK_ID(b, bi) == ID_BLOCK_ID(a, ai) ) {
			ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai);
		}
	}

	if ( ni == 0 ) {
		bdb2i_idl_free( n );
		return( NULL );
	}
	ID_BLOCK_NIDS(n) = ni;

	return( n );
}


/*
 * bdb2i_idl_union - return a union b
 */
ID_BLOCK *
bdb2i_idl_union(
    BackendDB	*be,
    ID_BLOCK	*a,
    ID_BLOCK	*b
)
{
	unsigned int	ai, bi, ni;
	ID_BLOCK		*n;

	if ( a == NULL ) {
		return( idl_dup( b ) );
	}
	if ( b == NULL ) {
		return( idl_dup( a ) );
	}
	if ( ID_BLOCK_ALLIDS( a ) || ID_BLOCK_ALLIDS( b ) ) {
		return( bdb2i_idl_allids( be ) );
	}

	if ( ID_BLOCK_NIDS(b) < ID_BLOCK_NIDS(a) ) {
		n = a;
		a = b;
		b = n;
	}

	n = bdb2i_idl_alloc( ID_BLOCK_NIDS(a) + ID_BLOCK_NIDS(b) );

	for ( ni = 0, ai = 0, bi = 0;
		ai < ID_BLOCK_NIDS(a) && bi < ID_BLOCK_NIDS(b);
		)
	{
		if ( ID_BLOCK_ID(a, ai) < ID_BLOCK_ID(b, bi) ) {
			ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai++);

		} else if ( ID_BLOCK_ID(b, bi) < ID_BLOCK_ID(a, ai) ) {
			ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(b, bi++);

		} else {
			ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai);
			ai++, bi++;
		}
	}

	for ( ; ai < ID_BLOCK_NIDS(a); ai++ ) {
		ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai);
	}
	for ( ; bi < ID_BLOCK_NIDS(b); bi++ ) {
		ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(b, bi);
	}
	ID_BLOCK_NIDS(n) = ni;

	return( n );
}


/*
 * bdb2i_idl_notin - return a intersection ~b (or a minus b)
 */
ID_BLOCK *
bdb2i_idl_notin(
    BackendDB	*be,
    ID_BLOCK 	*a,
    ID_BLOCK 	*b
)
{
	unsigned int	ni, ai, bi;
	ID_BLOCK		*n;

	if ( a == NULL ) {
		return( NULL );
	}
	if ( b == NULL || ID_BLOCK_ALLIDS( b )) {
		return( idl_dup( a ) );
	}

	if ( ID_BLOCK_ALLIDS( a ) ) {
		n = bdb2i_idl_alloc( SLAPD_LDBM_MIN_MAXIDS );
		ni = 0;

		for ( ai = 1, bi = 0;
			ai < ID_BLOCK_NIDS(a) && ni < ID_BLOCK_NMAX(n) && bi < ID_BLOCK_NMAX(b);
			ai++ )
		{
			if ( ID_BLOCK_ID(b, bi) == ai ) {
				bi++;
			} else {
				ID_BLOCK_ID(n, ni++) = ai;
			}
		}

		for ( ; ai < ID_BLOCK_NIDS(a) && ni < ID_BLOCK_NMAX(n); ai++ ) {
			ID_BLOCK_ID(n, ni++) = ai;
		}

		if ( ni == ID_BLOCK_NMAX(n) ) {
			bdb2i_idl_free( n );
			return( bdb2i_idl_allids( be ) );
		} else {
			ID_BLOCK_NIDS(n) = ni;
			return( n );
		}
	}

	n = idl_dup( a );

	ni = 0;
	for ( ai = 0, bi = 0; ai < ID_BLOCK_NIDS(a); ai++ ) {
		for ( ;
			bi < ID_BLOCK_NIDS(b) && ID_BLOCK_ID(b, bi) < ID_BLOCK_ID(a, ai);
		    bi++ )
		{
			;	/* NULL */
		}

		if ( bi == ID_BLOCK_NIDS(b) ) {
			break;
		}

		if ( ID_BLOCK_ID(b, bi) != ID_BLOCK_ID(a, ai) ) {
			ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai);
		}
	}

	for ( ; ai < ID_BLOCK_NIDS(a); ai++ ) {
		ID_BLOCK_ID(n, ni++) = ID_BLOCK_ID(a, ai);
	}
	ID_BLOCK_NIDS(n) = ni;

	return( n );
}


/*	return the first ID in the block
 *	if ALLIDS block
 *		NIDS > 1 return 1
 *		otherwise return NOID 
 *	otherwise return first ID
 *
 *  cursor is set to 1
 */         
ID
bdb2i_idl_firstid( ID_BLOCK *idl, ID *cursor )
{
	*cursor = 1;

	if ( idl == NULL || ID_BLOCK_NIDS(idl) == 0 ) {
		return( NOID );
	}

	if ( ID_BLOCK_ALLIDS( idl ) ) { 
		return( ID_BLOCK_NIDS(idl) > 1 ? 1 : NOID );
	}

	return( ID_BLOCK_ID(idl, 0) );
}


/*	return next ID after id
 *	if ALLIDS block, cursor is id
 *		increment id
 *		if id < NIDS return id
 *		otherwise NOID.
 *	otherwise cursor is index into block
 *		if index < nids
 *			return id at index then increment
 */ 
ID
bdb2i_idl_nextid( ID_BLOCK *idl, ID *cursor )
{
	if ( ID_BLOCK_ALLIDS( idl ) ) {
		if( ++(*cursor) < ID_BLOCK_NIDS(idl) ) {
			return *cursor;
		} else {
			return NOID;
		}
	}

	if ( *cursor < ID_BLOCK_NIDS(idl) ) {
		return ID_BLOCK_ID(idl, (*cursor)++);
	}
	return NOID;
}
