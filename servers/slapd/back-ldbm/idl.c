/* idl.c - ldap id list handling routines */

#include <stdio.h>
#include <sys/types.h>
#include "slap.h"
#include "ldapconfig.h"
#include "back-ldbm.h"

extern Datum	ldbm_cache_fetch();

IDList *
idl_alloc( int nids )
{
	IDList	*new;

	/* nmax + nids + space for the ids */
	new = (IDList *) ch_calloc( (2 + nids), sizeof(ID) );
	new->b_nmax = nids;
	new->b_nids = 0;

	return( new );
}

IDList	*
idl_allids( Backend *be )
{
	IDList	*idl;

	idl = idl_alloc( 0 );
	idl->b_nmax = ALLIDSBLOCK;
	idl->b_nids = next_id_get( be );

	return( idl );
}

void
idl_free( IDList *idl )
{
	if ( idl == NULL ) {
		return;
	}

	free( (char *) idl );
}

static IDList *
idl_fetch_one(
    Backend		*be,
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data, k2;
	IDList	*idl;
	IDList	**tmp;
	char	*kstr;
	int	i, nids;

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_fetch_one\n", 0, 0, 0 ); */

	data = ldbm_cache_fetch( db, key );

	idl = (IDList *) data.dptr;

	return( idl );
}

IDList *
idl_fetch(
    Backend		*be,
    struct dbcache	*db,
    Datum		key
)
{
	Datum	data, k2;
	IDList	*idl;
	IDList	**tmp;
	char	*kstr;
	int	i, nids;

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_fetch\n", 0, 0, 0 ); */

	data = ldbm_cache_fetch( db, key );

	if ( (idl = (IDList *) data.dptr) == NULL ) {
		return( NULL );
	}

	/* regular block */
	if ( ! INDIRECT_BLOCK( idl ) ) {
		/*
		Debug( LDAP_DEBUG_TRACE, "<= idl_fetch %d ids (%d max)\n",
		    idl->b_nids, idl->b_nmax, 0 );
		*/

		/* make sure we have the current value of highest id */
		if ( idl->b_nmax == ALLIDSBLOCK ) {
			idl_free( idl );
			idl = idl_allids( be );
		}
		return( idl );
	}

	/*
	 * this is an indirect block which points to other blocks.
	 * we need to read in all the blocks it points to and construct
	 * a big id list containing all the ids, which we will return.
	 */

	/* count the number of blocks & allocate space for pointers to them */
	for ( i = 0; idl->b_ids[i] != NOID; i++ )
		;	/* NULL */
	tmp = (IDList **) ch_malloc( (i + 1) * sizeof(IDList *) );

	/* read in all the blocks */
	kstr = (char *) ch_malloc( key.dsize + 20 );
	nids = 0;
	for ( i = 0; idl->b_ids[i] != NOID; i++ ) {
		sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr, idl->b_ids[i] );
		k2.dptr = kstr;
		k2.dsize = strlen( kstr ) + 1;

		if ( (tmp[i] = idl_fetch_one( be, db, k2 )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
			    "idl_fetch of (%s) returns NULL\n", k2.dptr, 0, 0 );
			continue;
		}

		nids += tmp[i]->b_nids;
	}
	tmp[i] = NULL;
	idl_free( idl );

	/* allocate space for the big block */
	idl = idl_alloc( nids );
	idl->b_nids = nids;
	nids = 0;

	/* copy in all the ids from the component blocks */
	for ( i = 0; tmp[i] != NULL; i++ ) {
		if ( tmp[i] == NULL ) {
			continue;
		}

		SAFEMEMCPY( (char *) &idl->b_ids[nids], (char *) tmp[i]->b_ids,
		    tmp[i]->b_nids * sizeof(ID) );
		nids += tmp[i]->b_nids;

		idl_free( tmp[i] );
	}
	free( (char *) tmp );

	Debug( LDAP_DEBUG_TRACE, "<= idl_fetch %d ids (%d max)\n", idl->b_nids,
	    idl->b_nmax, 0 );
	return( idl );
}

static int
idl_store(
    Backend		*be,
    struct dbcache	*db,
    Datum		key, 
    IDList		*idl
)
{
	int	rc, flags;
	Datum	data;
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_store\n", 0, 0, 0 ); */

	data.dptr = (char *) idl;
	data.dsize = (2 + idl->b_nmax) * sizeof(ID);
	
	flags = LDBM_REPLACE;
	if( li->li_flush_wrt ) flags |= LDBM_SYNC;
	rc = ldbm_cache_store( db, key, data, flags );

	/* Debug( LDAP_DEBUG_TRACE, "<= idl_store %d\n", rc, 0, 0 ); */
	return( rc );
}

static void
idl_split_block(
    IDList	*b,
    ID		id,
    IDList	**n1,
    IDList	**n2
)
{
	int	i;

	/* find where to split the block */
	for ( i = 0; i < b->b_nids && id > b->b_ids[i]; i++ )
		;	/* NULL */

	*n1 = idl_alloc( i == 0 ? 1 : i );
	*n2 = idl_alloc( b->b_nids - i + (i == 0 ? 0 : 1));

	/*
	 * everything before the id being inserted in the first block
	 * unless there is nothing, in which case the id being inserted
	 * goes there.
	 */
	SAFEMEMCPY( (char *) &(*n1)->b_ids[0], (char *) &b->b_ids[0],
	    i * sizeof(ID) );
	(*n1)->b_nids = (i == 0 ? 1 : i);

	if ( i == 0 ) {
		(*n1)->b_ids[0] = id;
	} else {
		(*n2)->b_ids[0] = id;
	}

	/* the id being inserted & everything after in the second block */
	SAFEMEMCPY( (char *) &(*n2)->b_ids[i == 0 ? 0 : 1],
	    (char *) &b->b_ids[i], (b->b_nids - i) * sizeof(ID) );
	(*n2)->b_nids = b->b_nids - i + (i == 0 ? 0 : 1);
}

/*
 * idl_change_first - called when an indirect block's first key has
 * changed, meaning it needs to be stored under a new key, and the
 * header block pointing to it needs updating.
 */

static int
idl_change_first(
    Backend		*be,
    struct dbcache	*db,
    Datum		hkey,		/* header block key	*/
    IDList		*h,		/* header block 	*/
    int			pos,		/* pos in h to update	*/
    Datum		bkey,		/* data block key	*/
    IDList		*b		/* data block 		*/
)
{
	int	rc;

	/* Debug( LDAP_DEBUG_TRACE, "=> idl_change_first\n", 0, 0, 0 ); */

	/* delete old key block */
	if ( (rc = ldbm_cache_delete( db, bkey )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "ldbm_delete of (%s) returns %d\n", bkey.dptr, rc,
		    0 );
		return( rc );
	}

	/* write block with new key */
	sprintf( bkey.dptr, "%c%s%d", CONT_PREFIX, hkey.dptr, b->b_ids[0] );
	bkey.dsize = strlen( bkey.dptr ) + 1;
	if ( (rc = idl_store( be, db, bkey, b )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "idl_store of (%s) returns %d\n", bkey.dptr, rc, 0 );
		return( rc );
	}

	/* update + write indirect header block */
	h->b_ids[pos] = b->b_ids[0];
	if ( (rc = idl_store( be, db, hkey, h )) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "idl_store of (%s) returns %d\n", hkey.dptr, rc, 0 );
		return( rc );
	}

	return( 0 );
}

int
idl_insert_key(
    Backend		*be,
    struct dbcache	*db,
    Datum		key,
    ID			id
)
{
	int	i, j, first, rc;
	IDList	*idl, *tmp, *tmp2, *tmp3;
	char	*kstr;
	Datum	k2;

	if ( (idl = idl_fetch_one( be, db, key )) == NULL ) {
		idl = idl_alloc( 1 );
		idl->b_ids[idl->b_nids++] = id;
		rc = idl_store( be, db, key, idl );

		idl_free( idl );
		return( rc );
	}

	/* regular block */
	if ( ! INDIRECT_BLOCK( idl ) ) {
		switch ( idl_insert( &idl, id, db->dbc_maxids ) ) {
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
				idl_free( idl );
				idl = idl_allids( be );
				rc = idl_store( be, db, key, idl );
				idl_free( idl );

				return( rc );
			}

			idl_split_block( idl, id, &tmp, &tmp2 );
			idl_free( idl );

			/* create the header indirect block */
			idl = idl_alloc( 3 );
			idl->b_nmax = 3;
			idl->b_nids = INDBLOCK;
			idl->b_ids[0] = tmp->b_ids[0];
			idl->b_ids[1] = tmp2->b_ids[0];
			idl->b_ids[2] = NOID;

			/* store it */
			rc = idl_store( be, db, key, idl );

			/* store the first id block */
			kstr = (char *) ch_malloc( key.dsize + 20 );
			sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
			    tmp->b_ids[0] );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			rc = idl_store( be, db, k2, tmp );

			/* store the second id block */
			sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
			    tmp2->b_ids[0] );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			rc = idl_store( be, db, k2, tmp2 );

			free( kstr );
			idl_free( tmp );
			idl_free( tmp2 );
			break;
		}

		idl_free( idl );
		return( rc );
	}

	/*
	 * this is an indirect block which points to other blocks.
	 * we need to read in the block into which the id should be
	 * inserted, then insert the id and store the block.  we might
	 * have to split the block if it is full, which means we also
	 * need to write a new "header" block.
	 */

	/* select the block to try inserting into */
	for ( i = 0; idl->b_ids[i] != NOID && id > idl->b_ids[i]; i++ )
		;	/* NULL */
	if ( i != 0 ) {
		i--;
		first = 0;
	} else {
		first = 1;
	}

	/* get the block */
	kstr = (char *) ch_malloc( key.dsize + 20 );
	sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr, idl->b_ids[i] );
	k2.dptr = kstr;
	k2.dsize = strlen( kstr ) + 1;
	if ( (tmp = idl_fetch_one( be, db, k2 )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "nonexistent continuation block (%s)\n",
		    k2.dptr, 0, 0 );
		return( -1 );
	}

	/* insert the id */
	switch ( idl_insert( &tmp, id, db->dbc_maxids ) ) {
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

	case 2:		/* id not inserted - already there */
		break;

	case 3:		/* id not inserted - block is full */
		/*
		 * first, see if it will fit in the next block,
		 * without splitting, unless we're trying to insert
		 * into the beginning of the first block.
		 */

		/* is there a next block? */
		if ( !first && idl->b_ids[i + 1] != NOID ) {
			/* read it in */
			sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
			    idl->b_ids[i + 1] );
			k2.dptr = kstr;
			k2.dsize = strlen( kstr ) + 1;
			if ( (tmp2 = idl_fetch_one( be, db, k2 )) == NULL ) {
				Debug( LDAP_DEBUG_ANY,
				    "idl_fetch_one (%s) returns NULL\n",
				    k2.dptr, 0, 0 );
				break;
			}

			switch ( (rc = idl_insert( &tmp2, id,
			    db->dbc_maxids )) ) {
			case 1:		/* id inserted first in block */
				rc = idl_change_first( be, db, key, idl,
				    i + 1, k2, tmp2 );
				/* FALL */

			case 2:		/* id already there - how? */
			case 0:		/* id inserted */
				if ( rc == 2 ) {
					Debug( LDAP_DEBUG_ANY,
					    "id %d already in next block\n",
					    id, 0, 0 );
				}
				free( kstr );
				idl_free( tmp );
				idl_free( tmp2 );
				idl_free( idl );
				return( 0 );

			case 3:		/* split the original block */
				idl_free( tmp2 );
				break;
			}

		}

		/*
		 * must split the block, write both new blocks + update
		 * and write the indirect header block.
		 */

		/* count how many indirect blocks */
		for ( j = 0; idl->b_ids[j] != NOID; j++ )
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
			for ( j = 0; idl->b_ids[j] != NOID; j++ ) {
				sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
				    idl->b_ids[j] );
				k2.dptr = kstr;
				k2.dsize = strlen( kstr ) + 1;

				rc = ldbm_cache_delete( db, k2 );
			}

			/* store allid block in place of header block */
			idl_free( idl );
			idl = idl_allids( be );
			rc = idl_store( be, db, key, idl );

			free( kstr );
			idl_free( idl );
			idl_free( tmp );
			return( rc );
		}

		idl_split_block( tmp, id, &tmp2, &tmp3 );
		idl_free( tmp );

		/* create a new updated indirect header block */
		tmp = idl_alloc( idl->b_nmax + 1 );
		tmp->b_nids = INDBLOCK;
		/* everything up to the split block */
		SAFEMEMCPY( (char *) tmp->b_ids, (char *) idl->b_ids,
		    i * sizeof(ID) );
		/* the two new blocks */
		tmp->b_ids[i] = tmp2->b_ids[0];
		tmp->b_ids[i + 1] = tmp3->b_ids[0];
		/* everything after the split block */
		SAFEMEMCPY( (char *) &tmp->b_ids[i + 2], (char *)
		    &idl->b_ids[i + 1], (idl->b_nmax - i - 1) * sizeof(ID) );

		/* store the header block */
		rc = idl_store( be, db, key, tmp );

		/* store the first id block */
		sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
		    tmp2->b_ids[0] );
		k2.dptr = kstr;
		k2.dsize = strlen( kstr ) + 1;
		rc = idl_store( be, db, k2, tmp2 );

		/* store the second id block */
		sprintf( kstr, "%c%s%d", CONT_PREFIX, key.dptr,
		    tmp3->b_ids[0] );
		k2.dptr = kstr;
		k2.dsize = strlen( kstr ) + 1;
		rc = idl_store( be, db, k2, tmp3 );

		idl_free( tmp2 );
		idl_free( tmp3 );
		break;
	}

	free( kstr );
	idl_free( tmp );
	idl_free( idl );
	return( rc );
}

/*
 * idl_insert - insert an id into an id list.
 * returns	0	id inserted
 *		1	id inserted, first id in block has changed
 *		2	id not inserted, already there
 *		3	id not inserted, block must be split
 */

int
idl_insert( IDList **idl, ID id, int maxids )
{
	int	i, j;

	if ( ALLIDS( *idl ) ) {
		return( 2 );	/* already there */
	}

	/* is it already there? XXX bin search XXX */
	for ( i = 0; i < (*idl)->b_nids && id > (*idl)->b_ids[i]; i++ ) {
		;	/* NULL */
	}
	if ( i < (*idl)->b_nids && (*idl)->b_ids[i] == id ) {
		return( 2 );	/* already there */
	}

	/* do we need to make room for it? */
	if ( (*idl)->b_nids == (*idl)->b_nmax ) {
		/* make room or indicate block needs splitting */
		if ( (*idl)->b_nmax == maxids ) {
			return( 3 );	/* block needs splitting */
		}

		(*idl)->b_nmax *= 2;
		if ( (*idl)->b_nmax > maxids ) {
			(*idl)->b_nmax = maxids;
		}
		*idl = (IDList *) ch_realloc( (char *) *idl,
		    ((*idl)->b_nmax + 2) * sizeof(ID) );
	}

	/* make a slot for the new id */
	for ( j = (*idl)->b_nids; j != i; j-- ) {
		(*idl)->b_ids[j] = (*idl)->b_ids[j-1];
	}
	(*idl)->b_ids[i] = id;
	(*idl)->b_nids++;
	(void) memset( (char *) &(*idl)->b_ids[(*idl)->b_nids], '\0',
	    ((*idl)->b_nmax - (*idl)->b_nids) * sizeof(ID) );

	return( i == 0 ? 1 : 0 );	/* inserted - first id changed or not */
}

static IDList *
idl_dup( IDList *idl )
{
	IDList	*new;

	if ( idl == NULL ) {
		return( NULL );
	}

	new = idl_alloc( idl->b_nmax );
	SAFEMEMCPY( (char *) new, (char *) idl, (idl->b_nmax + 2)
	    * sizeof(ID) );

	return( new );
}

static IDList *
idl_min( IDList *a, IDList *b )
{
	return( a->b_nids > b->b_nids ? b : a );
}

/*
 * idl_intersection - return a intersection b
 */

IDList *
idl_intersection(
    Backend	*be,
    IDList	*a,
    IDList	*b
)
{
	int	ai, bi, ni;
	IDList	*n;

	if ( a == NULL || b == NULL ) {
		return( NULL );
	}
	if ( ALLIDS( a ) ) {
		return( idl_dup( b ) );
	}
	if ( ALLIDS( b ) ) {
		return( idl_dup( a ) );
	}

	n = idl_dup( idl_min( a, b ) );

	for ( ni = 0, ai = 0, bi = 0; ai < a->b_nids; ai++ ) {
		for ( ; bi < b->b_nids && b->b_ids[bi] < a->b_ids[ai]; bi++ )
			;	/* NULL */

		if ( bi == b->b_nids ) {
			break;
		}

		if ( b->b_ids[bi] == a->b_ids[ai] ) {
			n->b_ids[ni++] = a->b_ids[ai];
		}
	}

	if ( ni == 0 ) {
		idl_free( n );
		return( NULL );
	}
	n->b_nids = ni;

	return( n );
}

/*
 * idl_union - return a union b
 */

IDList *
idl_union(
    Backend	*be,
    IDList	*a,
    IDList	*b
)
{
	int	ai, bi, ni;
	IDList	*n;

	if ( a == NULL ) {
		return( idl_dup( b ) );
	}
	if ( b == NULL ) {
		return( idl_dup( a ) );
	}
	if ( ALLIDS( a ) || ALLIDS( b ) ) {
		return( idl_allids( be ) );
	}

	if ( b->b_nids < a->b_nids ) {
		n = a;
		a = b;
		b = n;
	}

	n = idl_alloc( a->b_nids + b->b_nids );

	for ( ni = 0, ai = 0, bi = 0; ai < a->b_nids && bi < b->b_nids; ) {
		if ( a->b_ids[ai] < b->b_ids[bi] ) {
			n->b_ids[ni++] = a->b_ids[ai++];
		} else if ( b->b_ids[bi] < a->b_ids[ai] ) {
			n->b_ids[ni++] = b->b_ids[bi++];
		} else {
			n->b_ids[ni++] = a->b_ids[ai];
			ai++, bi++;
		}
	}

	for ( ; ai < a->b_nids; ai++ ) {
		n->b_ids[ni++] = a->b_ids[ai];
	}
	for ( ; bi < b->b_nids; bi++ ) {
		n->b_ids[ni++] = b->b_ids[bi];
	}
	n->b_nids = ni;

	return( n );
}

/*
 * idl_notin - return a intersection ~b (or a minus b)
 */

IDList *
idl_notin(
    Backend	*be,
    IDList 	*a,
    IDList 	*b
)
{
	int	ni, ai, bi;
	IDList	*n;

	if ( a == NULL ) {
		return( NULL );
	}
	if ( b == NULL || ALLIDS( b )) {
		return( idl_dup( a ) );
	}

	if ( ALLIDS( a ) ) {
		n = idl_alloc( SLAPD_LDBM_MIN_MAXIDS );
		ni = 0;

		for ( ai = 1, bi = 0; ai < a->b_nids && ni < n->b_nmax &&
		    bi < b->b_nmax; ai++ ) {
			if ( b->b_ids[bi] == ai ) {
				bi++;
			} else {
				n->b_ids[ni++] = ai;
			}
		}

		for ( ; ai < a->b_nids && ni < n->b_nmax; ai++ ) {
			n->b_ids[ni++] = ai;
		}

		if ( ni == n->b_nmax ) {
			idl_free( n );
			return( idl_allids( be ) );
		} else {
			n->b_nids = ni;
			return( n );
		}
	}

	n = idl_dup( a );

	ni = 0;
	for ( ai = 0, bi = 0; ai < a->b_nids; ai++ ) {
		for ( ; bi < b->b_nids && b->b_ids[bi] < a->b_ids[ai];
		    bi++ ) {
			;	/* NULL */
		}

		if ( bi == b->b_nids ) {
			break;
		}

		if ( b->b_ids[bi] != a->b_ids[ai] ) {
			n->b_ids[ni++] = a->b_ids[ai];
		}
	}

	for ( ; ai < a->b_nids; ai++ ) {
		n->b_ids[ni++] = a->b_ids[ai];
	}
	n->b_nids = ni;

	return( n );
}

ID
idl_firstid( IDList *idl )
{
	if ( idl == NULL || idl->b_nids == 0 ) {
		return( NOID );
	}

	if ( ALLIDS( idl ) ) {
		return( idl->b_nids == 1 ? NOID : 1 );
	}

	return( idl->b_ids[0] );
}

ID
idl_nextid( IDList *idl, ID id )
{
	int	i;

	if ( ALLIDS( idl ) ) {
		return( ++id < idl->b_nids ? id : NOID );
	}

	for ( i = 0; i < idl->b_nids && idl->b_ids[i] < id; i++ ) {
		;	/* NULL */
	}
	i++;

	if ( i >= idl->b_nids ) {
		return( NOID );
	} else {
		return( idl->b_ids[i] );
	}
}
