/* dn2id.c - routines to deal with the dn2id index */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

extern struct dbcache	*ldbm_cache_open();
extern Entry		*cache_find_entry_dn();
extern Entry		*id2entry();
extern char		*dn_parent();
extern Datum		ldbm_cache_fetch();

int
dn2id_add(
    Backend	*be,
    char	*dn,
    ID		id
)
{
	int		rc;
	struct dbcache	*db;
	Datum		key, data;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_add( \"%s\", %ld )\n", dn, id, 0 );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create dn2id%s\n",
		    LDBM_SUFFIX, 0, 0 );
		return( -1 );
	}

	dn = strdup( dn );
	dn_normalize_case( dn );

	key.dptr = dn;
	key.dsize = strlen( dn ) + 1;
	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

#ifdef LDBM_PESSIMISTIC
	rc = ldbm_cache_store( db, key, data, LDBM_INSERT | LDBM_SYNC );
#else
	rc = ldbm_cache_store( db, key, data, LDBM_INSERT );
#endif

	free( dn );
	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_add %d\n", rc, 0, 0 );
	return( rc );
}

ID
dn2id(
    Backend	*be,
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Entry		*e;
	ID		id;
	Datum		key, data;


	dn = strdup( dn );
	dn_normalize_case( dn );
	Debug( LDAP_DEBUG_TRACE, "=> dn2id( \"%s\" )\n", dn, 0, 0 );

	/* first check the cache */
	if ( (e = cache_find_entry_dn( &li->li_cache, dn )) != NULL ) {
		id = e->e_id;
		free( dn );
		Debug( LDAP_DEBUG_TRACE, "<= dn2id %d (in cache)\n", e->e_id,
		    0, 0 );
		cache_return_entry( &li->li_cache, e );

		return( id );
	}

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		free( dn );
		Debug( LDAP_DEBUG_ANY, "<= dn2id could not open dn2id%s\n",
		    LDBM_SUFFIX, 0, 0 );
		return( NOID );
	}

	key.dptr = dn;
	key.dsize = strlen( dn ) + 1;

	data = ldbm_cache_fetch( db, key );

	ldbm_cache_close( be, db );
	free( dn );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= dn2id NOID\n", 0, 0, 0 );
		return( NOID );
	}

	(void) memcpy( (char *) &id, data.dptr, sizeof(ID) );

	ldbm_datum_free( db->dbc_db, data );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id %d\n", id, 0, 0 );
	return( id );
}

int
dn2id_delete(
    Backend	*be,
    char	*dn
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct dbcache	*db;
	Datum		key;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_delete( \"%s\" )\n", dn, 0, 0 );

	if ( (db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= dn2id_delete could not open dn2id%s\n", LDBM_SUFFIX,
		    0, 0 );
		return( -1 );
	}

	dn_normalize_case( dn );
	key.dptr = dn;
	key.dsize = strlen( dn ) + 1;

	rc = ldbm_cache_delete( db, key );

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_delete %d\n", rc, 0, 0 );
	return( rc );
}

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

Entry *
dn2entry(
    Backend	*be,
    char	*dn,
    char	**matched
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;
	ID		id;
	Entry		*e;
	char		*pdn;

	if ( (id = dn2id( be, dn )) != NOID && (e = id2entry( be, id ))
	    != NULL ) {
		return( e );
	}
	*matched = NULL;

	/* stop when we get to the suffix */
	if ( be_issuffix( be, dn ) ) {
		return( NULL );
	}

	/* entry does not exist - see how much of the dn does exist */
	if ( (pdn = dn_parent( be, dn )) != NULL ) {
		if ( (e = dn2entry( be, pdn, matched )) != NULL ) {
			*matched = pdn;
			cache_return_entry( &li->li_cache, e );
		} else {
			free( pdn );
		}
	}

	return( NULL );
}
