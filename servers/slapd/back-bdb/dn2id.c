/* dn2id.c - routines to deal with the dn2id index */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

int
bdb_dn2id_add(
    BackendDB	*be,
	DB_TXN *txn,
    const char	*dn,
    ID		id
)
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_add( \"%s\", 0x%08lx )\n",
		dn, id, 0 );
	assert( id != NOID );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

	DBTzero( &data );
	data.data = (char *) &id;
	data.size = sizeof( id );

	/* store it -- don't override */
	rc = db->put( db, txn, &key, &data, DB_NOOVERWRITE );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_add: put failed: %s %d\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}

	{
		char *pdn = dn_parent( NULL, dn );
		((char *)(key.data))[0] = DN_ONE_PREFIX;

		if( pdn != NULL ) {
			key.size = strlen( pdn ) + 2;
			AC_MEMCPY( &((char*)key.data)[1],
				pdn, key.size - 1 );

			rc = bdb_idl_insert_key( be, db, txn, &key, id );

			if( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"=> bdb_dn2id_add: parent (%s) insert failed: %d\n",
					pdn, rc, 0 );
				free( pdn );
				goto done;
			}
			free( pdn );
		}
	}

	{
		char **subtree = dn_subtree( NULL, dn );

		if( subtree != NULL ) {
			int i;
			((char *)key.data)[0] = DN_SUBTREE_PREFIX;
			for( i=0; subtree[i] != NULL; i++ ) {
				key.size = strlen( subtree[i] ) + 2;
				AC_MEMCPY( &((char *)key.data)[1],
					subtree[i], key.size - 1 );

				rc = bdb_idl_insert_key( be, db, txn, &key, id );

				if( rc != 0 ) {
					Debug( LDAP_DEBUG_ANY,
						"=> bdb_dn2id_add: subtree (%s) insert failed: %d\n",
						subtree[i], rc, 0 );
					break;
				}
			}

			charray_free( subtree );
		}
	}

done:
	ch_free( key.data );
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_add: %d\n", rc, 0, 0 );
	return rc;
}

int
bdb_dn2id_delete(
    BackendDB	*be,
	DB_TXN *txn,
    const char	*dn,
    ID		id )
{
	int		rc;
	DBT		key;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_delete( \"%s\", 0x%08lx )\n",
		dn, id, 0 );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

	/* store it -- don't override */
	rc = db->del( db, txn, &key, 0 );
	if( rc != 0 ) {
		Debug( LDAP_DEBUG_ANY, "=> bdb_dn2id_delete: delete failed: %s %d\n",
			db_strerror(rc), rc, 0 );
		goto done;
	}

	{
		char *pdn = dn_parent( NULL, dn );
		((char *)(key.data))[0] = DN_ONE_PREFIX;

		if( pdn != NULL ) {
			key.size = strlen( pdn ) + 2;
			AC_MEMCPY( &((char*)key.data)[1],
				pdn, key.size - 1 );

			rc = bdb_idl_delete_key( be, db, txn, &key, id );

			if( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"=> bdb_dn2id_delete: parent (%s) delete failed: %d\n",
					pdn, rc, 0 );
				free( pdn );
				goto done;
			}
			free( pdn );
		}
	}

	{
		char **subtree = dn_subtree( NULL, dn );

		if( subtree != NULL ) {
			int i;
			((char *)key.data)[0] = DN_SUBTREE_PREFIX;
			for( i=0; subtree[i] != NULL; i++ ) {
				key.size = strlen( subtree[i] ) + 2;
				AC_MEMCPY( &((char *)key.data)[1],
					subtree[i], key.size - 1 );

				rc = bdb_idl_delete_key( be, db, txn, &key, id );

				if( rc != 0 ) {
					Debug( LDAP_DEBUG_ANY,
						"=> bdb_dn2id_delete: subtree (%s) delete failed: %d\n",
						subtree[i], rc, 0 );
					charray_free( subtree );
					goto done;
				}
			}

			charray_free( subtree );
		}
	}

done:
	ch_free( key.data );
	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_delete %d\n", rc, 0, 0 );
	return rc;
}

int
bdb_dn2id(
    BackendDB	*be,
	DB_TXN *txn,
    const char	*dn,
	ID *id )
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id( \"%s\" )\n", dn, 0, 0 );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_BASE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

	/* store the ID */
	DBTzero( &data );
	data.data = id;
	data.ulen = sizeof(ID);
	data.flags = DB_DBT_USERMEM;

	/* fetch it */
	rc = db->get( db, txn, &key, &data, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id: id=0x%08lx: %s (%d)\n",
		id, db_strerror( rc ), rc );

	ch_free( key.data );
	return rc;
}

int
bdb_dn2id_matched(
    BackendDB	*be,
	DB_TXN *txn,
    const char	*in,
	ID *id,
	char **matchedDN )
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	const char *dn = in;
	char *tmp = NULL;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_matched( \"%s\" )\n", dn, 0, 0 );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_BASE_PREFIX;

	/* store the ID */
	DBTzero( &data );
	data.data = id;
	data.ulen = sizeof(ID);
	data.flags = DB_DBT_USERMEM;

	*matchedDN = NULL;

	while(1) {
		AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

		*id = NOID;

		/* fetch it */
		rc = db->get( db, txn, &key, &data, 0 );

		if( rc == DB_NOTFOUND ) {
			char *pdn = dn_parent( be, dn );
			ch_free( tmp );
			tmp = NULL;

			if( pdn == NULL || *pdn == '\0' ) {
				Debug( LDAP_DEBUG_TRACE,
					"<= bdb_dn2id_matched: no match\n",
					0, 0, 0 );
				ch_free( pdn );
				break;
			}

			dn = pdn;
			tmp = pdn;
			key.size = strlen( dn ) + 2;

		} else if ( rc == 0 ) {
			if( data.size != sizeof( ID ) ) {
				Debug( LDAP_DEBUG_ANY,
					"<= bdb_dn2id_matched: get size mismatch: "
					"expected %ld, got %ld\n",
					(long) sizeof(ID), (long) data.size, 0 );
				ch_free( tmp );
			}

			if( in != dn ) {
				*matchedDN = (char *) dn;
			}

			Debug( LDAP_DEBUG_TRACE,
				"<= bdb_dn2id_matched: id=0x%08lx: %s\n",
				*id, dn, 0 );
			break;

		} else {
			Debug( LDAP_DEBUG_ANY,
				"<= bdb_dn2id_matched: get failed: %s (%d)\n",
				db_strerror(rc), rc, 0 );
			ch_free( tmp );
			break;
		}
	}

	ch_free( key.data );
	return rc;
}

int
bdb_dn2id_children(
    BackendDB	*be,
	DB_TXN *txn,
    const char *dn )
{
	int		rc;
	DBT		key, data;
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_dn2id->bdi_db;
	ID		id;

	Debug( LDAP_DEBUG_TRACE, "=> bdb_dn2id_children( %s )\n",
		dn, 0, 0 );

	DBTzero( &key );
	key.size = strlen( dn ) + 2;
	key.data = ch_malloc( key.size );
	((char *)key.data)[0] = DN_ONE_PREFIX;
	AC_MEMCPY( &((char *)key.data)[1], dn, key.size - 1 );

	/* we actually could do a empty get... */
	DBTzero( &data );
	data.data = &id;
	data.ulen = sizeof(id);
	data.flags = DB_DBT_USERMEM;
	data.doff = 0;
	data.dlen = sizeof(id);

	rc = db->get( db, txn, &key, &data, 0 );

	Debug( LDAP_DEBUG_TRACE, "<= bdb_dn2id_children( %s ): %s (%d)\n",
		dn,
		rc == 0 ? "yes" : ( rc == DB_NOTFOUND ? "no" :
			db_strerror(rc) ), rc );

	return rc;
}
