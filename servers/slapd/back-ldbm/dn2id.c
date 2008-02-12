/* dn2id.c - routines to deal with the dn2id index */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

int
dn2id_add(
    Backend	*be,
    struct berval *dn,
    ID		id
)
{
	int		rc, flags;
	DBCache	*db;
	Datum		key, data;
	char		*buf;
	struct berval	ptr, pdn;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_add( \"%s\", %ld )\n", dn->bv_val, id, 0 );

	assert( id != NOID );

	db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT );
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create dn2id%s\n",
		    LDBM_SUFFIX, 0, 0 );

		return( -1 );
	}

	ldbm_datum_init( key );
	key.dsize = dn->bv_len + 2;
	buf = ch_malloc( key.dsize );
	key.dptr = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = dn->bv_len;
	AC_MEMCPY( ptr.bv_val, dn->bv_val, dn->bv_len );
	ptr.bv_val[ dn->bv_len ] = '\0';

	ldbm_datum_init( data );
	data.dptr = (char *) &id;
	data.dsize = sizeof(ID);

	flags = LDBM_INSERT;
	rc = ldbm_cache_store( db, key, data, flags );

	if ( rc != -1 && !be_issuffix( be, &ptr )) {
		buf[0] = DN_SUBTREE_PREFIX;
		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		rc = idl_insert_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		if ( rc != -1 ) {
			dnParent( &ptr, &pdn );

			pdn.bv_val[-1] = DN_ONE_PREFIX;
			key.dsize = pdn.bv_len + 2;
			key.dptr = pdn.bv_val - 1;
			ptr = pdn;
			ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
			rc = idl_insert_key( be, db, key, id );
			ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );
		}
	}

	while ( rc != -1 && !be_issuffix( be, &ptr )) {
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		rc = idl_insert_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		if( rc != 0 ) break;
		dnParent( &ptr, &pdn );
		key.dsize = pdn.bv_len + 2;
		key.dptr = pdn.bv_val - 1;
		ptr = pdn;
	}

	free( buf );
	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_add %d\n", rc, 0, 0 );

	return( rc );
}

int
dn2id(
    Backend	*be,
    struct berval *dn,
    ID          *idp
)
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	DBCache	*db;
	Datum		key, data;
	unsigned char	*tmp;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id( \"%s\" )\n", dn->bv_val, 0, 0 );

	assert( idp != NULL );

	/* first check the cache */
	*idp = cache_find_entry_ndn2id( be, &li->li_cache, dn );
	if ( *idp != NOID ) {
		Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld (in cache)\n", *idp,
			0, 0 );

		return( 0 );
	}

	db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT );
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= dn2id could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );
		/*
		 * return code !0 if ldbm cache open failed;
		 * callers should handle this
		 */
		*idp = NOID;
		return( -1 );
	}

	ldbm_datum_init( key );

	key.dsize = dn->bv_len + 2;
	key.dptr = ch_malloc( key.dsize );
	tmp = (unsigned char *)key.dptr;
	tmp[0] = DN_BASE_PREFIX;
	tmp++;
	AC_MEMCPY( tmp, dn->bv_val, dn->bv_len );
	tmp[dn->bv_len] = '\0';

	data = ldbm_cache_fetch( db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	if ( data.dptr == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<= dn2id NOID\n", 0, 0, 0 );

		*idp = NOID;
		return( 0 );
	}

	AC_MEMCPY( (char *) idp, data.dptr, sizeof(ID) );

	assert( *idp != NOID );

	ldbm_datum_free( db->dbc_db, data );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id %ld\n", *idp, 0, 0 );

	return( 0 );
}

int
dn2idl(
    Backend	*be,
    struct berval	*dn,
    int		prefix,
    ID_BLOCK    **idlp
)
{
	DBCache	*db;
	Datum		key;
	unsigned char	*tmp;

	Debug( LDAP_DEBUG_TRACE, "=> dn2idl( \"%c%s\" )\n", prefix, dn->bv_val, 0 );

	assert( idlp != NULL );
	*idlp = NULL;

	if ( prefix == DN_SUBTREE_PREFIX && be_issuffix(be, dn) ) {
		*idlp = idl_allids( be );
		return 0;
	}

	db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT );
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY, "<= dn2idl could not open dn2id%s\n",
			LDBM_SUFFIX, 0, 0 );

		return -1;
	}

	ldbm_datum_init( key );

	key.dsize = dn->bv_len + 2;
	key.dptr = ch_malloc( key.dsize );
	tmp = (unsigned char *)key.dptr;
	tmp[0] = prefix;
	tmp++;
	AC_MEMCPY( tmp, dn->bv_val, dn->bv_len );
	tmp[dn->bv_len] = '\0';

	*idlp = idl_fetch( be, db, key );

	ldbm_cache_close( be, db );

	free( key.dptr );

	return( 0 );
}


int
dn2id_delete(
    Backend	*be,
    struct berval *dn,
	ID id
)
{
	DBCache	*db;
	Datum		key;
	int		rc;
	char		*buf;
	struct berval	ptr, pdn;

	Debug( LDAP_DEBUG_TRACE, "=> dn2id_delete( \"%s\", %ld )\n", dn->bv_val, id, 0 );


	assert( id != NOID );

	db = ldbm_cache_open( be, "dn2id", LDBM_SUFFIX, LDBM_WRCREAT );
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= dn2id_delete could not open dn2id%s\n", LDBM_SUFFIX,
		    0, 0 );

		return( -1 );
	}

	ldbm_datum_init( key );
	key.dsize = dn->bv_len + 2;
	buf = ch_malloc( key.dsize );
	key.dptr = buf;
	buf[0] = DN_BASE_PREFIX;
	ptr.bv_val = buf + 1;
	ptr.bv_len = dn->bv_len;
	AC_MEMCPY( ptr.bv_val, dn->bv_val, dn->bv_len );
	ptr.bv_val[dn->bv_len] = '\0';

	rc = ldbm_cache_delete( db, key );
	
	if( !be_issuffix( be, &ptr )) {
		buf[0] = DN_SUBTREE_PREFIX;
		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		(void) idl_delete_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		dnParent( &ptr, &pdn );

		pdn.bv_val[-1] = DN_ONE_PREFIX;
		key.dsize = pdn.bv_len + 2;
		key.dptr = pdn.bv_val - 1;
		ptr = pdn;

		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		(void) idl_delete_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );
	}

	while ( rc != -1 && !be_issuffix( be, &ptr )) {
		ptr.bv_val[-1] = DN_SUBTREE_PREFIX;

		ldap_pvt_thread_mutex_lock( &db->dbc_write_mutex );
		(void) idl_delete_key( be, db, key, id );
		ldap_pvt_thread_mutex_unlock( &db->dbc_write_mutex );

		dnParent( &ptr, &pdn );
		key.dsize = pdn.bv_len + 2;
		key.dptr = pdn.bv_val - 1;
		ptr = pdn;
	}

	free( buf );

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= dn2id_delete %d\n", rc, 0, 0 );

	return( rc );
}

/*
 * dn2entry - look up dn in the cache/indexes and return the corresponding
 * entry.
 */

Entry *
dn2entry_rw(
    Backend	*be,
    struct berval *dn,
    Entry	**matched,
    int		rw
)
{
	ID		id;
	Entry		*e = NULL;
	struct berval	pdn;

	Debug(LDAP_DEBUG_TRACE, "dn2entry_%s: dn: \"%s\"\n",
		rw ? "w" : "r", dn->bv_val, 0);


	if( matched != NULL ) {
		/* caller cares about match */
		*matched = NULL;
	}

	if ( dn2id( be, dn, &id ) ) {
		/* something bad happened to ldbm cache */
		return( NULL );

	}
	
	if ( id != NOID ) {
		/* try to return the entry */
		if ((e = id2entry_rw( be, id, rw )) != NULL ) {
			return( e );
		}

		Debug(LDAP_DEBUG_ANY,
			"dn2entry_%s: no entry for valid id (%ld), dn \"%s\"\n",
			rw ? "w" : "r", id, dn->bv_val);

		/* must have been deleted from underneath us */
		/* treat as if NOID was found */
	}

	/* caller doesn't care about match */
	if( matched == NULL ) return NULL;

	/* entry does not exist - see how much of the dn does exist */
	if ( !be_issuffix( be, dn ) && (dnParent( dn, &pdn ), pdn.bv_len) ) {
		/* get entry with reader lock */
		if ((e = dn2entry_r( be, &pdn, matched )) != NULL )
		{
			*matched = e;
		}
	}

	return NULL;
}

