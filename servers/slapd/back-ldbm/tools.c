/* tools.c - tools for slap tools */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

static LDBMCursor *cursorp = NULL;
static DBCache *id2entry = NULL;

int ldbm_tool_entry_open(
	BackendDB *be, int mode )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	int flags;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry == NULL );

	switch( mode ) {
	case 1:
		flags = LDBM_WRCREAT;
		break;
	case 2:
#ifdef TRUNCATE_MODE
		flags = LDBM_NEWDB;
#else
		flags = LDBM_WRCREAT;
#endif
		break;
	default:
		flags = LDBM_READER;
	}

	li->li_dbwritesync = 0;

	if ( (id2entry = ldbm_cache_open( be, "id2entry", LDBM_SUFFIX, flags ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY, "Could not open/create id2entry" LDBM_SUFFIX "\n",
		    0, 0, 0 );
		return( -1 );
	}

	return 0;
}

int ldbm_tool_entry_close(
	BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry != NULL );

	ldbm_cache_close( be, id2entry );
	li->li_dbwritesync = 1;
	id2entry = NULL;

	return 0;
}

ID ldbm_tool_entry_first(
	BackendDB *be )
{
	Datum key;
	ID id;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry != NULL );

	key = ldbm_firstkey( id2entry->dbc_db, &cursorp );

	if( key.dptr == NULL ) {
		return NOID;
	}

	memcpy( &id, key.dptr, key.dsize );

	ldbm_datum_free( id2entry->dbc_db, key );

	return id;
}

ID ldbm_tool_entry_next(
	BackendDB *be )
{
	Datum key;
	ID id;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry != NULL );

	/* allow for NEXTID */
	ldbm_datum_init( key );

	key = ldbm_nextkey( id2entry->dbc_db, key, cursorp );

	if( key.dptr == NULL ) {
		return NOID;
	}

	memcpy( &id, key.dptr, key.dsize );

	ldbm_datum_free( id2entry->dbc_db, key );

	return id;
}

Entry* ldbm_tool_entry_get( BackendDB *be, ID id )
{
	Entry *e;
	Datum key, data;
	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry != NULL );

	ldbm_datum_init( key );

	key.dptr = (char *) &id;
	key.dsize = sizeof(ID);

	data = ldbm_cache_fetch( id2entry, key );

	if ( data.dptr == NULL ) {
		return NULL;
	}

	e = str2entry( data.dptr );
	ldbm_datum_free( id2entry->dbc_db, data );

	return e;
}

ID ldbm_tool_entry_put(
	BackendDB *be,
	Entry *e )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	Datum key, data;
	int rc, len;

	assert( slapMode & SLAP_TOOL_MODE );
	assert( id2entry != NULL );

	if( next_id_get( be ) == NOID ) {
		return NOID;
	}

	e->e_id = li->li_nextid++;

	Debug( LDAP_DEBUG_TRACE, "=> ldbm_tool_entry_put( %ld, \"%s\" )\n",
		e->e_id, e->e_dn, 0 );

	rc = index_add_entry( be, e );

	if( rc != 0 ) {
		return NOID;
	}

	rc = dn2id_add( be, e->e_ndn, e->e_id );

	if( rc != 0 ) {
		return NOID;
	}

	ldbm_datum_init( key );
	ldbm_datum_init( data );

	key.dptr = (char *) &e->e_id;
	key.dsize = sizeof(ID);

	data.dptr = entry2str( e, &len );
	data.dsize = len + 1;

	/* store it */
	rc = ldbm_cache_store( id2entry, key, data, LDBM_REPLACE );

	if( rc != 0 ) {
		(void) dn2id_delete( be, e->e_ndn, e->e_id );
		return NOID;
	}

	return e->e_id;
}

int ldbm_tool_index_attr(
	BackendDB *be,
	char* type )
{
	static DBCache *db = NULL;
	int indexmask;
	char * at_cn;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeType *at;
#endif

	assert( slapMode & SLAP_TOOL_MODE );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	at = at_find( type );

	if( at == NULL ) {
		Debug( LDAP_DEBUG_ANY,
	    	"<= index_attr NULL (could not find attribute type %s)\n",
			type, 0, 0 );
		return 0;
	}

	at_cn = at_canonical_name( at );

	if( at_cn ) {
		Debug( LDAP_DEBUG_ANY,
			"<= index_attr NULL (attribute type %s (%s) has no canonical name)\n",
			at->sat_oid, type, 0 );
		return 0;
	}
#else
	attr_normalize( type );
	at_cn = at_canonical_name( type );

	if( at_cn ) {
		Debug( LDAP_DEBUG_ANY,
			"<= index_attr NULL (attribute type %s has no canonical name)\n",
			type, 0, 0 );
		return 0;
	}
#endif

	attr_mask( be->be_private, at_cn, &indexmask );

	if ( (db = ldbm_cache_open( be, at_cn, LDBM_SUFFIX, LDBM_NEWDB ))
	    == NULL )
	{
		Debug( LDAP_DEBUG_ANY,
		    "<= index_attr NULL (could not open %s%s)\n", at_cn,
		    LDBM_SUFFIX, 0 );
		return 0;
	}

	ldbm_cache_close( be, db );

	return indexmask != 0;
}

int ldbm_tool_index_change(
	BackendDB *be,
	char* type,
	struct berval **bv,
	ID id,
	int op )
{
	assert( slapMode & SLAP_TOOL_MODE );

	index_change_values( be,
		type, bv, id, op );

	return 0;
}

int ldbm_tool_sync( BackendDB *be )
{
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	assert( slapMode & SLAP_TOOL_MODE );

	if ( li->li_nextid != NOID ) {
		next_id_write( be, li->li_nextid );
	}

	return 0;
}
