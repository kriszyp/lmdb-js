/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

/*
 * The dncache, at present, maps an entry to the target that holds it.
 */

struct metadncacheentry {
	struct berval	dn;
	int 		target;

	time_t 		lastupdated;
};

/*
 * meta_dncache_cmp
 *
 * compares two struct metadncacheentry; used by avl stuff
 * FIXME: modify avl stuff to delete an entry based on cmp
 * (e.g. when ttl expired?)
 */
int
meta_dncache_cmp(
		const void *c1,
		const void *c2
)
{
	struct metadncacheentry *cc1 = ( struct metadncacheentry * )c1;
	struct metadncacheentry *cc2 = ( struct metadncacheentry * )c2;

	/*
	 * case sensitive, because the dn MUST be normalized
	 */
 	return ber_bvcmp( &cc1->dn, &cc2->dn);
}

/*
 * meta_dncache_dup
 *
 * returns -1 in case a duplicate struct metadncacheentry has been inserted;
 * used by avl stuff
 */
int
meta_dncache_dup(
		void *c1,
		void *c2
)
{
	struct metadncacheentry *cc1 = ( struct metadncacheentry * )c1;
	struct metadncacheentry *cc2 = ( struct metadncacheentry * )c2;
	
	/*
	 * case sensitive, because the dn MUST be normalized
	 */
 	return ( ber_bvcmp( &cc1->dn, &cc2->dn ) == 0 ) ? -1 : 0;
}

/*
 * meta_dncache_get_target
 *
 * returns the target a dn belongs to, or -1 in case the dn is not
 * in the cache
 */
int
meta_dncache_get_target(
		struct metadncache	*cache,
		struct berval		*ndn
)
{
	struct metadncacheentry tmp_entry, *entry;
	time_t curr_time;
	int target = -1;

	assert( cache );
	assert( ndn );

	tmp_entry.dn = *ndn;
	ldap_pvt_thread_mutex_lock( &cache->mutex );
	entry = ( struct metadncacheentry * )avl_find( cache->tree,
			( caddr_t )&tmp_entry, meta_dncache_cmp );

	if ( entry != NULL ) {
		
		/*
		 * if cache->ttl < 0, cache never expires;
		 * if cache->ttl = 0 no cache is used; shouldn't get here
		 * else, cache is used with ttl
		 */
		if ( cache->ttl < 0 ) { 
			target = entry->target;
		} else {

			/*
			 * Need mutex?
			 */	
			curr_time = time( NULL );

			if ( entry->lastupdated+cache->ttl > curr_time ) {
				target = entry->target;
			}
		}
	}
	ldap_pvt_thread_mutex_unlock( &cache->mutex );

	return target;
}

/*
 * meta_dncache_update_entry
 *
 * updates target and lastupdated of a struct metadncacheentry if exists,
 * otherwise it gets created; returns -1 in case of error
 */
int
meta_dncache_update_entry(
		struct metadncache      *cache,
		struct berval		*ndn,
		int 			target
)
{
	struct metadncacheentry *entry, tmp_entry;
	time_t curr_time = 0L;
	int err = 0;

	assert( cache );
	assert( ndn );

	/*
	 * if cache->ttl < 0, cache never expires;
	 * if cache->ttl = 0 no cache is used; shouldn't get here
	 * else, cache is used with ttl
	 */
	if ( cache->ttl > 0 ) {

		/*
		 * Need mutex?
		 */
		curr_time = time( NULL );
	}

	tmp_entry.dn = *ndn;

	ldap_pvt_thread_mutex_lock( &cache->mutex );
	entry = ( struct metadncacheentry * )avl_find( cache->tree,
			( caddr_t )&tmp_entry, meta_dncache_cmp );

	if ( entry != NULL ) {
		entry->target = target;
		entry->lastupdated = curr_time;
	} else {
		entry = ch_calloc( sizeof( struct metadncacheentry ), 1 );
		if ( entry == NULL ) {
			ldap_pvt_thread_mutex_unlock( &cache->mutex );
			return -1;
		}

		ber_dupbv( &entry->dn, ndn );
		if ( entry->dn.bv_val == NULL ) {
			ldap_pvt_thread_mutex_unlock( &cache->mutex );
			return -1;
		}
		entry->target = target;
		entry->lastupdated = curr_time;

		err = avl_insert( &cache->tree, ( caddr_t )entry,
				meta_dncache_cmp, meta_dncache_dup );
	}
	ldap_pvt_thread_mutex_unlock( &cache->mutex );

	return err;
}

/*
 * meta_dncache_update_entry
 *
 * updates target and lastupdated of a struct metadncacheentry if exists,
 * otherwise it gets created; returns -1 in case of error
 */
int
meta_dncache_delete_entry(
		struct metadncache      *cache,
		struct berval		*ndn
)
{
	struct metadncacheentry *entry, tmp_entry;

	assert( cache );
	assert( ndn );

	tmp_entry.dn = *ndn;

	ldap_pvt_thread_mutex_lock( &cache->mutex );
	entry = avl_delete( &cache->tree, ( caddr_t )&tmp_entry,
 			meta_dncache_cmp );
	ldap_pvt_thread_mutex_unlock( &cache->mutex );

	if ( entry != NULL ) {
		meta_dncache_free( ( void * )entry );
	}

	return 0;
}

/*
 * meta_dncache_free
 *
 * frees an entry
 * 
 */
void
meta_dncache_free(
		void *e
)
{
	struct metadncacheentry *entry = ( struct metadncacheentry * )e;

	free( entry->dn.bv_val );
}

