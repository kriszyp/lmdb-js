/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_open(
	BackendInfo *bi
)
{
	bi->bi_controls = slap_known_controls;
	return 0;
}

int
meta_back_initialize(
		BackendInfo	*bi
)
{
	bi->bi_open = meta_back_open;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = meta_back_db_init;
	bi->bi_db_config = meta_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = meta_back_db_destroy;

	bi->bi_op_bind = meta_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = meta_back_search;
	bi->bi_op_compare = meta_back_compare;
	bi->bi_op_modify = meta_back_modify;
	bi->bi_op_modrdn = meta_back_modrdn;
	bi->bi_op_add = meta_back_add;
	bi->bi_op_delete = meta_back_delete;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = meta_back_conn_destroy;

	return 0;
}

int
meta_back_db_init(
		Backend	*be
)
{
	struct metainfo	*li;

	struct rewrite_info	*rwinfo;

	rwinfo = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
	if ( rwinfo == NULL ) {
		return -1;
	}

	li = ch_calloc( 1, sizeof( struct metainfo ) );
	if ( li == NULL ) {
		rewrite_info_delete( &rwinfo );
 		return -1;
 	}

	/*
	 * At present the default is no default target;
	 * this may change
	 */
	li->defaulttarget = META_DEFAULT_TARGET_NONE;
	li->rwinfo = rwinfo;

	ldap_pvt_thread_mutex_init( &li->conn_mutex );
	ldap_pvt_thread_mutex_init( &li->cache.mutex );
	be->be_private = li;

	return 0;
}

static void
conn_free( 
	void *v_lc
)
{
	struct metaconn		*lc = v_lc;
	struct metasingleconn	*lsc;

	for ( lsc = lc->mc_conns; !META_LAST( lsc ); lsc++ ) {
		if ( lsc->msc_ld != NULL ) {
			ldap_unbind_ext_s( lsc->msc_ld, NULL, NULL );
		}
		if ( !BER_BVISNULL( &lsc->msc_bound_ndn ) ) {
			ber_memfree( lsc->msc_bound_ndn.bv_val );
		}
		if ( !BER_BVISNULL( &lsc->msc_cred ) ) {
			/* destroy sensitive data */
			memset( lsc->msc_cred.bv_val, 0, lsc->msc_cred.bv_len );
			ber_memfree( lsc->msc_cred.bv_val );
		}
	}
	free( lc->mc_conns );
	free( lc );
}

static void
mapping_free( void *v_mapping )
{
	struct ldapmapping *mapping = v_mapping;
	ch_free( mapping->src.bv_val );
	ch_free( mapping->dst.bv_val );
	ch_free( mapping );
}

static void
target_free(
		struct metatarget *lt
)
{
	if ( lt->mt_uri ) {
		free( lt->mt_uri );
	}
	if ( !BER_BVISNULL( &lt->mt_psuffix ) ) {
		free( lt->mt_psuffix.bv_val );
	}
	if ( !BER_BVISNULL( &lt->mt_nsuffix ) ) {
		free( lt->mt_nsuffix.bv_val );
	}
	if ( !BER_BVISNULL( &lt->mt_binddn ) ) {
		free( lt->mt_binddn.bv_val );
	}
	if ( !BER_BVISNULL( &lt->mt_bindpw ) ) {
		free( lt->mt_bindpw.bv_val );
	}
	if ( !BER_BVISNULL( &lt->mt_pseudorootdn ) ) {
		free( lt->mt_pseudorootdn.bv_val );
	}
	if ( !BER_BVISNULL( &lt->mt_pseudorootpw ) ) {
		free( lt->mt_pseudorootpw.bv_val );
	}
	if ( lt->mt_rwmap.rwm_rw ) {
		rewrite_info_delete( &lt->mt_rwmap.rwm_rw );
	}
	avl_free( lt->mt_rwmap.rwm_oc.remap, NULL );
	avl_free( lt->mt_rwmap.rwm_oc.map, mapping_free );
	avl_free( lt->mt_rwmap.rwm_at.remap, NULL );
	avl_free( lt->mt_rwmap.rwm_at.map, mapping_free );
}

int
meta_back_db_destroy(
    Backend	*be
)
{
	struct metainfo *li;

	if ( be->be_private ) {
		int i;

		li = ( struct metainfo * )be->be_private;

		/*
		 * Destroy the connection tree
		 */
		ldap_pvt_thread_mutex_lock( &li->conn_mutex );

		if ( li->conntree ) {
			avl_free( li->conntree, conn_free );
		}

		/*
		 * Destroy the per-target stuff (assuming there's at
		 * least one ...)
		 */
		for ( i = 0; i < li->ntargets; i++ ) {
			target_free( li->targets[ i ] );
			free( li->targets[ i ] );
		}

		free( li->targets );

		ldap_pvt_thread_mutex_lock( &li->cache.mutex );
		if ( li->cache.tree ) {
			avl_free( li->cache.tree, meta_dncache_free );
		}
		
		ldap_pvt_thread_mutex_unlock( &li->cache.mutex );
		ldap_pvt_thread_mutex_destroy( &li->cache.mutex );

		ldap_pvt_thread_mutex_unlock( &li->conn_mutex );
		ldap_pvt_thread_mutex_destroy( &li->conn_mutex );
	}

	free( be->be_private );
	return 0;
}

#if SLAPD_META == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( meta )

#endif /* SLAPD_META == SLAPD_MOD_DYNAMIC */


