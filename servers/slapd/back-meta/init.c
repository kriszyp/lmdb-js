/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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
	BackendInfo	*bi )
{
	/* FIXME: need to remove the pagedResults, and likely more... */
	bi->bi_controls = slap_known_controls;

	return 0;
}

int
meta_back_initialize(
	BackendInfo	*bi )
{
	bi->bi_flags =
#if 0
	/* this is not (yet) set essentially because back-meta does not
	 * directly support extended operations... */
#ifdef LDAP_DYNAMIC_OBJECTS
		/* this is set because all the support a proxy has to provide
		 * is the capability to forward the refresh exop, and to
		 * pass thru entries that contain the dynamicObject class
		 * and the entryTtl attribute */
		SLAP_BFLAG_DYNAMIC |
#endif /* LDAP_DYNAMIC_OBJECTS */
#endif
		0;

	bi->bi_open = meta_back_open;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = meta_back_db_init;
	bi->bi_db_config = meta_back_db_config;
	bi->bi_db_open = meta_back_db_open;
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
	Backend		*be )
{
	metainfo_t	*mi;

	mi = ch_calloc( 1, sizeof( metainfo_t ) );
	if ( mi == NULL ) {
 		return -1;
 	}

	/*
	 * At present the default is no default target;
	 * this may change
	 */
	mi->mi_defaulttarget = META_DEFAULT_TARGET_NONE;
	mi->mi_bind_timeout.tv_sec = 0;
	mi->mi_bind_timeout.tv_usec = META_BIND_TIMEOUT;

	ldap_pvt_thread_mutex_init( &mi->mi_conninfo.lai_mutex );
	ldap_pvt_thread_mutex_init( &mi->mi_cache.mutex );

	/* safe default */
	mi->mi_nretries = META_RETRY_DEFAULT;
	mi->mi_version = LDAP_VERSION3;
	
	be->be_private = mi;

	return 0;
}

int
meta_back_db_open(
	Backend		*be )
{
	metainfo_t	*mi = (metainfo_t *)be->be_private;

	int		i, rc;

	for ( i = 0; i < mi->mi_ntargets; i++ ) {
		if ( mi->mi_targets[ i ].mt_flags & LDAP_BACK_F_SUPPORT_T_F_DISCOVER )
		{
			mi->mi_targets[ i ].mt_flags &= ~LDAP_BACK_F_SUPPORT_T_F_DISCOVER;
			rc = slap_discover_feature( mi->mi_targets[ i ].mt_uri,
					mi->mi_targets[ i ].mt_version,
					slap_schema.si_ad_supportedFeatures->ad_cname.bv_val,
					LDAP_FEATURE_ABSOLUTE_FILTERS );
			if ( rc == LDAP_COMPARE_TRUE ) {
				mi->mi_targets[ i ].mt_flags |= LDAP_BACK_F_SUPPORT_T_F;
			}
		}
	}

	return 0;
}

void
meta_back_conn_free( 
	void 		*v_mc )
{
	metaconn_t		*mc = v_mc;
	int			i, ntargets;

	assert( mc != NULL );
	assert( mc->mc_refcnt == 0 );

	if ( !BER_BVISNULL( &mc->mc_local_ndn ) ) {
		free( mc->mc_local_ndn.bv_val );
	}

	assert( mc->mc_conns != NULL );

	/* at least one must be present... */
	ntargets = mc->mc_conns[ 0 ].msc_info->mi_ntargets;

	for ( i = 0; i < ntargets; i++ ) {
		(void)meta_clear_one_candidate( &mc->mc_conns[ i ] );
	}

	ldap_pvt_thread_mutex_destroy( &mc->mc_mutex );
	free( mc );
}

static void
mapping_free(
	void		*v_mapping )
{
	struct ldapmapping *mapping = v_mapping;
	ch_free( mapping->src.bv_val );
	ch_free( mapping->dst.bv_val );
	ch_free( mapping );
}

static void
mapping_dst_free(
	void		*v_mapping )
{
	struct ldapmapping *mapping = v_mapping;

	if ( BER_BVISEMPTY( &mapping->dst ) ) {
		mapping_free( &mapping[ -1 ] );
	}
}

static void
target_free(
	metatarget_t	*mt )
{
	if ( mt->mt_uri ) {
		free( mt->mt_uri );
	}
	if ( !BER_BVISNULL( &mt->mt_psuffix ) ) {
		free( mt->mt_psuffix.bv_val );
	}
	if ( !BER_BVISNULL( &mt->mt_nsuffix ) ) {
		free( mt->mt_nsuffix.bv_val );
	}
	if ( !BER_BVISNULL( &mt->mt_binddn ) ) {
		free( mt->mt_binddn.bv_val );
	}
	if ( !BER_BVISNULL( &mt->mt_bindpw ) ) {
		free( mt->mt_bindpw.bv_val );
	}
	if ( !BER_BVISNULL( &mt->mt_pseudorootdn ) ) {
		free( mt->mt_pseudorootdn.bv_val );
	}
	if ( !BER_BVISNULL( &mt->mt_pseudorootpw ) ) {
		free( mt->mt_pseudorootpw.bv_val );
	}
	if ( mt->mt_rwmap.rwm_rw ) {
		rewrite_info_delete( &mt->mt_rwmap.rwm_rw );
	}
	avl_free( mt->mt_rwmap.rwm_oc.remap, mapping_dst_free );
	avl_free( mt->mt_rwmap.rwm_oc.map, mapping_free );
	avl_free( mt->mt_rwmap.rwm_at.remap, mapping_dst_free );
	avl_free( mt->mt_rwmap.rwm_at.map, mapping_free );
}

int
meta_back_db_destroy(
	Backend		*be )
{
	metainfo_t	*mi;

	if ( be->be_private ) {
		int i;

		mi = ( metainfo_t * )be->be_private;

		/*
		 * Destroy the connection tree
		 */
		ldap_pvt_thread_mutex_lock( &mi->mi_conninfo.lai_mutex );

		if ( mi->mi_conninfo.lai_tree ) {
			avl_free( mi->mi_conninfo.lai_tree, meta_back_conn_free );
		}

		/*
		 * Destroy the per-target stuff (assuming there's at
		 * least one ...)
		 */
		if ( mi->mi_targets != NULL ) {
			for ( i = 0; i < mi->mi_ntargets; i++ ) {
				target_free( &mi->mi_targets[ i ] );
			}

			free( mi->mi_targets );
		}

		ldap_pvt_thread_mutex_lock( &mi->mi_cache.mutex );
		if ( mi->mi_cache.tree ) {
			avl_free( mi->mi_cache.tree, meta_dncache_free );
		}
		
		ldap_pvt_thread_mutex_unlock( &mi->mi_cache.mutex );
		ldap_pvt_thread_mutex_destroy( &mi->mi_cache.mutex );

		ldap_pvt_thread_mutex_unlock( &mi->mi_conninfo.lai_mutex );
		ldap_pvt_thread_mutex_destroy( &mi->mi_conninfo.lai_mutex );

		if ( mi->mi_candidates != NULL ) {
			ber_memfree_x( mi->mi_candidates, NULL );
		}
	}

	free( be->be_private );
	return 0;
}

#if SLAPD_META == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( meta )

#endif /* SLAPD_META == SLAPD_MOD_DYNAMIC */


