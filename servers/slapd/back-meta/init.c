/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This work has been developed to fulfill the requirements
 * of SysNet s.n.c. <http:www.sys-net.it> and it has been donated
 * to the OpenLDAP Foundation in the hope that it may be useful
 * to the Open Source community, but WITHOUT ANY WARRANTY.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from 
 *    flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 *
 * 4. This notice may not be removed or altered.
 *
 *
 * This software is based on the backend back-ldap, implemented
 * by Howard Chu <hyc@highlandsun.com>, and modified by Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. The contribution of the original software to the present
 * implementation is acknowledged in this copyright statement.
 *
 * A special acknowledgement goes to Howard for the overall architecture
 * (and for borrowing large pieces of code), and to Mark, who implemented
 * from scratch the attribute/objectclass mapping.
 *
 * The original copyright statement follows.
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the
 *    documentation.
 *
 * 4. This notice may not be removed or altered.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

#ifdef SLAPD_META_DYNAMIC

int
back_meta_LTX_init_module( int argc, char *argv[] ) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof( bi ) );
    bi.bi_type = "meta";
    bi.bi_init = meta_back_initialize;

    backend_add( &bi );
    return 0;
}

#endif /* SLAPD_META_DYNAMIC */

int
meta_back_initialize(
		BackendInfo	*bi
)
{
	bi->bi_controls = slap_known_controls;

	bi->bi_open = 0;
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

	bi->bi_acl_group = meta_back_group;
	bi->bi_acl_attribute = meta_back_attribute;
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

	li = ch_calloc( 1, sizeof( struct metainfo ) );
	if ( li == NULL ) {
 		return -1;
 	}
	
	/*
	 * At present the default is no default target;
	 * this may change
	 */
	li->defaulttarget = META_DEFAULT_TARGET_NONE;

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
	struct metaconn *lc = v_lc;
	struct metasingleconn *lsc;

	for ( lsc = lc->conns; !META_LAST(lsc); lsc++ ) {
		if ( lsc->ld != NULL ) {
			ldap_unbind( lsc->ld );
		}
		if ( lsc->bound_dn.bv_val ) {
			ber_memfree( lsc->bound_dn.bv_val );
		}
		free( lsc );
	}
	free( lc->conns );
	free( lc );
}

static void
target_free(
		struct metatarget *lt
)
{
	if ( lt->uri ) {
		free( lt->uri );
	}
	if ( lt->psuffix.bv_val ) {
		free( lt->psuffix.bv_val );
	}
	if ( lt->suffix.bv_val ) {
		free( lt->suffix.bv_val );
	}
	if ( lt->binddn.bv_val ) {
		free( lt->binddn.bv_val );
	}
	if ( lt->bindpw.bv_val ) {
		free( lt->bindpw.bv_val );
	}
	if ( lt->pseudorootdn.bv_val ) {
		free( lt->pseudorootdn.bv_val );
	}
	if ( lt->pseudorootpw.bv_val ) {
		free( lt->pseudorootpw.bv_val );
	}
	if ( lt->rwinfo ) {
		rewrite_info_delete( lt->rwinfo );
	}
	avl_free( lt->oc_map.remap, NULL );
	avl_free( lt->oc_map.map, mapping_free );
	avl_free( lt->at_map.remap, NULL );
	avl_free( lt->at_map.map, mapping_free );
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

