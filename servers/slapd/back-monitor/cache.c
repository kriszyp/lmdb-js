/* cache.c - routines to maintain an in-core cache of entries */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 * 
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
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
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"

#include "back-monitor.h"

/*
 * compares entries based on the dn
 */
int
monitor_cache_cmp(
		const void *c1,
		const void *c2
)
{
	struct monitorcache *cc1 = ( struct monitorcache * )c1;
	struct monitorcache *cc2 = ( struct monitorcache * )c2;
	
	/*
	 * case sensitive, because the dn MUST be normalized
	 */
	return strcmp( cc1->mc_ndn, cc2->mc_ndn );
}

/*
 * checks for duplicate entries
 */
int
monitor_cache_dup(
		void *c1,
		void *c2
)
{
	struct monitorcache *cc1 = ( struct monitorcache * )c1;
	struct monitorcache *cc2 = ( struct monitorcache * )c2;
	
	/*
	 * case sensitive, because the dn MUST be normalized
	 */
	return ( strcmp( cc1->mc_ndn, cc2->mc_ndn ) == 0 ) ? -1 : 0;
}

/*
 * adds an entry to the cache and inits the mutex
 */
int
monitor_cache_add(
		struct monitorinfo	*mi,
		Entry			*e
)
{
	struct monitorcache	*mc;
	struct monitorentrypriv *mp;
	int			rc;

	assert( mi != NULL );
	assert( e != NULL );

	mp = ( struct monitorentrypriv *)e->e_private;
	ldap_pvt_thread_mutex_init( &mp->mp_mutex );

	mc = ( struct monitorcache * )ch_malloc( sizeof( struct monitorcache ) );
	mc->mc_ndn = e->e_ndn;
	mc->mc_e = e;
	ldap_pvt_thread_mutex_lock( &mi->mi_cache_mutex );
	rc = avl_insert( &mi->mi_cache, ( caddr_t )mc,
			monitor_cache_cmp, monitor_cache_dup );
	ldap_pvt_thread_mutex_unlock( &mi->mi_cache_mutex );

	return rc;
}

/*
 * locks the entry (no r/w)
 */
int
monitor_cache_lock(
		Entry			*e
)
{
		struct monitorentrypriv *mp;

		assert( e != NULL );
		assert( e->e_private != NULL );

		mp = ( struct monitorentrypriv * )e->e_private;
		ldap_pvt_thread_mutex_lock( &mp->mp_mutex );

		return( 0 );
}

/*
 * gets an entry from the cache based on the normalized dn 
 * with mutex locked
 */
int
monitor_cache_get(
		struct monitorinfo      *mi,
		const char		*ndn,
		Entry			**ep
)
{
	struct monitorcache tmp_mc, *mc;

	assert( mi != NULL );
	assert( ndn != NULL );
	assert( ep != NULL );

	tmp_mc.mc_ndn = ( char * )ndn;
	ldap_pvt_thread_mutex_lock( &mi->mi_cache_mutex );
	mc = ( struct monitorcache * )avl_find( mi->mi_cache,
			( caddr_t )&tmp_mc, monitor_cache_cmp );

	if ( mc != NULL ) {
		/* entry is returned with mutex locked */
		monitor_cache_lock( mc->mc_e );
		ldap_pvt_thread_mutex_unlock( &mi->mi_cache_mutex );
		*ep = mc->mc_e;

		return( 0 );
	}
	
	ldap_pvt_thread_mutex_unlock( &mi->mi_cache_mutex );
	*ep = NULL;

	return( -1 );
}

/*
 * If the entry exists in cache, it is returned in locked status;
 * otherwise, if the parent exists, if it may generate volatile 
 * descendants an attempt to generate the required entry is
 * performed and, if successful, the entry is returned
 */
int
monitor_cache_dn2entry(
		struct monitorinfo      *mi,
		const char		*ndn,
		Entry			**ep
)
{
	int rc;

	char *p_ndn;
	Entry *e_parent;
	struct monitorentrypriv *mp;
		
	assert( mi != NULL );
	assert( ndn != NULL );
	assert( ep != NULL );

	rc = monitor_cache_get( mi, ndn, ep );
       	if ( !rc && *ep != NULL ) {
		return( 0 );
	}

	/* try with parent/ancestors */
	p_ndn = dn_parent( NULL, ndn );
	rc = monitor_cache_dn2entry( mi, p_ndn, &e_parent );
	free( p_ndn );
	if ( rc || e_parent == NULL) {
		return( -1 );
	}

	mp = ( struct monitorentrypriv * )e_parent->e_private;
	rc = -1;
	if ( mp->mp_flags & MONITOR_F_VOLATILE_CH ) {
		/* parent entry generates volatile children */
		rc = monitor_entry_create( mi, ndn, e_parent, ep );
	}
	monitor_cache_release( mi, e_parent );
	
	return( rc );
}

/*
 * releases the lock of the entry; if it is marked as volatile, it is
 * destroyed.
 */
int
monitor_cache_release(
	struct monitorinfo	*mi,
	Entry			*e
)
{
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );
	
	mp = ( struct monitorentrypriv * )e->e_private;

	if ( mp->mp_flags & MONITOR_F_VOLATILE ) {
		/* volatile entries do not return to cache */
		ldap_pvt_thread_mutex_destroy( &mp->mp_mutex );
		ch_free( mp );
		e->e_private = NULL;
		entry_free( e );
		return( 0 );
	}
	
	ldap_pvt_thread_mutex_unlock( &mp->mp_mutex );
	return( 0 );
}

