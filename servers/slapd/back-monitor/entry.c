/* entry.c - monitor backend entry handling routines */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
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

#include <slap.h>
#include "back-monitor.h"

int
monitor_entry_update(
	struct monitorinfo 	*mi, 
	Entry 			*e
)
{
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( struct monitorentrypriv * )e->e_private;


	if ( mp->mp_info && mp->mp_info->mss_update ) {
		return ( *mp->mp_info->mss_update )( mi, e );
	}

	return( 0 );
}

int
monitor_entry_create(
	struct monitorinfo 	*mi,
	struct berval		*ndn,
	Entry			*e_parent,
	Entry			**ep
)
{
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e_parent != NULL );
	assert( e_parent->e_private != NULL );
	assert( ep != NULL );

	mp = ( struct monitorentrypriv * )e_parent->e_private;

	if ( mp->mp_info && mp->mp_info->mss_create ) {
		return ( *mp->mp_info->mss_create )( mi, ndn, e_parent, ep );
	}
	
	return( 0 );
}

int
monitor_entry_modify(
	struct monitorinfo 	*mi, 
	Entry 			*e,
	Modifications		*modlist
)
{
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( struct monitorentrypriv * )e->e_private;

	if ( mp->mp_info && mp->mp_info->mss_modify ) {
		return ( *mp->mp_info->mss_modify )( mi, e, modlist );
	}

	return( 0 );
}

int
monitor_entry_test_flags(
	struct monitorentrypriv	*mp,
	int			cond
)
{
	assert( mp != NULL );

	return( ( mp->mp_flags & cond ) || ( mp->mp_info->mss_flags & cond ) );
}

