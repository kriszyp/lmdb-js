/* entry.c - monitor backend entry handling routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <slap.h>
#include "back-monitor.h"

int
monitor_entry_update(
	Operation		*op,
	Entry 			*e
)
{
	struct monitorinfo	*mi =
		(struct monitorinfo *)op->o_bd->be_private;
	struct monitorentrypriv *mp;
	int			rc = 0;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( struct monitorentrypriv * )e->e_private;

	if ( mp->mp_info && mp->mp_info->mss_update ) {
		rc = ( *mp->mp_info->mss_update )( op, e );
	}

	if ( rc == 0 && mp->mp_update ) {
		rc = ( *mp->mp_update )( op, e );
	}

	return rc;
}

int
monitor_entry_create(
	Operation		*op,
	struct berval		*ndn,
	Entry			*e_parent,
	Entry			**ep
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e_parent != NULL );
	assert( e_parent->e_private != NULL );
	assert( ep != NULL );

	mp = ( struct monitorentrypriv * )e_parent->e_private;

	if ( mp->mp_info && mp->mp_info->mss_create ) {
		return ( *mp->mp_info->mss_create )( op, ndn, e_parent, ep );
	}
	
	return( 0 );
}

int
monitor_entry_modify(
	Operation		*op,
	Entry 			*e
)
{
	struct monitorinfo *mi = (struct monitorinfo *)op->o_bd->be_private;
	struct monitorentrypriv *mp;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( struct monitorentrypriv * )e->e_private;

	if ( mp->mp_info && mp->mp_info->mss_modify ) {
		return ( *mp->mp_info->mss_modify )( op, e );
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

struct monitorentrypriv *
monitor_entrypriv_create( void )
{
	struct monitorentrypriv	*mp;

	mp = ( struct monitorentrypriv * )ch_calloc( sizeof( struct monitorentrypriv ), 1 );

	mp->mp_next = NULL;
	mp->mp_children = NULL;
	mp->mp_info = NULL;
	mp->mp_flags = MONITOR_F_NONE;
	mp->mp_update = NULL;
	mp->mp_private = NULL;

	return mp;
}
