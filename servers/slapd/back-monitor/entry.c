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
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;
	monitor_entry_t *mp;
	int			rc = 0;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( monitor_entry_t * )e->e_private;

	if ( mp->mp_info && mp->mp_info->mss_update ) {
		rc = ( *mp->mp_info->mss_update )( op, e );
	}

	if ( rc == 0 && mp->mp_cb ) {
		struct monitor_callback_t	*mc;

		for ( mc = mp->mp_cb; mc; mc = mc->mc_next ) {
			rc = ( *mc->mc_update )( op, e, mc->mc_private );
			if ( rc != 0 ) {
				break;
			}
		}
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
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;
	monitor_entry_t *mp;

	assert( mi != NULL );
	assert( e_parent != NULL );
	assert( e_parent->e_private != NULL );
	assert( ep != NULL );

	mp = ( monitor_entry_t * )e_parent->e_private;

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
	monitor_info_t	*mi = ( monitor_info_t * )op->o_bd->be_private;
	monitor_entry_t *mp;

	assert( mi != NULL );
	assert( e != NULL );
	assert( e->e_private != NULL );

	mp = ( monitor_entry_t * )e->e_private;

	if ( mp->mp_info && mp->mp_info->mss_modify ) {
		return ( *mp->mp_info->mss_modify )( op, e );
	}

	return( 0 );
}

int
monitor_entry_test_flags(
	monitor_entry_t		*mp,
	int			cond
)
{
	assert( mp != NULL );

	return( ( mp->mp_flags & cond ) || ( mp->mp_info->mss_flags & cond ) );
}

monitor_entry_t *
monitor_entrypriv_create( void )
{
	monitor_entry_t	*mp;

	mp = ( monitor_entry_t * )ch_calloc( sizeof( monitor_entry_t ), 1 );

	mp->mp_next = NULL;
	mp->mp_children = NULL;
	mp->mp_info = NULL;
	mp->mp_flags = MONITOR_F_NONE;
	mp->mp_cb = NULL;

	return mp;
}
