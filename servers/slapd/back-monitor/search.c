/* search.c - monitor backend search function */
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

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-monitor.h"
#include "proto-back-monitor.h"

static int
monitor_send_children(
	Operation	*op,
	SlapReply	*rs,
	Entry		*e_parent,
	int		sub
)
{
	struct monitorinfo	*mi =
		(struct monitorinfo *) op->o_bd->be_private;
	Entry 			*e, *e_tmp, *e_ch;
	struct monitorentrypriv *mp;
	int			rc;

	mp = ( struct monitorentrypriv * )e_parent->e_private;
	e = mp->mp_children;

	e_ch = NULL;
	if ( MONITOR_HAS_VOLATILE_CH( mp ) ) {
		monitor_entry_create( op, NULL, e_parent, &e_ch );
	}
	monitor_cache_release( mi, e_parent );

	/* no volatile entries? */
	if ( e_ch == NULL ) {
		/* no persistent entries? return */
		if ( e == NULL ) {
			return( 0 );
		}
	
	/* volatile entries */
	} else {
		/* if no persistent, return only volatile */
		if ( e == NULL ) {
			e = e_ch;
			monitor_cache_lock( e_ch );

		/* else append persistent to volatile */
		} else {
			e_tmp = e_ch;
			do {
				mp = ( struct monitorentrypriv * )e_tmp->e_private;
				e_tmp = mp->mp_next;
	
				if ( e_tmp == NULL ) {
					mp->mp_next = e;
					break;
				}
			} while ( e_tmp );
			e = e_ch;
		}
	}

	/* return entries */
	for ( ; e != NULL; ) {
		mp = ( struct monitorentrypriv * )e->e_private;

		monitor_entry_update( op, e );
		
		rc = test_filter( op, e, op->oq_search.rs_filter );
		if ( rc == LDAP_COMPARE_TRUE ) {
			rs->sr_entry = e;
			rs->sr_flags = 0;
			send_search_entry( op, rs );
			rs->sr_entry = NULL;
		}

		if ( ( mp->mp_children || MONITOR_HAS_VOLATILE_CH( mp ) )
				&& sub ) {
			rc = monitor_send_children( op, rs, e, sub );
			if ( rc ) {
				return( rc );
			}
		}

		e_tmp = mp->mp_next;
		if ( e_tmp != NULL ) {
			monitor_cache_lock( e_tmp );
		}
		monitor_cache_release( mi, e );
		e = e_tmp;
	}
	
	return( 0 );
}

int
monitor_back_search( Operation *op, SlapReply *rs )
{
	struct monitorinfo	*mi
		= (struct monitorinfo *) op->o_bd->be_private;
	int		rc = LDAP_SUCCESS;
	Entry		*e, *matched = NULL;

	Debug( LDAP_DEBUG_TRACE, "=> monitor_back_search\n", 0, 0, 0 );


	/* get entry with reader lock */
	monitor_cache_dn2entry( op, &op->o_req_ndn, &e, &matched );
	if ( e == NULL ) {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		if ( matched ) {
			rs->sr_matched = matched->e_dn;
		}

		send_ldap_result( op, rs );
		if ( matched ) {
			monitor_cache_release( mi, matched );
			rs->sr_matched = NULL;
		}

		return( 0 );
	}

	rs->sr_attrs = op->oq_search.rs_attrs;
	switch ( op->oq_search.rs_scope ) {
	case LDAP_SCOPE_BASE:
		monitor_entry_update( op, e );
		rc = test_filter( op, e, op->oq_search.rs_filter );
 		if ( rc == LDAP_COMPARE_TRUE ) {
			rs->sr_entry = e;
			rs->sr_flags = 0;
			send_search_entry( op, rs );
			rs->sr_entry = NULL;
		}
		rc = LDAP_SUCCESS;
		monitor_cache_release( mi, e );
		break;

	case LDAP_SCOPE_ONELEVEL:
		rc = monitor_send_children( op, rs, e, 0 );
		if ( rc ) {
			rc = LDAP_OTHER;
		}
		
		break;

	case LDAP_SCOPE_SUBTREE:
		monitor_entry_update( op, e );
		rc = test_filter( op, e, op->oq_search.rs_filter );
		if ( rc == LDAP_COMPARE_TRUE ) {
			rs->sr_entry = e;
			rs->sr_flags = 0;
			send_search_entry( op, rs );
			rs->sr_entry = NULL;
		}

		rc = monitor_send_children( op, rs, e, 1 );
		if ( rc ) {
			rc = LDAP_OTHER;
		}

		break;
	}
	
	rs->sr_attrs = NULL;
	rs->sr_err = rc;
	send_ldap_result( op, rs );

	return( rc == LDAP_SUCCESS ? 0 : 1 );
}

