/* search.c - monitor backend search function */
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

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-monitor.h"
#include "proto-back-monitor.h"

static int
monitor_send_children(
	Backend		*be,
    	Connection	*conn,
    	Operation	*op,
    	Filter		*filter,
    	AttributeName	*attrs,
    	int		attrsonly,
	Entry		*e_parent,
	int		sub,
	int		*nentriesp
)
{
	struct monitorinfo	*mi = (struct monitorinfo *) be->be_private;
	Entry 			*e, *e_tmp, *e_ch;
	struct monitorentrypriv *mp;
	int			nentries;
	int			rc;

	mp = ( struct monitorentrypriv * )e_parent->e_private;
	e = mp->mp_children;

	e_ch = NULL;
	if ( MONITOR_HAS_VOLATILE_CH( mp ) ) {
		monitor_entry_create( mi, NULL, e_parent, &e_ch );
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
	for ( nentries = *nentriesp; e != NULL; ) {
		mp = ( struct monitorentrypriv * )e->e_private;

		monitor_entry_update( mi, e );
		
		rc = test_filter( be, conn, op, e, filter );
		if ( rc == LDAP_COMPARE_TRUE ) {
			send_search_entry( be, conn, op, e, 
					attrs, attrsonly, NULL );
			nentries++;
		}

		if ( ( mp->mp_children || MONITOR_HAS_VOLATILE_CH( mp ) )
				&& sub ) {
			rc = monitor_send_children( be, conn, op, filter, 
					attrs, attrsonly, 
					e, sub, &nentries );
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
monitor_back_search(
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*base,
	struct berval	*nbase,
	int		scope,
	int		deref,
	int		slimit,
	int		tlimit,
	Filter		*filter,
	struct berval	*filterstr,
	AttributeName	*attrs,
	int		attrsonly 
)
{
	struct monitorinfo	*mi = (struct monitorinfo *) be->be_private;
	int		rc;
	Entry		*e, *matched = NULL;
	int		nentries = 0;

#ifdef NEW_LOGGING
	LDAP_LOG(( "backend", LDAP_LEVEL_ENTRY,
		   "monitor_back_search: enter\n" ));
#else
	Debug(LDAP_DEBUG_TRACE, "=> monitor_back_search\n%s%s%s", "", "", "");
#endif


	/* get entry with reader lock */
	monitor_cache_dn2entry( mi, nbase, &e, &matched );
	if ( e == NULL ) {
		send_ldap_result( conn, op, LDAP_NO_SUCH_OBJECT,
			matched ? matched->e_dn : NULL, 
			NULL, NULL, NULL );
		if ( matched ) {
			monitor_cache_release( mi, matched );
		}

		return( 0 );
	}

	nentries = 0;
	switch ( scope ) {
	case LDAP_SCOPE_BASE:
		monitor_entry_update( mi, e );
		rc = test_filter( be, conn, op, e, filter );
 		if ( rc == LDAP_COMPARE_TRUE ) {			
			send_search_entry( be, conn, op, e, attrs, 
					attrsonly, NULL );
			nentries = 1;
		}
		monitor_cache_release( mi, e );
		break;

	case LDAP_SCOPE_ONELEVEL:
		rc = monitor_send_children( be, conn, op, filter,
				attrs, attrsonly,
				e, 0, &nentries );
		if ( rc ) {
			// error
		}		
		
		break;

	case LDAP_SCOPE_SUBTREE:
		monitor_entry_update( mi, e );
		rc = test_filter( be, conn, op, e, filter );
		if ( rc == LDAP_COMPARE_TRUE ) {
			send_search_entry( be, conn, op, e, attrs,
					attrsonly, NULL );
			nentries++;
		}

		rc = monitor_send_children( be, conn, op, filter,
				attrs, attrsonly,
				e, 1, &nentries );
		if ( rc ) {
			// error
		}

		break;
	}
	
	send_search_result( conn, op, LDAP_SUCCESS,
			NULL, NULL, NULL, NULL, nentries );

	return( 0 );
}
