/* modify.c - monitor backend modify routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2003 The OpenLDAP Foundation.
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

int
monitor_back_modify( Operation *op, SlapReply *rs )
	/*
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn,
	Modifications	*modlist
	*/
{
	int 			rc = 0;
	struct monitorinfo	*mi
		= (struct monitorinfo *) op->o_bd->be_private;
	Entry			*matched;
	Entry			*e;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_MON, ENTRY, "monitor_back_modify: enter\n", 0, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "monitor_back_modify:\n", 0, 0, 0);
#endif

	/* acquire and lock entry */
	monitor_cache_dn2entry( op, &op->o_req_ndn, &e, &matched );
	if ( e == NULL ) {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		if ( matched ) {
			rs->sr_matched = matched->e_name.bv_val;
		}
		send_ldap_result( op, rs );
		if ( matched != NULL ) {
			rs->sr_matched = NULL;
			monitor_cache_release( mi, matched );
		}
		return( 0 );
	}

	if ( !acl_check_modlist( op, e, op->oq_modify.rs_modlist )) {
		rc = LDAP_INSUFFICIENT_ACCESS;
	} else {
		rc = monitor_entry_modify( op, e );
	}

	rs->sr_err = rc;
	send_ldap_result( op, rs );

	monitor_cache_release( mi, e );

	return( 0 );
}

