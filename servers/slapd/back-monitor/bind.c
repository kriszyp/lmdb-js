/* bind.c - monitor backend bind routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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
/* This is an altered version */
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

#include <slap.h>
#include "back-monitor.h"

/*
 * At present, only rootdn can bind with simple bind
 */

int
monitor_back_bind( Operation *op, SlapReply *rs )
{
#if 0	/* not used yet */
	struct monitorinfo	*mi
		= (struct monitorinfo *) op->o_bd->be_private;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_MON, ENTRY, "monitor_back_bind: dn: %s.\n",
			op->o_req_dn.bv_val, 0, 0 );
#else
	Debug(LDAP_DEBUG_ARGS, "==> monitor_back_bind: dn: %s\n", 
			op->o_req_dn.bv_val, 0, 0 );
#endif
	
	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE 
			&& be_isroot_pw( op ) ) {
		ber_dupbv( &op->oq_bind.rb_edn, be_root_dn( op->o_bd ) );
		return( 0 );
	}

	rs->sr_err = LDAP_INVALID_CREDENTIALS;
	send_ldap_result( op, rs );

	return( 1 );
}

