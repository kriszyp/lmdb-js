/* bind.c - DNS SRV backend bind function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2008 The OpenLDAP Foundation.
 * Portions Copyright 2000-2003 Kurt D. Zeilenga.
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
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by Kurt D. Zeilenga for inclusion
 * in OpenLDAP Software.
 */


#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "proto-dnssrv.h"

int
dnssrv_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	Debug( LDAP_DEBUG_TRACE, "DNSSRV: bind %s (%d)\n",
		op->o_req_dn.bv_val == NULL ? "" : op->o_req_dn.bv_val, 
		op->oq_bind.rb_method, NULL );
		
	if ( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE &&
		!BER_BVISNULL( &op->oq_bind.rb_cred ) &&
		!BER_BVISEMPTY( &op->oq_bind.rb_cred ) )
	{
		Statslog( LDAP_DEBUG_STATS,
		   	"%s DNSSRV BIND dn=\"%s\" provided passwd\n",
	   		op->o_log_prefix,
			BER_BVISNULL( &op->o_req_dn ) ? "" : op->o_req_dn.bv_val , 0, 0, 0 );

		Debug( LDAP_DEBUG_TRACE,
			"DNSSRV: BIND dn=\"%s\" provided cleartext password\n",
			BER_BVISNULL( &op->o_req_dn ) ? "" : op->o_req_dn.bv_val, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"you shouldn't send strangers your password" );

	} else {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: BIND dn=\"%s\"\n",
			BER_BVISNULL( &op->o_req_dn ) ? "" : op->o_req_dn.bv_val, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"anonymous bind expected" );
	}

	return 1;
}
