/* bind.c - DNS SRV backend bind function */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "external.h"

int
dnssrv_back_bind(
    Operation		*op,
    SlapReply		*rs )
{
	Debug( LDAP_DEBUG_TRACE, "DNSSRV: bind %s (%d)\n",
		op->o_req_dn.bv_val == NULL ? "" : op->o_req_dn.bv_val, 
		op->oq_bind.rb_method, NULL );
		
	if( op->oq_bind.rb_method == LDAP_AUTH_SIMPLE && op->oq_bind.rb_cred.bv_val != NULL && op->oq_bind.rb_cred.bv_len ) {
		Statslog( LDAP_DEBUG_STATS,
		   	"conn=%lu op=%lu DNSSRV BIND dn=\"%s\" provided passwd\n",
	   		 op->o_connid, op->o_opid,
			op->o_req_dn.bv_val == NULL ? "" : op->o_req_dn.bv_val , 0, 0 );

		Debug( LDAP_DEBUG_TRACE,
			"DNSSRV: BIND dn=\"%s\" provided cleartext password\n",
			op->o_req_dn.bv_val == NULL ? "" : op->o_req_dn.bv_val, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"you shouldn\'t send strangers your password" );

	} else {
		Debug( LDAP_DEBUG_TRACE, "DNSSRV: BIND dn=\"%s\"\n",
			op->o_req_dn.bv_val == NULL ? "" : op->o_req_dn.bv_val, 0, 0 );

		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
			"anonymous bind expected" );
	}

	return 1;
}
