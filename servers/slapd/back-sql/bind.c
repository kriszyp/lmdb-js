/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
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
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>

#include "slap.h"
#include "proto-sql.h"

int 
backsql_bind( Operation *op, SlapReply *rs )
{
	SQLHDBC			dbh;
	AttributeDescription	*password = slap_schema.si_ad_userPassword;
	Entry			*e, user_entry;
	Attribute		*a;
	backsql_srch_info	bsi;
	AttributeName		anlist[2];
	int			rc;
	struct berval		dn;
 
 	Debug( LDAP_DEBUG_TRACE, "==>backsql_bind()\n", 0, 0, 0 );

	if ( be_isroot_pw( op ) ) {
     		ber_dupbv( &op->oq_bind.rb_edn, be_root_dn( op->o_bd ) );
		Debug( LDAP_DEBUG_TRACE, "<==backsql_bind() root bind\n", 
				0, 0, 0 );
		return 0;
	}

	ber_dupbv( &op->oq_bind.rb_edn, &op->o_req_ndn );

	if ( op->oq_bind.rb_method != LDAP_AUTH_SIMPLE ) {
		rs->sr_err = LDAP_STRONG_AUTH_NOT_SUPPORTED;
		rs->sr_text = "authentication method not supported"; 
		send_ldap_result( op, rs );
		return 1;
	}

	/*
	 * method = LDAP_AUTH_SIMPLE
	 */
	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if (!dbh) {
     		Debug( LDAP_DEBUG_TRACE, "backsql_bind(): "
			"could not get connection handle - exiting\n",
			0, 0, 0 );

		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		send_ldap_result( op, rs );
		return 1;
	}

	dn = op->o_req_dn;
	if ( backsql_api_dn2odbc( op, rs, &dn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"backsql_api_dn2odbc failed\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto error_return;
	}

	anlist[0].an_name = password->ad_cname;
	anlist[0].an_desc = password;
	anlist[1].an_name.bv_val = NULL;

	rc = backsql_init_search( &bsi, &dn, LDAP_SCOPE_BASE, 
			-1, -1, -1, NULL, dbh, op, rs, anlist, 1 );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_bind(): "
			"could not retrieve bind dn id - no such entry\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		send_ldap_result( op, rs );
		return 1;
	}

	bsi.bsi_e = &user_entry;
	rc = backsql_id2entry( &bsi, &bsi.bsi_base_id );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_bind(): "
			"error %d in backsql_id2entry() "
			"- auth failed\n", rc, 0, 0 );
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto error_return;
	}
	e = &user_entry;

	if ( ! access_allowed( op, e, password, NULL, ACL_AUTH, NULL ) ) {
#if 1
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
#else
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
#endif
		goto error_return;
	}

	a = attr_find( e->e_attrs, password );
	if ( a == NULL ) {
#if 1
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
#else
		rs->sr_err = LDAP_INAPPROPRIATE_AUTH;
#endif
		goto error_return;
	}

	if ( slap_passwd_check( op->o_conn, a, &op->oq_bind.rb_cred, &rs->sr_text ) != 0 ) {
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto error_return;
	}

error_return:;
	if ( !BER_BVISNULL( &bsi.bsi_base_id.eid_dn ) ) {
		(void)backsql_free_entryID( &bsi.bsi_base_id, 0 );
	}

	if ( rs->sr_err ) {
		send_ldap_result( op, rs );
		return 1;
	}
	
	if ( dn.bv_val != op->o_req_dn.bv_val ) {
		ch_free( dn.bv_val );
	}

	Debug(LDAP_DEBUG_TRACE,"<==backsql_bind()\n",0,0,0);
	return 0;
}
 
#endif /* SLAPD_SQL */

