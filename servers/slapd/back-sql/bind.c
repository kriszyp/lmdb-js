/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
 * Portions Copyright 2002 Pierangelo Masarati.
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
 * by OpenLDAP Software.  Additional significant contributors include
 * Pierangelo Masarati.
 */

#include "portable.h"

#include <stdio.h>
#include <sys/types.h>

#include "slap.h"
#include "proto-sql.h"

int 
backsql_bind( Operation *op, SlapReply *rs )
{
	SQLHDBC			dbh = SQL_NULL_HDBC;
	Entry			*e = NULL,
				user_entry = { 0 };
	Attribute		*a;
	backsql_srch_info	bsi;
	AttributeName		anlist[2];
	int			rc;
 
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
	if ( !dbh ) {
     		Debug( LDAP_DEBUG_TRACE, "backsql_bind(): "
			"could not get connection handle - exiting\n",
			0, 0, 0 );

		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		send_ldap_result( op, rs );
		return 1;
	}

	anlist[0].an_name = slap_schema.si_ad_userPassword->ad_cname;
	anlist[0].an_desc = slap_schema.si_ad_userPassword;
	anlist[1].an_name.bv_val = NULL;

	rc = backsql_init_search( &bsi, &op->o_req_ndn, LDAP_SCOPE_BASE, 
			SLAP_NO_LIMIT, SLAP_NO_LIMIT,
			(time_t)(-1), NULL, dbh, op, rs, anlist,
			BACKSQL_ISF_GET_ID );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_bind(): "
			"could not retrieve bindDN ID - no such entry\n", 
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

	a = attr_find( e->e_attrs, slap_schema.si_ad_userPassword );
	if ( a == NULL ) {
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto error_return;
	}

	if ( slap_passwd_check( op, e, a, &op->oq_bind.rb_cred,
				&rs->sr_text ) != 0 )
	{
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		goto error_return;
	}

error_return:;
	if ( !BER_BVISNULL( &bsi.bsi_base_id.eid_ndn ) ) {
		(void)backsql_free_entryID( &bsi.bsi_base_id, 0 );
	}

	if ( e ) {
		entry_clean( e );
	}

	if ( rs->sr_err ) {
		send_ldap_result( op, rs );
		return 1;
	}
	
	Debug(LDAP_DEBUG_TRACE,"<==backsql_bind()\n",0,0,0);

	return 0;
}
 
