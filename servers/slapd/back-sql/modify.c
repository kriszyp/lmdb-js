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
#include "ac/string.h"

#include "slap.h"
#include "ldap_pvt.h"
#include "proto-sql.h"

int
backsql_modify( Operation *op, SlapReply *rs )
{
	backsql_info		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh;
	backsql_oc_map_rec	*oc = NULL;
	backsql_entryID		e_id;
	Entry			e;

	/*
	 * FIXME: in case part of the operation cannot be performed
	 * (missing mapping, SQL write fails or so) the entire operation
	 * should be rolled-back
	 */
	Debug( LDAP_DEBUG_TRACE, "==>backsql_modify(): modifying entry \"%s\"\n",
		op->o_req_ndn.bv_val, 0, 0 );

	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		send_ldap_result( op, rs );
		return 1;
	}

	rs->sr_err = backsql_dn2id( bi, &e_id, dbh, &op->o_req_ndn );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
			"could not lookup entry id\n", 0, 0, 0 );
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		send_ldap_result( op, rs );
		return 1;
	}

	Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
		"modifying entry \"%s\" (id=%ld)\n", 
		e_id.dn.bv_val, e_id.id, 0 );

	oc = backsql_id2oc( bi, e_id.oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		/*
		 * FIXME: should never occur, since the entry was built!!!
		 */

		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		send_ldap_result( op, rs );
		return 1;
	}

	e.e_attrs = NULL;
	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;
	if ( !acl_check_modlist( op, &e, op->oq_modify.rs_modlist ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;

	} else {
		rs->sr_err = backsql_modify_internal( op, rs, dbh, oc, &e_id,
				op->oq_modify.rs_modlist );
	}

	if ( rs->sr_err == LDAP_SUCCESS ) {
		/*
		 * Commit only if all operations succeed
		 */
		SQLTransact( SQL_NULL_HENV, dbh, 
				op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );
	}
	send_ldap_result( op, rs );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify()\n", 0, 0, 0 );

	return op->o_noop;
}

#endif /* SLAPD_SQL */

