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
#include "ac/string.h"

#include "slap.h"
#include "proto-sql.h"

int
backsql_modify( Operation *op, SlapReply *rs )
{
	backsql_info		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh = SQL_NULL_HDBC;
	backsql_oc_map_rec	*oc = NULL;
	backsql_srch_info	bsi = { 0 };
	Entry			e = { 0 };

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
		goto done;
	}

	/* FIXME: using all attributes because of access control later ... */
	rs->sr_err = backsql_init_search( &bsi, &op->o_req_ndn,
			LDAP_SCOPE_BASE, 
			SLAP_NO_LIMIT, SLAP_NO_LIMIT,
			(time_t)(-1), NULL, dbh, op, rs,
			slap_anlist_all_attributes,
			BACKSQL_ISF_GET_ID );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"could not retrieve modifyDN ID - no such entry\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
		goto done;
	}

	bsi.bsi_e = &e;
	rs->sr_err = backsql_id2entry( &bsi, &bsi.bsi_base_id );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"error %d in backsql_id2entry()\n",
			rs->sr_err, 0, 0 );
		goto done;
	}

#ifdef BACKSQL_ARBITRARY_KEY
	Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
		"modifying entry \"%s\" (id=%s)\n", 
		bsi.bsi_base_id.eid_dn.bv_val,
		bsi.bsi_base_id.eid_id.bv_val, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
	Debug( LDAP_DEBUG_TRACE, "   backsql_modify(): "
		"modifying entry \"%s\" (id=%ld)\n", 
		bsi.bsi_base_id.eid_dn.bv_val, bsi.bsi_base_id.eid_id, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

	oc = backsql_id2oc( bi, bsi.bsi_base_id.eid_oc_id );
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
		goto done;
	}

	e.e_attrs = NULL;
	e.e_name = op->o_req_dn;
	e.e_nname = op->o_req_ndn;
	if ( !acl_check_modlist( op, &e, op->oq_modify.rs_modlist ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;

	} else {
		rs->sr_err = backsql_modify_internal( op, rs, dbh, oc,
				&bsi.bsi_base_id,
				op->oq_modify.rs_modlist );
	}

	if ( rs->sr_err == LDAP_SUCCESS ) {
		/*
		 * Commit only if all operations succeed
		 */
		SQLTransact( SQL_NULL_HENV, dbh, 
				op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );
	}

done:;
	send_ldap_result( op, rs );

	if ( !BER_BVISNULL( &bsi.bsi_base_id.eid_ndn ) ) {
		(void)backsql_free_entryID( &bsi.bsi_base_id, 0 );
	}

	if ( bsi.bsi_e != NULL ) {
		entry_clean( bsi.bsi_e );
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify()\n", 0, 0, 0 );

	return rs->sr_err != LDAP_SUCCESS ? rs->sr_err : op->o_noop;
}

