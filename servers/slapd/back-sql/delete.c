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
backsql_delete( Operation *op, SlapReply *rs )
{
	backsql_info 		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_oc_map_rec	*oc = NULL;
	backsql_entryID		e_id = BACKSQL_ENTRYID_INIT;
	Entry			e;
	/* first parameter no */
	SQLUSMALLINT		pno;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_delete(): deleting entry \"%s\"\n",
			op->o_req_ndn.bv_val, 0, 0 );

	dnParent( &op->o_req_dn, &e.e_name );
	dnParent( &op->o_req_ndn, &e.e_nname );
	e.e_attrs = NULL;

	/* check parent for "children" acl */
	if ( !access_allowed( op, &e, slap_schema.si_ad_children, 
			NULL, ACL_WRITE, NULL ) ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"no write access to parent\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto done;

	}
	
	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		goto done;
	}
	
	rs->sr_err = backsql_dn2id( bi, &e_id, dbh, &op->o_req_ndn );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"could not lookup entry id\n", 0, 0, 0 );
		goto done;
	}

	rs->sr_err = backsql_has_children( bi, dbh, &op->o_req_ndn );
	switch ( rs->sr_err ) {
	case LDAP_COMPARE_TRUE:
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"entry \"%s\" has children\n",
			op->o_req_dn.bv_val, 0, 0 );
		rs->sr_err = LDAP_NOT_ALLOWED_ON_NONLEAF;
		rs->sr_text = "subtree delete not supported";
		goto done;

	case LDAP_COMPARE_FALSE:
		break;

	default:
		goto done;
	}

	oc = backsql_id2oc( bi, e_id.eid_oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
 		goto done;
	}

	if ( oc->bom_delete_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"delete procedure is not defined "
			"for this objectclass - aborting\n", 0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;
	}

	SQLAllocStmt( dbh, &sth );

	rc = backsql_Prepare( dbh, &sth, oc->bom_delete_proc, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	if ( BACKSQL_IS_DEL( oc->bom_expect_return ) ) {
		pno = 1;
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG,
				SQL_INTEGER, 0, 0, &rc, 0, 0 );
	} else {
		pno = 0;
	}

#ifdef BACKSQL_ARBITRARY_KEY
	SQLBindParameter( sth, pno + 1, SQL_PARAM_INPUT, 
			SQL_C_CHAR, SQL_VARCHAR, 0, 0, e_id.eid_keyval.bv_val,
			0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
	SQLBindParameter( sth, pno + 1, SQL_PARAM_INPUT, 
			SQL_C_ULONG, SQL_INTEGER, 0, 0, &e_id.eid_keyval,
			0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"delete_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
#ifndef BACKSQL_REALLOC_STMT
	SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
	SQLFreeStmt( sth, SQL_DROP );
	SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */

	rc = backsql_Prepare( dbh, &sth, bi->delentry_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_entries delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

#ifdef BACKSQL_ARBITRARY_KEY
	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
			0, 0, e_id.eid_id.bv_val, 0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,
			0, 0, &e_id.eid_id, 0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */
	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"failed to delete record from ldap_entries\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	/*
	 * Commit only if all operations succeed
	 *
	 * FIXME: backsql_add() does not fail if add operations 
	 * are not available for some attributes, or if
	 * a multiple value add actually results in a replace, 
	 * or if a single operation on an attribute fails 
	 * for any reason
	 */
	SQLTransact( SQL_NULL_HENV, dbh, 
			op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );

	rs->sr_err = LDAP_SUCCESS;

done:;
	send_ldap_result( op, rs );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_delete()\n", 0, 0, 0 );

	return ( ( rs->sr_err == LDAP_SUCCESS ) ? op->o_noop : 1 );
}

#endif /* SLAPD_SQL */

