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
#include "proto-sql.h"

typedef struct backsql_delete_attr_t {
	Operation 		*op;
	SlapReply		*rs;
	SQLHDBC			dbh; 
	backsql_entryID		*e_id;
} backsql_delete_attr_t;

static int
backsql_delete_attr_f( void *v_at, void *v_bda )
{
	backsql_at_map_rec	*at = (backsql_at_map_rec *)v_at;
	backsql_delete_attr_t	*bda = (backsql_delete_attr_t *)v_bda;
	int			rc;

	rc = backsql_modify_delete_all_values( bda->op,
			bda->rs, bda->dbh, bda->e_id, at );

	if ( rc != LDAP_SUCCESS ) {
		return BACKSQL_AVL_STOP;
	}

	return BACKSQL_AVL_CONTINUE;
}

static int
backsql_delete_all_attrs(
	Operation 		*op,
	SlapReply		*rs,
	SQLHDBC			dbh, 
	backsql_entryID		*e_id,
	backsql_oc_map_rec	*oc )
{
	backsql_delete_attr_t	bda;
	int			rc;

	bda.op = op;
	bda.rs = rs;
	bda.dbh = dbh;
	bda.e_id = e_id;
	
	rc = avl_apply( oc->bom_attrs, backsql_delete_attr_f, &bda,
			BACKSQL_AVL_STOP, AVL_INORDER );
	if ( rc == BACKSQL_AVL_STOP ) {
		return rs->sr_err;
	}

	return LDAP_SUCCESS;
}

int
backsql_delete( Operation *op, SlapReply *rs )
{
	backsql_info 		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT		sth;
	RETCODE			rc;
	int			retval;
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
	
	/* FIXME: API... */
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

	/* avl_apply ... */
	rs->sr_err = backsql_delete_all_attrs( op, rs, dbh, &e_id, oc );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		goto done;
	}

	rc = backsql_Prepare( dbh, &sth, oc->bom_delete_proc, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	if ( BACKSQL_IS_DEL( oc->bom_expect_return ) ) {
		pno = 1;
		rc = backsql_BindParamInt( sth, 1, SQL_PARAM_OUTPUT, &retval );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_delete(): "
				"error binding output parameter for objectClass %s\n",
				oc->bom_oc->soc_cname.bv_val, 0, 0 );
			backsql_PrintErrors( bi->sql_db_env, dbh, 
				sth, rc );
			SQLFreeStmt( sth, SQL_DROP );

			rs->sr_text = "SQL-backend error";
			rs->sr_err = LDAP_OTHER;
			goto done;
		}

	} else {
		pno = 0;
	}

	rc = backsql_BindParamID( sth, pno + 1, SQL_PARAM_INPUT, &e_id.eid_keyval );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error binding keyval parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"delete_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	/* delete "auxiliary" objectClasses, if any... */
	rc = backsql_Prepare( dbh, &sth, bi->sql_delobjclasses_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_entry_objclasses delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rc = backsql_BindParamID( sth, 1, SQL_PARAM_INPUT, &e_id.eid_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error binding auxiliary objectClasses "
			"entry ID parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = SQLExecute( sth );
	switch ( rc ) {
	case SQL_NO_DATA:
		/* apparently there were no "auxiliary" objectClasses
		 * for this entry... */
	case SQL_SUCCESS:
		break;

	default:
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"failed to delete record from ldap_entry_objclasses\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	/* delete referrals, if any... */
	rc = backsql_Prepare( dbh, &sth, bi->sql_delreferrals_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_referrals delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rc = backsql_BindParamID( sth, 1, SQL_PARAM_INPUT, &e_id.eid_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error binding referrals entry ID parameter "
			"for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = SQLExecute( sth );
	switch ( rc ) {
	case SQL_NO_DATA:
		/* apparently there were no referrals
		 * for this entry... */
	case SQL_SUCCESS:
		break;

	default:
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"failed to delete record from ldap_referrals\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	/* delete entry... */
	rc = backsql_Prepare( dbh, &sth, bi->sql_delentry_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_entries delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rc = backsql_BindParamID( sth, 1, SQL_PARAM_INPUT, &e_id.eid_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error binding entry ID parameter "
			"for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"failed to delete record from ldap_entries\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

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

