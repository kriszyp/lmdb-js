/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
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
	SQLHDBC 		dbh = SQL_NULL_HDBC;
	SQLHSTMT		sth = SQL_NULL_HSTMT;
	RETCODE			rc;
	int			prc = LDAP_SUCCESS;
	backsql_oc_map_rec	*oc = NULL;
	backsql_srch_info	bsi = { 0 };
	backsql_entryID		e_id = { 0 };
	Entry			d = { 0 }, p = { 0 }, *e = NULL;
	struct berval		pdn = BER_BVNULL;
	int			manageDSAit = get_manageDSAit( op );
	/* first parameter no */
	SQLUSMALLINT		pno = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_delete(): deleting entry \"%s\"\n",
			op->o_req_ndn.bv_val, 0, 0 );

	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			? "SQL-backend error" : NULL;
		e = NULL;
		goto done;
	}
	
	/*
	 * Get the entry
	 */
	bsi.bsi_e = &d;
	rs->sr_err = backsql_init_search( &bsi, &op->o_req_ndn,
			LDAP_SCOPE_BASE, 
			(time_t)(-1), NULL, dbh, op, rs, slap_anlist_no_attrs,
			( BACKSQL_ISF_MATCHED | BACKSQL_ISF_GET_ENTRY ) );
	switch ( rs->sr_err ) {
	case LDAP_SUCCESS:
		break;

	case LDAP_REFERRAL:
		if ( manageDSAit && !BER_BVISNULL( &bsi.bsi_e->e_nname ) &&
				dn_match( &op->o_req_ndn, &bsi.bsi_e->e_nname ) )
		{
			rs->sr_err = LDAP_SUCCESS;
			rs->sr_text = NULL;
			rs->sr_matched = NULL;
			if ( rs->sr_ref ) {
				ber_bvarray_free( rs->sr_ref );
				rs->sr_ref = NULL;
			}
			break;
		}
		e = &d;
		/* fallthru */

	default:
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"could not retrieve deleteDN ID - no such entry\n", 
			0, 0, 0 );
		if ( !BER_BVISNULL( &d.e_nname ) ) {
			/* FIXME: should always be true! */
			e = &d;

		} else {
			e = NULL;
		}
		goto done;
	}

	if ( get_assert( op ) &&
			( test_filter( op, &d, get_assertion( op ) )
			  != LDAP_COMPARE_TRUE ) )
	{
		rs->sr_err = LDAP_ASSERTION_FAILED;
		e = &d;
		goto done;
	}

	if ( !access_allowed( op, &d, slap_schema.si_ad_entry, 
			NULL, ACL_WDEL, NULL ) )
	{
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"no write access to entry\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		e = &d;
		goto done;
	}

	rs->sr_err = backsql_has_children( op, dbh, &op->o_req_ndn );
	switch ( rs->sr_err ) {
	case LDAP_COMPARE_FALSE:
		rs->sr_err = LDAP_SUCCESS;
		break;

	case LDAP_COMPARE_TRUE:
		if ( get_treeDelete( op ) ) {
			/* not supported yet */ ;
		}
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"entry \"%s\" has children\n",
			op->o_req_dn.bv_val, 0, 0 );
		rs->sr_err = LDAP_NOT_ALLOWED_ON_NONLEAF;
		rs->sr_text = "subordinate objects must be deleted first";
		/* fallthru */

	default:
		e = &d;
		goto done;
	}

	oc = backsql_id2oc( bi, bsi.bsi_base_id.eid_oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		e = NULL;
 		goto done;
	}

	if ( oc->bom_delete_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"delete procedure is not defined "
			"for this objectclass - aborting\n", 0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		e = NULL;
		goto done;
	}

	/*
	 * Get the parent
	 */
	e_id = bsi.bsi_base_id;
	if ( !be_issuffix( op->o_bd, &op->o_req_ndn ) ) {
		dnParent( &op->o_req_ndn, &pdn );
		bsi.bsi_e = &p;
		rs->sr_err = backsql_init_search( &bsi, &pdn,
				LDAP_SCOPE_BASE, 
				(time_t)(-1), NULL, dbh, op, rs,
				slap_anlist_no_attrs,
				BACKSQL_ISF_GET_ENTRY );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
				"could not retrieve deleteDN ID "
				"- no such entry\n", 
				0, 0, 0 );
			e = &p;
			goto done;
		}

		(void)backsql_free_entryID( op, &bsi.bsi_base_id, 0 );

		/* check parent for "children" acl */
		if ( !access_allowed( op, &p, slap_schema.si_ad_children, 
				NULL, ACL_WDEL, NULL ) )
		{
			Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
				"no write access to parent\n", 
				0, 0, 0 );
			rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
			e = &p;
			goto done;

		}
	}

	/* avl_apply ... */
	rs->sr_err = backsql_delete_all_attrs( op, rs, dbh, &e_id, oc );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		e = &d;
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
		e = NULL;
		goto done;
	}

	if ( BACKSQL_IS_DEL( oc->bom_expect_return ) ) {
		pno = 1;
		rc = backsql_BindParamInt( sth, 1, SQL_PARAM_OUTPUT, &prc );
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
			e = NULL;
			goto done;
		}
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
		e = NULL;
		goto done;
	}

	rc = SQLExecute( sth );
	if ( rc == SQL_SUCCESS && prc == LDAP_SUCCESS ) {
		rs->sr_err = LDAP_SUCCESS;

	} else {
		Debug( LDAP_DEBUG_TRACE, "   backsql_delete(): "
			"delete_proc execution failed (rc=%d, prc=%d)\n",
			rc, prc, 0 );


		if ( prc != LDAP_SUCCESS ) {
			/* SQL procedure executed fine 
			 * but returned an error */
			rs->sr_err = BACKSQL_SANITIZE_ERROR( prc );

		} else {
			backsql_PrintErrors( bi->sql_db_env, dbh,
					sth, rc );
			rs->sr_err = LDAP_OTHER;
		}
		SQLFreeStmt( sth, SQL_DROP );
		e = &d;
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	/* delete "auxiliary" objectClasses, if any... */
	rc = backsql_Prepare( dbh, &sth, bi->sql_delobjclasses_stmt, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_entry_objclasses delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		e = NULL;
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
		e = NULL;
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
		e = NULL;
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	/* delete entry... */
	rc = backsql_Prepare( dbh, &sth, bi->sql_delentry_stmt, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_delete(): "
			"error preparing ldap_entries delete query\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->sql_db_env, dbh, sth, rc );

		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		e = NULL;
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
		e = NULL;
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
		e = NULL;
		goto done;
	}
	SQLFreeStmt( sth, SQL_DROP );

	rs->sr_err = LDAP_SUCCESS;

	/*
	 * Commit only if all operations succeed
	 */
	if ( sth != SQL_NULL_HSTMT ) {
		SQLUSMALLINT	CompletionType = SQL_ROLLBACK;
	
		if ( rs->sr_err == LDAP_SUCCESS && !op->o_noop ) {
			assert( e == NULL );
			CompletionType = SQL_COMMIT;
		}

		SQLTransact( SQL_NULL_HENV, dbh, CompletionType );
	}

done:;
#ifdef SLAP_ACL_HONOR_DISCLOSE
	if ( e != NULL ) {
		if ( !access_allowed( op, e, slap_schema.si_ad_entry, NULL,
					ACL_DISCLOSE, NULL ) )
		{
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			rs->sr_text = NULL;
			rs->sr_matched = NULL;
			if ( rs->sr_ref ) {
				ber_bvarray_free( rs->sr_ref );
				rs->sr_ref = NULL;
			}
		}
	}
#endif /* SLAP_ACL_HONOR_DISCLOSE */

	if ( op->o_noop && rs->sr_err == LDAP_SUCCESS ) {
		rs->sr_err = LDAP_X_NO_OPERATION;
	}

	send_ldap_result( op, rs );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_delete()\n", 0, 0, 0 );

	if ( !BER_BVISNULL( &e_id.eid_ndn ) ) {
		(void)backsql_free_entryID( op, &e_id, 0 );
	}

	if ( !BER_BVISNULL( &d.e_nname ) ) {
		backsql_entry_clean( op, &d );
	}

	if ( !BER_BVISNULL( &p.e_nname ) ) {
		backsql_entry_clean( op, &p );
	}

	if ( rs->sr_ref ) {
		ber_bvarray_free( rs->sr_ref );
		rs->sr_ref = NULL;
	}

	return rs->sr_err;
}

