/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>
#include "ac/string.h"
#include "slap.h"
#include "ldap_pvt.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "entry-id.h"
#include "util.h"

/*
 * PostgreSQL 7.0 doesn't work without :(
 */
#define	BACKSQL_REALLOC_STMT

/*
 * Skip:
 * - the first occurrence of objectClass, which is used
 *   to determine how to bulid the SQL entry (FIXME ?!?)
 * - operational attributes
 *   empty attributes (FIXME ?!?)
 */
#define	backsql_attr_skip(ad,vals) \
	( \
		( (ad) == slap_schema.si_ad_objectClass \
				&& (vals)[ 1 ].bv_val == NULL ) \
		|| is_at_operational( (ad)->ad_type ) \
		|| ( (vals)[ 0 ].bv_val == NULL ) \
	)

static int
backsql_modify_internal(
	BackendDB 		*be,
	Connection 		*conn,
	Operation 		*op,
	SQLHDBC			dbh, 
	backsql_oc_map_rec	*oc,
	backsql_entryID		*e_id,
	Modifications		*modlist,
	const char		**text )
{
	backsql_info	*bi = (backsql_info*)be->be_private;
	RETCODE		rc;
	SQLHSTMT	sth;
	Modifications	*ml;
	int		res = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
		"traversing modifications list\n", 0, 0, 0 );

	*text = NULL;

#ifndef BACKSQL_REALLOC_STMT
	SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		AttributeDescription	*ad;
		backsql_at_map_rec	*at = NULL;
		struct berval		*at_val;
		Modification		*c_mod;
		int			i;
		/* first parameter no, parameter order */
		SQLUSMALLINT		pno, po;
		/* procedure return code */
		int			prc;

#ifdef BACKSQL_REALLOC_STMT
		SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */

		c_mod = &ml->sml_mod;
		ad = c_mod->sm_desc;

		Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
			"modifying attribute '%s'\n",
			ad->ad_cname.bv_val, 0, 0 );

		if ( backsql_attr_skip( ad, c_mod->sm_bvalues ) ) {
			continue;
		}

  		at = backsql_ad2at( oc, ad );
		if ( at == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
				"attribute provided is not registered "
				"in objectClass '%s'\n",
				ad->ad_cname.bv_val, 0, 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				res = LDAP_UNWILLING_TO_PERFORM;
				*text = "operation not permitted "
					"within namingContext";
				goto done;
			}

			continue;
		}
  
		switch( c_mod->sm_op ) {
		case LDAP_MOD_REPLACE: {
			SQLHSTMT asth;
			BACKSQL_ROW_NTS row;
			
			Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
				"replacing values for attribute '%s'\n",
				at->ad->ad_cname.bv_val, 0, 0 );

			if ( at->add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"add procedure is not defined "
					"for attribute '%s' "
					"- unable to perform replacements\n",
					at->ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_UNWILLING_TO_PERFORM;
					*text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}

			if ( at->delete_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"delete procedure is not defined "
					"for attribute '%s' "
					"- adding only\n",
					at->ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_UNWILLING_TO_PERFORM;
					*text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				goto add_only;
			}
			
del_all:
			rc = backsql_Prepare( dbh, &asth, at->query, 0 );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"error preparing query\n", 0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_OTHER;
					*text = "SQL-backend error";
					goto done;
				}

				break;
			}

			rc = backsql_BindParamID( asth, 1, &e_id->keyval );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"error binding key value parameter\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_OTHER;
					*text = "SQL-backend error";
					goto done;
				}

				break;
			}
			
			rc = SQLExecute( asth );
			if ( !BACKSQL_SUCCESS( rc ) ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"error executing attribute query\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_OTHER;
					*text = "SQL-backend error";
					goto done;
				}

				break;
			}

			backsql_BindRowAsStrings( asth, &row );
			rc = SQLFetch( asth );
			for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( asth ) ) {
				for ( i = 0; i < row.ncols; i++ ) {
			   		if ( BACKSQL_IS_DEL( at->expect_return ) ) {
						pno = 1;
						SQLBindParameter(sth, 1,
							SQL_PARAM_OUTPUT,
							SQL_C_ULONG,
							SQL_INTEGER,
							0, 0, &prc, 0, 0 );
					} else {
						pno = 0;
					}
					po = ( BACKSQL_IS_DEL( at->param_order ) ) > 0;
					SQLBindParameter( sth, pno + 1 + po,
						SQL_PARAM_INPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &e_id->keyval, 0, 0 );

					/*
					 * check for syntax needed here 
					 * maybe need binary bind?
					 */
					SQLBindParameter(sth, pno + 2 - po,
						SQL_PARAM_INPUT,
						SQL_C_CHAR, SQL_CHAR,
						0, 0, row.cols[ i ],
						strlen( row.cols[ i ] ), 0 );
			 
					Debug( LDAP_DEBUG_TRACE, 
						"backsql_modify_internal(): "
						"executing '%s'\n",
						at->delete_proc, 0, 0 );
					rc = SQLExecDirect( sth,
						at->delete_proc, SQL_NTS );
					if ( rc != SQL_SUCCESS ) {
						Debug( LDAP_DEBUG_TRACE,
							"backsql_modify_internal(): "
							"delete_proc "
							"execution failed\n",
							0, 0, 0 );
						backsql_PrintErrors( bi->db_env,
								dbh, sth, rc );

						if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
							res = LDAP_OTHER;
							*text = "SQL-backend error";
							goto done;
						}
					}
#ifdef BACKSQL_REALLOC_STMT
					SQLFreeStmt( sth, SQL_DROP );
					SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */
				}
			}
			backsql_FreeRow( &row );
	   		SQLFreeStmt( asth, SQL_DROP );
	       	}
				       
		/*
		 * PASSTHROUGH - to add new attributes -- do NOT add break
		 */
		case LDAP_MOD_ADD:
		case SLAP_MOD_SOFTADD:
add_only:;
			if ( at->add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"add procedure is not defined "
					"for attribute '%s'\n",
					at->ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_UNWILLING_TO_PERFORM;
					*text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}
			
			Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
				"adding new values for attribute '%s'\n",
				at->ad->ad_cname.bv_val, 0, 0 );
			for ( i = 0, at_val = c_mod->sm_bvalues;
					at_val->bv_val != NULL; 
					i++, at_val++ ) {
				if ( BACKSQL_IS_ADD( at->expect_return ) ) {
					pno = 1;
	      				SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0);
				} else {
	      				pno = 0;
				}
				po = ( BACKSQL_IS_ADD( at->param_order ) ) > 0;
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id->keyval, 0, 0 );

				/*
				 * check for syntax needed here
				 * maybe need binary bind?
				 */
				SQLBindParameter( sth, pno + 2 - po,
					SQL_PARAM_INPUT,
					SQL_C_CHAR, SQL_CHAR,
					0, 0, at_val->bv_val, 
					at_val->bv_len, 0 );

				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"executing '%s'\n", 
					at->add_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->add_proc, 
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"backsql_modify_internal(): "
						"add_proc execution failed\n",
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						res = LDAP_OTHER;
						*text = "SQL-backend error";
						goto done;
					}
				}
#ifdef BACKSQL_REALLOC_STMT
				SQLFreeStmt( sth, SQL_DROP );
				SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */
			}
			break;
			
	      	case LDAP_MOD_DELETE:
			if ( at->delete_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"delete procedure is not defined "
					"for attribute '%s'\n",
					at->ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					res = LDAP_UNWILLING_TO_PERFORM;
					*text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}

			if ( c_mod->sm_bvalues == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"no values given to delete "
					"for attribute '%s' "
					"-- deleting all values\n",
					at->ad->ad_cname.bv_val, 0, 0 );
				goto del_all;
			}

			Debug( LDAP_DEBUG_TRACE, "backsql_modify_internal(): "
				"deleting values for attribute '%s'\n",
				at->ad->ad_cname.bv_val, 0, 0 );

			for ( i = 0, at_val = c_mod->sm_bvalues;
					at_val->bv_val != NULL;
					i++, at_val++ ) {
				if ( BACKSQL_IS_DEL( at->expect_return ) ) {
					pno = 1;
					SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0 );
				} else {
					pno = 0;
				}
				po = ( BACKSQL_IS_DEL( at->param_order ) ) > 0;
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id->keyval, 0, 0 );

				/*
				 * check for syntax needed here 
				 * maybe need binary bind?
				 */
				SQLBindParameter( sth, pno + 2 - po,
					SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR,
					0, 0, at_val->bv_val, 
					at_val->bv_len, 0 );

				Debug( LDAP_DEBUG_TRACE,
					"backsql_modify_internal(): "
					"executing '%s'\n", 
					at->delete_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->delete_proc,
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"backsql_modify_internal(): "
						"delete_proc execution "
						"failed\n", 0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						res = LDAP_OTHER;
						*text = "SQL-backend error";
						goto done;
					}
				}
#ifdef BACKSQL_REALLOC_STMT
				SQLFreeStmt( sth, SQL_DROP );
				SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */
			}
			break;
		}
#ifndef BACKSQL_REALLOC_STMT
		SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
		SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */
	}

done:;
	
#ifndef BACKSQL_REALLOC_STMT
	SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */

	/*
	 * FIXME: should fail in case one change fails?
	 */
	return res;
}

int
backsql_modify(
	BackendDB 	*be,
	Connection 	*conn,
	Operation 	*op,
	struct berval	*dn,
	struct berval	*ndn,
	Modifications 	*modlist )
{
	backsql_info		*bi = (backsql_info*)be->be_private;
	SQLHDBC 		dbh;
	backsql_oc_map_rec	*oc = NULL;
	backsql_entryID		e_id;
	Entry			e;
	int			res;
	const char		*text = NULL;

	/*
	 * FIXME: in case part of the operation cannot be performed
	 * (missing mapping, SQL write fails or so) the entire operation
	 * should be rolled-back
	 */

	Debug( LDAP_DEBUG_TRACE, "==>backsql_modify(): changing entry '%s'\n",
		ndn->bv_val, 0, 0 );
	res = backsql_get_db_conn( be, conn, &dbh );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		send_ldap_result( conn, op, res, NULL,
				res == LDAP_OTHER ?  "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res , NULL, 
				res == LDAP_OTHER ? "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
		"modifying entry '%s' (id=%ld)\n", 
		e_id.dn.bv_val, e_id.id, 0 );

	oc = backsql_id2oc( bi, e_id.oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		/*
		 * FIXME: should never occur, since the entry was built!!!
		 */

		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		send_ldap_result( conn, op, LDAP_OTHER, NULL,
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	e.e_attrs = NULL;
	e.e_name = *dn;
	e.e_nname = *ndn;
	if ( !acl_check_modlist( be, conn, op, &e, modlist )) {
		res = LDAP_INSUFFICIENT_ACCESS;

	} else {
		res = backsql_modify_internal( be, conn, op,
				dbh, oc, &e_id, modlist, &text );
	}

	if ( res == LDAP_SUCCESS ) {
		/*
		 * Commit only if all operations succeed
		 */
		SQLTransact( SQL_NULL_HENV, dbh, 
				op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );
	}
	send_ldap_result( conn, op, res, NULL, text, NULL, NULL );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify()\n", 0, 0, 0 );

	return op->o_noop;
}

int
backsql_modrdn(
	BackendDB 	*be,
	Connection 	*conn,
	Operation 	*op,
	struct berval	*dn,
	struct berval	*ndn,
	struct berval	*newrdn,
	struct berval	*nnewrdn,
	int 		deleteoldrdn,
	struct berval	*newSuperior,
	struct berval	*nnewSuperior )
{
	backsql_info		*bi = (backsql_info*)be->be_private;
	SQLHDBC			dbh;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_entryID		e_id, pe_id, new_pid;
	backsql_oc_map_rec	*oc = NULL;
	int			res;
	struct berval		p_dn, p_ndn,
				*new_pdn = NULL, *new_npdn = NULL,
				new_dn, new_ndn;
	const char		*text = NULL;
	LDAPRDN			*new_rdn = NULL;
	LDAPRDN			*old_rdn = NULL;
	Entry			e;
	Modifications		*mod;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_modrdn() renaming entry '%s', "
			"newrdn='%s', newSuperior='%s'\n",
			dn->bv_val, newrdn->bv_val, 
			newSuperior ? newSuperior->bv_val : "(NULL)" );
	res = backsql_get_db_conn( be, conn, &dbh );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, res, NULL,
				res == LDAP_OTHER ?  "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, NULL,
				res == LDAP_OTHER ?  "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	/*
	 * FIXME: check whether entry has children
	 */

	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): entry id is %ld\n",
		e_id.id, 0, 0 );

	if ( backsql_has_children( bi, dbh, ndn ) == LDAP_COMPARE_TRUE ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"entry \"%s\" has children\n", dn->bv_val, 0, 0 );
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
                        	NULL, "subtree delete not supported",
				NULL, NULL );
		return 1;
	}

	dnParent( dn, &p_dn );
	dnParent( ndn, &p_ndn );

	/*
	 * namingContext "" is not supported
	 */
	if ( p_dn.bv_len == 0 ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"parent is \"\" - aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, 
				NULL, "not allowed within namingContext", 
				NULL, NULL );
		goto modrdn_return;
	}

	/*
	 * Check for children access to parent
	 */
	e.e_attrs = NULL;
	e.e_name = p_dn;
	e.e_nname = p_ndn;
	if ( !access_allowed( be, conn, op, &e, slap_schema.si_ad_children, 
				NULL, ACL_WRITE, NULL ) ) {
		Debug( LDAP_DEBUG_TRACE, "no access to parent\n", 0, 0, 0 );
		res = LDAP_INSUFFICIENT_ACCESS;
		goto modrdn_return;
	}

	if ( newSuperior ) {
		/*
		 * namingContext "" is not supported
		 */
		if ( newSuperior->bv_len == 0 ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
				"newSuperior is \"\" - aborting\n", 0, 0, 0 );
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, 
					NULL,
					"not allowed within namingContext", 
					NULL, NULL );
			goto modrdn_return;
		}

		new_pdn = newSuperior;
		new_npdn = nnewSuperior;

		e.e_name = *new_pdn;
		e.e_nname = *new_npdn;

		/*
		 * Check for children access to new parent
		 */
		if ( !access_allowed( be, conn, op, &e, 
					slap_schema.si_ad_children, 
					NULL, ACL_WRITE, NULL ) ) {
			Debug( LDAP_DEBUG_TRACE, "no access to new parent\n", 
					0, 0, 0 );
			res = LDAP_INSUFFICIENT_ACCESS;
			goto modrdn_return;
		}

	} else {
		new_pdn = &p_dn;
		new_npdn = &p_ndn;
	}

	if ( newSuperior && dn_match( &p_ndn, new_npdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"newSuperior is equal to old parent - ignored\n",
			0, 0, 0 );
		newSuperior = NULL;
	}

	if ( newSuperior && dn_match( ndn, new_npdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"newSuperior is equal to entry being moved "
			"- aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, "newSuperior is equal to old DN",
				NULL, NULL );
		goto modrdn_return;
	}

	build_new_dn( &new_dn, new_pdn, newrdn ); 
	if ( dnNormalize2( NULL, &new_dn, &new_ndn ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"new dn is invalid ('%s') - aborting\n",
			new_dn.bv_val, 0, 0 );
		send_ldap_result( conn, op, LDAP_INVALID_DN_SYNTAX,
				NULL, "new DN is invalid", NULL, NULL );
		goto modrdn_return;
	}
	
	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): new entry dn is '%s'\n",
			new_dn.bv_val, 0, 0 );

	res = backsql_dn2id( bi, &pe_id, dbh, &p_ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup old parent entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, NULL, 
				res == LDAP_OTHER ? "SQL-backend error" : "",
				NULL, NULL );
		goto modrdn_return;
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"old parent entry id is %ld\n", pe_id.id, 0, 0 );

	res = backsql_dn2id( bi, &new_pid, dbh, new_npdn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup new parent entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, NULL,
				res == LDAP_OTHER ? "SQL-backend error" : "",
				NULL, NULL );
		goto modrdn_return;
	}
	
	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"new parent entry id is %ld\n", new_pid.id, 0, 0 );

 
	Debug(	LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"executing delentry_query\n", 0, 0, 0 );
	SQLAllocStmt( dbh, &sth );
	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,
			0, 0, &e_id.id, 0, 0 );
	rc = SQLExecDirect( sth, bi->delentry_query, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"failed to delete record from ldap_entries\n",
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		goto modrdn_return;
	}

	SQLFreeStmt( sth, SQL_RESET_PARAMS );

	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"executing insentry_query\n", 0, 0, 0 );
	backsql_BindParamStr( sth, 1, new_dn.bv_val, BACKSQL_MAX_DN_LEN );
	SQLBindParameter( sth, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &e_id.oc_id, 0, 0 );
	SQLBindParameter( sth, 3, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &new_pid.id, 0, 0 );
	SQLBindParameter( sth, 4, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &e_id.keyval, 0, 0 );
	rc = SQLExecDirect( sth, bi->insentry_query, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not insert ldap_entries record\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		goto modrdn_return;
	}

	/*
	 * Get attribute type and attribute value of our new rdn,
	 * we will need to add that to our new entry
	 */
	if ( ldap_bv2rdn( newrdn, &new_rdn, (char **)&text, 
				LDAP_DN_FORMAT_LDAP ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG ( OPERATION, ERR, 
			"backsql_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"backsql_modrdn: can't figure out "
			"type(s)/values(s) of newrdn\n", 
			0, 0, 0 );
#endif
		rc = LDAP_INVALID_DN_SYNTAX;
		goto modrdn_return;
	}

#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, RESULTS, 
		"backsql_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ][ 0 ]->la_attr.bv_val, 
		new_rdn[ 0 ][ 0 ]->la_value.bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"backsql_modrdn: new_rdn_type=\"%s\", "
		"new_rdn_val=\"%s\"\n",
		new_rdn[ 0 ][ 0 ]->la_attr.bv_val,
		new_rdn[ 0 ][ 0 ]->la_value.bv_val, 0 );
#endif

	if ( deleteoldrdn ) {
		if ( ldap_bv2rdn( dn, &old_rdn, (char **)&text,
			LDAP_DN_FORMAT_LDAP ) ) {
#ifdef NEW_LOGGING
			LDAP_LOG ( OPERATION, ERR, 
				"backsql_modrdn: can't figure out "
				"type(s)/values(s) of old_rdn\n", 
				0, 0, 0 );
#else
			Debug( LDAP_DEBUG_TRACE,
				"backsql_modrdn: can't figure out "
				"the old_rdn type(s)/value(s)\n", 
				0, 0, 0 );
#endif
			rc = LDAP_OTHER;
			goto modrdn_return;		
		}
	}

	e.e_name = new_dn;
	e.e_nname = new_ndn;
	res = slap_modrdn2mods( be, conn, op, &e, old_rdn, new_rdn, 
			deleteoldrdn, &mod );
	if ( res != LDAP_SUCCESS ) {
		goto modrdn_return;
	}

	if ( !acl_check_modlist( be, conn, op, &e, mod )) {
		res = LDAP_INSUFFICIENT_ACCESS;
		goto modrdn_return;
	}

	oc = backsql_id2oc( bi, e_id.oc_id );
	res = backsql_modify_internal( be, conn, op, 
			dbh, oc, &e_id, mod, &text );

	if ( res == LDAP_SUCCESS ) {

		/*
		 * Commit only if all operations succeed
		 */
		SQLTransact( SQL_NULL_HENV, dbh,
				op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );
	}

modrdn_return:
	SQLFreeStmt( sth, SQL_DROP );

	if ( new_dn.bv_val ) {
		ch_free( new_dn.bv_val );
	}
	
	if ( new_ndn.bv_val ) {
		ch_free( new_ndn.bv_val );
	}
	
	/* LDAP v2 supporting correct attribute handling. */
	if ( new_rdn != NULL ) {
		ldap_rdnfree( new_rdn );
	}
	if ( old_rdn != NULL ) {
		ldap_rdnfree( old_rdn );
	}
	if( mod != NULL ) {
		Modifications *tmp;
		for (; mod; mod=tmp ) {
			tmp = mod->sml_next;
			free( mod );
		}
	}

	send_ldap_result( conn, op, res, NULL, text, NULL, NULL );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_modrdn()\n", 0, 0, 0 );
	return op->o_noop;
}

int
backsql_add(
	BackendDB	*be,
	Connection 	*conn,
	Operation 	*op,
	Entry 		*e )
{
	backsql_info		*bi = (backsql_info*)be->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT 		sth;
	unsigned long		new_keyval = 0;
	long			i;
	RETCODE			rc;
	backsql_oc_map_rec 	*oc = NULL;
	backsql_at_map_rec	*at_rec = NULL;
	backsql_entryID		e_id, parent_id;
	Entry			p;
	int			res;
	Attribute		*at;
	struct berval		*at_val;
	struct berval		pdn;
	/* first parameter #, parameter order */
	SQLUSMALLINT		pno, po;
	/* procedure return code */
	int			prc;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_add(): adding entry '%s'\n",
			e->e_name.bv_val, 0, 0 );

	/* check schema */
	if ( global_schemacheck ) {
		const char	*text = NULL;
		char		textbuf[ SLAP_TEXT_BUFLEN ] = { '\0' };
		int		rc;
		rc = entry_schema_check( be, e, NULL,
				&text, textbuf, sizeof( textbuf ) );
		if ( rc != LDAP_SUCCESS ) {

			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"entry failed schema check -- aborting\n",
				0, 0, 0 );
			send_ldap_result( conn, op, rc, NULL,
					"operation not permitted "
					"within namingContext",
					NULL, NULL );
			return 1;
		}
	}

	/* search structural objectClass */
	for ( at = e->e_attrs; at != NULL; at = at->a_next ) {
		if ( at->a_desc == slap_schema.si_ad_structuralObjectClass ) {
			break;
		}
	}

	/* there must exist */
	assert( at != NULL );

	/* I guess we should play with sub/supertypes to find a suitable oc */
	oc = backsql_name2oc( bi, &at->a_vals[0] );

	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
				"operation not permitted within namingContext",
				NULL, NULL );
		return 1;
	}

	if ( oc->create_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"create procedure is not defined for this objectclass "
			"- aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
				"operation not permitted within namingContext",
				NULL, NULL );
		return 1;

	} else if ( BACKSQL_CREATE_NEEDS_SELECT( bi )
			&& oc->create_keyval == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"create procedure needs select procedure, "
			"but none is defined - aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
				"operation not permitted within namingContext",
				NULL, NULL );
		return 1;
	}

	prc = backsql_get_db_conn( be, conn, &dbh );
	if ( prc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, prc, NULL,
				prc == LDAP_OTHER ?  "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	/*
	 * Check if entry exists
	 */
	res = backsql_dn2id( bi, &e_id, dbh, &e->e_name );
	if ( res == LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"entry '%s' exists\n",
			e->e_name.bv_val, 0, 0 );
		send_ldap_result( conn, op, LDAP_ALREADY_EXISTS,
				NULL, NULL, NULL, NULL );
		return 1;
	}

	/*
	 * Check if parent exists
	 */
	dnParent( &e->e_name, &pdn );
	res = backsql_dn2id( bi, &parent_id, dbh, &pdn );
	if ( res != LDAP_SUCCESS ) {
		
		/*
		 * NO SUCH OBJECT seems more appropriate
		 */
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"could not lookup parent entry for new record '%s'\n",
			pdn.bv_val, 0, 0 );

		if ( res != LDAP_NO_SUCH_OBJECT ) {
			send_ldap_result( conn, op, res,
					NULL, NULL, NULL, NULL );
			return 1;
		}

		/*
		 * Look for matched
		 */
		while ( 1 ) {
			struct berval	dn;
			char		*matched = NULL;

			dn = pdn;
			dnParent( &dn, &pdn );

			/*
			 * Empty DN ("") defaults to LDAP_SUCCESS
			 */
			res = backsql_dn2id( bi, &parent_id, dbh, &pdn );
			switch ( res ) {
			case LDAP_NO_SUCH_OBJECT:
				if ( pdn.bv_len > 0 ) {
					break;
				}
				/* fail over to next case */
				
			case LDAP_SUCCESS:
				matched = pdn.bv_val;
				/* fail over to next case */

			default:
				send_ldap_result( conn, op, res,
						matched, NULL, NULL, NULL );
				return 1;
			} 
		}
	}

	/*
	 * create_proc is executed; if expect_return is set, then
	 * an output parameter is bound, which should contain 
	 * the id of the added row; otherwise the procedure
	 * is expected to return the id as the first column of a select
	 */

	p.e_attrs = NULL;
	p.e_name = pdn;
	dnParent( &e->e_nname, &p.e_nname );
	if ( !access_allowed( be, conn, op, &p, slap_schema.si_ad_children,
				NULL, ACL_WRITE, NULL ) ) {
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, 
				NULL, NULL, NULL, NULL );
		return 1;
	}

	rc = SQLAllocStmt( dbh, &sth );
	if ( rc != SQL_SUCCESS ) {
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
	}

	if ( BACKSQL_IS_ADD( oc->expect_return ) ) {
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG, 
				SQL_INTEGER, 0, 0, &new_keyval, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_add(): executing '%s'\n",
		oc->create_proc, 0, 0 );
	rc = SQLExecDirect( sth, oc->create_proc, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"create_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc);
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
	}
	if ( op->o_noop ) {
		SQLTransact( SQL_NULL_HENV, dbh, SQL_ROLLBACK );
	}

	if ( !BACKSQL_IS_ADD( oc->expect_return ) ) {
		SWORD		ncols;
		SQLINTEGER	value_len;

		if ( BACKSQL_CREATE_NEEDS_SELECT( bi ) ) {
#ifndef BACKSQL_REALLOC_STMT
			SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
			SQLFreeStmt( sth, SQL_DROP );
			rc = SQLAllocStmt( dbh, &sth );
			if ( rc != SQL_SUCCESS ) {
				send_ldap_result( conn, op, LDAP_OTHER,
						NULL, "SQL-backend error",
						NULL, NULL );
				return 1;
			}
#endif /* BACKSQL_REALLOC_STMT */

			rc = SQLExecDirect( sth, oc->create_keyval, SQL_NTS );
			if ( rc != SQL_SUCCESS ) {
				send_ldap_result( conn, op, LDAP_OTHER,
						NULL, "SQL-backend error",
						NULL, NULL );
				return 1;
			}
		}

		/*
		 * the query to know the id of the inserted entry
		 * must be embedded in the create procedure
		 */
		rc = SQLNumResultCols( sth, &ncols );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"create_proc result evaluation failed\n",
				0, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "SQL-backend error", NULL, NULL );
			return 1;

		} else if ( ncols != 1 ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"create_proc result is bogus (ncols=%d)\n",
				ncols, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "SQL-backend error", NULL, NULL );
			return 1;
		}

#if 0
		{
			SQLCHAR		colname[ 64 ];
			SQLSMALLINT	name_len, col_type, col_scale, col_null;
			UDWORD		col_prec;

			/*
			 * FIXME: check whether col_type is compatible,
			 * if it can be null and so on ...
			 */
			rc = SQLDescribeCol( sth, (SQLUSMALLINT)1, 
					&colname[ 0 ], 
					(SQLUINTEGER)( sizeof( colname ) - 1 ),
					&name_len, &col_type,
					&col_prec, &col_scale, &col_null );
		}
#endif

		rc = SQLBindCol( sth, (SQLUSMALLINT)1, SQL_C_ULONG,
				(SQLPOINTER)&new_keyval, 
				(SQLINTEGER)sizeof( new_keyval ), 
				&value_len );

		rc = SQLFetch( sth );

		if ( value_len <= 0 ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"create_proc result is empty?\n",
				0, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			send_ldap_result( conn, op, LDAP_OTHER,
					NULL, "SQL-backend error", NULL, NULL );
			return 1;
		}
	}

#ifndef BACKSQL_REALLOC_STMT
	SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
	SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */

	Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
		"create_proc returned keyval=%ld\n", new_keyval, 0, 0 );

	for ( at = e->e_attrs; at != NULL; at = at->a_next ) {
		SQLUSMALLINT	currpos;

		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"adding attribute '%s'\n", 
			at->a_desc->ad_cname.bv_val, 0, 0 );

		/*
		 * Skip:
		 * - the first occurrence of objectClass, which is used
		 *   to determine how to bulid the SQL entry (FIXME ?!?)
		 * - operational attributes
		 *   empty attributes (FIXME ?!?)
		 */
		if ( backsql_attr_skip( at->a_desc, at->a_vals ) ) {
			continue;
		}

		at_rec = backsql_ad2at( oc, at->a_desc ); 
  
		if ( at_rec == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"attribute '%s' is not registered "
				"in objectclass '%s'\n",
				at->a_desc->ad_cname.bv_val,
				BACKSQL_OC_NAME( oc ), 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				send_ldap_result( conn, op, 
						LDAP_UNWILLING_TO_PERFORM, NULL,
						"operation not permitted "
						"within namingContext",
						NULL, NULL );
				return 1;
			}

			continue;
		}
		
		if ( at_rec->add_proc == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"add procedure is not defined "
				"for attribute '%s'\n",
				at->a_desc->ad_cname.bv_val, 0, 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				send_ldap_result( conn, op, 
						LDAP_UNWILLING_TO_PERFORM, NULL,
						"operation not permitted "
						"within namingContext",
						NULL, NULL );
				return 1;
			}

			continue;
		}

#ifdef BACKSQL_REALLOC_STMT
		rc = backsql_Prepare( dbh, &sth, at_rec->add_proc, 0 );
		if ( rc != SQL_SUCCESS ) {

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				send_ldap_result( conn, op, LDAP_OTHER,
						NULL, "SQL-backend error",
						NULL, NULL );
				return 1;
			}

			continue;
		}
#endif /* BACKSQL_REALLOC_STMT */

		if ( BACKSQL_IS_ADD( at_rec->expect_return ) ) {
			pno = 1;
			SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT,
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &prc, 0, 0 );
		} else {
			pno = 0;
		}

		po = ( BACKSQL_IS_ADD( at_rec->param_order ) ) > 0;
		currpos = pno + 1 + po;
		SQLBindParameter( sth, currpos,
				SQL_PARAM_INPUT, SQL_C_ULONG,
				SQL_INTEGER, 0, 0, &new_keyval, 0, 0 );
		currpos = pno + 2 - po;

		for ( i = 0, at_val = &at->a_vals[ i ];
			       	at_val->bv_val != NULL;
				i++, at_val = &at->a_vals[ i ] ) {

			/*
			 * Do not deal with the objectClass that is used
			 * to build the entry
			 */
			if ( at->a_desc == slap_schema.si_ad_objectClass ) {
				if ( bvmatch( at_val, &oc->oc->soc_cname ) ) {
					continue;
				}
			}

			/*
			 * check for syntax needed here 
			 * maybe need binary bind?
			 */

			backsql_BindParamStr( sth, currpos,
					at_val->bv_val, at_val->bv_len + 1 );
#ifdef SECURITY_PARANOID
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"executing '%s', id=%ld\n", 
				at_rec->add_proc, new_keyval, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"executing '%s' with val='%s', id=%ld\n", 
				at_rec->add_proc, at_val->bv_val, new_keyval );
#endif
#ifndef BACKSQL_REALLOC_STMT
			rc = SQLExecDirect( sth, at_rec->add_proc, SQL_NTS );
#else /* BACKSQL_REALLOC_STMT */
			rc = SQLExecute( sth );
#endif /* BACKSQL_REALLOC_STMT */
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
					"add_proc execution failed\n", 
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, sth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					send_ldap_result( conn, op, LDAP_OTHER,
							NULL,
							"SQL-backend error",
							NULL, NULL );
					return 1;
				}
			}
		}
#ifndef BACKSQL_REALLOC_STMT
		SQLFreeStmt( sth, SQL_RESET_PARAMS ); 
#else /* BACKSQL_REALLOC_STMT */
		SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */
	}

#ifdef BACKSQL_REALLOC_STMT
	rc = backsql_Prepare( dbh, &sth, bi->insentry_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
	}
#endif /* BACKSQL_REALLOC_STMT */
	
	backsql_BindParamStr( sth, 1, e->e_name.bv_val, BACKSQL_MAX_DN_LEN );
	SQLBindParameter( sth, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &oc->id, 0, 0 );
	SQLBindParameter( sth, 3, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &parent_id.id, 0, 0 );
	SQLBindParameter( sth, 4, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &new_keyval, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "backsql_add(): executing '%s' for dn '%s'\n",
			bi->insentry_query, e->e_name.bv_val, 0 );
	Debug( LDAP_DEBUG_TRACE, " for oc_map_id=%ld, parent_id=%ld, "
			"keyval=%ld\n", oc->id, parent_id.id, new_keyval );
#ifndef BACKSQL_REALLOC_STMT
	rc = SQLExecDirect( sth, bi->insentry_query, SQL_NTS );
#else /* BACKSQL_REALLOC_STMT */
	rc = SQLExecute( sth );
#endif /* BACKSQL_REALLOC_STMT */
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"could not insert ldap_entries record\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		
		/*
		 * execute delete_proc to delete data added !!!
		 */
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
	}
	
	SQLFreeStmt( sth, SQL_DROP );

	/*
	 * Commit only if all operations succeed
	 */
	SQLTransact( SQL_NULL_HENV, dbh, 
			op->o_noop ? SQL_ROLLBACK : SQL_COMMIT );

	/*
	 * FIXME: NOOP does not work for add -- it works for all 
	 * the other operations, and I don't get the reason :(
	 */

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );

	return op->o_noop;
}

int
backsql_delete(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*dn,
	struct berval	*ndn )
{
	backsql_info 		*bi = (backsql_info*)be->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_oc_map_rec	*oc = NULL;
	backsql_entryID		e_id;
	Entry			e;
	int			res;
	/* first parameter no */
	SQLUSMALLINT		pno;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_delete(): deleting entry '%s'\n",
			ndn->bv_val, 0, 0 );

	dnParent( dn, &e.e_name );
	dnParent( ndn, &e.e_nname );
	e.e_attrs = NULL;

	/* check parent for "children" acl */
	if ( !access_allowed( be, conn, op, &e, slap_schema.si_ad_children, 
			NULL, ACL_WRITE, NULL ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"no write access to parent\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_INSUFFICIENT_ACCESS, 
				NULL, NULL, NULL, NULL );
		return 1;

	}
	
	res = backsql_get_db_conn( be, conn, &dbh );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, res, NULL, 
				res == LDAP_OTHER ? "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}
	
	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, NULL, NULL, NULL, NULL );
		return 1;
	}

	res = backsql_has_children( bi, dbh, ndn );
	switch ( res ) {
	case LDAP_COMPARE_TRUE:
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"entry \"%s\" has children\n", dn->bv_val, 0, 0 );
		send_ldap_result( conn, op, LDAP_NOT_ALLOWED_ON_NONLEAF,
                        	NULL, "subtree delete not supported",
				NULL, NULL );
		return 1;

	case LDAP_COMPARE_FALSE:
		break;

	default:
		send_ldap_result( conn, op, res, NULL, NULL, NULL, NULL );
		return 1;
	}

	oc = backsql_id2oc( bi, e_id.oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
				"operation not permitted within namingContext",
				NULL, NULL );
 		return 1;
	}

	if ( oc->delete_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"delete procedure is not defined "
			"for this objectclass - aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
				"operation not permitted within namingContext",
				NULL, NULL );
		return 1;
	}

	SQLAllocStmt( dbh, &sth );
	if ( BACKSQL_IS_DEL( oc->expect_return ) ) {
		pno = 1;
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG,
				SQL_INTEGER, 0, 0, &rc, 0, 0 );
	} else {
		pno = 0;
	}

	SQLBindParameter( sth, pno + 1, SQL_PARAM_INPUT, 
			SQL_C_ULONG, SQL_INTEGER, 0, 0, &e_id.keyval, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "backsql_delete(): executing '%s'\n",
			oc->delete_proc, 0, 0 );
	rc = SQLExecDirect( sth, oc->delete_proc, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"delete_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
	}
#ifndef BACKSQL_REALLOC_STMT
	SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
	SQLFreeStmt( sth, SQL_DROP );
	SQLAllocStmt( dbh, &sth );
#endif /* BACKSQL_REALLOC_STMT */

	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,
			0, 0, &e_id.id, 0, 0 );
	rc = SQLExecDirect( sth, bi->delentry_query, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"failed to delete record from ldap_entries\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "SQL-backend error", NULL, NULL );
		return 1;
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

	send_ldap_result( conn, op, LDAP_SUCCESS, NULL, NULL, NULL, NULL );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_delete()\n", 0, 0, 0 );
	return op->o_noop;
}

#endif /* SLAPD_SQL */

