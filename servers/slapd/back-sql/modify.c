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
#include <string.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "entry-id.h"
#include "util.h"

/*
 * PostgreSQL doesn't work without :(
 */
#define	BACKSQL_REALLOC_STMT

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
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_oc_map_rec	*oc = NULL;
	backsql_entryID		e_id;
	int			res;
	Modification		*c_mod;
	Modifications		*ml;
	backsql_at_map_rec	*at = NULL;
	struct berval		*at_val;
	int			i;
	/* first parameter no, parameter order */
	SQLUSMALLINT		pno, po;
	/* procedure return code */
	int			prc;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_modify(): changing entry '%s'\n",
		ndn->bv_val, 0, 0 );
	dbh = backsql_get_db_conn( be, conn );
	if ( !dbh ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res , "", NULL, NULL, NULL );
		return 1;
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
		"modifying entry '%s' (id=%ld)\n", 
		e_id.dn.bv_val, e_id.id, 0 );

	oc = backsql_oc_with_id( bi, e_id.oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		/*
		 * FIXME: we don't want to send back 
		 * excessively detailed messages
		 */
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	SQLAllocStmt( dbh, &sth );
	Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
		"traversing modifications list\n", 0, 0, 0 );
	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		char *attrname;

		c_mod = &ml->sml_mod;

		attrname = c_mod->sm_desc->ad_cname.bv_val;
		Debug( LDAP_DEBUG_TRACE, "backsql_modify(): attribute '%s'\n",
				attrname, 0, 0 );
  		at = backsql_at_with_name( oc, attrname );
		if ( at == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
				"attribute provided is not registered "
				"in objectclass '%s'\n",
				attrname, 0, 0 );
			continue;
		}
  
		switch( c_mod->sm_op ) {
		case LDAP_MOD_REPLACE: {
			SQLHSTMT asth;
			BACKSQL_ROW_NTS row;
			 
			Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
				"replacing values for attribute '%s'\n",
				at->name, 0, 0 );

			if ( at->add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"add procedure is not defined "
					"for attribute '%s' "
					"- unable to perform replacements\n",
					at->name, 0, 0 );
				break;
			}

			if ( at->delete_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"delete procedure is not defined "
					"for attribute '%s' "
					"- adding only\n",
					at->name, 0, 0 );
				goto add_only;
			}
			
del_all:
			rc = backsql_Prepare( dbh, &asth, at->query, 0 );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"error preparing query\n", 0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				break;
			}

			rc = backsql_BindParamID( asth, 1, &e_id.keyval );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"error binding key value parameter\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );
				break;
			}
			
			rc = SQLExecute( asth );
			if ( !BACKSQL_SUCCESS( rc ) ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"error executing attribute query\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );
				break;
			}

			backsql_BindRowAsStrings( asth, &row );
			rc = SQLFetch( asth );
			for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( asth ) ) {
				for ( i = 0; i < row.ncols; i++ ) {
			   		if ( at->expect_return & BACKSQL_DEL ) {
						pno = 1;
						SQLBindParameter(sth, 1,
							SQL_PARAM_OUTPUT,
							SQL_C_ULONG,
							SQL_INTEGER,
							0, 0, &prc, 0, 0 );
					} else {
						pno = 0;
					}
					po = ( at->param_order & BACKSQL_DEL ) > 0;
					SQLBindParameter( sth, pno + 1 + po,
						SQL_PARAM_INPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &e_id.keyval, 0, 0 );

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
						"backsql_modify(): "
						"executing '%s'\n",
						at->delete_proc, 0, 0 );
					rc = SQLExecDirect( sth,
						at->delete_proc, SQL_NTS );
					if ( rc != SQL_SUCCESS ) {
						Debug( LDAP_DEBUG_TRACE,
							"backsql_modify(): "
							"delete_proc "
							"execution failed\n",
							0, 0, 0 );
						backsql_PrintErrors( bi->db_env,
								dbh, sth, rc );
					}
				}
			}
			backsql_FreeRow( &row );
	   		SQLFreeStmt( asth, SQL_DROP );
	       	}
				       
		/*
		 * PASSTHROUGH - to add new attributes -- do NOT add break
		 */
		case LDAP_MOD_ADD:
add_only:;
			if ( at->add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"add procedure is not defined "
					"for attribute '%s'\n",
					at->name, 0, 0 );
				break;
			}
			
			if ( c_mod->sm_bvalues == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"no values given to add "
					"for attribute '%s'\n",
					at->name, 0, 0 );
				break;
			}
			
			Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
				"adding new values for attribute '%s'\n",
				at->name, 0, 0 );
			for ( i = 0, at_val = &c_mod->sm_bvalues[ 0 ];
					at_val->bv_val != NULL; 
					i++, at_val = &c_mod->sm_bvalues[ i ] ) {
				if ( at->expect_return & BACKSQL_ADD ) {
					pno = 1;
	      				SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0);
				} else {
	      				pno = 0;
				}
				po = ( at->param_order & BACKSQL_ADD ) > 0;
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id.keyval, 0, 0 );

				/*
				 * check for syntax needed here
				 * maybe need binary bind?
				 */
				SQLBindParameter( sth, pno + 2 - po,
					SQL_PARAM_INPUT,
					SQL_C_CHAR, SQL_CHAR,
					0, 0, at_val->bv_val, 
					at_val->bv_len, 0 );

				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"executing '%s'\n", 
					at->add_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->add_proc, 
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"backsql_modify(): "
						"add_proc execution failed\n",
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );
				}
			}
			break;
			
	      	case LDAP_MOD_DELETE:
			if ( at->delete_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"delete procedure is not defined "
					"for attribute '%s'\n",
					at->name, 0, 0 );
				break;
			}

			if ( c_mod->sm_bvalues == NULL ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"no values given to delete "
					"for attribute '%s' "
					"-- deleting all values\n",
					at->name, 0, 0 );
				goto del_all;
			}

			Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
				"deleting values for attribute '%s'\n",
				at->name, 0, 0 );
			for( i = 0, at_val = &c_mod->sm_bvalues[ 0 ];
					at_val->bv_val != NULL;
					i++, at_val = &c_mod->sm_bvalues[ i ] ) {
				if ( at->expect_return & BACKSQL_DEL ) {
					pno = 1;
					SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0 );
				} else {
					pno = 0;
				}
				po = ( at->param_order & BACKSQL_DEL ) > 0;
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id.keyval, 0, 0 );

				/*
				 * check for syntax needed here 
				 * maybe need binary bind?
				 */
				SQLBindParameter( sth, pno + 2 - po,
					SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR,
					0, 0, at_val->bv_val, 
					at_val->bv_len, 0 );

				Debug( LDAP_DEBUG_TRACE, "backsql_modify(): "
					"executing '%s'\n", 
					at->delete_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->delete_proc,
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"backsql_modify(): "
						"delete_proc execution "
						"failed\n", 0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );
				}
			}
			break;
		}
		
		SQLFreeStmt( sth, SQL_RESET_PARAMS );
	}

	SQLFreeStmt( sth, SQL_DROP );
	send_ldap_result( conn, op, LDAP_SUCCESS, "", NULL, NULL, NULL );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify()\n", 0, 0, 0 );

	return 0;
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
	int			res;
	struct berval		p_dn, p_ndn,
				*new_pdn = NULL, *new_npdn = NULL,
				new_dn, new_ndn;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_modrdn() renaming entry '%s', "
			"newrdn='%s', newSuperior='%s'\n",
			dn->bv_val, newrdn->bv_val, newSuperior->bv_val );
	dbh = backsql_get_db_conn( be, conn );
	if ( !dbh ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
			"SQL-backend error", NULL, NULL );
		return 1;
	}

	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res , "", NULL, NULL, NULL );
		return 1;
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): entry id is %ld\n",
		e_id.id, 0, 0 );

	dnParent( dn, &p_dn );
	dnParent( ndn, &p_ndn );

	if ( newSuperior ) {
		new_pdn = newSuperior;
		new_npdn = nnewSuperior;
	} else {
		new_pdn = &p_dn;
		new_npdn = &p_ndn;
	}

	SQLAllocStmt( dbh, &sth );

	if ( newSuperior && dn_match( &p_ndn, new_npdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"newSuperior is equal to old parent - aborting\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", 
				NULL, NULL, NULL );
  		goto modrdn_return;
	}

	if ( newSuperior && dn_match( ndn, new_npdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"newSuperior is equal to entry being moved "
			"- aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, "", 
				NULL, NULL, NULL );
		goto modrdn_return;
	}

	build_new_dn( &new_dn, new_pdn, newrdn ); 
	if ( dnNormalize2( NULL, &new_dn, &new_ndn ) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"new dn is invalid ('%s') - aborting\n",
			new_dn.bv_val, 0, 0 );
		send_ldap_result( conn, op, LDAP_INVALID_DN_SYNTAX, "", 
				NULL, NULL, NULL );
		goto modrdn_return;
	}
	
	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): new entry dn is '%s'\n",
			new_dn.bv_val, 0, 0 );

	res = backsql_dn2id( bi, &pe_id, dbh, &p_ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup old parent entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, "", NULL, NULL, NULL );
		goto modrdn_return;
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"old parent entry id is %ld\n", pe_id.id, 0, 0 );

	res = backsql_dn2id( bi, &new_pid, dbh, new_npdn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"could not lookup new parent entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, "", NULL, NULL, NULL );
		goto modrdn_return;
	}
	
	Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"new parent entry id is %ld\n", new_pid.id, 0, 0 );

 
	Debug(	LDAP_DEBUG_TRACE, "backsql_modrdn(): "
		"executing delentry_query\n", 0, 0, 0 );
	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,
			0, 0, &e_id.id, 0, 0 );
	rc = SQLExecDirect( sth, bi->delentry_query, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_modrdn(): "
			"failed to delete record from ldap_entries\n",
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
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
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		goto modrdn_return;
	}

	/*
	 * FIXME: should process deleteoldrdn here...
	 */

	send_ldap_result( conn, op, LDAP_SUCCESS, "", NULL, NULL, NULL );

modrdn_return:
	SQLFreeStmt( sth, SQL_DROP );

	if ( new_dn.bv_val ) {
		ch_free( new_dn.bv_val );
	}
	
	if ( new_ndn.bv_val ) {
		ch_free( new_ndn.bv_val );
	}
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_modrdn()\n", 0, 0, 0 );
	return 0;
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
	backsql_entryID		parent_id;
	int			res;
	Attribute		*at;
	struct berval		*at_val;
	struct berval		pdn;
	/* first parameter no, parameter order */
	SQLUSMALLINT		pno, po;
	/* procedure return code */
	int			prc;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_add(): adding entry '%s'\n",
			e->e_dn, 0, 0 );

	for ( at = e->e_attrs; at != NULL; at = at->a_next ) {
#if 0
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): scanning entry "
			"-- %s\n", at->a_type, 0, 0 );
#endif
		if ( !strcasecmp( at->a_desc->ad_cname.bv_val, "objectclass" ) ) {
			oc = backsql_oc_with_name( bi, at->a_vals[ 0 ].bv_val );
		     	break;
		}
	}

	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	if ( oc->create_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"create procedure is not defined for this objectclass "
			"- aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	dbh = backsql_get_db_conn( be, conn );
	if ( !dbh ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

#ifndef BACKSQL_REALLOC_STMT
	SQLAllocStmt( dbh, &sth );
#else /* BACKSQL_REALLOC_STMT */
	rc = backsql_Prepare( dbh, &sth, oc->create_proc, 0 );
	if ( rc != SQL_SUCCESS ) {
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}
#endif /* BACKSQL_REALLOC_STMT */

	if ( oc->expect_return ) {
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG, 
				SQL_INTEGER, 0, 0, &new_keyval, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "backsql_add(): executing '%s'\n",
		oc->create_proc, 0, 0 );
#ifndef BACKSQL_REALLOC_STMT
	rc = SQLExecDirect( sth, oc->create_proc, SQL_NTS );
#else /* BACKSQL_REALLOC_STMT */
	rc = SQLExecute( sth );
#endif /* BACKSQL_REALLOC_STMT */
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"create_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc);
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	if ( !oc->expect_return ) {
		/*
		 * FIXME: need query to know the id of the inserted entry
		 */
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

		if ( at->a_vals[ 0 ].bv_val == NULL ) {
			continue;
		}

		at_rec = backsql_at_with_name( oc, 
				at->a_desc->ad_cname.bv_val ); 
  
		if ( at_rec == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"attribute '%s' is not registered "
				"in objectclass '%s'\n",
				at->a_desc->ad_cname.bv_val, oc->name, 0 );
			continue;
		}
		
		if ( at_rec->add_proc == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"add procedure is not defined "
				"for attribute '%s'\n",
				at->a_desc->ad_cname.bv_val, 0, 0 );
			continue;
		}

#ifdef BACKSQL_REALLOC_STMT
		rc = backsql_Prepare( dbh, &sth, at_rec->add_proc, 0 );
		if ( rc != SQL_SUCCESS ) {
			continue;
		}
#endif /* BACKSQL_REALLOC_STMT */

		if ( at_rec->expect_return & BACKSQL_ADD ) {
			pno = 1;
			SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT,
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &prc, 0, 0 );
		} else {
			pno = 0;
		}

		po = ( at_rec->param_order & BACKSQL_ADD ) > 0;
		currpos = pno + 1 + po;
		SQLBindParameter( sth, currpos,
				SQL_PARAM_INPUT, SQL_C_ULONG,
				SQL_INTEGER, 0, 0, &new_keyval, 0, 0 );
		currpos = pno + 2 - po;

		for ( i = 0, at_val = &at->a_vals[ 0 ];
				at_val->bv_val != NULL;
				i++, at_val = &at->a_vals[ i ] ) {

			/*
			 * check for syntax needed here 
			 * maybe need binary bind?
			 */

			backsql_BindParamStr( sth, currpos,
					at_val->bv_val, at_val->bv_len + 1 );

			Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
				"executing '%s' with val='%s', id=%ld\n", 
				at_rec->add_proc, at_val->bv_val, new_keyval );
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
			}
		}
#ifndef BACKSQL_REALLOC_STMT
		SQLFreeStmt( sth, SQL_RESET_PARAMS ); 
#else /* BACKSQL_REALLOC_STMT */
		SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */
	}

	dnParent( &e->e_name, &pdn );
	res = backsql_dn2id( bi, &parent_id, dbh, &pdn );
	if ( res != LDAP_SUCCESS ) {
		/*
		 * NO SUCH OBJECT seems more appropriate
		 */
		Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
			"could not lookup parent entry for new record '%s'\n",
			pdn.bv_val, 0, 0 );
		send_ldap_result( conn, op, res, "", NULL, NULL, NULL );
		return 1;
	}
#ifdef BACKSQL_REALLOC_STMT
	rc = backsql_Prepare( dbh, &sth, bi->insentry_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
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
		send_ldap_result( conn, op, LDAP_OTHER, "", 
				"SQL-backend error", NULL, NULL );
		return 1;
	}
	
	SQLFreeStmt( sth, SQL_DROP );
	send_ldap_result( conn, op, LDAP_SUCCESS, "",
			NULL, NULL, NULL );
	return 0;
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
	int			res;
	/* first parameter no */
	SQLUSMALLINT		pno;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_delete(): deleting entry '%s'\n",
			ndn->bv_val, 0, 0 );
	dbh = backsql_get_db_conn( be, conn );
	if ( !dbh ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}
	
	res = backsql_dn2id( bi, &e_id, dbh, ndn );
	if ( res != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"could not lookup entry id\n", 0, 0, 0 );
		send_ldap_result( conn, op, res, "", NULL, NULL, NULL );
		return 1;
	}

	oc = backsql_oc_with_id( bi, e_id.oc_id );
	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"cannot determine objectclass of entry "
			"-- aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
 		return 1;
	}

	if ( oc->delete_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"delete procedure is not defined "
			"for this objectclass - aborting\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	SQLAllocStmt( dbh, &sth );
	if ( oc->expect_return ) {
		pno = 1;
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG,
				SQL_INTEGER, 0, 0, &rc, 0, 0 );
	} else {
		pno = 0;
	}

	SQLBindParameter( sth, pno + 1, SQL_PARAM_INPUT, 
			SQL_C_ULONG, SQL_INTEGER, 0, 0, &e_id.keyval, 0, 0 );
#if 0
	SQLBindParameter( sth, 2, SQL_PARAM_OUTPUT, SQL_C_SLONG, SQL_INTEGER,
			0, 0, &retcode, 0, 0 );
#endif

	Debug( LDAP_DEBUG_TRACE, "backsql_delete(): executing '%s'\n",
			oc->delete_proc, 0, 0 );
	rc = SQLExecDirect( sth, oc->delete_proc, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"delete_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}
	SQLFreeStmt( sth, SQL_RESET_PARAMS );

	SQLBindParameter( sth, 1, SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,
			0, 0, &e_id.id, 0, 0 );
	rc = SQLExecDirect( sth, bi->delentry_query, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_delete(): "
			"failed to delete record from ldap_entries\n", 
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}
	
	SQLFreeStmt( sth, SQL_DROP );
	send_ldap_result( conn, op, LDAP_SUCCESS, "", NULL, NULL, NULL );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_delete()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */

