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

/*
 * Skip:
 * - the first occurrence of objectClass, which is used
 *   to determine how to build the SQL entry (FIXME ?!?)
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

int
backsql_modify_internal(
	Operation 		*op,
	SlapReply		*rs,
	SQLHDBC			dbh, 
	backsql_oc_map_rec	*oc,
	backsql_entryID		*e_id,
	Modifications		*modlist )
{
	backsql_info	*bi = (backsql_info*)op->o_bd->be_private;
	RETCODE		rc;
	SQLHSTMT	sth;
	Modifications	*ml;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_modify_internal(): "
		"traversing modifications list\n", 0, 0, 0 );

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

		Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
			"modifying attribute \"%s\" according to "
			"mappings for objectClass \"%s\"\n",
			ad->ad_cname.bv_val, BACKSQL_OC_NAME( oc ), 0 );

		if ( backsql_attr_skip( ad, c_mod->sm_values ) ) {
			continue;
		}

  		at = backsql_ad2at( oc, ad );
		if ( at == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"attribute \"%s\" is not registered "
				"in objectClass \"%s\"\n",
				ad->ad_cname.bv_val, oc, 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text = "operation not permitted "
					"within namingContext";
				goto done;
			}

			continue;
		}
  
		switch( c_mod->sm_op ) {
		case LDAP_MOD_REPLACE: {
			SQLHSTMT asth;
			BACKSQL_ROW_NTS row;
			
			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"replacing values for attribute \"%s\"\n",
				at->bam_ad->ad_cname.bv_val, 0, 0 );

			if ( at->bam_add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"add procedure is not defined "
					"for attribute \"%s\" "
					"- unable to perform replacements\n",
					at->bam_ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					rs->sr_text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}

			if ( at->bam_delete_proc == NULL ) {
				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"delete procedure is not defined "
						"for attribute \"%s\"\n",
						at->bam_ad->ad_cname.bv_val, 0, 0 );

					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					rs->sr_text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"delete procedure is not defined "
					"for attribute \"%s\" "
					"- adding only\n",
					at->bam_ad->ad_cname.bv_val, 0, 0 );

				goto add_only;
			}
			
del_all:
			rc = backsql_Prepare( dbh, &asth, at->bam_query, 0 );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"error preparing query\n", 0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}

				break;
			}

#ifdef BACKSQL_ARBITRARY_KEY
			rc = backsql_BindParamStr( asth, 1,
					e_id->eid_keyval.bv_val,
					BACKSQL_MAX_KEY_LEN );
#else /* ! BACKSQL_ARBITRARY_KEY */
			rc = backsql_BindParamID( asth, 1, &e_id->eid_keyval );
#endif /* ! BACKSQL_ARBITRARY_KEY */
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"error binding key value parameter\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}

				break;
			}
			
			rc = SQLExecute( asth );
			if ( !BACKSQL_SUCCESS( rc ) ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"error executing attribute query\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						asth, rc );
				SQLFreeStmt( asth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}

				break;
			}

			backsql_BindRowAsStrings( asth, &row );
			rc = SQLFetch( asth );
			for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( asth ) ) {
				for ( i = 0; i < row.ncols; i++ ) {
			   		if ( BACKSQL_IS_DEL( at->bam_expect_return ) ) {
						pno = 1;
						SQLBindParameter(sth, 1,
							SQL_PARAM_OUTPUT,
							SQL_C_ULONG,
							SQL_INTEGER,
							0, 0, &prc, 0, 0 );
					} else {
						pno = 0;
					}
					po = ( BACKSQL_IS_DEL( at->bam_param_order ) ) > 0;
#ifdef BACKSQL_ARBITRARY_KEY
					SQLBindParameter( sth, pno + 1 + po,
						SQL_PARAM_INPUT,
						SQL_C_CHAR, SQL_VARCHAR,
						0, 0, e_id->eid_keyval.bv_val, 
						0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
					SQLBindParameter( sth, pno + 1 + po,
						SQL_PARAM_INPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &e_id->eid_keyval, 0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

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
						"   backsql_modify_internal(): "
						"executing \"%s\"\n",
						at->bam_delete_proc, 0, 0 );
					rc = SQLExecDirect( sth,
						at->bam_delete_proc, SQL_NTS );
					if ( rc != SQL_SUCCESS ) {
						Debug( LDAP_DEBUG_TRACE,
							"   backsql_modify_internal(): "
							"delete_proc "
							"execution failed\n",
							0, 0, 0 );
						backsql_PrintErrors( bi->db_env,
								dbh, sth, rc );

						if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
							rs->sr_err = LDAP_OTHER;
							rs->sr_text = "SQL-backend error";
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
			if ( at->bam_add_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"add procedure is not defined "
					"for attribute \"%s\"\n",
					at->bam_ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					rs->sr_text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}
			
			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"adding new values for attribute \"%s\"\n",
				at->bam_ad->ad_cname.bv_val, 0, 0 );
			for ( i = 0, at_val = c_mod->sm_values;
					at_val->bv_val != NULL; 
					i++, at_val++ ) {
				if ( BACKSQL_IS_ADD( at->bam_expect_return ) ) {
					pno = 1;
	      				SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0);
				} else {
	      				pno = 0;
				}
				po = ( BACKSQL_IS_ADD( at->bam_param_order ) ) > 0;
#ifdef BACKSQL_ARBITRARY_KEY
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_CHAR, SQL_VARCHAR,
					0, 0, e_id->eid_keyval.bv_val, 0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id->eid_keyval, 0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

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
					"   backsql_modify_internal(): "
					"executing \"%s\"\n", 
					at->bam_add_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->bam_add_proc, 
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"add_proc execution failed\n",
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "SQL-backend error";
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
			if ( at->bam_delete_proc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"delete procedure is not defined "
					"for attribute \"%s\"\n",
					at->bam_ad->ad_cname.bv_val, 0, 0 );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
					rs->sr_text = "operation not permitted "
						"within namingContext";
					goto done;
				}

				break;
			}

			if ( c_mod->sm_values == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"no values given to delete "
					"for attribute \"%s\" "
					"-- deleting all values\n",
					at->bam_ad->ad_cname.bv_val, 0, 0 );
				goto del_all;
			}

			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"deleting values for attribute \"%s\"\n",
				at->bam_ad->ad_cname.bv_val, 0, 0 );

			for ( i = 0, at_val = c_mod->sm_values;
					at_val->bv_val != NULL;
					i++, at_val++ ) {
				if ( BACKSQL_IS_DEL( at->bam_expect_return ) ) {
					pno = 1;
					SQLBindParameter( sth, 1,
						SQL_PARAM_OUTPUT,
						SQL_C_ULONG, SQL_INTEGER,
						0, 0, &prc, 0, 0 );
				} else {
					pno = 0;
				}
				po = ( BACKSQL_IS_DEL( at->bam_param_order ) ) > 0;
#ifdef BACKSQL_ARBITRARY_KEY
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_CHAR, SQL_VARCHAR,
					0, 0, e_id->eid_keyval.bv_val, 0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
				SQLBindParameter( sth, pno + 1 + po,
					SQL_PARAM_INPUT, 
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &e_id->eid_keyval, 0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

				/*
				 * check for syntax needed here 
				 * maybe need binary bind?
				 */
				SQLBindParameter( sth, pno + 2 - po,
					SQL_PARAM_INPUT, SQL_C_CHAR, SQL_CHAR,
					0, 0, at_val->bv_val, 
					at_val->bv_len, 0 );

				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"executing \"%s\"\n", 
					at->bam_delete_proc, 0, 0 );
				rc = SQLExecDirect( sth, at->bam_delete_proc,
						SQL_NTS );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"delete_proc execution "
						"failed\n", 0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "SQL-backend error";
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

	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify_internal(): %d%d%s\n",
		rs->sr_err, rs->sr_text ? ": " : "",
		rs->sr_text ? rs->sr_text : "" );

	/*
	 * FIXME: should fail in case one change fails?
	 */
	return rs->sr_err;
}

int
backsql_add( Operation *op, SlapReply *rs )
{
	backsql_info		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT 		sth;
	unsigned long		new_keyval = 0;
	long			i;
	RETCODE			rc;
	backsql_oc_map_rec 	*oc = NULL;
	backsql_at_map_rec	*at_rec = NULL;
	backsql_entryID		parent_id = BACKSQL_ENTRYID_INIT;
	Entry			p;
	Attribute		*at;
	struct berval		*at_val;
	struct berval		pdn;
	/* first parameter #, parameter order */
	SQLUSMALLINT		pno, po;
	/* procedure return code */
	int			prc;
	struct berval		realdn, realpdn;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_add(): adding entry \"%s\"\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );

	/* check schema */
	if ( global_schemacheck ) {
		char		textbuf[ SLAP_TEXT_BUFLEN ] = { '\0' };

		rs->sr_err = entry_schema_check( op->o_bd, op->oq_add.rs_e,
				NULL,
				&rs->sr_text, textbuf, sizeof( textbuf ) );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"entry failed schema check -- aborting\n",
				0, 0, 0 );
			goto done;
		}
	}

	/* search structural objectClass */
	for ( at = op->oq_add.rs_e->e_attrs; at != NULL; at = at->a_next ) {
		if ( at->a_desc == slap_schema.si_ad_structuralObjectClass ) {
			break;
		}
	}

	/* there must exist */
	assert( at != NULL );

	/* I guess we should play with sub/supertypes to find a suitable oc */
	oc = backsql_name2oc( bi, &at->a_vals[0] );

	if ( oc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"cannot determine objectclass of entry -- aborting\n",
			0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;
	}

	if ( oc->bom_create_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"create procedure is not defined for this objectclass "
			"- aborting\n", 0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;

	} else if ( BACKSQL_CREATE_NEEDS_SELECT( bi )
			&& oc->bom_create_keyval == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"create procedure needs select procedure, "
			"but none is defined - aborting\n", 0, 0, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;
	}

	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			?  "SQL-backend error" : NULL;
		goto done;
	}

	/*
	 * Check if entry exists
	 */
	realdn = op->oq_add.rs_e->e_name;
	if ( backsql_api_dn2odbc( op, rs, &realdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"backsql_api_dn2odbc failed\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rs->sr_err = backsql_dn2id( bi, NULL, dbh, &realdn );
	if ( rs->sr_err == LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"entry \"%s\" exists\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );
		rs->sr_err = LDAP_ALREADY_EXISTS;
		goto done;
	}

	/*
	 * Check if parent exists
	 */
	dnParent( &op->oq_add.rs_e->e_name, &pdn );
	realpdn = pdn;
	if ( backsql_api_dn2odbc( op, rs, &realpdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"backsql_api_dn2odbc failed\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rs->sr_err = backsql_dn2id( bi, &parent_id, dbh, &realpdn );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"could not lookup parent entry for new record \"%s\"\n",
			pdn.bv_val, 0, 0 );

		if ( rs->sr_err != LDAP_NO_SUCH_OBJECT ) {
			goto done;
		}

		/*
		 * Look for matched
		 */
		while ( 1 ) {
			struct berval	dn;
			char		*matched = NULL;

			if ( realpdn.bv_val != pdn.bv_val ) {
				ch_free( realpdn.bv_val );
			}

			dn = pdn;
			dnParent( &dn, &pdn );

			/*
			 * Empty DN ("") defaults to LDAP_SUCCESS
			 */
			realpdn = pdn;
			if ( backsql_api_dn2odbc( op, rs, &realpdn ) ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_add(): "
					"backsql_api_dn2odbc failed\n", 
					0, 0, 0 );
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}

			rs->sr_err = backsql_dn2id( bi, NULL, dbh, &realpdn );
			switch ( rs->sr_err ) {
			case LDAP_NO_SUCH_OBJECT:
				if ( pdn.bv_len > 0 ) {
					break;
				}
				/* fail over to next case */
				
			case LDAP_SUCCESS:
				matched = pdn.bv_val;
				/* fail over to next case */

			default:
				rs->sr_err = LDAP_NO_SUCH_OBJECT;
				rs->sr_matched = matched;
				goto done;
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
	dnParent( &op->oq_add.rs_e->e_nname, &p.e_nname );
	if ( !access_allowed( op, &p, slap_schema.si_ad_children,
				NULL, ACL_WRITE, NULL ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto done;
	}

	rc = SQLAllocStmt( dbh, &sth );
	if ( rc != SQL_SUCCESS ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	if ( BACKSQL_IS_ADD( oc->bom_expect_return ) ) {
		SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT, SQL_C_ULONG, 
				SQL_INTEGER, 0, 0, &new_keyval, 0, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "   backsql_add(): executing \"%s\"\n",
		oc->bom_create_proc, 0, 0 );
	rc = SQLExecDirect( sth, oc->bom_create_proc, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"create_proc execution failed\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc);
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	if ( op->o_noop ) {
		SQLTransact( SQL_NULL_HENV, dbh, SQL_ROLLBACK );
	}

	if ( !BACKSQL_IS_ADD( oc->bom_expect_return ) ) {
		SWORD		ncols;
		SQLINTEGER	value_len;

		if ( BACKSQL_CREATE_NEEDS_SELECT( bi ) ) {
#ifndef BACKSQL_REALLOC_STMT
			SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
			SQLFreeStmt( sth, SQL_DROP );
			rc = SQLAllocStmt( dbh, &sth );
			if ( rc != SQL_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}
#endif /* BACKSQL_REALLOC_STMT */

			rc = SQLExecDirect( sth, oc->bom_create_keyval, SQL_NTS );
			if ( rc != SQL_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}
		}

		/*
		 * the query to know the id of the inserted entry
		 * must be embedded in the create procedure
		 */
		rc = SQLNumResultCols( sth, &ncols );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"create_proc result evaluation failed\n",
				0, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "SQL-backend error";
			goto done;

		} else if ( ncols != 1 ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"create_proc result is bogus (ncols=%d)\n",
				ncols, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "SQL-backend error";
			goto done;
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
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"create_proc result is empty?\n",
				0, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "SQL-backend error";
			goto done;
		}
	}

#ifndef BACKSQL_REALLOC_STMT
	SQLFreeStmt( sth, SQL_RESET_PARAMS );
#else /* BACKSQL_REALLOC_STMT */
	SQLFreeStmt( sth, SQL_DROP );
#endif /* BACKSQL_REALLOC_STMT */

	Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
		"create_proc returned keyval=%ld\n", new_keyval, 0, 0 );

	for ( at = op->oq_add.rs_e->e_attrs; at != NULL; at = at->a_next ) {
		SQLUSMALLINT	currpos;

		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"adding attribute \"%s\"\n", 
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
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"attribute \"%s\" is not registered "
				"in objectclass \"%s\"\n",
				at->a_desc->ad_cname.bv_val,
				BACKSQL_OC_NAME( oc ), 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text = "operation not permitted "
					"within namingContext";
				goto done;
			}

			continue;
		}
		
		if ( at_rec->bam_add_proc == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"add procedure is not defined "
				"for attribute \"%s\"\n",
				at->a_desc->ad_cname.bv_val, 0, 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text = "operation not permitted "
					"within namingContext";
				goto done;
			}

			continue;
		}

#ifdef BACKSQL_REALLOC_STMT
		rc = backsql_Prepare( dbh, &sth, at_rec->bam_add_proc, 0 );
		if ( rc != SQL_SUCCESS ) {

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}

			continue;
		}
#endif /* BACKSQL_REALLOC_STMT */

		if ( BACKSQL_IS_ADD( at_rec->bam_expect_return ) ) {
			pno = 1;
			SQLBindParameter( sth, 1, SQL_PARAM_OUTPUT,
					SQL_C_ULONG, SQL_INTEGER,
					0, 0, &prc, 0, 0 );
		} else {
			pno = 0;
		}

		po = ( BACKSQL_IS_ADD( at_rec->bam_param_order ) ) > 0;
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
				if ( bvmatch( at_val, &oc->bom_oc->soc_cname ) ) {
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
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"executing \"%s\", id=%ld\n", 
				at_rec->bam_add_proc, new_keyval, 0 );
#else
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
				"executing \"%s\" for val[%d], id=%ld\n", 
				at_rec->bam_add_proc, i, new_keyval );
#endif
#ifndef BACKSQL_REALLOC_STMT
			rc = SQLExecDirect( sth, at_rec->bam_add_proc, SQL_NTS );
#else /* BACKSQL_REALLOC_STMT */
			rc = SQLExecute( sth );
#endif /* BACKSQL_REALLOC_STMT */
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
					"add_proc execution failed\n", 
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, sth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
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
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
#endif /* BACKSQL_REALLOC_STMT */
	
	backsql_BindParamStr( sth, 1, op->oq_add.rs_e->e_name.bv_val,
			BACKSQL_MAX_DN_LEN );
	SQLBindParameter( sth, 2, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &oc->bom_id, 0, 0 );
#ifdef BACKSQL_ARBITRARY_KEY
	SQLBindParameter( sth, 3, SQL_PARAM_INPUT, SQL_C_CHAR, SQL_VARCHAR,
			0, 0, parent_id.eid_id.bv_val, 0, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
	SQLBindParameter( sth, 3, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &parent_id.eid_id, 0, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */
	SQLBindParameter( sth, 4, SQL_PARAM_INPUT, SQL_C_LONG, SQL_INTEGER,
			0, 0, &new_keyval, 0, 0 );

	Debug( LDAP_DEBUG_TRACE, "   backsql_add(): executing \"%s\" for dn \"%s\"\n",
			bi->insentry_query, op->oq_add.rs_e->e_name.bv_val, 0 );
#ifdef BACKSQL_ARBITRARY_KEY
	Debug( LDAP_DEBUG_TRACE, "                  for oc_map_id=%ld, "
			"parent_id=%s, keyval=%ld\n",
			oc->bom_id, parent_id.eid_id.bv_val, new_keyval );
#else /* ! BACKSQL_ARBITRARY_KEY */
	Debug( LDAP_DEBUG_TRACE, "                  for oc_map_id=%ld, "
			"parent_id=%ld, keyval=%ld\n",
			oc->bom_id, parent_id.eid_id, new_keyval );
#endif /* ! BACKSQL_ARBITRARY_KEY */
#ifndef BACKSQL_REALLOC_STMT
	rc = SQLExecDirect( sth, bi->insentry_query, SQL_NTS );
#else /* BACKSQL_REALLOC_STMT */
	rc = SQLExecute( sth );
#endif /* BACKSQL_REALLOC_STMT */
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"could not insert ldap_entries record\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		
		/*
		 * execute delete_proc to delete data added !!!
		 */
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
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
	 * 
	 * hint: there might be some autocommit in Postgres
	 * so that when the unique id of the key table is
	 * automatically increased, there's no rollback.
	 * We might implement a "rollback" procedure consisting
	 * in deleting that row.
	 */

done:;
	send_ldap_result( op, rs );

	if ( realdn.bv_val != op->oq_add.rs_e->e_name.bv_val ) {
		ch_free( realdn.bv_val );
	}
	if ( realpdn.bv_val != pdn.bv_val ) {
		ch_free( realpdn.bv_val );
	}
	if ( parent_id.eid_dn.bv_val != NULL ) {
		backsql_free_entryID( &parent_id, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_add(): %d%s%s\n",
			rs->sr_err,
			rs->sr_text ? ": " : "",
			rs->sr_text ? rs->sr_text : "" );

	return ( ( rs->sr_err == LDAP_SUCCESS ) ? op->o_noop : 1 );
}

#endif /* SLAPD_SQL */

