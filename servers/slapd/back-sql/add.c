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
 * - empty attributes (FIXME ?!?)
 */
#define	backsql_attr_skip(ad,vals) \
	( \
		( (ad) == slap_schema.si_ad_objectClass \
				&& BER_BVISNULL( &((vals)[ 1 ]) ) ) \
		|| is_at_operational( (ad)->ad_type ) \
		|| ( (vals) && BER_BVISNULL( &((vals)[ 0 ]) ) ) \
	)

int
backsql_modify_delete_all_values(
	Operation 		*op,
	SlapReply		*rs,
	SQLHDBC			dbh, 
	backsql_entryID		*e_id,
	backsql_at_map_rec	*at )
{
	backsql_info	*bi = (backsql_info *)op->o_bd->be_private;
	RETCODE		rc;
	SQLHSTMT	asth;
	BACKSQL_ROW_NTS	row;

	rc = backsql_Prepare( dbh, &asth, at->bam_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_modify_delete_all_values(): "
			"error preparing query\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
				asth, rc );

		if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
			rs->sr_text = "SQL-backend error";
			return rs->sr_err = LDAP_OTHER;
		}
		return LDAP_SUCCESS;
	}

	rc = backsql_BindParamID( asth, 1, SQL_PARAM_INPUT, &e_id->eid_keyval );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_modify_delete_all_values(): "
			"error binding key value parameter\n",
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
				asth, rc );
		SQLFreeStmt( asth, SQL_DROP );

		if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
			rs->sr_text = "SQL-backend error";
			return rs->sr_err = LDAP_OTHER;
		}

		return LDAP_SUCCESS;
	}
			
	rc = SQLExecute( asth );
	if ( !BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_modify_delete_all_values(): "
			"error executing attribute query\n",
			0, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
				asth, rc );
		SQLFreeStmt( asth, SQL_DROP );

		if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
			rs->sr_text = "SQL-backend error";
			return rs->sr_err = LDAP_OTHER;
		}

		return LDAP_SUCCESS;
	}

	backsql_BindRowAsStrings( asth, &row );
	for ( rc = SQLFetch( asth );
			BACKSQL_SUCCESS( rc );
			rc = SQLFetch( asth ) )
	{
		int			i;
		/* first parameter no, parameter order */
		SQLUSMALLINT		pno, po;
		/* procedure return code */
		int			prc;
		
		for ( i = 0; i < row.ncols; i++ ) {
			SQLHSTMT	sth;
			ber_len_t	col_len;
			
			rc = backsql_Prepare( dbh, &sth, at->bam_delete_proc, 0 );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_delete_all_values(): "
					"error preparing query %s\n",
					at->bam_delete_proc, 0, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_text = "SQL-backend error";
					return rs->sr_err = LDAP_OTHER;
				}

				continue;
			}

	   		if ( BACKSQL_IS_DEL( at->bam_expect_return ) ) {
				pno = 1;
				rc = backsql_BindParamInt( sth, 1,
						SQL_PARAM_OUTPUT, &prc );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_delete_all_values(): "
						"error binding output parameter for %s[%d]\n",
						at->bam_ad->ad_cname.bv_val, i, 0 );
					backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );
					SQLFreeStmt( sth, SQL_DROP );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						rs->sr_text = "SQL-backend error";
						return rs->sr_err = LDAP_OTHER;
					}

					continue;
				}

			} else {
				pno = 0;
			}
			po = ( BACKSQL_IS_DEL( at->bam_param_order ) ) > 0;
			rc = backsql_BindParamID( sth, pno + 1 + po,
				SQL_PARAM_INPUT, &e_id->eid_keyval );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_delete_all_values(): "
					"error binding keyval parameter for %s[%d]\n",
					at->bam_ad->ad_cname.bv_val, i, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
					sth, rc );
				SQLFreeStmt( sth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_text = "SQL-backend error";
					return rs->sr_err = LDAP_OTHER;
				}

				continue;
			}
#ifdef BACKSQL_ARBITRARY_KEY
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_modify_delete_all_values() "
				"arg%d=%s\n",
				pno + 1 + po, e_id->eid_keyval.bv_val, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_modify_delete_all_values() "
				"arg%d=%lu\n",
				pno + 1 + po, e_id->eid_keyval, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

			/*
			 * check for syntax needed here 
			 * maybe need binary bind?
			 */
			col_len = strlen( row.cols[ i ] );
			rc = backsql_BindParamStr( sth, pno + 2 - po,
				SQL_PARAM_INPUT, row.cols[ i ], col_len );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_delete_all_values(): "
					"error binding value parameter for %s[%d]\n",
					at->bam_ad->ad_cname.bv_val, i, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
					sth, rc );
				SQLFreeStmt( sth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_text = "SQL-backend error";
					return rs->sr_err = LDAP_OTHER;
				}

				continue;
			}
	 
			Debug( LDAP_DEBUG_TRACE, 
				"   backsql_modify_delete_all_values(): "
				"arg%d=%s; executing \"%s\"\n",
				pno + 2 - po, row.cols[ i ],
				at->bam_delete_proc );
			rc = SQLExecute( sth );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_delete_all_values(): "
					"delete_proc "
					"execution failed\n",
					0, 0, 0 );
				backsql_PrintErrors( bi->db_env,
						dbh, sth, rc );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					SQLFreeStmt( sth, SQL_DROP );
					rs->sr_text = "SQL-backend error";
					return rs->sr_err = LDAP_OTHER;
				}
			}
			SQLFreeStmt( sth, SQL_DROP );
		}
	}
	backsql_FreeRow( &row );
	SQLFreeStmt( asth, SQL_DROP );

	return LDAP_SUCCESS;
}

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

	for ( ml = modlist; ml != NULL; ml = ml->sml_next ) {
		AttributeDescription	*ad;
		int			sm_op;
		static char		*sm_ops[] = { "add", "delete", "replace", "increment", NULL };

		BerVarray		sm_values;
#if 0
		/* NOTE: some time we'll have to pass 
		 * the normalized values as well */
		BerVarray		nvalues;
#endif
		backsql_at_map_rec	*at = NULL;
		struct berval		*at_val;
		int			i;
		/* first parameter no, parameter order */
		SQLUSMALLINT		pno, po;
		/* procedure return code */
		int			prc;
		
		ad = ml->sml_mod.sm_desc;
		sm_op = ( ml->sml_mod.sm_op & LDAP_MOD_OP );
		sm_values = ml->sml_mod.sm_values;
#if 0
		sm_nvalues = ml->sml_mod.sm_nvalues;
#endif

		Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
			"modifying attribute \"%s\" (%s) according to "
			"mappings for objectClass \"%s\"\n",
			ad->ad_cname.bv_val, sm_ops[ sm_op ], BACKSQL_OC_NAME( oc ) );

		if ( backsql_attr_skip( ad, sm_values ) ) {
			continue;
		}

  		at = backsql_ad2at( oc, ad );
		if ( at == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"attribute \"%s\" is not registered "
				"in objectClass \"%s\"\n",
				ad->ad_cname.bv_val, BACKSQL_OC_NAME( oc ), 0 );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				rs->sr_text = "operation not permitted "
					"within namingContext";
				goto done;
			}

			continue;
		}
  
		switch ( sm_op ) {
		case LDAP_MOD_REPLACE: {
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
			rs->sr_err = backsql_modify_delete_all_values( op, rs, dbh, e_id, at );
			if ( rs->sr_err != LDAP_SUCCESS ) {
				goto done;
			}

			/* LDAP_MOD_DELETE gets here if all values must be deleted */
			if ( sm_op == LDAP_MOD_DELETE ) {
				break;
			}
	       	}

		/*
		 * PASSTHROUGH - to add new attributes -- do NOT add break
		 */
		case LDAP_MOD_ADD:
		/* case SLAP_MOD_SOFTADD: */
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
			for ( i = 0, at_val = sm_values;
					!BER_BVISNULL( at_val ); 
					i++, at_val++ )
			{
				rc = backsql_Prepare( dbh, &sth, at->bam_add_proc, 0 );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error preparing add query\n", 
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env, dbh, sth, rc );

					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}

				if ( BACKSQL_IS_ADD( at->bam_expect_return ) ) {
					pno = 1;
	      				rc = backsql_BindParamInt( sth, 1,
						SQL_PARAM_OUTPUT, &prc );
					if ( rc != SQL_SUCCESS ) {
						Debug( LDAP_DEBUG_TRACE,
							"   backsql_modify_internal(): "
							"error binding output parameter for %s[%d]\n",
							at->bam_ad->ad_cname.bv_val, i, 0 );
						backsql_PrintErrors( bi->db_env, dbh, 
							sth, rc );
						SQLFreeStmt( sth, SQL_DROP );

						rs->sr_text = "SQL-backend error";
						rs->sr_err = LDAP_OTHER;
						goto done;
					}
	 
				} else {
	      				pno = 0;
				}
				po = ( BACKSQL_IS_ADD( at->bam_param_order ) ) > 0;
				rc = backsql_BindParamID( sth, pno + 1 + po,
					SQL_PARAM_INPUT, &e_id->eid_keyval );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error binding keyval parameter for %s[%d]\n",
						at->bam_ad->ad_cname.bv_val, i, 0 );
					backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );
					SQLFreeStmt( sth, SQL_DROP );

					rs->sr_text = "SQL-backend error";
					rs->sr_err = LDAP_OTHER;
					goto done;
				}
#ifdef BACKSQL_ARBITRARY_KEY
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"arg%d=\"%s\"\n", 
					pno + 1 + po, e_id->eid_keyval.bv_val, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"arg%d=\"%lu\"\n", 
					pno + 1 + po, e_id->eid_keyval, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

				/*
				 * check for syntax needed here
				 * maybe need binary bind?
				 */
				rc = backsql_BindParamBerVal( sth, pno + 2 - po,
					SQL_PARAM_INPUT, at_val );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error binding value parameter for %s[%d]\n",
						at->bam_ad->ad_cname.bv_val, i, 0 );
					backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );
					SQLFreeStmt( sth, SQL_DROP );

					rs->sr_text = "SQL-backend error";
					rs->sr_err = LDAP_OTHER;
					goto done;
				}
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"arg%d=\"%s\"; executing \"%s\"\n", 
					pno + 2 - po, at_val->bv_val,
					at->bam_add_proc );

				rc = SQLExecute( sth );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"add_proc execution failed\n",
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						SQLFreeStmt( sth, SQL_DROP );
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "SQL-backend error";
						goto done;
					}
				}
				SQLFreeStmt( sth, SQL_DROP );
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

			if ( sm_values == NULL ) {
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

			for ( i = 0, at_val = sm_values;
					!BER_BVISNULL( at_val );
					i++, at_val++ )
			{
				rc = backsql_Prepare( dbh, &sth, at->bam_delete_proc, 0 );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error preparing delete query\n", 
						0, 0, 0 );
					backsql_PrintErrors( bi->db_env, dbh, sth, rc );

					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}

				if ( BACKSQL_IS_DEL( at->bam_expect_return ) ) {
					pno = 1;
					rc = backsql_BindParamInt( sth, 1,
						SQL_PARAM_OUTPUT, &prc );
					if ( rc != SQL_SUCCESS ) {
						Debug( LDAP_DEBUG_TRACE,
							"   backsql_modify_internal(): "
							"error binding output parameter for %s[%d]\n",
							at->bam_ad->ad_cname.bv_val, i, 0 );
						backsql_PrintErrors( bi->db_env, dbh, 
							sth, rc );
						SQLFreeStmt( sth, SQL_DROP );

						rs->sr_text = "SQL-backend error";
						rs->sr_err = LDAP_OTHER;
						goto done;
					}

				} else {
					pno = 0;
				}
				po = ( BACKSQL_IS_DEL( at->bam_param_order ) ) > 0;
				rc = backsql_BindParamID( sth, pno + 1 + po,
					SQL_PARAM_INPUT, &e_id->eid_keyval );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error binding keyval parameter for %s[%d]\n",
						at->bam_ad->ad_cname.bv_val, i, 0 );
					backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );
					SQLFreeStmt( sth, SQL_DROP );

					rs->sr_text = "SQL-backend error";
					rs->sr_err = LDAP_OTHER;
					goto done;
				}
#ifdef BACKSQL_ARBITRARY_KEY
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"arg%d=\"%s\"\n", 
					pno + 1 + po, e_id->eid_keyval.bv_val, 0 );
#else /* ! BACKSQL_ARBITRARY_KEY */
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"arg%d=\"%lu\"\n", 
					pno + 1 + po, e_id->eid_keyval, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */

				/*
				 * check for syntax needed here 
				 * maybe need binary bind?
				 */
				rc = backsql_BindParamBerVal( sth, pno + 2 - po,
					SQL_PARAM_INPUT, at_val );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"error binding value parameter for %s[%d]\n",
						at->bam_ad->ad_cname.bv_val, i, 0 );
					backsql_PrintErrors( bi->db_env, dbh, 
						sth, rc );
					SQLFreeStmt( sth, SQL_DROP );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						rs->sr_text = "SQL-backend error";
						rs->sr_err = LDAP_OTHER;
						goto done;
					}
				}

				Debug( LDAP_DEBUG_TRACE,
					"   backsql_modify_internal(): "
					"executing \"%s\"\n", 
					at->bam_delete_proc, 0, 0 );
				rc = SQLExecute( sth );
				if ( rc != SQL_SUCCESS ) {
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_modify_internal(): "
						"delete_proc execution "
						"failed\n", 0, 0, 0 );
					backsql_PrintErrors( bi->db_env,
							dbh, sth, rc );

					if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
						SQLFreeStmt( sth, SQL_DROP );
						rs->sr_err = LDAP_OTHER;
						rs->sr_text = "SQL-backend error";
						goto done;
					}
				}
				SQLFreeStmt( sth, SQL_DROP );
			}
			break;

	      	case LDAP_MOD_INCREMENT:
			Debug( LDAP_DEBUG_TRACE, "   backsql_modify_internal(): "
				"increment not supported yet\n", 0, 0, 0 );
			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}
			break;
		}
	}

done:;
	Debug( LDAP_DEBUG_TRACE, "<==backsql_modify_internal(): %d%s%s\n",
		rs->sr_err,
		rs->sr_text ? ": " : "",
		rs->sr_text ? rs->sr_text : "" );

	/*
	 * FIXME: should fail in case one change fails?
	 */
	return rs->sr_err;
}

static int
backsql_add_attr(
	Operation		*op,
	SlapReply		*rs,
	SQLHDBC 		dbh,
	backsql_oc_map_rec 	*oc,
	Attribute		*at,
	unsigned long		new_keyval )
{
	backsql_info		*bi = (backsql_info*)op->o_bd->be_private;
	backsql_at_map_rec	*at_rec = NULL;
	struct berval		*at_val;
	unsigned long		i;
	RETCODE			rc;
	/* first parameter #, parameter order */
	SQLUSMALLINT		pno, po;
	/* procedure return code */
	int			prc;
	SQLUSMALLINT		currpos;
	SQLHSTMT 		sth;

	at_rec = backsql_ad2at( oc, at->a_desc ); 
  
	if ( at_rec == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add_attr(\"%s\"): "
			"attribute \"%s\" is not registered "
			"in objectclass \"%s\"\n",
			op->oq_add.rs_e->e_name.bv_val,
			at->a_desc->ad_cname.bv_val,
			BACKSQL_OC_NAME( oc ) );

		if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
			rs->sr_text = "operation not permitted "
				"within namingContext";
			return rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		}

		return LDAP_SUCCESS;
	}
	
	if ( at_rec->bam_add_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add_attr(\"%s\"): "
			"add procedure is not defined "
			"for attribute \"%s\" "
			"of structuralObjectClass \"%s\"\n",
			op->oq_add.rs_e->e_name.bv_val,
			at->a_desc->ad_cname.bv_val,
			BACKSQL_OC_NAME( oc ) );

		if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
			rs->sr_text = "operation not permitted "
				"within namingContext";
			return rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		}

		return LDAP_SUCCESS;
	}

	for ( i = 0, at_val = &at->a_vals[ i ];
		       	!BER_BVISNULL( at_val );
			i++, at_val = &at->a_vals[ i ] )
	{
		char logbuf[] = "val[18446744073709551615UL], id=18446744073709551615UL";
		
		/*
		 * Do not deal with the objectClass that is used
		 * to build the entry
		 */
		if ( at->a_desc == slap_schema.si_ad_objectClass ) {
			if ( bvmatch( at_val, &oc->bom_oc->soc_cname ) )
			{
				continue;
			}
		}

		rc = backsql_Prepare( dbh, &sth, at_rec->bam_add_proc, 0 );
		if ( rc != SQL_SUCCESS ) {

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_text = "SQL-backend error";
				return rs->sr_err = LDAP_OTHER;
			}

			return LDAP_SUCCESS;
		}

		if ( BACKSQL_IS_ADD( at_rec->bam_expect_return ) ) {
			pno = 1;
			rc = backsql_BindParamInt( sth, 1, SQL_PARAM_OUTPUT, &prc );
			if ( rc != SQL_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE,
					"   backsql_add_attr(): "
					"error binding output parameter for %s[%d]\n",
					at_rec->bam_ad->ad_cname.bv_val, i, 0 );
				backsql_PrintErrors( bi->db_env, dbh, 
					sth, rc );
				SQLFreeStmt( sth, SQL_DROP );

				if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
					rs->sr_text = "SQL-backend error";
					return rs->sr_err = LDAP_OTHER;
				}

				return LDAP_SUCCESS;
			}

		} else {
			pno = 0;
		}

		po = ( BACKSQL_IS_ADD( at_rec->bam_param_order ) ) > 0;
		currpos = pno + 1 + po;
		rc = backsql_BindParamInt( sth, currpos,
				SQL_PARAM_INPUT, &new_keyval );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_add_attr(): "
				"error binding keyval parameter for %s[%d]\n",
				at_rec->bam_ad->ad_cname.bv_val, i, 0 );
			backsql_PrintErrors( bi->db_env, dbh, 
				sth, rc );
			SQLFreeStmt( sth, SQL_DROP );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_text = "SQL-backend error";
				return rs->sr_err = LDAP_OTHER;
			}

			return LDAP_SUCCESS;
		}

		currpos = pno + 2 - po;

		/*
		 * check for syntax needed here 
		 * maybe need binary bind?
		 */

		rc = backsql_BindParamBerVal( sth, currpos, SQL_PARAM_INPUT, at_val );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_add_attr(): "
				"error binding value parameter for %s[%d]\n",
				at_rec->bam_ad->ad_cname.bv_val, i, 0 );
			backsql_PrintErrors( bi->db_env, dbh, 
				sth, rc );
			SQLFreeStmt( sth, SQL_DROP );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				rs->sr_text = "SQL-backend error";
				return rs->sr_err = LDAP_OTHER;
			}

			return LDAP_SUCCESS;
		}

#ifdef LDAP_DEBUG
		snprintf( logbuf, sizeof( logbuf ), "val[%lu], id=%lu",
				i, new_keyval );
		Debug( LDAP_DEBUG_TRACE, "   backsql_add_attr(\"%s\"): "
			"executing \"%s\" %s\n", 
			op->oq_add.rs_e->e_name.bv_val,
			at_rec->bam_add_proc, logbuf );
#endif
		rc = SQLExecute( sth );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_add_attr(\"%s\"): "
				"add_proc execution failed\n", 
				op->oq_add.rs_e->e_name.bv_val, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc );

			if ( BACKSQL_FAIL_IF_NO_MAPPING( bi ) ) {
				SQLFreeStmt( sth, SQL_DROP );
				rs->sr_text = "SQL-backend error";
				return rs->sr_err = LDAP_OTHER;
			}
		}
		SQLFreeStmt( sth, SQL_DROP );
	}

	return LDAP_SUCCESS;
}

int
backsql_add( Operation *op, SlapReply *rs )
{
	backsql_info		*bi = (backsql_info*)op->o_bd->be_private;
	SQLHDBC 		dbh;
	SQLHSTMT 		sth;
	unsigned long		new_keyval = 0;
	RETCODE			rc;
	backsql_oc_map_rec 	*oc = NULL;
	backsql_entryID		parent_id = BACKSQL_ENTRYID_INIT;
	Entry			p;
	Attribute		*at,
				*at_objectClass = NULL;
	struct berval		pdn;
	struct berval		realdn = BER_BVNULL,
				realpdn = BER_BVNULL;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_add(\"%s\")\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );

	/* check schema */
	if ( global_schemacheck ) {
		char		textbuf[ SLAP_TEXT_BUFLEN ] = { '\0' };

		rs->sr_err = entry_schema_check( op->o_bd, op->oq_add.rs_e,
				NULL,
				&rs->sr_text, textbuf, sizeof( textbuf ) );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
				"entry failed schema check -- aborting\n",
				op->oq_add.rs_e->e_name.bv_val, 0, 0 );
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
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"cannot map structuralObjectClass \"%s\" -- aborting\n",
			op->oq_add.rs_e->e_name.bv_val,
			at->a_vals[0].bv_val, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;
	}

	if ( oc->bom_create_proc == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"create procedure is not defined "
			"for structuralObjectClass \"%s\" - aborting\n",
			op->oq_add.rs_e->e_name.bv_val,
			at->a_vals[0].bv_val, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;

	} else if ( BACKSQL_CREATE_NEEDS_SELECT( bi )
			&& oc->bom_create_keyval == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"create procedure needs select procedure, "
			"but none is defined for structuralObjectClass \"%s\" "
			"- aborting\n",
			op->oq_add.rs_e->e_name.bv_val,
			at->a_vals[0].bv_val, 0 );
		rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		rs->sr_text = "operation not permitted within namingContext";
		goto done;
	}

	rs->sr_err = backsql_get_db_conn( op, &dbh );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"could not get connection handle - exiting\n", 
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );
		rs->sr_text = ( rs->sr_err == LDAP_OTHER )
			?  "SQL-backend error" : NULL;
		goto done;
	}

	/*
	 * Check if entry exists
	 */
	realdn = op->oq_add.rs_e->e_name;
	if ( backsql_api_dn2odbc( op, rs, &realdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"backsql_api_dn2odbc(\"%s\") failed\n", 
			op->oq_add.rs_e->e_name.bv_val,
			op->oq_add.rs_e->e_name.bv_val, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rs->sr_err = backsql_dn2id( bi, NULL, dbh, &realdn );
	if ( rs->sr_err == LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"entry exists\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );
		rs->sr_err = LDAP_ALREADY_EXISTS;
		goto done;
	}

	/*
	 * Get the parent dn and see if the corresponding entry exists.
	 */
	if ( be_issuffix( op->o_bd, &op->oq_add.rs_e->e_nname ) ) {
		pdn = slap_empty_bv;

	} else {
		dnParent( &op->oq_add.rs_e->e_nname, &pdn );
	}

	realpdn = pdn;
	if ( backsql_api_dn2odbc( op, rs, &realpdn ) ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"backsql_api_dn2odbc(\"%s\") failed\n", 
			op->oq_add.rs_e->e_name.bv_val, pdn.bv_val, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	rs->sr_err = backsql_dn2id( bi, &parent_id, dbh, &realpdn );
	if ( rs->sr_err != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"could not lookup parent entry for new record \"%s\"\n",
			op->oq_add.rs_e->e_name.bv_val, pdn.bv_val, 0 );

		if ( rs->sr_err != LDAP_NO_SUCH_OBJECT ) {
			goto done;
		}

		/*
		 * no parent!
		 *  if not attempting to add entry at suffix or with parent ""
		 */
		if ( ( ( !be_isroot( op ) && !be_shadow_update( op ) )
			|| !BER_BVISEMPTY( &pdn ) ) && !is_entry_glue( op->oq_add.rs_e ) )
		{
			Debug( LDAP_DEBUG_TRACE, "   backsql_add: %s denied\n",
				BER_BVISEMPTY( &pdn ) ? "suffix" : "entry at root",
				0, 0 );
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
					Debug( LDAP_DEBUG_TRACE,
						"   backsql_add(\"%s\"): "
						"backsql_api_dn2odbc failed\n", 
						op->oq_add.rs_e->e_name.bv_val, 0, 0 );
					rs->sr_err = LDAP_OTHER;
					rs->sr_text = "SQL-backend error";
					goto done;
				}
	
				rs->sr_err = backsql_dn2id( bi, NULL, dbh, &realpdn );
				switch ( rs->sr_err ) {
				case LDAP_NO_SUCH_OBJECT:
					if ( !BER_BVISEMPTY( &pdn ) ) {
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
		} else {

#ifdef BACKSQL_ARBITRARY_KEY
			ber_str2bv( "SUFFIX", 0, 1, &parent_id.eid_id );
#else /* ! BACKSQL_ARBITRARY_KEY */
			parent_id.eid_id = 0;
#endif /* ! BACKSQL_ARBITRARY_KEY */
			rs->sr_err = LDAP_SUCCESS;
		}
	}

	/* check "children" pseudo-attribute access to parent */
	p.e_attrs = NULL;
	p.e_name = pdn;
	dnParent( &op->oq_add.rs_e->e_nname, &p.e_nname );
	if ( !access_allowed( op, &p, slap_schema.si_ad_children,
				NULL, ACL_WRITE, NULL ) ) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		goto done;
	}

	/*
	 * create_proc is executed; if expect_return is set, then
	 * an output parameter is bound, which should contain 
	 * the id of the added row; otherwise the procedure
	 * is expected to return the id as the first column of a select
	 */

	rc = SQLAllocStmt( dbh, &sth );
	if ( rc != SQL_SUCCESS ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	if ( BACKSQL_IS_ADD( oc->bom_expect_return ) ) {
		rc = backsql_BindParamInt( sth, 1, SQL_PARAM_OUTPUT, &new_keyval );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"   backsql_add_attr(): "
				"error binding keyval parameter for objectClass %s\n",
				oc->bom_oc->soc_cname.bv_val, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, 
				sth, rc );
			SQLFreeStmt( sth, SQL_DROP );

			rs->sr_text = "SQL-backend error";
			rs->sr_err = LDAP_OTHER;
			goto done;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): executing \"%s\"\n",
		op->oq_add.rs_e->e_name.bv_val, oc->bom_create_proc, 0 );
	rc = SQLExecDirect( sth, oc->bom_create_proc, SQL_NTS );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"create_proc execution failed\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );
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
			SQLFreeStmt( sth, SQL_DROP );
			rc = SQLAllocStmt( dbh, &sth );
			if ( rc != SQL_SUCCESS ) {
				rs->sr_err = LDAP_OTHER;
				rs->sr_text = "SQL-backend error";
				goto done;
			}

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
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
				"create_proc result evaluation failed\n",
				op->oq_add.rs_e->e_name.bv_val, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "SQL-backend error";
			goto done;

		} else if ( ncols != 1 ) {
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
				"create_proc result is bogus (ncols=%d)\n",
				op->oq_add.rs_e->e_name.bv_val, ncols, 0 );
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
			Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
				"create_proc result is empty?\n",
				op->oq_add.rs_e->e_name.bv_val, 0, 0 );
			backsql_PrintErrors( bi->db_env, dbh, sth, rc);
			SQLFreeStmt( sth, SQL_DROP );
			rs->sr_err = LDAP_OTHER;
			rs->sr_text = "SQL-backend error";
			goto done;
		}
	}

	SQLFreeStmt( sth, SQL_DROP );

	Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
		"create_proc returned keyval=%ld\n",
		op->oq_add.rs_e->e_name.bv_val, new_keyval, 0 );

	for ( at = op->oq_add.rs_e->e_attrs; at != NULL; at = at->a_next ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(): "
			"adding attribute \"%s\"\n", 
			at->a_desc->ad_cname.bv_val, 0, 0 );

		/*
		 * Skip:
		 * - the first occurrence of objectClass, which is used
		 *   to determine how to build the SQL entry (FIXME ?!?)
		 * - operational attributes
		 * - empty attributes (FIXME ?!?)
		 */
		if ( backsql_attr_skip( at->a_desc, at->a_vals ) ) {
			continue;
		}

		if ( at->a_desc == slap_schema.si_ad_objectClass ) {
			at_objectClass = at;
			continue;
		}

		rs->sr_err = backsql_add_attr( op, rs, dbh, oc, at, new_keyval );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			goto done;
		}
	}

	rc = backsql_Prepare( dbh, &sth, bi->insentry_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}
	
	rc = backsql_BindParamBerVal( sth, 1, SQL_PARAM_INPUT, &realdn );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_add_attr(): "
			"error binding DN parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = backsql_BindParamInt( sth, 2, SQL_PARAM_INPUT, &oc->bom_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_add_attr(): "
			"error binding objectClass ID parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = backsql_BindParamID( sth, 3, SQL_PARAM_INPUT, &parent_id.eid_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_add_attr(): "
			"error binding parent ID parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

	rc = backsql_BindParamInt( sth, 4, SQL_PARAM_INPUT, &new_keyval );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE,
			"   backsql_add_attr(): "
			"error binding entry ID parameter for objectClass %s\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, 
			sth, rc );
		SQLFreeStmt( sth, SQL_DROP );

		rs->sr_text = "SQL-backend error";
		rs->sr_err = LDAP_OTHER;
		goto done;
	}

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
	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "   backsql_add(\"%s\"): "
			"could not insert ldap_entries record\n",
			op->oq_add.rs_e->e_name.bv_val, 0, 0 );
		backsql_PrintErrors( bi->db_env, dbh, sth, rc );
		
		/*
		 * execute delete_proc to delete data added !!!
		 */
		SQLFreeStmt( sth, SQL_DROP );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		goto done;
	}

	/* FIXME: need ldap_entries.id of newly added entry */
	if ( at_objectClass ) {
		rs->sr_err = backsql_add_attr( op, rs, dbh, oc, at_objectClass, new_keyval );
		if ( rs->sr_err != LDAP_SUCCESS ) {
			goto done;
		}
	}

	SQLFreeStmt( sth, SQL_DROP );

done:;
	/*
	 * Commit only if all operations succeed
	 */
	if ( rs->sr_err == LDAP_SUCCESS && !op->o_noop ) {
		SQLTransact( SQL_NULL_HENV, dbh, SQL_COMMIT );

	} else {
		SQLTransact( SQL_NULL_HENV, dbh, SQL_ROLLBACK );
	}

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

	send_ldap_result( op, rs );

	if ( !BER_BVISNULL( &realdn )
			&& realdn.bv_val != op->oq_add.rs_e->e_name.bv_val )
	{
		ch_free( realdn.bv_val );
	}
	if ( !BER_BVISNULL( &realpdn ) && realpdn.bv_val != pdn.bv_val ) {
		ch_free( realpdn.bv_val );
	}
	if ( !BER_BVISNULL( &parent_id.eid_dn ) ) {
		backsql_free_entryID( &parent_id, 0 );
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_add(\"%s\"): %d \"%s\"\n",
			op->oq_add.rs_e->e_name.bv_val,
			rs->sr_err,
			rs->sr_text ? rs->sr_text : "" );

	return ( ( rs->sr_err == LDAP_SUCCESS ) ? op->o_noop : 1 );
}

#endif /* SLAPD_SQL */

