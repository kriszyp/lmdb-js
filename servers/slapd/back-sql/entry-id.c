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
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "entry-id.h"
#include "util.h"

backsql_entryID *
backsql_free_entryID( backsql_entryID *id, int freeit )
{
	backsql_entryID 	*next;

	assert( id );

	next = id->next;

	if ( id->dn.bv_val != NULL ) {
		free( id->dn.bv_val );
	}

	if ( freeit ) {
		free( id );
	}

	return next;
}

int
backsql_dn2id(
	backsql_info		*bi,
	backsql_entryID		*id,
	SQLHDBC			dbh,
	struct berval		*dn )
{
	SQLHSTMT		sth; 
	BACKSQL_ROW_NTS		row;
	RETCODE 		rc;
	int			res;

	/* TimesTen */
	char			upperdn[ BACKSQL_MAX_DN_LEN + 1 ];
	char			*toBind;
	int			i, j;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_dn2id(): dn='%s'\n", 
			dn->bv_val, 0, 0 );

	assert( id );

	if ( dn->bv_len > BACKSQL_MAX_DN_LEN ) {
		Debug( LDAP_DEBUG_TRACE, 
			"backsql_dn2id(): DN \"%s\" (%ld bytes) "
			"exceeds max DN length (%d):\n",
			dn->bv_val, dn->bv_len, BACKSQL_MAX_DN_LEN );
		return LDAP_OTHER;
	}
	
	/* begin TimesTen */
	Debug(LDAP_DEBUG_TRACE, "id_query '%s'\n", bi->id_query, 0, 0);
	assert( bi->id_query );
 	rc = backsql_Prepare( dbh, &sth, bi->id_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, 
			"backsql_dn2id(): error preparing SQL:\n%s", 
			bi->id_query, 0, 0);
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	if ( BACKSQL_HAS_LDAPINFO_DN_RU( bi ) ) {
		/*
		 * Prepare an upper cased, byte reversed version 
		 * that can be searched using indexes
		 */

		for ( i = 0, j = dn->bv_len - 1; dn->bv_val[ i ]; i++, j--) {
			upperdn[ i ] = dn->bv_val[ j ];
		}
		upperdn[ i ] = '\0';
		ldap_pvt_str2upper( upperdn );

		Debug( LDAP_DEBUG_TRACE, "==>backsql_dn2id(): upperdn='%s'\n",
				upperdn, 0, 0 );
		toBind = upperdn;
	} else {
		if ( BACKSQL_USE_REVERSE_DN( bi ) ) {
			AC_MEMCPY( upperdn, dn->bv_val, dn->bv_len + 1 );
			ldap_pvt_str2upper( upperdn );
			Debug( LDAP_DEBUG_TRACE,
				"==>backsql_dn2id(): upperdn='%s'\n",
				upperdn, 0, 0 );
			toBind = upperdn;

		} else {
			toBind = dn->bv_val;
		}
	}

	rc = backsql_BindParamStr( sth, 1, toBind, BACKSQL_MAX_DN_LEN );
	if ( rc != SQL_SUCCESS) {
		/* end TimesTen */ 
		Debug( LDAP_DEBUG_TRACE, "backsql_dn2id(): "
			"error binding dn=\"%s\" parameter:\n", 
			toBind, 0, 0 );
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_dn2id(): "
			"error executing query (\"%s\", \"%s\"):\n", 
			bi->id_query, toBind, 0 );
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	backsql_BindRowAsStrings( sth, &row );
	rc = SQLFetch( sth );
	if ( BACKSQL_SUCCESS( rc ) ) {
		id->id = strtol( row.cols[ 0 ], NULL, 0 );
		id->keyval = strtol( row.cols[ 1 ], NULL, 0 );
		id->oc_id = strtol( row.cols[ 2 ], NULL, 0 );
		ber_dupbv( &id->dn, dn );
		id->next = NULL;

		res = LDAP_SUCCESS;

	} else {
		res = LDAP_NO_SUCH_OBJECT;
	}
	backsql_FreeRow( &row );

	SQLFreeStmt( sth, SQL_DROP );
	if ( res == LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_dn2id(): id=%ld\n",
				id->id, 0, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_dn2id(): no match\n",
				0, 0, 0 );
	}
	return res;
}

int
backsql_count_children(
	backsql_info		*bi,
	SQLHDBC			dbh,
	struct berval		*dn,
	unsigned long		*nchildren )
{
	SQLHSTMT		sth; 
	BACKSQL_ROW_NTS		row;
	RETCODE 		rc;
	int			res = LDAP_SUCCESS;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_count_children(): dn='%s'\n", 
			dn->bv_val, 0, 0 );

	if ( dn->bv_len > BACKSQL_MAX_DN_LEN ) {
		Debug( LDAP_DEBUG_TRACE, 
			"backsql_count_children(): DN \"%s\" (%ld bytes) "
			"exceeds max DN length (%d):\n",
			dn->bv_val, dn->bv_len, BACKSQL_MAX_DN_LEN );
		return LDAP_OTHER;
	}
	
	/* begin TimesTen */
	Debug(LDAP_DEBUG_TRACE, "children id query '%s'\n", 
			bi->has_children_query, 0, 0);
	assert( bi->has_children_query );
 	rc = backsql_Prepare( dbh, &sth, bi->has_children_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, 
			"backsql_count_children(): error preparing SQL:\n%s", 
			bi->has_children_query, 0, 0);
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	rc = backsql_BindParamStr( sth, 1, dn->bv_val, BACKSQL_MAX_DN_LEN );
	if ( rc != SQL_SUCCESS) {
		/* end TimesTen */ 
		Debug( LDAP_DEBUG_TRACE, "backsql_count_children(): "
			"error binding dn=\"%s\" parameter:\n", 
			dn->bv_val, 0, 0 );
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	rc = SQLExecute( sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_count_children(): "
			"error executing query (\"%s\", \"%s\"):\n", 
			bi->has_children_query, dn->bv_val, 0 );
		backsql_PrintErrors( SQL_NULL_HENV, dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return LDAP_OTHER;
	}

	backsql_BindRowAsStrings( sth, &row );
	
	rc = SQLFetch( sth );
	if ( BACKSQL_SUCCESS( rc ) ) {
		char *end;

		*nchildren = strtol( row.cols[ 0 ], &end, 0 );
		if ( end[ 0 ] != '\0' ) {
			res = LDAP_OTHER;
		}

	} else {
		res = LDAP_OTHER;
	}
	backsql_FreeRow( &row );

	SQLFreeStmt( sth, SQL_DROP );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_count_children(): %lu\n",
			*nchildren, 0, 0 );

	return res;
}

int
backsql_has_children(
	backsql_info		*bi,
	SQLHDBC			dbh,
	struct berval		*dn )
{
	unsigned long	nchildren;
	int		rc;

	rc = backsql_count_children( bi, dbh, dn, &nchildren );

	if ( rc == LDAP_SUCCESS ) {
		return nchildren > 0 ? LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE;
	}

	return rc;
}

static int
backsql_get_attr_vals( void *v_at, void *v_bsi )
{
	backsql_at_map_rec *at  = v_at;
	backsql_srch_info  *bsi = v_bsi;
	RETCODE		rc;
	SQLHSTMT	sth;
	BACKSQL_ROW_NTS	row;
	int		i;

	assert( at );
	assert( bsi );
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_get_attr_vals(): "
		"oc='%s' attr='%s' keyval=%ld\n",
		BACKSQL_OC_NAME( bsi->oc ), at->ad->ad_cname.bv_val, 
		bsi->c_eid->keyval );

	rc = backsql_Prepare( bsi->dbh, &sth, at->query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_get_attr_values(): "
			"error preparing query: %s\n", at->query, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		return 1;
	}

	rc = backsql_BindParamID( sth, 1, &bsi->c_eid->keyval );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_get_attr_values(): "
			"error binding key value parameter\n", 0, 0, 0 );
		return 1;
	}

	rc = SQLExecute( sth );
	if ( ! BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_get_attr_values(): "
			"error executing attribute query '%s'\n",
			at->query, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return 1;
	}

	backsql_BindRowAsStrings( sth, &row );

	rc = SQLFetch( sth );
	for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( sth ) ) {
		for ( i = 0; i < row.ncols; i++ ) {
			if ( row.value_len[ i ] > 0 ) {
				struct berval	bv;

				bv.bv_val = row.cols[ i ];
#if 0
				bv.bv_len = row.col_prec[ i ];
#else
				/*
				 * FIXME: what if a binary 
				 * is fetched?
				 */
				bv.bv_len = strlen( row.cols[ i ] );
#endif
       				backsql_entry_addattr( bsi->e, 
						&row.col_names[ i ], &bv );

#ifdef BACKSQL_TRACE
				Debug( LDAP_DEBUG_TRACE, "prec=%d\n",
					(int)row.col_prec[ i ], 0, 0 );
			} else {
      				Debug( LDAP_DEBUG_TRACE, "NULL value "
					"in this row for attribute '%s'\n",
					row.col_names[ i ].bv_val, 0, 0 );
#endif /* BACKSQL_TRACE */
			}
		}
	}

	backsql_FreeRow( &row );
	SQLFreeStmt( sth, SQL_DROP );
	Debug( LDAP_DEBUG_TRACE, "<==backsql_get_attr_vals()\n", 0, 0, 0 );

	return 1;
}

Entry *
backsql_id2entry( backsql_srch_info *bsi, Entry *e, backsql_entryID *eid )
{
	int			i;
	backsql_at_map_rec	*at;
	int			rc;
	AttributeDescription	*ad_oc = slap_schema.si_ad_objectClass;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_id2entry()\n", 0, 0, 0 );

	rc = dnPrettyNormal( NULL, &eid->dn, &e->e_name, &e->e_nname );
	if ( rc != LDAP_SUCCESS ) {
		return NULL;
	}

	bsi->oc = backsql_id2oc( bsi->bi, eid->oc_id );
	bsi->e = e;
	bsi->c_eid = eid;
	e->e_attrs = NULL;
	e->e_private = NULL;
 
	/* if ( bsi->base_dn != NULL)??? */
	
	e->e_id = eid->id;
 
	if ( bsi->attrs != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
			"custom attribute list\n", 0, 0, 0 );
		for ( i = 0; bsi->attrs[ i ].an_name.bv_val; i++ ) {
			AttributeName *attr = &bsi->attrs[ i ];

			if ( attr->an_desc == ad_oc
#if 0	/* FIXME: what is 0.10 ? */
					|| !BACKSQL_NCMP( &attr->an_name, &bv_n_0_10 ) 
#endif
					) {
#if 0
				backsql_entry_addattr( bsi->e, 
						&bv_n_objectclass,
						BACKSQL_OC_NAME( bsi->oc ) );
#endif
				continue;
			}

			at = backsql_ad2at( bsi->oc, attr->an_desc );
			if ( at != NULL ) {
    				backsql_get_attr_vals( at, bsi );
			} else {
				Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
					"attribute '%s' is not defined "
					"for objectlass '%s'\n",
					attr->an_name.bv_val, 
					BACKSQL_OC_NAME( bsi->oc ), 0 );
			}
		}

	} else {
		Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
			"retrieving all attributes\n", 0, 0, 0 );
		avl_apply( bsi->oc->attrs, backsql_get_attr_vals,
				bsi, 0, AVL_INORDER );
	}

	if ( attr_merge_one( bsi->e, ad_oc, &bsi->oc->oc->soc_cname ) ) {
		entry_free( e );
		return NULL;
	}

	if ( global_schemacheck ) {
		const char	*text = NULL;
		char		textbuf[ 1024 ];
		size_t		textlen = sizeof( textbuf );
		struct berval	bv[ 2 ];
		struct berval	soc;
		AttributeDescription	*ad_soc
			= slap_schema.si_ad_structuralObjectClass;
		int rc;

		bv[ 0 ] = bsi->oc->oc->soc_cname;
		bv[ 1 ].bv_val = NULL;

		rc = structural_class( bv, &soc, NULL, 
				&text, textbuf, textlen );
		if ( rc != LDAP_SUCCESS ) {
			entry_free( e );
			return NULL;
		}

		if ( bsi->bsi_flags | BSQL_SF_ALL_OPER 
				|| an_find( bsi->attrs, &AllOper ) ) {
			if ( attr_merge_one( bsi->e, ad_soc, &soc ) ) {
				entry_free( e );
				return NULL;
			}
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_id2entry()\n", 0, 0, 0 );

	return e;
}

#endif /* SLAPD_SQL */

