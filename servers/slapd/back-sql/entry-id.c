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

/*
 * FIXME: need to change API to pass backsql_entryID **id 
 * and return an error code, to distinguish LDAP_OTHER from
 * LDAP_NO_SUCH_OBJECT
 */
int
backsql_dn2id(
	backsql_info		*bi,
	backsql_entryID		*id,
	SQLHDBC			dbh,
	struct berval		*dn )
{
	SQLHSTMT		sth; 
	BACKSQL_ROW_NTS		row;
#if 0
 	SQLINTEGER		nrows = 0;
#endif
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

	if ( bi->has_ldapinfo_dn_ru ) {
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
		if ( bi->isTimesTen ) {
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
			"error binding dn=\"%s\" parameter:\n", toBind, 0, 0 );
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
		id->id = atoi( row.cols[ 0 ] );
		id->keyval = atoi( row.cols[ 1 ] );
		id->oc_id = atoi( row.cols[ 2 ] );
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
backsql_get_attr_vals( backsql_at_map_rec *at, backsql_srch_info *bsi )
{
	RETCODE		rc;
	SQLHSTMT	sth;
	BACKSQL_ROW_NTS	row;
	int		i;

	assert( at );
	assert( bsi );
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_get_attr_vals(): "
		"oc='%s' attr='%s' keyval=%ld\n",
		bsi->oc->name, at->name, bsi->c_eid->keyval );

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
			if ( row.is_null[ i ] > 0 ) {
       				backsql_entry_addattr( bsi->e, 
						row.col_names[ i ],
						row.cols[ i ],
#if 0
						row.col_prec[ i ]
#else
						/*
						 * FIXME: what if a binary 
						 * is fetched?
						 */
						strlen( row.cols[ i ] )
#endif
						);
#if 0
				Debug( LDAP_DEBUG_TRACE, "prec=%d\n",
					(int)row.col_prec[ i ], 0, 0 );
			} else {
      				Debug( LDAP_DEBUG_TRACE, "NULL value "
					"in this row for attribute '%s'\n",
					row.col_names[ i ], 0, 0 );
#endif
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
	char			**c_at_name;
	backsql_at_map_rec	*at;
	int			rc;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_id2entry()\n", 0, 0, 0 );

	rc = dnPrettyNormal( NULL, &eid->dn, &e->e_name, &e->e_nname );
	if ( rc != LDAP_SUCCESS ) {
		return NULL;
	}

	bsi->oc = backsql_oc_with_id( bsi->bi, eid->oc_id );
	bsi->e = e;
	bsi->c_eid = eid;
	e->e_attrs = NULL;
	e->e_private = NULL;
 
	/* if ( bsi->base_dn != NULL)??? */
	
	e->e_id = eid->id;
 
	if ( bsi->attrs != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
			"custom attribute list\n", 0, 0, 0 );
		for ( c_at_name = bsi->attrs; *c_at_name != NULL; c_at_name++ ) {
			if ( !strcasecmp( *c_at_name, "objectclass" ) 
					|| !strcasecmp( *c_at_name, "0.10" ) ) {
#if 0
				backsql_entry_addattr( bsi->e, "objectclass",
						bsi->oc->name,
						strlen( bsi->oc->name ) );
#endif
				continue;
			}
			at = backsql_at_with_name( bsi->oc, *c_at_name );
			if ( at != NULL ) {
    				backsql_get_attr_vals( at, bsi );
			} else {
				Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
					"attribute '%s' is not defined "
					"for objectlass '%s'\n",
					*c_at_name, bsi->oc->name, 0 );
			}
		}
	} else {
		Debug( LDAP_DEBUG_TRACE, "backsql_id2entry(): "
			"retrieving all attributes\n", 0, 0, 0 );
		avl_apply( bsi->oc->attrs, (AVL_APPLY)backsql_get_attr_vals,
				bsi, 0, AVL_INORDER );
	}

	backsql_entry_addattr( bsi->e, "objectclass", bsi->oc->name,
			strlen( bsi->oc->name ) );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_id2entry()\n", 0, 0, 0 );

	return e;
}

#endif /* SLAPD_SQL */

