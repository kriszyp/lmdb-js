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
#include "ldap_pvt.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "util.h"

/*
 * Deprecated
 */
#if 0
static int
backsql_cmp_oc_name( backsql_oc_map_rec *m1, backsql_oc_map_rec *m2 )
{
	return BACKSQL_NCMP( &m1->name, &m2->name );
}
#endif

/*
 * Uses the pointer to the ObjectClass structure
 */
static int
backsql_cmp_oc( backsql_oc_map_rec *m1, backsql_oc_map_rec *m2 )
{
	return ( m1->oc < m2->oc ? -1 : ( m1->oc > m2->oc ? 1 : 0 ) );
}

static int
backsql_cmp_oc_id( backsql_oc_map_rec *m1, backsql_oc_map_rec *m2 )
{
	return ( m1->id < m2->id ? -1 : ( m1->id > m2->id ? 1 : 0 ) );
}

/*
 * Deprecated
 */
#if 0
static int
backsql_cmp_attr_name( backsql_at_map_rec *m1, backsql_at_map_rec *m2 )
{
	return BACKSQL_NCMP( &m1->name, &m2->name );
}
#endif

/*
 * Uses the pointer to the AttributeDescription structure
 */
static int
backsql_cmp_attr( backsql_at_map_rec *m1, backsql_at_map_rec *m2 )
{
	return ( m1->ad < m2->ad ? -1 : ( m1->ad > m2->ad ? 1 : 0 ) );
}

static int
backsql_make_attr_query( 
	backsql_oc_map_rec 	*oc_map,
	backsql_at_map_rec 	*at_map )
{
	struct berval	tmps = { 0, NULL };
	int		tmpslen = 0;

	backsql_strcat( &tmps, &tmpslen, "SELECT ", at_map->sel_expr, 
			" AS ", at_map->name.bv_val, 
			" FROM ", at_map->from_tbls,
			" WHERE ", oc_map->keytbl,".", oc_map->keycol,
			"=?", NULL );
	if ( at_map->join_where != NULL ) {
		backsql_strcat( &tmps, &tmpslen, " AND ", 
				at_map->join_where, NULL );
	}

	at_map->query = tmps.bv_val;
	
	return 0;
}

static int
backsql_add_sysmaps( backsql_oc_map_rec *oc_map )
{
	backsql_at_map_rec	*at_map;
	int			len;
	char			s[ 30 ]; 
	struct berval		bv;

	snprintf( s, sizeof( s ), "%ld", oc_map->id );

	at_map = (backsql_at_map_rec *)ch_calloc(1, 
			sizeof( backsql_at_map_rec ) );
	at_map->ad = slap_schema.si_ad_objectClass;
	ber_dupbv( &at_map->name, &at_map->ad->ad_cname );
	at_map->sel_expr = ch_strdup( "ldap_entry_objclasses.oc_name" );
	at_map->from_tbls = ch_strdup( "ldap_entry_objclasses,ldap_entries" );
	len = strlen( at_map->from_tbls );
	backsql_merge_from_clause( &at_map->from_tbls, &len, oc_map->keytbl );

	len = 0;
	bv.bv_val = NULL;
	bv.bv_len = 0;
	backsql_strcat( &bv, &len,
			"ldap_entries.id=ldap_entry_objclasses.entry_id "
			"and ldap_entries.keyval=",
			oc_map->keytbl, ".", oc_map->keycol,
			" and ldap_entries.oc_map_id=", s, NULL );
	at_map->join_where = bv.bv_val;

	at_map->add_proc = NULL;
	at_map->delete_proc = NULL;
	at_map->param_order = 0;
	at_map->expect_return = 0;
	backsql_make_attr_query( oc_map, at_map );
	avl_insert( &oc_map->attrs, at_map, 
			(AVL_CMP)backsql_cmp_attr, NULL );

	at_map = (backsql_at_map_rec *)ch_calloc( 1, 
			sizeof( backsql_at_map_rec ) );
	at_map->ad = slap_schema.si_ad_ref;
	ber_dupbv( &at_map->name, &at_map->ad->ad_cname );
	at_map->sel_expr = ch_strdup( "ldap_referrals.url" );
	at_map->from_tbls = ch_strdup( "ldap_referrals,ldap_entries" );
	len = strlen( at_map->from_tbls );
	backsql_merge_from_clause( &at_map->from_tbls, &len,oc_map->keytbl );

	len = 0;
	bv.bv_val = NULL;
	bv.bv_len = 0;
	backsql_strcat( &bv, &len,
			"ldap_entries.id=ldap_referrals.entry_id "
			"and ldap_entries.keyval=",
			oc_map->keytbl, ".", oc_map->keycol,
			" and ldap_entries.oc_map_id=", s, NULL );
	at_map->join_where = bv.bv_val;

	at_map->add_proc = NULL;
	at_map->delete_proc = NULL;
	at_map->param_order = 0;
	at_map->expect_return = 0;
	backsql_make_attr_query( oc_map, at_map );
	avl_insert( &oc_map->attrs, at_map, 
			(AVL_CMP)backsql_cmp_attr, NULL );

	return 1;
}

int
backsql_load_schema_map( backsql_info *si, SQLHDBC dbh )
{
	SQLHSTMT 		oc_sth, at_sth;
	RETCODE			rc;
	BACKSQL_ROW_NTS		oc_row, at_row;
	unsigned long		oc_id;
	backsql_oc_map_rec	*oc_map;
	backsql_at_map_rec	*at_map;
	char			*tmps;
	int			tmpslen;

	Debug( LDAP_DEBUG_TRACE, "==>load_schema_map()\n", 0, 0, 0 );

	/* 
	 * TimesTen : See if the ldap_entries.dn_ru field exists in the schema
	 */
	if ( si->has_ldapinfo_dn_ru == -1 ) {
		rc = backsql_Prepare( dbh, &oc_sth, 
				backsql_check_dn_ru_query, 0 );
		if ( rc == SQL_SUCCESS ) {
			si->has_ldapinfo_dn_ru = 1;  /* Yes, the field exists */
   			Debug( LDAP_DEBUG_TRACE, "ldapinfo.dn_ru field exists "
				"in the schema\n", 0, 0, 0 );
		} else {
			si->has_ldapinfo_dn_ru = 0;  /* No such field exists */
		}

		SQLFreeStmt( oc_sth, SQL_DROP );
	}


	rc = backsql_Prepare( dbh, &oc_sth, si->oc_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"error preparing oc_query: '%s'\n", 
			si->oc_query, 0, 0 );
		backsql_PrintErrors( si->db_env, dbh, oc_sth, rc );
		return LDAP_OTHER;
	}
	Debug( LDAP_DEBUG_TRACE, "load_schema_map(): at_query '%s'\n", 
			si->at_query, 0, 0 );

	rc = backsql_Prepare( dbh, &at_sth, si->at_query, 0 );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"error preparing at_query: '%s'\n", 
			si->at_query, 0, 0 );
		backsql_PrintErrors( si->db_env, dbh, at_sth, rc );
		return LDAP_OTHER;
	}

	rc = backsql_BindParamID( at_sth, 1, &oc_id );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"error binding param for at_query: \n", 0, 0, 0 );
		backsql_PrintErrors( si->db_env, dbh, at_sth, rc );
		return LDAP_OTHER;
	}

	rc = SQLExecute( oc_sth );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"error executing oc_query: \n", 0, 0, 0 );
		backsql_PrintErrors( si->db_env, dbh, oc_sth, rc );
		return LDAP_OTHER;
	}

	backsql_BindRowAsStrings( oc_sth, &oc_row );
	rc = SQLFetch( oc_sth );
	for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( oc_sth ) ) {
		oc_map = (backsql_oc_map_rec *)ch_calloc( 1,
				sizeof( backsql_oc_map_rec ) );

		oc_map->id = atoi( oc_row.cols[ 0 ] );

		ber_str2bv( oc_row.cols[ 1 ], 0, 1, &oc_map->name );
		oc_map->oc = oc_bvfind( &oc_map->name );
		if ( oc_map->oc == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
				"objectClass '%s' is not defined in schema\n", 
				oc_map->name.bv_val, 0, 0 );
			return LDAP_OTHER;	/* undefined objectClass ? */
		}
		
		oc_map->keytbl = ch_strdup( oc_row.cols[ 2 ] );
		oc_map->keycol = ch_strdup( oc_row.cols[ 3 ] );
		oc_map->create_proc = ( oc_row.is_null[ 4 ] < 0 ) ? NULL 
			: ch_strdup( oc_row.cols[ 4 ] );
		oc_map->delete_proc = ( oc_row.is_null[ 5 ] < 0 ) ? NULL 
			: ch_strdup( oc_row.cols[ 5 ] );
		oc_map->expect_return = atoi( oc_row.cols[ 6 ] );

		/*
		 * FIXME: first attempt to check for offending
		 * instructions in {create|delete}_proc
		 */

		oc_map->attrs = NULL;
		avl_insert( &si->oc_by_oc, oc_map,
				(AVL_CMP)backsql_cmp_oc, NULL );
		avl_insert( &si->oc_by_id, oc_map,
				(AVL_CMP)backsql_cmp_oc_id, NULL );
		oc_id = oc_map->id;
		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"objectClass '%s': keytbl='%s' keycol='%s'\n",
			oc_map->name.bv_val, oc_map->keytbl, oc_map->keycol );
		if ( oc_map->create_proc ) {
			Debug( LDAP_DEBUG_TRACE, "create_proc='%s'\n",
				oc_map->create_proc, 0, 0 );
		}
		if ( oc_map->delete_proc ) {
			Debug( LDAP_DEBUG_TRACE, "delete_proc='%s'\n", 
				oc_map->delete_proc, 0, 0 );
		}
		Debug( LDAP_DEBUG_TRACE, "expect_return: "
			"add=%s, del=%s; attributes:\n",
			BACKSQL_IS_ADD( oc_map->expect_return ), 
			BACKSQL_IS_DEL( oc_map->expect_return ), 0 );

		Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
			"autoadding 'objectClass' and 'ref' mappings\n",
			0, 0, 0 );
		backsql_add_sysmaps( oc_map );
		rc = SQLExecute( at_sth );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
				"error executing at_query: \n", 0, 0, 0 );
			backsql_PrintErrors( SQL_NULL_HENV, dbh, at_sth, rc );
			return LDAP_OTHER;
		}

		backsql_BindRowAsStrings( at_sth, &at_row );
		rc = SQLFetch( at_sth );
		for ( ; BACKSQL_SUCCESS(rc); rc = SQLFetch( at_sth ) ) {
			const char	*text = NULL;

			Debug( LDAP_DEBUG_TRACE, "********'%s'\n",
				at_row.cols[ 0 ], 0, 0 );
			Debug( LDAP_DEBUG_TRACE, 
				"name='%s',sel_expr='%s' from='%s'",
				at_row.cols[ 0 ], at_row.cols[ 1 ],
				at_row.cols[ 2 ] );
			Debug( LDAP_DEBUG_TRACE, 
				"join_where='%s',add_proc='%s'",
				at_row.cols[ 3 ], at_row.cols[ 4 ], 0 );
			Debug( LDAP_DEBUG_TRACE, "delete_proc='%s'\n",
					at_row.cols[ 5 ], 0, 0 );
			/* TimesTen */
			Debug( LDAP_DEBUG_TRACE, "sel_expr_u='%s'\n",
					at_row.cols[ 8 ], 0, 0 );
			at_map = (backsql_at_map_rec *)ch_calloc( 1,
					sizeof( backsql_at_map_rec ) );
			ber_str2bv( at_row.cols[ 0 ], 0, 1, &at_map->name );
			rc = slap_bv2ad( &at_map->name, &at_map->ad, &text );
			if ( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
					"attribute '%s' for objectClass '%s' "
					"is not defined in schema: %s\n", 
					at_map->name.bv_val, 
					oc_map->name.bv_val, text );
				return LDAP_CONSTRAINT_VIOLATION;
			}
				
			at_map->sel_expr = ch_strdup( at_row.cols[ 1 ] );
			at_map->sel_expr_u = ( at_row.is_null[ 8 ] < 0 ) ? NULL
				: ch_strdup( at_row.cols[ 8 ] );
			tmps = NULL;
			tmpslen = 0;
			backsql_merge_from_clause( &tmps, &tmpslen,
					at_row.cols[ 2 ] );
			at_map->from_tbls = tmps;
			at_map->join_where = ( at_row.is_null[ 3 ] < 0 ) ? NULL 
				: ch_strdup( at_row.cols[ 3 ] );
			at_map->add_proc = ( at_row.is_null[ 4 ] < 0 ) ? NULL
				: ch_strdup( at_row.cols[4] );
			at_map->delete_proc = ( at_row.is_null[ 5 ] < 0 ) ? NULL
				: ch_strdup( at_row.cols[ 5 ] );
			at_map->param_order = atoi( at_row.cols[ 6 ] );
			at_map->expect_return = atoi( at_row.cols[ 7 ] );
			backsql_make_attr_query( oc_map, at_map );
			Debug( LDAP_DEBUG_TRACE, "load_schema_map(): "
				"preconstructed query '%s'\n",
				at_map->query, 0, 0 );
			avl_insert( &oc_map->attrs, at_map, 
					(AVL_CMP)backsql_cmp_attr, NULL );
		}
		backsql_FreeRow( &at_row );
		SQLFreeStmt( at_sth, SQL_CLOSE );
	}
	backsql_FreeRow( &oc_row );
	SQLFreeStmt( at_sth, SQL_DROP );
	SQLFreeStmt( oc_sth, SQL_DROP );
	si->schema_loaded = 1;
	Debug( LDAP_DEBUG_TRACE, "<==load_schema_map()\n", 0, 0, 0 );
	return LDAP_SUCCESS;
}

backsql_oc_map_rec *
backsql_oc2oc( backsql_info *si, ObjectClass *oc )
{
	backsql_oc_map_rec	tmp, *res;

#if 0
	Debug( LDAP_DEBUG_TRACE, "==>backsql_oc2oc(): "
		"searching for objectclass with name='%s'\n",
		objclass, 0, 0 );
#endif

	tmp.oc = oc;
	res = (backsql_oc_map_rec *)avl_find( si->oc_by_oc, &tmp,
			(AVL_CMP)backsql_cmp_oc );
#if 0
	if ( res != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_oc2oc(): "
			"found name='%s', id=%d\n", res->name, res->id, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_oc2oc(): "
			"not found\n", 0, 0, 0 );
	}
#endif
 
	return res;
}

/*
 * Deprecated
 */
backsql_oc_map_rec *
backsql_name2oc( backsql_info *si, struct berval *oc_name )
{
	backsql_oc_map_rec	tmp, *res;

#if 0
	Debug( LDAP_DEBUG_TRACE, "==>oc_with_name(): "
		"searching for objectclass with name='%s'\n",
		objclass, 0, 0 );
#endif

	tmp.oc = oc_bvfind( oc_name );
	if ( tmp.oc == NULL ) {
		return NULL;
	}

	res = (backsql_oc_map_rec *)avl_find( si->oc_by_oc, &tmp,
			(AVL_CMP)backsql_cmp_oc );
#if 0
	if ( res != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<==oc_with_name(): "
			"found name='%s', id=%d\n", res->name, res->id, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==oc_with_name(): "
			"not found\n", 0, 0, 0 );
	}
#endif
 
	return res;
}

backsql_oc_map_rec *
backsql_id2oc( backsql_info *si, unsigned long id )
{
	backsql_oc_map_rec	tmp, *res;
 
#if 0
	Debug( LDAP_DEBUG_TRACE, "==>oc_with_id(): "
		"searching for objectclass with id='%d'\n", id, 0, 0 );
#endif

	tmp.id = id;
	res = (backsql_oc_map_rec *)avl_find( si->oc_by_id, &tmp,
			(AVL_CMP)backsql_cmp_oc_id );

#if 0
	if ( res != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<==oc_with_name(): "
			"found name='%s', id=%d\n", res->name, res->id, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==oc_with_name(): "
			"not found\n", 0, 0, 0 );
	}
#endif
	
	return res;
}

backsql_at_map_rec *
backsql_ad2at( backsql_oc_map_rec* objclass, AttributeDescription *ad )
{
	backsql_at_map_rec	tmp, *res;
 
#if 0
	Debug( LDAP_DEBUG_TRACE, "==>backsql_ad2at(): "
		"searching for attribute '%s' for objectclass '%s'\n",
		attr, objclass->name, 0 );
#endif
	tmp.ad = ad;
	res = (backsql_at_map_rec *)avl_find( objclass->attrs, &tmp,
			(AVL_CMP)backsql_cmp_attr );

#if 0
	if ( res != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_ad2at(): "
			"found name='%s', sel_expr='%s'\n",
			res->name, res->sel_expr, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_ad2at(): "
			"not found\n", 0, 0, 0 );
	}
#endif

	return res;
}

/*
 * Deprecated
 */
backsql_at_map_rec *
backsql_name2at( backsql_oc_map_rec* objclass, struct berval *attr )
{
	backsql_at_map_rec	tmp, *res;
	const char		*text = NULL;
 
#if 0
	Debug( LDAP_DEBUG_TRACE, "==>backsql_name2at(): "
		"searching for attribute '%s' for objectclass '%s'\n",
		attr, objclass->name, 0 );
#endif

	if ( slap_bv2ad( attr, &tmp.ad, &text ) != LDAP_SUCCESS ) {
		return NULL;
	}

	res = (backsql_at_map_rec *)avl_find( objclass->attrs, &tmp,
			(AVL_CMP)backsql_cmp_attr );

#if 0
	if ( res != NULL ) {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_name2at(): "
			"found name='%s', sel_expr='%s'\n",
			res->name, res->sel_expr, 0 );
	} else {
		Debug( LDAP_DEBUG_TRACE, "<==backsql_name2at(): "
			"not found\n", 0, 0, 0 );
	}
#endif

	return res;
}

static void
backsql_free_attr( backsql_at_map_rec *at )
{
	Debug( LDAP_DEBUG_TRACE, "==>free_attr(): '%s'\n", 
			at->name.bv_val, 0, 0 );
	ch_free( at->name.bv_val );
	ch_free( at->sel_expr );
	if ( at->from_tbls != NULL ) {
		ch_free( at->from_tbls );
	}
	if ( at->join_where != NULL ) {
		ch_free( at->join_where );
	}
	if ( at->add_proc != NULL ) {
		ch_free( at->add_proc );
	}
	if ( at->delete_proc != NULL ) {
		ch_free( at->delete_proc );
	}
	if ( at->query ) {
		ch_free( at->query );
	}

	/* TimesTen */
	if ( at->sel_expr_u ) {
		ch_free( at->sel_expr_u );
	}
	
	ch_free( at );

	Debug( LDAP_DEBUG_TRACE, "<==free_attr()\n", 0, 0, 0 );
}

static void
backsql_free_oc( backsql_oc_map_rec *oc )
{
	Debug( LDAP_DEBUG_TRACE, "==>free_oc(): '%s'\n", 
			oc->name.bv_val, 0, 0 );
	avl_free( oc->attrs, (AVL_FREE)backsql_free_attr );
	ch_free( oc->name.bv_val );
	ch_free( oc->keytbl );
	ch_free( oc->keycol );
	if ( oc->create_proc != NULL ) {
		ch_free( oc->create_proc );
	}
	if ( oc->delete_proc != NULL ) {
		ch_free( oc->delete_proc );
	}
	ch_free( oc );

	Debug( LDAP_DEBUG_TRACE, "<==free_oc()\n", 0, 0, 0 );
}

int
backsql_destroy_schema_map( backsql_info *si )
{
	Debug( LDAP_DEBUG_TRACE, "==>destroy_schema_map()\n", 0, 0, 0 );
	avl_free( si->oc_by_oc, NULL );
	avl_free( si->oc_by_id, (AVL_FREE)backsql_free_oc );
	Debug( LDAP_DEBUG_TRACE, "<==destroy_schema_map()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */

