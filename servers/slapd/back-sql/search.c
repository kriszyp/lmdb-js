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
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "entry-id.h"
#include "util.h"

static struct berval AllUser = BER_BVC( LDAP_ALL_USER_ATTRIBUTES );
static struct berval AllOper = BER_BVC( LDAP_ALL_OPERATIONAL_ATTRIBUTES );
#if 0
static struct berval NoAttrs = BER_BVC( LDAP_NO_ATTRS );
#endif

static int
backsql_attrlist_add( backsql_srch_info *bsi, struct berval *at_name )
{
	int 	n_attrs = 0;
	char	**tmp;

	if ( bsi->attrs == NULL ) {
		return 1;
	}

	for ( ; bsi->attrs[ n_attrs ]; n_attrs++ ) {
		Debug( LDAP_DEBUG_TRACE, "==>backsql_attrlist_add(): "
			"attribute '%s' is in list\n", 
			bsi->attrs[ n_attrs ], 0, 0 );
		/*
		 * We can live with strcmp because the attribute 
		 * list has been normalized before calling be_search
		 */
		if ( !strcmp( bsi->attrs[ n_attrs ], at_name->bv_val ) ) {
			return 1;
		}
	}
	
	Debug( LDAP_DEBUG_TRACE, "==>backsql_attrlist_add(): "
		"adding '%s' to list\n", at_name->bv_val, 0, 0 );
	tmp = (char **)ch_realloc( bsi->attrs, (n_attrs + 2)*sizeof( char * ) );
	if ( tmp == NULL ) {
		return -1;
	}
	bsi->attrs = tmp;
	bsi->attrs[ n_attrs ] = ch_strdup( at_name->bv_val );
	bsi->attrs[ n_attrs + 1 ] = NULL;
	return 1;
}

void
backsql_init_search(
	backsql_srch_info 	*bsi, 
	backsql_info 		*bi,
	struct berval		*nbase, 
	int 			scope, 
	int 			slimit,
	int 			tlimit,
	time_t 			stoptime, 
	Filter 			*filter, 
	SQLHDBC 		dbh,
	BackendDB 		*be, 
	Connection 		*conn, 
	Operation 		*op,
	AttributeName 		*attrs )
{
	AttributeName		*p;
	
	bsi->base_dn = nbase;
	bsi->scope = scope;
	bsi->slimit = slimit;
	bsi->tlimit = tlimit;
	bsi->filter = filter;
	bsi->dbh = dbh;
	bsi->be = be;
	bsi->conn = conn;
	bsi->op = op;

	/*
	 * FIXME: need to discover how to deal with 1.1 (NoAttrs)
	 */
	
	/*
	 * handle "*"
	 */
	if ( attrs == NULL || an_find( attrs, &AllUser ) ) {
		bsi->attrs = NULL;

	} else {
		bsi->attrs = (char **)ch_calloc( 1, sizeof( char * ) );
		bsi->attrs[ 0 ] = NULL;
		
		for ( p = attrs; p->an_name.bv_val; p++ ) {
			/*
			 * ignore "+"
			 */
			if ( strcmp( p->an_name.bv_val, AllOper.bv_val ) == 0 ) {
				continue;
			}
			backsql_attrlist_add( bsi, &p->an_name );
		}
	}

	bsi->abandon = 0;
	bsi->id_list = NULL;
	bsi->n_candidates = 0;
	bsi->stoptime = stoptime;
	bsi->bi = bi;
	bsi->sel.bv_val = NULL;
	bsi->sel.bv_len = 0;
	bsi->sel_len = 0;
	bsi->from.bv_val = NULL;
	bsi->from.bv_len = 0;
	bsi->from_len = 0;
	bsi->join_where.bv_val = NULL;
	bsi->join_where.bv_len = 0;
	bsi->jwhere_len = 0;
	bsi->flt_where.bv_val = NULL;
	bsi->flt_where.bv_len = 0;
	bsi->fwhere_len = 0;

	bsi->status = LDAP_SUCCESS;
}

int
backsql_process_filter_list( backsql_srch_info *bsi, Filter *f, int op )
{
	int		res;

	if ( !f ) {
		return 0;
	}
	
	backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, "(", NULL );

	while ( 1 ) {
		res = backsql_process_filter( bsi, f );
		if ( res < 0 ) {
			/*
			 * TimesTen : If the query has no answers,
			 * don't bother to run the query.
			 */
			return -1;
		}
 
		f = f->f_next;
		if ( f == NULL ) {
			break;
		}

		switch ( op ) {
		case LDAP_FILTER_AND:
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					" AND ", NULL );
			break;

		case LDAP_FILTER_OR:
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					" OR ", NULL );
			break;
		}
	}

	backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, /* ( */ ")", NULL );

	return 1;
}

int
backsql_process_sub_filter( backsql_srch_info *bsi, Filter *f )
{
	int			i;
	backsql_at_map_rec	*at;

	if ( !f ) {
		return 0;
	}

	at = backsql_at_with_name( bsi->oc, f->f_sub_desc->ad_cname.bv_val );

	backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, "(" /* ) */ , NULL );

	/* TimesTen */
	Debug( LDAP_DEBUG_TRACE, "expr: '%s' '%s'\n", at->sel_expr,
		at->sel_expr_u ? at->sel_expr_u : "<NULL>", 0 );
	if ( bsi->bi->upper_func ) {
		/*
		 * If a pre-upper-cased version of the column exists, use it
		 */
		if ( at->sel_expr_u ) {
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len,
					at->sel_expr_u, " LIKE '", NULL);
   		} else {
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					bsi->bi->upper_func,
					"(", at->sel_expr, ")", 
					" LIKE '", NULL );
		}
	} else {
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len,
				at->sel_expr, " LIKE '", NULL );
	}
 
	if ( f->f_sub_initial.bv_val != NULL ) {
		size_t	start;

		start = bsi->flt_where.bv_len;
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len,
				f->f_sub_initial.bv_val, NULL );
		if ( bsi->bi->upper_func ) {
			ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
		}
	}

	backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, "%", NULL );

	if ( f->f_sub_any != NULL ) {
		for ( i = 0; f->f_sub_any[ i ].bv_val != NULL; i++ ) {
			size_t	start;

#if 0
			Debug( LDAP_DEBUG_TRACE, 
				"==>backsql_process_sub_filter(): "
				"sub_any='%s'\n", f->f_sub_any[ i ].bv_val,
				0, 0 );
#endif

			start = bsi->flt_where.bv_len;
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					f->f_sub_any[ i ].bv_val, "%", NULL );
			if ( bsi->bi->upper_func) {
				/*
				 * Note: toupper('%') = '%'
				 */
				ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
			}
		}

		if ( f->f_sub_final.bv_val != NULL ) {
			size_t	start;

			start = bsi->flt_where.bv_len;
    			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len,
					f->f_sub_final.bv_val, NULL);
  			if ( bsi->bi->upper_func ) {
				ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
			}
		}
	}

	backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, /* ( */ "')", NULL );
 
	return 1;
}

int
backsql_process_filter( backsql_srch_info *bsi, Filter *f )
{
	backsql_at_map_rec	*at;
	backsql_at_map_rec 	oc_attr 
		= { "objectClass", "", "", NULL, NULL, NULL, NULL };
	AttributeDescription	*ad = NULL;
	int 			done = 0, len = 0;
	/* TimesTen */
	int			rc = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_process_filter()\n", 0, 0, 0 );
	if ( f == NULL || f->f_choice == SLAPD_FILTER_COMPUTED ) {
		return 0;
	}

	switch( f->f_choice ) {
	case LDAP_FILTER_OR:
		rc = backsql_process_filter_list( bsi, f->f_or, 
				LDAP_FILTER_OR );
		done = 1;
		break;
		
	case LDAP_FILTER_AND:
		rc = backsql_process_filter_list( bsi, f->f_and,
				LDAP_FILTER_AND);
		done = 1;
		break;

	case LDAP_FILTER_NOT:
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
				"NOT (", NULL );
		rc = backsql_process_filter( bsi, f->f_not );
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, ")", NULL );
		done = 1;
		break;

	case LDAP_FILTER_PRESENT:
		ad = f->f_desc;
		break;
		
	default:
		ad = f->f_av_desc;
		break;
	}

	if ( rc == -1 ) {
		/* TimesTen : Don't run the query */
		goto impossible;
	}
 
	if ( done ) {
		goto done;
	}

	if ( strcasecmp( ad->ad_cname.bv_val, "objectclass" ) ) {
		at = backsql_at_with_name( bsi->oc, ad->ad_cname.bv_val );

	} else {
		struct berval	bv;
		
		at = &oc_attr;

		/*
		 * FIXME: use berval for at->sel_expr ?
		 */
		bv.bv_val = at->sel_expr;
		bv.bv_len = at->sel_expr ? strlen( at->sel_expr ) : 0;
		backsql_strcat( &bv, &len, "'", bsi->oc->name, "'", NULL );
		at->sel_expr = bv.bv_val;
	}
	if ( at == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_process_filter(): "
			"attribute '%s' is not defined for objectclass '%s'\n",
			ad->ad_cname.bv_val, bsi->oc->name, 0 );
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
				" 1=0 ", NULL );
		goto impossible;
	}

	backsql_merge_from_clause( &bsi->from.bv_val, &bsi->from_len, 
			at->from_tbls );
	/*
	 * need to add this attribute to list of attrs to load,
	 * so that we could do test_filter() later
	 */
	backsql_attrlist_add( bsi, &ad->ad_cname );

	if ( at->join_where != NULL && strstr( bsi->join_where.bv_val, at->join_where ) == NULL ) {
	       	backsql_strcat( &bsi->join_where, &bsi->jwhere_len, 
				" AND ", at->join_where, NULL );
	}

#if 0	
	if ( at != &oc_attr ) {
		backsql_strcat( &bsi->sel, &bsi->sel_len,
				",", at->sel_expr, " AS ", at->name, NULL );
 	}
#endif

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		/*
		 * maybe we should check type of at->sel_expr here somehow,
		 * to know whether upper_func is applicable, but for now
		 * upper_func stuff is made for Oracle, where UPPER is
		 * safely applicable to NUMBER etc.
		 */
		if ( bsi->bi->upper_func ) {
			size_t	start;

			if ( at->sel_expr_u ) {
				backsql_strcat( &bsi->flt_where,
						&bsi->fwhere_len, "(",
						at->sel_expr_u, "='", NULL );
			} else {
				backsql_strcat( &bsi->flt_where,
						&bsi->fwhere_len, "(",
						bsi->bi->upper_func, "(",
						at->sel_expr, ")='", NULL );
			}

			start = bsi->flt_where.bv_len;

			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					f->f_av_value.bv_val, "')", NULL );

			ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );

		} else {
			backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
					"(", at->sel_expr, "='",
					f->f_av_value.bv_val, "')", NULL );
		}
		break;

	case LDAP_FILTER_GE:
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
				"(", at->sel_expr, ">=", 
				f->f_av_value.bv_val, ")", NULL );
		break;
		
	case LDAP_FILTER_LE:
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
				"(", at->sel_expr, "<=", 
				f->f_av_value.bv_val, ")", NULL );
		break;

	case LDAP_FILTER_PRESENT:
		backsql_strcat( &bsi->flt_where, &bsi->fwhere_len, 
				"NOT (", at->sel_expr, " IS NULL)", NULL );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		backsql_process_sub_filter( bsi, f );
		break;
	}

done:
	if ( oc_attr.sel_expr != NULL ) {
		free( oc_attr.sel_expr );
	}
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_process_filter()\n", 0, 0, 0 );
	return 1;

impossible:
	if ( oc_attr.sel_expr != NULL ) {
		free( oc_attr.sel_expr );
	}
	Debug( LDAP_DEBUG_TRACE, "<==backsql_process_filter() returns -1\n",
			0, 0, 0 );
	return -1;
}

static int
backsql_srch_query( backsql_srch_info *bsi, struct berval *query )
{
	backsql_info	*bi = (backsql_info *)bsi->be->be_private;
	int		q_len = 0;
	int		rc;

	assert( query );
	query->bv_val = NULL;
	query->bv_len = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_srch_query()\n", 0, 0, 0 );
	bsi->sel.bv_val = NULL;
	bsi->sel.bv_len = 0;
	bsi->sel_len = 0;
	bsi->from.bv_val = NULL;
	bsi->from.bv_len = 0;
	bsi->from_len = 0;
	bsi->join_where.bv_val = NULL;
	bsi->join_where.bv_len = 0;
	bsi->jwhere_len = 0;
	bsi->flt_where.bv_val = NULL;
	bsi->flt_where.bv_len = 0;
	bsi->fwhere_len = 0;
#if 0
	backsql_strcat( &bsi->sel, &bsi->sel_len,
			"SELECT DISTINCT ldap_entries.id,", 
			bsi->oc->keytbl, ".", bsi->oc->keycol,
			",'", bsi->oc->name, "' AS objectClass",
			",ldap_entries.dn AS dn", NULL );
#endif
	backsql_strcat( &bsi->sel, &bsi->sel_len,
			"SELECT DISTINCT ldap_entries.id,", 
			bsi->oc->keytbl, ".", bsi->oc->keycol, ",", NULL );
	if ( bi->strcast_func ) {
		backsql_strcat( &bsi->sel, &bsi->sel_len,
				bi->strcast_func, 
				"('", bsi->oc->name, "')", NULL );
	} else {
		backsql_strcat( &bsi->sel, &bsi->sel_len,
				"'", bsi->oc->name, "'", NULL );
	}
	backsql_strcat( &bsi->sel, &bsi->sel_len,
			" AS objectClass,ldap_entries.dn AS dn", NULL );

	backsql_strcat( &bsi->from, &bsi->from_len,
			" FROM ldap_entries,", bsi->oc->keytbl, NULL );
	backsql_strcat( &bsi->join_where, &bsi->jwhere_len,
			" WHERE ", bsi->oc->keytbl, ".", bsi->oc->keycol,
			"=ldap_entries.keyval AND ",
			"ldap_entries.oc_map_id=? AND ", NULL );

	switch ( bsi->scope ) {
	case LDAP_SCOPE_BASE:
		if ( bsi->bi->upper_func ) {
      			backsql_strcat( &bsi->join_where, &bsi->jwhere_len, 
					bsi->bi->upper_func,
					"(","ldap_entries.dn)=",
					bsi->bi->upper_func, "(?)", NULL );
		} else {
			backsql_strcat( &bsi->join_where, &bsi->jwhere_len, 
					"ldap_entries.dn=?", NULL );
		}
		break;
		
	case LDAP_SCOPE_ONELEVEL:
		backsql_strcat( &bsi->join_where, &bsi->jwhere_len, 
				"ldap_entries.parent=?", NULL );
		break;

	case LDAP_SCOPE_SUBTREE:
		backsql_strcat( &bsi->join_where, &bsi->jwhere_len,
				bsi->bi->subtree_cond, NULL );
		break;

	default:
		assert( 0 );
	}

	rc = backsql_process_filter( bsi, bsi->filter );
	if ( rc > 0 ) {
		backsql_strcat( query, &q_len,
				bsi->sel.bv_val, bsi->from.bv_val, 
				bsi->join_where.bv_val,
				" AND ", bsi->flt_where.bv_val, NULL );

	} else if ( rc < 0 ) {
		/* 
		 * Indicates that there's no possible way the filter matches
		 * anything.  No need to issue the query
		 */
		Debug( LDAP_DEBUG_TRACE,
			"<==backsql_srch_query() returns NULL\n", 0, 0, 0 );
		free( query->bv_val );
		query->bv_val = NULL;
	}
 
	free( bsi->sel.bv_val );
	bsi->sel.bv_len = 0;
	bsi->sel_len = 0;
	free( bsi->from.bv_val );
	bsi->from.bv_len = 0;
	bsi->from_len = 0;
	free( bsi->join_where.bv_val );
	bsi->join_where.bv_len = 0;
	bsi->jwhere_len = 0;
	free( bsi->flt_where.bv_val );
	bsi->flt_where.bv_len = 0;
	bsi->fwhere_len = 0;
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_srch_query()\n", 0, 0, 0 );
	
	return ( query->bv_val == NULL ? 1 : 0 );
}

int
backsql_oc_get_candidates( backsql_oc_map_rec *oc, backsql_srch_info *bsi )
{
	struct berval		query;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_entryID		base_id, *c_id;
	int			res;
#if 0
	Entry			*e;
#endif
	BACKSQL_ROW_NTS		row;
	int			i;
	int			j;
	/* TimesTen */
	char			temp_base_dn[ BACKSQL_MAX_DN_LEN + 1 ];
 
	Debug(	LDAP_DEBUG_TRACE, "==>backsql_oc_get_candidates(): oc='%s'\n",
			oc->name, 0, 0 );
	bsi->oc = oc;
	if ( backsql_srch_query( bsi, &query ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"could not construct query for objectclass\n",
			0, 0, 0 );
		return 1;
	}

	Debug( LDAP_DEBUG_TRACE, "Constructed query: %s\n", 
			query.bv_val, 0, 0 );

	rc = backsql_Prepare( bsi->dbh, &sth, query.bv_val, 0 );
	free( query.bv_val );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error preparing query\n", 0, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		return 1;
	}

	if ( backsql_BindParamID( sth, 1, &bsi->oc->id ) != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error binding objectclass id parameter\n", 0, 0, 0 );
		return 1;
	}

	switch ( bsi->scope ) {
	case LDAP_SCOPE_BASE:
		rc = backsql_BindParamStr( sth, 2, bsi->base_dn->bv_val,
				BACKSQL_MAX_DN_LEN );
		if ( rc != SQL_SUCCESS ) {
         		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base_dn parameter\n", 0, 0, 0 );
			backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, 
					sth, rc );
			return 1;
		}
		break;

	case LDAP_SCOPE_SUBTREE:
		/* 
		 * Sets the parameters for the SQL built earlier
		 * NOTE that all the databases could actually use 
		 * the TimesTen version, which would be cleaner 
		 * and would also eliminate the need for the
		 * subtree_cond line in the configuration file.  
		 * For now, I'm leaving it the way it is, 
		 * so non-TimesTen databases use the original code.
		 * But at some point this should get cleaned up.
		 *
		 * If "dn" is being used, do a suffix search.
		 * If "dn_ru" is being used, do a prefix search.
		 */
		if ( bsi->bi->has_ldapinfo_dn_ru ) {
			temp_base_dn[ 0 ] = '\0';
			for ( i = 0, j = bsi->base_dn->bv_len - 1;
					j >= 0; i++, j--) {
				temp_base_dn[ i ] = bsi->base_dn->bv_val[ j ];
			}
			temp_base_dn[ i ] = '%';
			temp_base_dn[ i + 1 ] = '\0';
			ldap_pvt_str2upper( temp_base_dn );

		} else {
			temp_base_dn[ 0 ] = '%';
			AC_MEMCPY( &temp_base_dn[ 1 ], bsi->base_dn->bv_val,
				bsi->base_dn->bv_len + 1 );
			ldap_pvt_str2upper( &temp_base_dn[ 1 ] );
		}

		Debug( LDAP_DEBUG_TRACE, "dn '%s'\n", temp_base_dn, 0, 0 );

		rc = backsql_BindParamStr( sth, 2, temp_base_dn, 
				BACKSQL_MAX_DN_LEN );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base_dn parameter (2)\n",
				0, 0, 0 );
			backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, 
					sth, rc );
			return 1;
		}
		break;

 	case LDAP_SCOPE_ONELEVEL:
		res = backsql_dn2id( bsi->bi, &base_id, 
				bsi->dbh, bsi->base_dn );
		if ( res != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"could not retrieve base_dn id%s\n",
				res == LDAP_NO_SUCH_OBJECT ? ": no such entry"
				: "", 0, 0 );
			bsi->status = res;
			return 0;
		}
		
		rc = backsql_BindParamID( sth, 2, &base_id.id );
		backsql_free_entryID( &base_id, 0 );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base id parameter\n", 0, 0, 0 );
			return 1;
		}
		break;
	}
	
	rc = SQLExecute( sth );
	if ( !BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error executing query\n", 0, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return 1;
	}

	backsql_BindRowAsStrings( sth, &row );
	rc = SQLFetch( sth );
	for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( sth ) ) {
#if 0
		e = (Entry *)ch_calloc( 1, sizeof( Entry ) ); 
		for ( i = 1; i < row.ncols; i++ ) {
			if ( row.is_null[ i ] > 0 ) {
				backsql_entry_addattr( e, row.col_names[ i ],
						row.cols[ i ], 
						row.col_prec[ i ] );
				Debug( LDAP_DEBUG_TRACE, "prec=%d\n", 
						(int)row.col_prec[ i ], 0, 0 );
			} else {
				Debug( LDAP_DEBUG_TRACE, 
					"NULL value in this row "
					"for attribute '%s'\n", 
					row.col_names[ i ], 0, 0 );
			}
		}
#endif

		c_id = (backsql_entryID *)ch_calloc( 1, 
				sizeof( backsql_entryID ) );
		c_id->id = atoi( row.cols[ 0 ] );
		c_id->keyval = atoi( row.cols[ 1 ] );
		c_id->oc_id = bsi->oc->id;
		ber_str2bv( row.cols[ 3 ], 0, 1, &c_id->dn );
		c_id->next = bsi->id_list;
		bsi->id_list = c_id;
		bsi->n_candidates++;
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"added entry id=%ld, keyval=%ld dn='%s'\n",
			c_id->id, c_id->keyval, row.cols[ 3 ] );
	}
	backsql_FreeRow( &row );
	SQLFreeStmt( sth, SQL_DROP );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_oc_get_candidates()\n", 0, 0, 0 );

	return 1;
}

int
backsql_search(
	BackendDB	*be,
	Connection	*conn,
	Operation	*op,
	struct berval	*base,
	struct berval	*nbase,
	int		scope,
	int		deref,
	int		slimit,
	int		tlimit,
	Filter		*filter,
	struct berval	*filterstr,
	AttributeName	*attrs,
	int		attrsonly )
{
	backsql_info		*bi = (backsql_info *)be->be_private;
	SQLHDBC			dbh;
	int			sres;
	int			nentries;
	Entry			*entry, *res;
	int			manageDSAit = get_manageDSAit( op );
	BerVarray		v2refs = NULL;
	time_t			stoptime = 0;
	backsql_srch_info	srch_info;
	backsql_entryID		*eid = NULL;
	struct slap_limits_set	*limit = NULL;
	int			isroot = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_search(): "
		"base='%s', filter='%s', scope=%d,", 
		nbase->bv_val, filterstr->bv_val, scope );
	Debug( LDAP_DEBUG_TRACE, " deref=%d, attrsonly=%d, "
		"attributes to load: %s\n",
		deref, attrsonly, attrs == NULL ? "all" : "custom list" );
	dbh = backsql_get_db_conn( be, conn );

	if ( !dbh ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_OTHER, "",
				"SQL-backend error", NULL, NULL );
		return 1;
	}

	/* TimesTen : Pass it along to the lower level routines */ 
	srch_info.isTimesTen = bi->isTimesTen; 
 
	/* if not root, get appropriate limits */
	if ( be_isroot( be, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, &op->o_ndn, &limit );
	}

	/* The time/size limits come first because they require very little
	 * effort, so there's no chance the candidates are selected and then 
	 * the request is not honored only because of time/size constraints */

	/* if no time limit requested, use soft limit (unless root!) */
	if ( isroot ) {
		if ( tlimit == 0 ) {
			tlimit = -1;	/* allow root to set no limit */
		}

		if ( slimit == 0 ) {
			slimit = -1;
		}

	} else {
		/* if no limit is required, use soft limit */
		if ( tlimit <= 0 ) {
			tlimit = limit->lms_t_soft;

		/* if requested limit higher than hard limit, abort */
		} else if ( tlimit > limit->lms_t_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_t_hard == 0 && tlimit > limit->lms_t_soft ) {
				tlimit = limit->lms_t_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_t_hard > 0 ) {
				send_search_result( conn, op, 
						LDAP_UNWILLING_TO_PERFORM,
						NULL, NULL, NULL, NULL, 0 );
				return 0;
			}
		
			/* negative hard limit means no limit */
		}
		
		/* if no limit is required, use soft limit */
		if ( slimit <= 0 ) {
			slimit = limit->lms_s_soft;

		/* if requested limit higher than hard limit, abort */
		} else if ( slimit > limit->lms_s_hard ) {
			/* no hard limit means use soft instead */
			if ( limit->lms_s_hard == 0 && slimit > limit->lms_s_soft ) {
				slimit = limit->lms_s_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_s_hard > 0 ) {
				send_search_result( conn, op, 
						LDAP_UNWILLING_TO_PERFORM,
						NULL, NULL, NULL, NULL, 0 );
				return 0;
			}
			
			/* negative hard limit means no limit */
		}
	}

	/* compute it anyway; root does not use it */
	stoptime = op->o_time + tlimit;

	backsql_init_search( &srch_info, bi, nbase, scope,
			slimit, tlimit, stoptime, filter, dbh,
			be, conn, op, attrs );

	/*
	 * for each objectclass we try to construct query which gets IDs
	 * of entries matching LDAP query filter and scope (or at least 
	 * candidates), and get the IDs
	 */
	avl_apply( bi->oc_by_name, (AVL_APPLY)backsql_oc_get_candidates,
			&srch_info, 0, AVL_INORDER );

	if ( !isroot && limit->lms_s_unchecked != -1 ) {
		if ( srch_info.n_candidates > limit->lms_s_unchecked ) {
			send_search_result( conn, op,
					LDAP_ADMINLIMIT_EXCEEDED,
					NULL, NULL, NULL, NULL, 0 );
			goto done;
		}
	}
	
	nentries = 0;
	/*
	 * now we load candidate entries (only those attributes 
	 * mentioned in attrs and filter), test it against full filter 
	 * and then send to client
	 */
	for ( eid = srch_info.id_list; eid != NULL; eid = eid->next ) {

		/* check for abandon */
		if ( op->o_abandon ) {
			break;
		}

		/* check time limit */
		if ( tlimit != -1 && slap_get_time() > stoptime ) {
			send_search_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			break;
		}

		Debug(LDAP_DEBUG_TRACE, "backsql_search(): loading data "
			"for entry id=%ld, oc_id=%ld, keyval=%ld\n",
			eid->id, eid->oc_id, eid->keyval );

		entry = (Entry *)ch_calloc( sizeof( Entry ), 1 );
		res = backsql_id2entry( &srch_info, entry, eid );
		if ( res == NULL ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
				"error in backsql_id2entry() "
				"- skipping entry\n", 0, 0, 0 );
			continue;
		}

		if ( !manageDSAit && scope != LDAP_SCOPE_BASE &&
			is_entry_referral( entry ) ) {
			BerVarray refs = get_entry_referrals( be, conn,
					op, entry );

			send_search_reference( be, conn, op, entry, refs, 
					NULL, &v2refs );
			ber_bvarray_free( refs );
			continue;
		}

		if ( test_filter( be, conn, op, entry, filter ) 
				== LDAP_COMPARE_TRUE ) {
			sres = send_search_entry( be, conn, op, entry,
					attrs, attrsonly, NULL );
			if ( sres == -1 ) {
				Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
					"connection lost\n", 0, 0, 0 );
				break;
			}
			nentries += !sres;					
		}
		entry_free( entry );

		if ( slimit != -1 && nentries > slimit ) {
			send_search_result( conn, op, LDAP_SIZELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			break;
		}
     
	}

	if ( nentries > 0 ) {
		send_search_result( conn, op,
			v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
			NULL, NULL, v2refs, NULL, nentries );
	} else {
		send_ldap_result( conn, op, srch_info.status,
				NULL, NULL, NULL, 0 );
	}
	
done:;
	for ( eid = srch_info.id_list; eid != NULL; 
			eid = backsql_free_entryID( eid, 1 ) );

	charray_free( srch_info.attrs );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_search()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */

