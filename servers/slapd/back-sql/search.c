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

#define BACKSQL_STOP		0
#define BACKSQL_CONTINUE	1

static int backsql_process_filter( backsql_srch_info *bsi, Filter *f );

static int
backsql_attrlist_add( backsql_srch_info *bsi, AttributeDescription *ad )
{
	int 		n_attrs = 0;
	AttributeName	*an = NULL;

	if ( bsi->attrs == NULL ) {
		return 1;
	}

	/*
	 * clear the list (retrieve all attrs)
	 */
	if ( ad == NULL ) {
		ch_free( bsi->attrs );
		bsi->attrs = NULL;
		return 1;
	}

	for ( ; bsi->attrs[ n_attrs ].an_name.bv_val; n_attrs++ ) {
		an = &bsi->attrs[ n_attrs ];
		
		Debug( LDAP_DEBUG_TRACE, "==>backsql_attrlist_add(): "
			"attribute '%s' is in list\n", 
			an->an_name.bv_val, 0, 0 );
		/*
		 * We can live with strcmp because the attribute 
		 * list has been normalized before calling be_search
		 */
		if ( !BACKSQL_NCMP( &an->an_name, &ad->ad_cname ) ) {
			return 1;
		}
	}
	
	Debug( LDAP_DEBUG_TRACE, "==>backsql_attrlist_add(): "
		"adding '%s' to list\n", ad->ad_cname.bv_val, 0, 0 );

	an = (AttributeName *)ch_realloc( bsi->attrs,
			sizeof( AttributeName ) * ( n_attrs + 2 ) );
	if ( an == NULL ) {
		return -1;
	}

	an[ n_attrs ].an_name = ad->ad_cname;
	an[ n_attrs ].an_desc = ad;
	an[ n_attrs + 1 ].an_name.bv_val = NULL;
	an[ n_attrs + 1 ].an_name.bv_len = 0;

	bsi->attrs = an;
	
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
	bsi->bsi_flags = 0;

	/*
	 * handle "*"
	 */
	if ( attrs == NULL || an_find( attrs, &AllUser ) ) {
		bsi->attrs = NULL;

	} else {
		bsi->attrs = (AttributeName *)ch_calloc( 1, 
				sizeof( AttributeName ) );
		bsi->attrs[ 0 ].an_name.bv_val = NULL;
		bsi->attrs[ 0 ].an_name.bv_len = 0;
		
		for ( p = attrs; p->an_name.bv_val; p++ ) {
			/*
			 * ignore "1.1"; handle "+"
			 */
			if ( BACKSQL_NCMP( &p->an_name, &AllOper ) == 0 ) {
				bsi->bsi_flags |= BSQL_SF_ALL_OPER;
				continue;

			} else if ( BACKSQL_NCMP( &p->an_name, &NoAttrs ) == 0 ) {
				continue;
			}

			backsql_attrlist_add( bsi, p->an_desc );
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

static int
backsql_process_filter_list( backsql_srch_info *bsi, Filter *f, int op )
{
	int		res;

	if ( !f ) {
		return 0;
	}

	backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "c", '(' /* ) */  );

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
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
					(ber_len_t)sizeof( " AND " ) - 1, 
						" AND " );
			break;

		case LDAP_FILTER_OR:
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
					(ber_len_t)sizeof( " OR " ) - 1,
						" OR " );
			break;
		}
	}

	backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "c", /* ( */ ')' );

	return 1;
}

static int
backsql_process_sub_filter( backsql_srch_info *bsi, Filter *f )
{
	int			i;
	backsql_at_map_rec	*at;

	if ( !f ) {
		return 0;
	}

	at = backsql_ad2at( bsi->oc, f->f_sub_desc );

	assert( at );

	/*
	 * When dealing with case-sensitive strings 
	 * we may omit normalization; however, normalized
	 * SQL filters are more liberal.
	 */

	backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "c", '(' /* ) */  );

	/* TimesTen */
	Debug( LDAP_DEBUG_TRACE, "expr: '%s' '%s'\n", at->sel_expr.bv_val,
		at->sel_expr_u.bv_val ? at->sel_expr_u.bv_val : "<NULL>", 0 );
	if ( bsi->bi->upper_func.bv_val ) {
		/*
		 * If a pre-upper-cased version of the column exists, use it
		 */
		if ( at->sel_expr_u.bv_val ) {
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, 
					"bl",
					&at->sel_expr_u,
					(ber_len_t)sizeof( " LIKE '" ) - 1,
						" LIKE '" );
   		} else {
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"bcbcl",
					&bsi->bi->upper_func,
					'(',
					&at->sel_expr,
					')', 
					(ber_len_t)sizeof( " LIKE '" ) - 1,
						" LIKE '" );
		}
	} else {
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "bl",
				&at->sel_expr,
				(ber_len_t)sizeof( " LIKE '" ) - 1, " LIKE '" );
	}
 
	if ( f->f_sub_initial.bv_val != NULL ) {
		size_t	start;

		start = bsi->flt_where.bv_len;
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "b",
				&f->f_sub_initial );
		if ( bsi->bi->upper_func.bv_val ) {
			ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
		}
	}

	backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "c", '%' );

	if ( f->f_sub_any != NULL ) {
		for ( i = 0; f->f_sub_any[ i ].bv_val != NULL; i++ ) {
			size_t	start;

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, 
				"==>backsql_process_sub_filter(): "
				"sub_any='%s'\n", f->f_sub_any[ i ].bv_val,
				0, 0 );
#endif /* BACKSQL_TRACE */

			start = bsi->flt_where.bv_len;
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"bc",
					&f->f_sub_any[ i ],
					'%' );
			if ( bsi->bi->upper_func.bv_val ) {
				/*
				 * Note: toupper('%') = '%'
				 */
				ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
			}
		}

		if ( f->f_sub_final.bv_val != NULL ) {
			size_t	start;

			start = bsi->flt_where.bv_len;
    			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "b",
					&f->f_sub_final );
  			if ( bsi->bi->upper_func.bv_val ) {
				ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );
			}
		}
	}

	backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l", 
			(ber_len_t)sizeof( /* (' */ "')" ) - 1, /* ( */ "')" );
 
	return 1;
}

static int
backsql_process_filter( backsql_srch_info *bsi, Filter *f )
{
	backsql_at_map_rec	*at;
	backsql_at_map_rec 	oc_attr = {
		slap_schema.si_ad_objectClass, BER_BVC(""), BER_BVC(""), 
		BER_BVNULL, NULL, NULL, NULL };
	AttributeDescription	*ad = NULL;
	int 			done = 0;
	ber_len_t		len = 0;
	/* TimesTen */
	int			rc = 0;
	struct berval		*filter_value = NULL;

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
				LDAP_FILTER_AND );
		done = 1;
		break;

	case LDAP_FILTER_NOT:
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
				(ber_len_t)sizeof( "NOT (" /* ) */ ) - 1,
					"NOT (" /* ) */ );
		rc = backsql_process_filter( bsi, f->f_not );
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "c",
				/* ( */ ')' );
		done = 1;
		break;

	case LDAP_FILTER_PRESENT:
		ad = f->f_desc;
		break;
		
	case LDAP_FILTER_EXT:
		ad = f->f_mra->ma_desc;
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

	/*
	 * Turn structuralObjectClass into objectClass
	 */
	if ( ad == slap_schema.si_ad_objectClass 
			|| ad == slap_schema.si_ad_structuralObjectClass ) {
		at = &oc_attr;
		backsql_strfcat( &at->sel_expr, &len, "cbc",
				'\'', 
				&bsi->oc->oc->soc_cname, 
				'\'' );

	} else if ( ad == slap_schema.si_ad_hasSubordinates || ad == NULL ) {
		/*
		 * FIXME: this is not robust; e.g. a filter
		 * '(!(hasSubordinates=TRUE))' fails because
		 * in SQL it would read 'NOT (1=1)' instead 
		 * of no condition.  
		 * Note however that hasSubordinates is boolean, 
		 * so a more appropriate filter would be 
		 * '(hasSubordinates=FALSE)'
		 */
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
				(ber_len_t)sizeof( "1=1" ) - 1, "1=1" );
		if ( ad == slap_schema.si_ad_hasSubordinates ) {
			/*
			 * We use this flag since we need to parse
			 * the filter anyway; we should have used
			 * the frontend API function
			 * filter_has_subordinates()
			 */
			bsi->bsi_flags |= BSQL_SF_FILTER_HASSUBORDINATE;

		} else {
			/*
			 * clear attributes to fetch, to require ALL
			 * and try extended match on all attributes
			 */
			backsql_attrlist_add( bsi, NULL );
		}
		goto done;
		
	} else {
		at = backsql_ad2at( bsi->oc, ad );
	}

	if ( at == NULL ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_process_filter(): "
			"attribute '%s' is not defined for objectclass '%s'\n",
			ad->ad_cname.bv_val, BACKSQL_OC_NAME( bsi->oc ), 0 );
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
				(ber_len_t)sizeof( "1=0" ) - 1, "1=0" );
		goto impossible;
	}

	backsql_merge_from_clause( &bsi->from, &bsi->from_len, 
			&at->from_tbls );
	/*
	 * need to add this attribute to list of attrs to load,
	 * so that we could do test_filter() later
	 */
	backsql_attrlist_add( bsi, ad );

	if ( at->join_where.bv_val != NULL 
			&& strstr( bsi->join_where.bv_val, at->join_where.bv_val ) == NULL ) {
	       	backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, "lb",
				(ber_len_t)sizeof( " AND " ) - 1, " AND ",
				&at->join_where );
	}

#if 0
	/*
	 * FIXME: this is not required any more; however, note that
	 * attribute name syntax might collide with SQL legal aliases
	 */
	if ( at != &oc_attr ) {
		backsql_strfcat( &bsi->sel, &bsi->sel_len, "cblb",
				',',
				&at->sel_expr,
				(ber_len_t)sizeof( " AS " ) - 1, " AS ", 
				&at->name );
 	}
#endif

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		filter_value = &f->f_av_value;
		goto equality_match;

		/* fail over next case */
		
	case LDAP_FILTER_EXT:
		filter_value = &f->f_mra->ma_value;

equality_match:;
		/*
		 * maybe we should check type of at->sel_expr here somehow,
		 * to know whether upper_func is applicable, but for now
		 * upper_func stuff is made for Oracle, where UPPER is
		 * safely applicable to NUMBER etc.
		 */
		if ( bsi->bi->upper_func.bv_val ) {
			size_t	start;

			if ( at->sel_expr_u.bv_val ) {
				backsql_strfcat( &bsi->flt_where,
						&bsi->fwhere_len, "cbl",
						'(',
						&at->sel_expr_u, 
						(ber_len_t)sizeof( "='" ) - 1,
							"='" );
			} else {
				backsql_strfcat( &bsi->flt_where,
						&bsi->fwhere_len, "cbcbl",
						'(' /* ) */ ,
						&bsi->bi->upper_func,
						'(' /* ) */ ,
						&at->sel_expr,
						(ber_len_t)sizeof( /* ( */ ")='" ) - 1,
							/* ( */ ")='" );
			}

			start = bsi->flt_where.bv_len;

			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"bl",
					filter_value, 
					(ber_len_t)sizeof( /* (' */ "')" ) - 1,
						/* (' */ "')" );

			ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );

		} else {
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"cblbl",
					'(',
					&at->sel_expr,
					(ber_len_t)sizeof( "='" ) - 1, "='",
					filter_value,
					(ber_len_t)sizeof( /* (' */ "')" ) - 1,
						/* (' */ "')" );
		}
		break;

	case LDAP_FILTER_GE:
		/*
		 * FIXME: should we uppercase the operands?
		 */
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "cblbc",
				'(' /* ) */ ,
				&at->sel_expr,
				(ber_len_t)sizeof( ">=" ) - 1, ">=", 
				&f->f_av_value,
				/* ( */ ')' );
		break;
		
	case LDAP_FILTER_LE:
		/*
		 * FIXME: should we uppercase the operands?
		 */
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "cblbc",
				'(' /* ) */ ,
				&at->sel_expr,
				(ber_len_t)sizeof( "<=" ) - 1, "<=", 
				&f->f_av_value,
				/* ( */ ')' );
		break;

	case LDAP_FILTER_PRESENT:
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "lbl",
				(ber_len_t)sizeof( "NOT (" ) - 1, "NOT (", 
				&at->sel_expr, 
				(ber_len_t)sizeof( " IS NULL)" ) - 1, " IS NULL)" );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		backsql_process_sub_filter( bsi, f );
		break;

	case LDAP_FILTER_APPROX:
		/* we do our best */

		/*
		 * maybe we should check type of at->sel_expr here somehow,
		 * to know whether upper_func is applicable, but for now
		 * upper_func stuff is made for Oracle, where UPPER is
		 * safely applicable to NUMBER etc.
		 */
		if ( bsi->bi->upper_func.bv_val ) {
			size_t	start;

			if ( at->sel_expr_u.bv_val ) {
				backsql_strfcat( &bsi->flt_where,
						&bsi->fwhere_len, "cbl",
						'(',
						&at->sel_expr_u, 
						(ber_len_t)sizeof( " LIKE '%" ) - 1,
							" LIKE '%" );
			} else {
				backsql_strfcat( &bsi->flt_where,
						&bsi->fwhere_len, "cbcbl",
						'(' /* ) */ ,
						&bsi->bi->upper_func,
						'(' /* ) */ ,
						&at->sel_expr,
						(ber_len_t)sizeof( /* ( */ ") LIKE '%" ) - 1,
							/* ( */ ") LIKE '%" );
			}

			start = bsi->flt_where.bv_len;

			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"bl",
					&f->f_av_value, 
					(ber_len_t)sizeof( /* (' */ "%')" ) - 1,
						/* (' */ "%')" );

			ldap_pvt_str2upper( &bsi->flt_where.bv_val[ start ] );

		} else {
			backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len,
					"cblbl",
					'(',
					&at->sel_expr,
					(ber_len_t)sizeof( " LIKE '%" ) - 1,
						" LIKE '%",
					&f->f_av_value,
					(ber_len_t)sizeof( /* (' */ "%')" ) - 1,
						/* (' */ "%')" );
		}
		break;

	default:
		/* unhandled filter type; should not happen */
		assert( 0 );
		backsql_strfcat( &bsi->flt_where, &bsi->fwhere_len, "l",
				(ber_len_t)sizeof( "1=1" ) - 1, "1=1" );
		break;

	}

done:
	if ( oc_attr.sel_expr.bv_val != NULL ) {
		free( oc_attr.sel_expr.bv_val );
	}
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_process_filter()\n", 0, 0, 0 );
	return 1;

impossible:
	if ( oc_attr.sel_expr.bv_val != NULL ) {
		free( oc_attr.sel_expr.bv_val );
	}
	Debug( LDAP_DEBUG_TRACE, "<==backsql_process_filter() returns -1\n",
			0, 0, 0 );
	return -1;
}

static int
backsql_srch_query( backsql_srch_info *bsi, struct berval *query )
{
	backsql_info	*bi = (backsql_info *)bsi->be->be_private;
	ber_len_t	q_len = 0;
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
	/*
	 * FIXME: this query has been split in case a string cast function
	 * is defined; more sophisticated (pattern based) function should
	 * be used
	 */
	backsql_strcat( &bsi->sel, &bsi->sel_len,
			"SELECT DISTINCT ldap_entries.id,", 
			bsi->oc->keytbl.bv_val, ".", bsi->oc->keycol.bv_val,
			",'", bsi->oc->name.bv_val, "' AS objectClass",
			",ldap_entries.dn AS dn", NULL );
#endif

	backsql_strfcat( &bsi->sel, &bsi->sel_len, "lbcbc",
			(ber_len_t)sizeof( "SELECT DISTINCT ldap_entries.id," ) - 1,
				"SELECT DISTINCT ldap_entries.id,", 
			&bsi->oc->keytbl, 
			'.', 
			&bsi->oc->keycol, 
			',' );

	if ( bi->strcast_func.bv_val ) {
		backsql_strfcat( &bsi->sel, &bsi->sel_len, "blbl",
				&bi->strcast_func, 
				(ber_len_t)sizeof( "('" /* ') */ ) - 1,
					"('" /* ') */ ,
				&bsi->oc->oc->soc_cname,
				(ber_len_t)sizeof( /* (' */ "')" ) - 1,
					/* (' */ "')" );
	} else {
		backsql_strfcat( &bsi->sel, &bsi->sel_len, "cbc",
				'\'',
				&bsi->oc->oc->soc_cname,
				'\'' );
	}
	backsql_strfcat( &bsi->sel, &bsi->sel_len, "l",
			(ber_len_t)sizeof( " AS objectClass,ldap_entries.dn AS dn" ) - 1,
			" AS objectClass,ldap_entries.dn AS dn" );

	backsql_strfcat( &bsi->from, &bsi->from_len, "lb",
			(ber_len_t)sizeof( " FROM ldap_entries," ) - 1,
				" FROM ldap_entries,",
			&bsi->oc->keytbl );

	backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, "lbcbl",
			(ber_len_t)sizeof( " WHERE " ) - 1, " WHERE ",
			&bsi->oc->keytbl,
			'.',
			&bsi->oc->keycol,
			(ber_len_t)sizeof( "=ldap_entries.keyval AND ldap_entries.oc_map_id=? AND " ) - 1,
				"=ldap_entries.keyval AND ldap_entries.oc_map_id=? AND " );

	switch ( bsi->scope ) {
	case LDAP_SCOPE_BASE:
		if ( bsi->bi->upper_func.bv_val ) {
      			backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, 
					"blbcb",
					&bsi->bi->upper_func,
					(ber_len_t)sizeof( "(ldap_entries.dn)=" ) - 1,
						"(ldap_entries.dn)=",
					&bsi->bi->upper_func_open,
					'?', 
					&bsi->bi->upper_func_close );
		} else {
			backsql_strfcat( &bsi->join_where, &bsi->jwhere_len,
					"l",
					(ber_len_t)sizeof( "ldap_entries.dn=?" ) - 1,
						"ldap_entries.dn=?" );
		}
		break;
		
	case LDAP_SCOPE_ONELEVEL:
		backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, "l",
				(ber_len_t)sizeof( "ldap_entries.parent=?" ) - 1,
					"ldap_entries.parent=?" );
		break;

	case LDAP_SCOPE_SUBTREE:
		if ( bsi->bi->upper_func.bv_val ) {
      			backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, 
					"blbcb",
					&bsi->bi->upper_func,
					(ber_len_t)sizeof( "(ldap_entries.dn) LIKE " ) - 1,
						"(ldap_entries.dn) LIKE ",
					&bsi->bi->upper_func_open,
					'?', 
					&bsi->bi->upper_func_close );
		} else {
			backsql_strfcat( &bsi->join_where, &bsi->jwhere_len,
					"l",
					(ber_len_t)sizeof( "ldap_entries.dn LIKE ?" ) - 1,
						"ldap_entries.dn LIKE ?" );
		}

#if 0
		backsql_strfcat( &bsi->join_where, &bsi->jwhere_len, "b",
				&bsi->bi->subtree_cond );
#endif
		break;

	default:
		assert( 0 );
	}

	rc = backsql_process_filter( bsi, bsi->filter );
	if ( rc > 0 ) {
		backsql_strfcat( query, &q_len, "bbblb",
				&bsi->sel,
				&bsi->from, 
				&bsi->join_where,
				(ber_len_t)sizeof( " AND " ) - 1, " AND ",
				&bsi->flt_where );

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

static int
backsql_oc_get_candidates( void *v_oc, void *v_bsi )
{
	backsql_oc_map_rec *oc  = v_oc;
	backsql_srch_info  *bsi = v_bsi;
	struct berval		query;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_entryID		base_id, *c_id;
	int			res;
	BACKSQL_ROW_NTS		row;
	int			i;
	int			j;
 
	Debug(	LDAP_DEBUG_TRACE, "==>backsql_oc_get_candidates(): oc='%s'\n",
			BACKSQL_OC_NAME( oc ), 0, 0 );

	if ( bsi->n_candidates == -1 ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"unchecked limit has been overcome\n", 0, 0, 0 );
		/* should never get here */
		assert( 0 );
		return BACKSQL_STOP;
	}
	
	bsi->oc = oc;
	if ( backsql_srch_query( bsi, &query ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"could not construct query for objectclass\n",
			0, 0, 0 );
		return BACKSQL_CONTINUE;
	}

	Debug( LDAP_DEBUG_TRACE, "Constructed query: %s\n", 
			query.bv_val, 0, 0 );

	rc = backsql_Prepare( bsi->dbh, &sth, query.bv_val, 0 );
	free( query.bv_val );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error preparing query\n", 0, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		return BACKSQL_CONTINUE;
	}

	if ( backsql_BindParamID( sth, 1, &bsi->oc->id ) != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error binding objectclass id parameter\n", 0, 0, 0 );
		return BACKSQL_CONTINUE;
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
			return BACKSQL_CONTINUE;
		}
		break;

	case LDAP_SCOPE_SUBTREE: {

		/* 
		 * + 1 because we need room for '%'; this makes a subtree
		 * search for a DN BACKSQL_MAX_DN_LEN long legal 
		 * if it returns that DN only
		 */
		char		temp_base_dn[ BACKSQL_MAX_DN_LEN + 1 + 1 ];

		/*
		 * We do not accept DNs longer than BACKSQL_MAX_DN_LEN;
		 * however this should be handled earlier
		 */
		assert( bsi->base_dn->bv_len <= BACKSQL_MAX_DN_LEN );
			
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
		if ( BACKSQL_HAS_LDAPINFO_DN_RU( bsi->bi ) ) {
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
			return BACKSQL_CONTINUE;
		}
		break;
	}

 	case LDAP_SCOPE_ONELEVEL:
		res = backsql_dn2id( bsi->bi, &base_id, 
				bsi->dbh, bsi->base_dn );
		if ( res != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"could not retrieve base_dn id%s\n",
				res == LDAP_NO_SUCH_OBJECT ? ": no such entry"
				: "", 0, 0 );
			bsi->status = res;
			return BACKSQL_CONTINUE;
		}
		
		rc = backsql_BindParamID( sth, 2, &base_id.id );
		backsql_free_entryID( &base_id, 0 );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base id parameter\n", 0, 0, 0 );
			return BACKSQL_CONTINUE;
		}
		break;
	}
	
	rc = SQLExecute( sth );
	if ( !BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error executing query\n", 0, 0, 0 );
		backsql_PrintErrors( bsi->bi->db_env, bsi->dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		return BACKSQL_CONTINUE;
	}

	backsql_BindRowAsStrings( sth, &row );
	rc = SQLFetch( sth );
	for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( sth ) ) {
		c_id = (backsql_entryID *)ch_calloc( 1, 
				sizeof( backsql_entryID ) );
		c_id->id = strtol( row.cols[ 0 ], NULL, 0 );
		c_id->keyval = strtol( row.cols[ 1 ], NULL, 0 );
		c_id->oc_id = bsi->oc->id;
		ber_str2bv( row.cols[ 3 ], 0, 1, &c_id->dn );
		c_id->next = bsi->id_list;
		bsi->id_list = c_id;
		bsi->n_candidates--;

		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"added entry id=%ld, keyval=%ld dn='%s'\n",
			c_id->id, c_id->keyval, row.cols[ 3 ] );

		if ( bsi->n_candidates == -1 ) {
			break;
		}
	}
	backsql_FreeRow( &row );
	SQLFreeStmt( sth, SQL_DROP );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_oc_get_candidates()\n", 0, 0, 0 );

	return ( bsi->n_candidates == -1 ? BACKSQL_STOP : BACKSQL_CONTINUE );
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

	if ( nbase->bv_len > BACKSQL_MAX_DN_LEN ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"search base length (%ld) exceeds max length (%ld)\n", 
			nbase->bv_len, BACKSQL_MAX_DN_LEN, 0 );
		/*
		 * FIXME: a LDAP_NO_SUCH_OBJECT could be appropriate
		 * since it is impossible that such a long DN exists
		 * in the backend
		 */
		send_ldap_result( conn, op, LDAP_ADMINLIMIT_EXCEEDED, 
				"", NULL, NULL, NULL );
		return 1;
	}

	sres = backsql_get_db_conn( be, conn, &dbh );
	if ( sres != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		send_ldap_result( conn, op, sres, "",
				sres == LDAP_OTHER ?  "SQL-backend error" : "",
				NULL, NULL );
		return 1;
	}

	/* TimesTen : Pass it along to the lower level routines */ 
	srch_info.use_reverse_dn = BACKSQL_USE_REVERSE_DN( bi ); 
 
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
			if ( limit->lms_t_hard == 0
					&& limit->lms_t_soft > -1
					&& tlimit > limit->lms_t_soft ) {
				tlimit = limit->lms_t_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_t_hard > 0 ) {
				send_search_result( conn, op, 
						LDAP_ADMINLIMIT_EXCEEDED,
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
			if ( limit->lms_s_hard == 0
					&& limit->lms_s_soft > -1
					&& slimit > limit->lms_s_soft ) {
				slimit = limit->lms_s_soft;

			/* positive hard limit means abort */
			} else if ( limit->lms_s_hard > 0 ) {
				send_search_result( conn, op, 
						LDAP_ADMINLIMIT_EXCEEDED,
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
	srch_info.n_candidates = ( isroot ? -2 : limit->lms_s_unchecked == -1 
			? -2 : limit->lms_s_unchecked );
	avl_apply( bi->oc_by_oc, backsql_oc_get_candidates,
			&srch_info, BACKSQL_STOP, AVL_INORDER );
	if ( !isroot && limit->lms_s_unchecked != -1 ) {
		if ( srch_info.n_candidates == -1 ) {
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
	for ( eid = srch_info.id_list; eid != NULL; 
			eid = backsql_free_entryID( eid, 1 ) ) {
		Attribute	*hasSubordinate = NULL,
				*a = NULL;

		/* check for abandon */
		if ( op->o_abandon ) {
			break;
		}

		/* check time limit */
		if ( tlimit != -1 && slap_get_time() > stoptime ) {
			send_search_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			goto end_of_search;
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

		/*
		 * We use this flag since we need to parse the filter
		 * anyway; we should have used the frontend API function
		 * filter_has_subordinates()
		 */
		if ( srch_info.bsi_flags & BSQL_SF_FILTER_HASSUBORDINATE ) {
			int		rc;

			rc = backsql_has_children( bi, dbh, &entry->e_nname );

			switch( rc ) {
			case LDAP_COMPARE_TRUE:
			case LDAP_COMPARE_FALSE:
				hasSubordinate = slap_operational_hasSubordinate( rc == LDAP_COMPARE_TRUE );
				if ( hasSubordinate != NULL ) {
					for ( a = entry->e_attrs; 
							a && a->a_next; 
							a = a->a_next );

					a->a_next = hasSubordinate;
				}
				rc = 0;
				break;

			default:
				Debug(LDAP_DEBUG_TRACE, 
					"backsql_search(): "
					"has_children failed( %d)\n", 
					rc, 0, 0 );
				rc = 1;
				break;
			}

			if ( rc ) {
				continue;
			}
		}

		if ( test_filter( be, conn, op, entry, filter ) 
				== LDAP_COMPARE_TRUE ) {
			if ( hasSubordinate && !( srch_info.bsi_flags & BSQL_SF_ALL_OPER ) 
					&& !ad_inlist( slap_schema.si_ad_hasSubordinates, attrs ) ) {
				a->a_next = NULL;
				attr_free( hasSubordinate );
				hasSubordinate = NULL;
			}

#if 0	/* noop is masked SLAP_CTRL_UPDATE */
			if ( op->o_noop ) {
				sres = 0;
			} else {
#endif
				sres = send_search_entry( be, conn, op, entry,
						attrs, attrsonly, NULL );
#if 0
			}
#endif

			switch ( sres ) {
			case 0:
				nentries++;
				break;

			case -1:
				Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
					"connection lost\n", 0, 0, 0 );
				goto end_of_search;

			default:
				/*
				 * FIXME: send_search_entry failed;
				 * better stop
				 */
				break;
			}
		}
		entry_free( entry );

		if ( slimit != -1 && nentries >= slimit ) {
			send_search_result( conn, op, LDAP_SIZELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
			goto end_of_search;
		}
	}

end_of_search:;

	if ( nentries > 0 ) {
		send_search_result( conn, op,
			v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
			NULL, NULL, v2refs, NULL, nentries );
	} else {
		send_ldap_result( conn, op, srch_info.status,
				NULL, NULL, NULL, 0 );
	}
	
done:;
	ch_free( srch_info.attrs );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_search()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */

