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
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "proto-sql.h"

static int backsql_process_filter( backsql_srch_info *bsi, Filter *f );
static int backsql_process_filter_eq( backsql_srch_info *bsi, 
		backsql_at_map_rec *at,
		int casefold, struct berval *filter_value );
static int backsql_process_filter_like( backsql_srch_info *bsi, 
		backsql_at_map_rec *at,
		int casefold, struct berval *filter_value );
static int backsql_process_filter_attr( backsql_srch_info *bsi, Filter *f, 
		backsql_at_map_rec *at );

static int
backsql_attrlist_add( backsql_srch_info *bsi, AttributeDescription *ad )
{
	int 		n_attrs = 0;
	AttributeName	*an = NULL;

	if ( bsi->bsi_attrs == NULL ) {
		return 1;
	}

	/*
	 * clear the list (retrieve all attrs)
	 */
	if ( ad == NULL ) {
		ch_free( bsi->bsi_attrs );
		bsi->bsi_attrs = NULL;
		return 1;
	}

	for ( ; !BER_BVISNULL( &bsi->bsi_attrs[ n_attrs ].an_name ); n_attrs++ ) {
		an = &bsi->bsi_attrs[ n_attrs ];
		
		Debug( LDAP_DEBUG_TRACE, "==>backsql_attrlist_add(): "
			"attribute \"%s\" is in list\n", 
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
		"adding \"%s\" to list\n", ad->ad_cname.bv_val, 0, 0 );

	an = (AttributeName *)ch_realloc( bsi->bsi_attrs,
			sizeof( AttributeName ) * ( n_attrs + 2 ) );
	if ( an == NULL ) {
		return -1;
	}

	an[ n_attrs ].an_name = ad->ad_cname;
	an[ n_attrs ].an_desc = ad;
	BER_BVZERO( &an[ n_attrs + 1 ].an_name );

	bsi->bsi_attrs = an;
	
	return 1;
}

void
backsql_init_search(
	backsql_srch_info 	*bsi, 
	struct berval		*base, 
	int 			scope, 
	int 			slimit,
	int 			tlimit,
	time_t 			stoptime, 
	Filter 			*filter, 
	SQLHDBC 		dbh,
	Operation 		*op,
	SlapReply		*rs,
	AttributeName 		*attrs )
{
	AttributeName		*p;

	bsi->bsi_base_dn = base;
	bsi->bsi_scope = scope;
	bsi->bsi_slimit = slimit;
	bsi->bsi_tlimit = tlimit;
	bsi->bsi_filter = filter;
	bsi->bsi_dbh = dbh;
	bsi->bsi_op = op;
	bsi->bsi_rs = rs;
	bsi->bsi_flags = 0;

	/*
	 * handle "*"
	 */
	if ( attrs == NULL || an_find( attrs, &AllUser ) ) {
		bsi->bsi_attrs = NULL;

	} else {
		bsi->bsi_attrs = (AttributeName *)ch_calloc( 1, 
				sizeof( AttributeName ) );
		BER_BVZERO( &bsi->bsi_attrs[ 0 ].an_name );
		
		for ( p = attrs; !BER_BVISNULL( &p->an_name ); p++ ) {
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

	bsi->bsi_abandon = 0;
	bsi->bsi_id_list = NULL;
	bsi->bsi_n_candidates = 0;
	bsi->bsi_stoptime = stoptime;
	BER_BVZERO( &bsi->bsi_sel.bb_val );
	bsi->bsi_sel.bb_len = 0;
	BER_BVZERO( &bsi->bsi_from.bb_val );
	bsi->bsi_from.bb_len = 0;
	BER_BVZERO( &bsi->bsi_join_where.bb_val );
	bsi->bsi_join_where.bb_len = 0;
	BER_BVZERO( &bsi->bsi_flt_where.bb_val );
	bsi->bsi_flt_where.bb_len = 0;
	bsi->bsi_filter_oc = NULL;

	bsi->bsi_status = LDAP_SUCCESS;
}

static int
backsql_process_filter_list( backsql_srch_info *bsi, Filter *f, int op )
{
	int		res;

	if ( !f ) {
		return 0;
	}

	backsql_strfcat( &bsi->bsi_flt_where, "c", '(' /* ) */  );

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
			backsql_strfcat( &bsi->bsi_flt_where, "l",
					(ber_len_t)STRLENOF( " AND " ), 
						" AND " );
			break;

		case LDAP_FILTER_OR:
			backsql_strfcat( &bsi->bsi_flt_where, "l",
					(ber_len_t)STRLENOF( " OR " ),
						" OR " );
			break;
		}
	}

	backsql_strfcat( &bsi->bsi_flt_where, "c", /* ( */ ')' );

	return 1;
}

static int
backsql_process_sub_filter( backsql_srch_info *bsi, Filter *f,
	backsql_at_map_rec *at )
{
	backsql_info		*bi = (backsql_info *)bsi->bsi_op->o_bd->be_private;
	int			i;
	int			casefold = 0;

	if ( !f ) {
		return 0;
	}

	/* always uppercase strings by now */
#ifdef BACKSQL_UPPERCASE_FILTER
	if ( SLAP_MR_ASSOCIATED( f->f_sub_desc->ad_type->sat_substr,
			bi->bi_caseIgnoreMatch ) )
#endif /* BACKSQL_UPPERCASE_FILTER */
	{
		casefold = 1;
	}

	if ( SLAP_MR_ASSOCIATED( f->f_sub_desc->ad_type->sat_substr,
			bi->bi_telephoneNumberMatch ) )
	{

		struct berval	bv;
		ber_len_t	i, s, a;

		/*
		 * to check for matching telephone numbers
		 * with intermixed chars, e.g. val='1234'
		 * use
		 * 
		 * val LIKE '%1%2%3%4%'
		 */

		BER_BVZERO( &bv );
		if ( f->f_sub_initial.bv_val ) {
			bv.bv_len += f->f_sub_initial.bv_len;
		}
		if ( f->f_sub_any != NULL ) {
			for ( a = 0; f->f_sub_any[ a ].bv_val != NULL; a++ ) {
				bv.bv_len += f->f_sub_any[ a ].bv_len;
			}
		}
		if ( f->f_sub_final.bv_val ) {
			bv.bv_len += f->f_sub_final.bv_len;
		}
		bv.bv_len = 2 * bv.bv_len - 1;
		bv.bv_val = ch_malloc( bv.bv_len + 1 );

		s = 0;
		if ( !BER_BVISNULL( &f->f_sub_initial ) ) {
			bv.bv_val[ s ] = f->f_sub_initial.bv_val[ 0 ];
			for ( i = 1; i < f->f_sub_initial.bv_len; i++ ) {
				bv.bv_val[ s + 2 * i - 1 ] = '%';
				bv.bv_val[ s + 2 * i ] = f->f_sub_initial.bv_val[ i ];
			}
			bv.bv_val[ s + 2 * i - 1 ] = '%';
			s += 2 * i;
		}

		if ( f->f_sub_any != NULL ) {
			for ( a = 0; !BER_BVISNULL( &f->f_sub_any[ a ] ); a++ ) {
				bv.bv_val[ s ] = f->f_sub_any[ a ].bv_val[ 0 ];
				for ( i = 1; i < f->f_sub_any[ a ].bv_len; i++ ) {
					bv.bv_val[ s + 2 * i - 1 ] = '%';
					bv.bv_val[ s + 2 * i ] = f->f_sub_any[ a ].bv_val[ i ];
				}
				bv.bv_val[ s + 2 * i - 1 ] = '%';
				s += 2 * i;
			}
		}

		if ( !BER_BVISNULL( &f->f_sub_final ) ) {
			bv.bv_val[ s ] = f->f_sub_final.bv_val[ 0 ];
			for ( i = 1; i < f->f_sub_final.bv_len; i++ ) {
				bv.bv_val[ s + 2 * i - 1 ] = '%';
				bv.bv_val[ s + 2 * i ] = f->f_sub_final.bv_val[ i ];
			}
				bv.bv_val[ s + 2 * i - 1 ] = '%';
			s += 2 * i;
		}

		bv.bv_val[ s - 1 ] = '\0';

		(void)backsql_process_filter_like( bsi, at, casefold, &bv );
		ch_free( bv.bv_val );

		return 1;
	}

	/*
	 * When dealing with case-sensitive strings 
	 * we may omit normalization; however, normalized
	 * SQL filters are more liberal.
	 */

	backsql_strfcat( &bsi->bsi_flt_where, "c", '(' /* ) */  );

	/* TimesTen */
	Debug( LDAP_DEBUG_TRACE, "backsql_process_sub_filter(%s):\n",
		at->bam_ad->ad_cname.bv_val, 0, 0 );
	Debug(LDAP_DEBUG_TRACE, "   expr: '%s%s%s'\n", at->bam_sel_expr.bv_val,
		at->bam_sel_expr_u.bv_val ? "' '" : "",
		at->bam_sel_expr_u.bv_val ? at->bam_sel_expr_u.bv_val : "" );
	if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
		/*
		 * If a pre-upper-cased version of the column 
		 * or a precompiled upper function exists, use it
		 */
		backsql_strfcat( &bsi->bsi_flt_where, 
				"bl",
				&at->bam_sel_expr_u,
				(ber_len_t)STRLENOF( " LIKE '" ),
					" LIKE '" );

	} else {
		backsql_strfcat( &bsi->bsi_flt_where, "bl",
				&at->bam_sel_expr,
				(ber_len_t)STRLENOF( " LIKE '" ), " LIKE '" );
	}
 
	if ( !BER_BVISNULL( &f->f_sub_initial ) ) {
		ber_len_t	start;

#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, 
			"==>backsql_process_sub_filter(%s): "
			"sub_initial=\"%s\"\n", at->bam_ad->ad_cname.bv_val,
			f->f_sub_initial.bv_val, 0 );
#endif /* BACKSQL_TRACE */

		start = bsi->bsi_flt_where.bb_val.bv_len;
		backsql_strfcat( &bsi->bsi_flt_where, "b",
				&f->f_sub_initial );
		if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
			ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );
		}
	}

	backsql_strfcat( &bsi->bsi_flt_where, "c", '%' );

	if ( f->f_sub_any != NULL ) {
		for ( i = 0; !BER_BVISNULL( &f->f_sub_any[ i ] ); i++ ) {
			ber_len_t	start;

#ifdef BACKSQL_TRACE
			Debug( LDAP_DEBUG_TRACE, 
				"==>backsql_process_sub_filter(%s): "
				"sub_any[%d]=\"%s\"\n", at->bam_ad->ad_cname.bv_val, 
				i, f->f_sub_any[ i ].bv_val );
#endif /* BACKSQL_TRACE */

			start = bsi->bsi_flt_where.bb_val.bv_len;
			backsql_strfcat( &bsi->bsi_flt_where,
					"bc",
					&f->f_sub_any[ i ],
					'%' );
			if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
				/*
				 * Note: toupper('%') = '%'
				 */
				ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );
			}
		}
	}

	if ( !BER_BVISNULL( &f->f_sub_final ) ) {
		ber_len_t	start;

#ifdef BACKSQL_TRACE
		Debug( LDAP_DEBUG_TRACE, 
			"==>backsql_process_sub_filter(%s): "
			"sub_final=\"%s\"\n", at->bam_ad->ad_cname.bv_val,
			f->f_sub_final.bv_val, 0 );
#endif /* BACKSQL_TRACE */

		start = bsi->bsi_flt_where.bb_val.bv_len;
    		backsql_strfcat( &bsi->bsi_flt_where, "b",
				&f->f_sub_final );
  		if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
			ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );
		}
	}

	backsql_strfcat( &bsi->bsi_flt_where, "l", 
			(ber_len_t)sizeof( /* (' */ "')" ) - 1, /* ( */ "')" );
 
	return 1;
}

static int
backsql_process_filter( backsql_srch_info *bsi, Filter *f )
{
	backsql_at_map_rec	**vat = NULL;
	AttributeDescription	*ad = NULL;
	unsigned		i;
	int 			done = 0;
	int			rc = 0;

	Debug( LDAP_DEBUG_TRACE, "==>backsql_process_filter()\n", 0, 0, 0 );
	if ( f->f_choice == SLAPD_FILTER_COMPUTED ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_process_filter(): "
			"invalid filter\n", 0, 0, 0 );
		rc = -1;
		goto done;
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
		backsql_strfcat( &bsi->bsi_flt_where, "l",
				(ber_len_t)sizeof( "NOT (" /* ) */ ) - 1,
					"NOT (" /* ) */ );
		rc = backsql_process_filter( bsi, f->f_not );
		backsql_strfcat( &bsi->bsi_flt_where, "c", /* ( */ ')' );
		done = 1;
		break;

	case LDAP_FILTER_PRESENT:
		ad = f->f_desc;
		break;
		
	case LDAP_FILTER_EXT:
		ad = f->f_mra->ma_desc;
		if ( f->f_mr_dnattrs ) {
			/*
			 * if dn attrs filtering is requested, better return 
			 * success and let test_filter() deal with candidate
			 * selection; otherwise we'd need to set conditions
			 * on the contents of the DN, e.g. "SELECT ... FROM
			 * ldap_entries AS attributeName WHERE attributeName.dn
			 * like '%attributeName=value%'"
			 */
			backsql_strfcat( &bsi->bsi_flt_where, "l",
					(ber_len_t)STRLENOF( "1=1" ), "1=1" );
			bsi->bsi_status = LDAP_SUCCESS;
			rc = 1;
			goto done;
		}
		break;
		
	default:
		ad = f->f_av_desc;
		break;
	}

	if ( rc == -1 ) {
		goto done;
	}
 
	if ( done ) {
		rc = 1;
		goto done;
	}

	/*
	 * Turn structuralObjectClass into objectClass
	 */
	if ( ad == slap_schema.si_ad_objectClass 
			|| ad == slap_schema.si_ad_structuralObjectClass ) {
		/*
		 * If the filter is LDAP_FILTER_PRESENT, then it's done;
		 * otherwise, let's see if we are lucky: filtering
		 * for "structural" objectclass or ancestor...
		 */
		switch ( f->f_choice ) {
		case LDAP_FILTER_EQUALITY:
		{
			ObjectClass	*oc = oc_bvfind( &f->f_av_value );

			if ( oc == NULL ) {
				Debug( LDAP_DEBUG_TRACE,
						"backsql_process_filter(): "
						"unknown objectClass \"%s\" "
						"in filter\n",
						f->f_av_value.bv_val, 0, 0 );
				bsi->bsi_status = LDAP_OTHER;
				rc = -1;
				goto done;
			}

			/*
			 * "structural" objectClass inheritance:
			 * - a search for "person" will also return 
			 *   "inetOrgPerson"
			 * - a search for "top" will return everything
			 */
			if ( is_object_subclass( oc, bsi->bsi_oc->bom_oc ) ) {
				goto filter_oc_success;
			}

			break;
		}

		case LDAP_FILTER_PRESENT:
filter_oc_success:;
			backsql_strfcat( &bsi->bsi_flt_where, "l",
					(ber_len_t)STRLENOF( "1=1" ), "1=1" );
			bsi->bsi_status = LDAP_SUCCESS;
			rc = 1;
			goto done;
			
		default:
			Debug( LDAP_DEBUG_TRACE,
					"backsql_process_filter(): "
					"illegal/unhandled filter "
					"on objectClass attribute",
					0, 0, 0 );
			bsi->bsi_status = LDAP_OTHER;
			rc = -1;
			goto done;
		}

	} else if ( ad == slap_schema.si_ad_hasSubordinates || ad == NULL ) {
		/*
		 * FIXME: this is not robust; e.g. a filter
		 * '(!(hasSubordinates=TRUE))' fails because
		 * in SQL it would read 'NOT (1=1)' instead 
		 * of no condition.  
		 * Note however that hasSubordinates is boolean, 
		 * so a more appropriate filter would be 
		 * '(hasSubordinates=FALSE)'
		 *
		 * A more robust search for hasSubordinates
		 * would * require joining the ldap_entries table
		 * selecting if there are descendants of the
		 * candidate.
		 */
		backsql_strfcat( &bsi->bsi_flt_where, "l",
				(ber_len_t)STRLENOF( "1=1" ), "1=1" );
		if ( ad == slap_schema.si_ad_hasSubordinates ) {
			/*
			 * instruct candidate selection algorithm
			 * and attribute list to try to detect
			 * if an entry has subordinates
			 */
			bsi->bsi_flags |= BSQL_SF_FILTER_HASSUBORDINATE;

		} else {
			/*
			 * clear attributes to fetch, to require ALL
			 * and try extended match on all attributes
			 */
			backsql_attrlist_add( bsi, NULL );
		}
		rc = 1;
		goto done;
	}

	/*
	 * attribute inheritance:
	 */
	if ( backsql_supad2at( bsi->bsi_oc, ad, &vat ) ) {
		bsi->bsi_status = LDAP_OTHER;
		rc = -1;
		goto done;
	}

	if ( vat == NULL ) {
		/* search anyway; other parts of the filter
		 * may succeeed */
		backsql_strfcat( &bsi->bsi_flt_where, "l",
				(ber_len_t)STRLENOF( "1=1" ), "1=1" );
		bsi->bsi_status = LDAP_SUCCESS;
		rc = 1;
		goto done;
	}

	/* if required, open extra level of parens */
	done = 0;
	if ( vat[0]->bam_next || vat[1] ) {
		backsql_strfcat( &bsi->bsi_flt_where, "c", '(' );
		done = 1;
	}

	i = 0;
next:;
	/* apply attr */
	if ( backsql_process_filter_attr( bsi, f, vat[i] ) == -1 ) {
		return -1;
	}

	/* if more definitions of the same attr, apply */
	if ( vat[i]->bam_next ) {
		backsql_strfcat( &bsi->bsi_flt_where, "l",
			STRLENOF( " OR " ), " OR " );
		vat[i] = vat[i]->bam_next;
		goto next;
	}

	/* if more descendants of the same attr, apply */
	i++;
	if ( vat[i] ) {
		backsql_strfcat( &bsi->bsi_flt_where, "l",
			STRLENOF( " OR " ), " OR " );
		goto next;
	}

	/* if needed, close extra level of parens */
	if ( done ) {
		backsql_strfcat( &bsi->bsi_flt_where, "c", ')' );
	}

	rc = 1;

done:;
	if ( vat ) {
		ch_free( vat );
	}

	Debug( LDAP_DEBUG_TRACE,
			"<==backsql_process_filter() %s\n",
			rc == 1 ? "succeeded" : "failed", 0, 0);

	return rc;
}

static int
backsql_process_filter_eq( backsql_srch_info *bsi, backsql_at_map_rec *at,
		int casefold, struct berval *filter_value )
{
	/*
	 * maybe we should check type of at->sel_expr here somehow,
	 * to know whether upper_func is applicable, but for now
	 * upper_func stuff is made for Oracle, where UPPER is
	 * safely applicable to NUMBER etc.
	 */
	if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
		ber_len_t	start;

		backsql_strfcat( &bsi->bsi_flt_where, "cbl",
				'(', /* ) */
				&at->bam_sel_expr_u, 
				(ber_len_t)STRLENOF( "='" ),
					"='" );

		start = bsi->bsi_flt_where.bb_val.bv_len;

		backsql_strfcat( &bsi->bsi_flt_where, "bl",
				filter_value, 
				(ber_len_t)sizeof( /* (' */ "')" ) - 1,
					/* (' */ "')" );

		ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );

	} else {
		backsql_strfcat( &bsi->bsi_flt_where, "cblbl",
				'(', /* ) */
				&at->bam_sel_expr,
				(ber_len_t)STRLENOF( "='" ), "='",
				filter_value,
				(ber_len_t)sizeof( /* (' */ "')" ) - 1,
					/* (' */ "')" );
	}

	return 1;
}
	
static int
backsql_process_filter_like( backsql_srch_info *bsi, backsql_at_map_rec *at,
		int casefold, struct berval *filter_value )
{
	/*
	 * maybe we should check type of at->sel_expr here somehow,
	 * to know whether upper_func is applicable, but for now
	 * upper_func stuff is made for Oracle, where UPPER is
	 * safely applicable to NUMBER etc.
	 */
	if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
		ber_len_t	start;

		backsql_strfcat( &bsi->bsi_flt_where, "cbl",
				'(', /* ) */
				&at->bam_sel_expr_u, 
				(ber_len_t)STRLENOF( " LIKE '%" ),
					" LIKE '%" );

		start = bsi->bsi_flt_where.bb_val.bv_len;

		backsql_strfcat( &bsi->bsi_flt_where, "bl",
				filter_value, 
				(ber_len_t)sizeof( /* (' */ "%')" ) - 1,
					/* (' */ "%')" );

		ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );

	} else {
		backsql_strfcat( &bsi->bsi_flt_where, "cblbl",
				'(', /* ) */
				&at->bam_sel_expr,
				(ber_len_t)STRLENOF( " LIKE '%" ),
					" LIKE '%",
				filter_value,
				(ber_len_t)sizeof( /* (' */ "%')" ) - 1,
					/* (' */ "%')" );
	}

	return 1;
}

static int
backsql_process_filter_attr( backsql_srch_info *bsi, Filter *f, backsql_at_map_rec *at )
{
	backsql_info		*bi = (backsql_info *)bsi->bsi_op->o_bd->be_private;
	int			casefold = 0;
	struct berval		*filter_value = NULL;
	MatchingRule		*matching_rule = NULL;
	struct berval		ordering = BER_BVC("<=");

	Debug( LDAP_DEBUG_TRACE, "==>backsql_process_filter_attr(%s)\n",
		at->bam_ad->ad_cname.bv_val, 0, 0 );

	backsql_merge_from_clause( &bsi->bsi_from, &at->bam_from_tbls );

	/*
	 * need to add this attribute to list of attrs to load,
	 * so that we can do test_filter() later
	 */
	backsql_attrlist_add( bsi, at->bam_ad );

	if ( !BER_BVISNULL( &at->bam_join_where )
			&& strstr( bsi->bsi_join_where.bb_val.bv_val, at->bam_join_where.bv_val ) == NULL ) {
	       	backsql_strfcat( &bsi->bsi_join_where, "lb",
				(ber_len_t)STRLENOF( " AND " ), " AND ",
				&at->bam_join_where );
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		filter_value = &f->f_av_value;
		matching_rule = at->bam_ad->ad_type->sat_equality;

		goto equality_match;

		/* fail over into next case */
		
	case LDAP_FILTER_EXT:
		filter_value = &f->f_mra->ma_value;
		matching_rule = f->f_mr_rule;

equality_match:;
		/* always uppercase strings by now */
#ifdef BACKSQL_UPPERCASE_FILTER
		if ( SLAP_MR_ASSOCIATED( matching_rule,
					bi->bi_caseIgnoreMatch ) )
#endif /* BACKSQL_UPPERCASE_FILTER */
		{
			casefold = 1;
		}

		if ( SLAP_MR_ASSOCIATED( matching_rule,
					bi->bi_telephoneNumberMatch ) )
		{
			struct berval	bv;
			ber_len_t	i;

			/*
			 * to check for matching telephone numbers
			 * with intermized chars, e.g. val='1234'
			 * use
			 * 
			 * val LIKE '%1%2%3%4%'
			 */

			bv.bv_len = 2 * filter_value->bv_len - 1;
			bv.bv_val = ch_malloc( bv.bv_len + 1 );

			bv.bv_val[ 0 ] = filter_value->bv_val[ 0 ];
			for ( i = 1; i < filter_value->bv_len; i++ ) {
				bv.bv_val[ 2 * i - 1 ] = '%';
				bv.bv_val[ 2 * i ] = filter_value->bv_val[ i ];
			}
			bv.bv_val[ 2 * i - 1 ] = '\0';

			(void)backsql_process_filter_like( bsi, at, casefold, &bv );
			ch_free( bv.bv_val );

			break;
		}

		/*
		 * maybe we should check type of at->sel_expr here somehow,
		 * to know whether upper_func is applicable, but for now
		 * upper_func stuff is made for Oracle, where UPPER is
		 * safely applicable to NUMBER etc.
		 */
		(void)backsql_process_filter_eq( bsi, at, casefold, filter_value );
		break;

	case LDAP_FILTER_GE:
		ordering.bv_val = ">=";

		/* fall thru to next case */
		
	case LDAP_FILTER_LE:
		/* always uppercase strings by now */
#ifdef BACKSQL_UPPERCASE_FILTER
		if ( SLAP_MR_ASSOCIATED( at->bam_ad->ad_type->sat_ordering,
				bi->bi_caseIgnoreMatch ) )
#endif /* BACKSQL_UPPERCASE_FILTER */
		{
			casefold = 1;
		}

		/*
		 * FIXME: should we uppercase the operands?
		 */
		if ( casefold && BACKSQL_AT_CANUPPERCASE( at ) ) {
			ber_len_t	start;

			backsql_strfcat( &bsi->bsi_flt_where, "cbbc",
					'(', /* ) */
					&at->bam_sel_expr_u, 
					&ordering,
					'\'' );

			start = bsi->bsi_flt_where.bb_val.bv_len;

			backsql_strfcat( &bsi->bsi_flt_where, "bl",
					filter_value, 
					(ber_len_t)sizeof( /* (' */ "')" ) - 1,
						/* (' */ "')" );

			ldap_pvt_str2upper( &bsi->bsi_flt_where.bb_val.bv_val[ start ] );
		
		} else {
			backsql_strfcat( &bsi->bsi_flt_where, "cbbcbl",
					'(' /* ) */ ,
					&at->bam_sel_expr,
					&ordering,
					'\'',
					&f->f_av_value,
					(ber_len_t)sizeof( /* (' */ "')" ) - 1,
						/* ( */ "')" );
		}
		break;

	case LDAP_FILTER_PRESENT:
		backsql_strfcat( &bsi->bsi_flt_where, "lbl",
				(ber_len_t)sizeof( "NOT (" /* ) */) - 1,
					"NOT (", /* ) */
				&at->bam_sel_expr, 
				(ber_len_t)sizeof( /* ( */ " IS NULL)" ) - 1,
					/* ( */ " IS NULL)" );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		backsql_process_sub_filter( bsi, f, at );
		break;

	case LDAP_FILTER_APPROX:
		/* we do our best */

		/*
		 * maybe we should check type of at->sel_expr here somehow,
		 * to know whether upper_func is applicable, but for now
		 * upper_func stuff is made for Oracle, where UPPER is
		 * safely applicable to NUMBER etc.
		 */
		(void)backsql_process_filter_like( bsi, at, 1, &f->f_av_value );
		break;

	default:
		/* unhandled filter type; should not happen */
		assert( 0 );
		backsql_strfcat( &bsi->bsi_flt_where, "l",
				(ber_len_t)STRLENOF( "1=1" ), "1=1" );
		break;

	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_process_filter_attr(%s)\n",
		at->bam_ad->ad_cname.bv_val, 0, 0 );

	return 1;
}

static int
backsql_srch_query( backsql_srch_info *bsi, struct berval *query )
{
	backsql_info	*bi = (backsql_info *)bsi->bsi_op->o_bd->be_private;
	int		rc;

	assert( query );
	BER_BVZERO( query );

	Debug( LDAP_DEBUG_TRACE, "==>backsql_srch_query()\n", 0, 0, 0 );
	BER_BVZERO( &bsi->bsi_sel.bb_val );
	BER_BVZERO( &bsi->bsi_sel.bb_val );
	bsi->bsi_sel.bb_len = 0;
	BER_BVZERO( &bsi->bsi_from.bb_val );
	bsi->bsi_from.bb_len = 0;
	BER_BVZERO( &bsi->bsi_join_where.bb_val );
	bsi->bsi_join_where.bb_len = 0;
	BER_BVZERO( &bsi->bsi_flt_where.bb_val );
	bsi->bsi_flt_where.bb_len = 0;

	backsql_strfcat( &bsi->bsi_sel, "lbcbc",
			(ber_len_t)STRLENOF( "SELECT DISTINCT ldap_entries.id," ),
				"SELECT DISTINCT ldap_entries.id,", 
			&bsi->bsi_oc->bom_keytbl, 
			'.', 
			&bsi->bsi_oc->bom_keycol, 
			',' );

	if ( !BER_BVISNULL( &bi->strcast_func ) ) {
		backsql_strfcat( &bsi->bsi_sel, "blbl",
				&bi->strcast_func, 
				(ber_len_t)sizeof( "('" /* ') */ ) - 1,
					"('" /* ') */ ,
				&bsi->bsi_oc->bom_oc->soc_cname,
				(ber_len_t)sizeof( /* (' */ "')" ) - 1,
					/* (' */ "')" );
	} else {
		backsql_strfcat( &bsi->bsi_sel, "cbc",
				'\'',
				&bsi->bsi_oc->bom_oc->soc_cname,
				'\'' );
	}
	backsql_strfcat( &bsi->bsi_sel, "l",
			(ber_len_t)STRLENOF( " AS objectClass,ldap_entries.dn AS dn" ),
			" AS objectClass,ldap_entries.dn AS dn" );

	backsql_strfcat( &bsi->bsi_from, "lb",
			(ber_len_t)STRLENOF( " FROM ldap_entries," ),
				" FROM ldap_entries,",
			&bsi->bsi_oc->bom_keytbl );

	backsql_strfcat( &bsi->bsi_join_where, "lbcbl",
			(ber_len_t)STRLENOF( " WHERE " ), " WHERE ",
			&bsi->bsi_oc->bom_keytbl,
			'.',
			&bsi->bsi_oc->bom_keycol,
			(ber_len_t)STRLENOF( "=ldap_entries.keyval AND ldap_entries.oc_map_id=? AND " ),
				"=ldap_entries.keyval AND ldap_entries.oc_map_id=? AND " );

	switch ( bsi->bsi_scope ) {
	case LDAP_SCOPE_BASE:
		if ( BACKSQL_CANUPPERCASE( bi ) ) {
			backsql_strfcat( &bsi->bsi_join_where, "bl",
					&bi->upper_func,
					(ber_len_t)STRLENOF( "(ldap_entries.dn)=?" ),
						"(ldap_entries.dn)=?" );
		} else {
			backsql_strfcat( &bsi->bsi_join_where, "l",
					(ber_len_t)STRLENOF( "ldap_entries.dn=?" ),
						"ldap_entries.dn=?" );
		}
		break;
		
	case BACKSQL_SCOPE_BASE_LIKE:
		if ( BACKSQL_CANUPPERCASE( bi ) ) {
			backsql_strfcat( &bsi->bsi_join_where, "bl",
					&bi->upper_func,
					(ber_len_t)STRLENOF( "(ldap_entries.dn) LIKE ?" ),
						"(ldap_entries.dn) LIKE ?" );
		} else {
			backsql_strfcat( &bsi->bsi_join_where, "l",
					(ber_len_t)STRLENOF( "ldap_entries.dn LIKE ?" ),
						"ldap_entries.dn LIKE ?" );
		}
		break;
		
	case LDAP_SCOPE_ONELEVEL:
		backsql_strfcat( &bsi->bsi_join_where, "l",
				(ber_len_t)STRLENOF( "ldap_entries.parent=?" ),
					"ldap_entries.parent=?" );
		break;

	case LDAP_SCOPE_SUBTREE:
		if ( BACKSQL_CANUPPERCASE( bi ) ) {
			backsql_strfcat( &bsi->bsi_join_where, "bl",
					&bi->upper_func,
					(ber_len_t)STRLENOF( "(ldap_entries.dn) LIKE ?" ),
						"(ldap_entries.dn) LIKE ?"  );
		} else {
			backsql_strfcat( &bsi->bsi_join_where, "l",
					(ber_len_t)STRLENOF( "ldap_entries.dn LIKE ?" ),
						"ldap_entries.dn LIKE ?" );
		}

		break;

	default:
		assert( 0 );
	}

	rc = backsql_process_filter( bsi, bsi->bsi_filter );
	if ( rc > 0 ) {
		struct berbuf	bb = BB_NULL;

		backsql_strfcat( &bb, "bbblb",
				&bsi->bsi_sel.bb_val,
				&bsi->bsi_from.bb_val, 
				&bsi->bsi_join_where.bb_val,
				(ber_len_t)STRLENOF( " AND " ), " AND ",
				&bsi->bsi_flt_where.bb_val );

		*query = bb.bb_val;

	} else if ( rc < 0 ) {
		/* 
		 * Indicates that there's no possible way the filter matches
		 * anything.  No need to issue the query
		 */
		free( query->bv_val );
		BER_BVZERO( query );
	}
 
	free( bsi->bsi_sel.bb_val.bv_val );
	BER_BVZERO( &bsi->bsi_sel.bb_val );
	bsi->bsi_sel.bb_len = 0;
	free( bsi->bsi_from.bb_val.bv_val );
	BER_BVZERO( &bsi->bsi_from.bb_val );
	bsi->bsi_from.bb_len = 0;
	free( bsi->bsi_join_where.bb_val.bv_val );
	BER_BVZERO( &bsi->bsi_join_where.bb_val );
	bsi->bsi_join_where.bb_len = 0;
	free( bsi->bsi_flt_where.bb_val.bv_val );
	BER_BVZERO( &bsi->bsi_flt_where.bb_val );
	bsi->bsi_flt_where.bb_len = 0;
	
	Debug( LDAP_DEBUG_TRACE, "<==backsql_srch_query() returns %s\n",
		query->bv_val ? query->bv_val : "NULL", 0, 0 );
	
	return ( rc <= 0 ? 1 : 0 );
}

static int
backsql_oc_get_candidates( void *v_oc, void *v_bsi )
{
	backsql_oc_map_rec	*oc = v_oc;
	backsql_srch_info	*bsi = v_bsi;
	backsql_info		*bi = (backsql_info *)bsi->bsi_op->o_bd->be_private;
	struct berval		query;
	SQLHSTMT		sth;
	RETCODE			rc;
	backsql_entryID		base_id = BACKSQL_ENTRYID_INIT;
	int			res;
	BACKSQL_ROW_NTS		row;
	int			i;
	int			j;
	int			n_candidates = bsi->bsi_n_candidates;

	/* 
	 * + 1 because we need room for '%'; this makes a subtree
	 * search for a DN BACKSQL_MAX_DN_LEN long legal 
	 * if it returns that DN only
	 */
	char			temp_base_dn[ BACKSQL_MAX_DN_LEN + 1 + 1 ];

	bsi->bsi_status = LDAP_SUCCESS;
 
	Debug( LDAP_DEBUG_TRACE, "==>backsql_oc_get_candidates(): oc=\"%s\"\n",
			BACKSQL_OC_NAME( oc ), 0, 0 );

	if ( bsi->bsi_n_candidates == -1 ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"unchecked limit has been overcome\n", 0, 0, 0 );
		/* should never get here */
		assert( 0 );
		bsi->bsi_status = LDAP_ADMINLIMIT_EXCEEDED;
		return BACKSQL_AVL_STOP;
	}
	
	bsi->bsi_oc = oc;
	res = backsql_srch_query( bsi, &query );
	if ( res ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error while constructing query for objectclass \"%s\"\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		/*
		 * FIXME: need to separate errors from legally
		 * impossible filters
		 */
		switch ( bsi->bsi_status ) {
		case LDAP_SUCCESS:
		case LDAP_UNDEFINED_TYPE:
		case LDAP_NO_SUCH_OBJECT:
			/* we are conservative... */
		default:
			bsi->bsi_status = LDAP_SUCCESS;
			/* try next */
			return BACKSQL_AVL_CONTINUE;

		case LDAP_ADMINLIMIT_EXCEEDED:
		case LDAP_OTHER:
			/* don't try any more */
			return BACKSQL_AVL_STOP;
		}
	}

	if ( BER_BVISNULL( &query ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"could not construct query for objectclass \"%s\"\n",
			oc->bom_oc->soc_cname.bv_val, 0, 0 );
		bsi->bsi_status = LDAP_SUCCESS;
		return BACKSQL_AVL_CONTINUE;
	}

	Debug( LDAP_DEBUG_TRACE, "Constructed query: %s\n", 
			query.bv_val, 0, 0 );

	rc = backsql_Prepare( bsi->bsi_dbh, &sth, query.bv_val, 0 );
	free( query.bv_val );
	BER_BVZERO( &query );
	if ( rc != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error preparing query\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, bsi->bsi_dbh, sth, rc );
		bsi->bsi_status = LDAP_OTHER;
		return BACKSQL_AVL_CONTINUE;
	}
	
	Debug( LDAP_DEBUG_TRACE, "id: '%ld'\n", bsi->bsi_oc->bom_id, 0, 0 );

	if ( backsql_BindParamID( sth, 1, &bsi->bsi_oc->bom_id ) != SQL_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error binding objectclass id parameter\n", 0, 0, 0 );
		bsi->bsi_status = LDAP_OTHER;
		return BACKSQL_AVL_CONTINUE;
	}

	switch ( bsi->bsi_scope ) {
	case LDAP_SCOPE_BASE:
	case BACKSQL_SCOPE_BASE_LIKE:
		/*
		 * We do not accept DNs longer than BACKSQL_MAX_DN_LEN;
		 * however this should be handled earlier
		 */
		if ( bsi->bsi_base_dn->bv_len > BACKSQL_MAX_DN_LEN ) {
			bsi->bsi_status = LDAP_OTHER;
			return BACKSQL_AVL_CONTINUE;
		}

		AC_MEMCPY( temp_base_dn, bsi->bsi_base_dn->bv_val,
				bsi->bsi_base_dn->bv_len + 1 );

		/* uppercase DN only if the stored DN can be uppercased
		 * for comparison */
		if ( BACKSQL_CANUPPERCASE( bi ) ) {
			ldap_pvt_str2upper( temp_base_dn );
		}

		Debug( LDAP_DEBUG_TRACE, "(base)dn: \"%s\"\n",
				temp_base_dn, 0, 0 );

		rc = backsql_BindParamStr( sth, 2, temp_base_dn,
				BACKSQL_MAX_DN_LEN );
		if ( rc != SQL_SUCCESS ) {
         		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base_dn parameter\n", 0, 0, 0 );
			backsql_PrintErrors( bi->db_env, bsi->bsi_dbh, 
					sth, rc );
			bsi->bsi_status = LDAP_OTHER;
			return BACKSQL_AVL_CONTINUE;
		}
		break;

	case LDAP_SCOPE_SUBTREE: {
		/*
		 * We do not accept DNs longer than BACKSQL_MAX_DN_LEN;
		 * however this should be handled earlier
		 */
		if ( bsi->bsi_base_dn->bv_len > BACKSQL_MAX_DN_LEN ) {
			bsi->bsi_status = LDAP_OTHER;
			return BACKSQL_AVL_CONTINUE;
		}

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
		if ( BACKSQL_HAS_LDAPINFO_DN_RU( bi ) ) {
			temp_base_dn[ 0 ] = '\0';
			for ( i = 0, j = bsi->bsi_base_dn->bv_len - 1;
					j >= 0; i++, j--) {
				temp_base_dn[ i ] = bsi->bsi_base_dn->bv_val[ j ];
			}
			temp_base_dn[ i ] = '%';
			temp_base_dn[ i + 1 ] = '\0';

		} else {
			temp_base_dn[ 0 ] = '%';
			AC_MEMCPY( &temp_base_dn[ 1 ], bsi->bsi_base_dn->bv_val,
				bsi->bsi_base_dn->bv_len + 1 );
		}

		/* uppercase DN only if the stored DN can be uppercased
		 * for comparison */
		if ( BACKSQL_CANUPPERCASE( bi ) ) {
			ldap_pvt_str2upper( temp_base_dn );
		}

		Debug( LDAP_DEBUG_TRACE, "(sub)dn: \"%s\"\n", temp_base_dn,
				0, 0 );

		rc = backsql_BindParamStr( sth, 2, temp_base_dn, 
				BACKSQL_MAX_DN_LEN );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base_dn parameter (2)\n",
				0, 0, 0 );
			backsql_PrintErrors( bi->db_env, bsi->bsi_dbh, 
					sth, rc );
			bsi->bsi_status = LDAP_OTHER;
			return BACKSQL_AVL_CONTINUE;
		}
		break;
	}

 	case LDAP_SCOPE_ONELEVEL:
		res = backsql_dn2id( bi, &base_id, 
				bsi->bsi_dbh, bsi->bsi_base_dn );
		if ( res != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"could not retrieve base_dn id%s\n",
				res == LDAP_NO_SUCH_OBJECT ? ": no such entry"
				: "", 0, 0 );
			bsi->bsi_status = res;
			return BACKSQL_AVL_CONTINUE;
		}

#ifdef BACKSQL_ARBITRARY_KEY
		Debug( LDAP_DEBUG_TRACE, "(one)id: \"%s\"\n",
				base_id.eid_id.bv_val, 0, 0 );

		rc = backsql_BindParamStr( sth, 2, base_id.eid_id.bv_val,
				BACKSQL_MAX_KEY_LEN );
#else /* ! BACKSQL_ARBITRARY_KEY */
		Debug( LDAP_DEBUG_TRACE, "(one)id: '%lu'\n", base_id.eid_id,
				0, 0 );

		rc = backsql_BindParamID( sth, 2, &base_id.eid_id );
#endif /* ! BACKSQL_ARBITRARY_KEY */
		backsql_free_entryID( &base_id, 0 );
		if ( rc != SQL_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
				"error binding base id parameter\n", 0, 0, 0 );
			bsi->bsi_status = LDAP_OTHER;
			return BACKSQL_AVL_CONTINUE;
		}
		break;
	}
	
	rc = SQLExecute( sth );
	if ( !BACKSQL_SUCCESS( rc ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"error executing query\n", 0, 0, 0 );
		backsql_PrintErrors( bi->db_env, bsi->bsi_dbh, sth, rc );
		SQLFreeStmt( sth, SQL_DROP );
		bsi->bsi_status = LDAP_OTHER;
		return BACKSQL_AVL_CONTINUE;
	}

	backsql_BindRowAsStrings( sth, &row );
	rc = SQLFetch( sth );
	for ( ; BACKSQL_SUCCESS( rc ); rc = SQLFetch( sth ) ) {
		struct berval		dn;
		backsql_entryID		*c_id = NULL;

		ber_str2bv( row.cols[ 3 ], 0, 0, &dn );

		if ( backsql_api_odbc2dn( bsi->bsi_op, bsi->bsi_rs, &dn ) ) {
			continue;
		}

		c_id = (backsql_entryID *)ch_calloc( 1, 
				sizeof( backsql_entryID ) );
#ifdef BACKSQL_ARBITRARY_KEY
		ber_str2bv( row.cols[ 0 ], 0, 1, &c_id->eid_id );
		ber_str2bv( row.cols[ 1 ], 0, 1, &c_id->eid_keyval );
#else /* ! BACKSQL_ARBITRARY_KEY */
		c_id->eid_id = strtol( row.cols[ 0 ], NULL, 0 );
		c_id->eid_keyval = strtol( row.cols[ 1 ], NULL, 0 );
#endif /* ! BACKSQL_ARBITRARY_KEY */
		c_id->eid_oc_id = bsi->bsi_oc->bom_id;

		if ( dn.bv_val == row.cols[ 3 ] ) {
			ber_dupbv( &c_id->eid_dn, &dn );
		} else {
			c_id->eid_dn = dn;
		}

		c_id->eid_next = bsi->bsi_id_list;
		bsi->bsi_id_list = c_id;
		bsi->bsi_n_candidates--;

#ifdef BACKSQL_ARBITRARY_KEY
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"added entry id=%s, keyval=%s dn=\"%s\"\n",
			c_id->eid_id.bv_val, c_id->eid_keyval.bv_val,
			row.cols[ 3 ] );
#else /* ! BACKSQL_ARBITRARY_KEY */
		Debug( LDAP_DEBUG_TRACE, "backsql_oc_get_candidates(): "
			"added entry id=%ld, keyval=%ld dn=\"%s\"\n",
			c_id->eid_id, c_id->eid_keyval, row.cols[ 3 ] );
#endif /* ! BACKSQL_ARBITRARY_KEY */

		if ( bsi->bsi_n_candidates == -1 ) {
			break;
		}
	}
	backsql_FreeRow( &row );
	SQLFreeStmt( sth, SQL_DROP );

	Debug( LDAP_DEBUG_TRACE, "<==backsql_oc_get_candidates(): %d\n",
			n_candidates - bsi->bsi_n_candidates, 0, 0 );

	return ( bsi->bsi_n_candidates == -1 ? BACKSQL_AVL_STOP : BACKSQL_AVL_CONTINUE );
}

int
backsql_search( Operation *op, SlapReply *rs )
{
	backsql_info		*bi = (backsql_info *)op->o_bd->be_private;
	SQLHDBC			dbh;
	int			sres;
	Entry			user_entry = { 0 };
	int			manageDSAit;
	time_t			stoptime = 0;
	backsql_srch_info	srch_info;
	backsql_entryID		*eid = NULL;
	struct berval		base;

	manageDSAit = get_manageDSAit( op );

	Debug( LDAP_DEBUG_TRACE, "==>backsql_search(): "
		"base=\"%s\", filter=\"%s\", scope=%d,", 
		op->o_req_ndn.bv_val,
		op->ors_filterstr.bv_val,
		op->ors_scope );
	Debug( LDAP_DEBUG_TRACE, " deref=%d, attrsonly=%d, "
		"attributes to load: %s\n",
		op->ors_deref,
		op->ors_attrsonly,
		op->ors_attrs == NULL ? "all" : "custom list" );

	if ( op->o_req_ndn.bv_len > BACKSQL_MAX_DN_LEN ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"search base length (%ld) exceeds max length (%ld)\n", 
			op->o_req_ndn.bv_len, BACKSQL_MAX_DN_LEN, 0 );
		/*
		 * FIXME: a LDAP_NO_SUCH_OBJECT could be appropriate
		 * since it is impossible that such a long DN exists
		 * in the backend
		 */
		rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
		send_ldap_result( op, rs );
		return 1;
	}

	sres = backsql_get_db_conn( op, &dbh );
	if ( sres != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"could not get connection handle - exiting\n", 
			0, 0, 0 );
		rs->sr_err = sres;
		rs->sr_text = sres == LDAP_OTHER ?  "SQL-backend error" : NULL;
		send_ldap_result( op, rs );
		return 1;
	}

	/* compute it anyway; root does not use it */
	stoptime = op->o_time + op->ors_tlimit;

	base = op->o_req_dn;
	if ( backsql_api_dn2odbc( op, rs, &base ) ) {
		Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
			"backsql_api_dn2odbc failed\n", 
			0, 0, 0 );
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "SQL-backend error";
		send_ldap_result( op, rs );
		return 1;
	}

	backsql_init_search( &srch_info, &base,
			op->ors_scope,
			op->ors_slimit, op->ors_tlimit,
			stoptime, op->ors_filter,
			dbh, op, rs, op->ors_attrs );

	/*
	 * for each objectclass we try to construct query which gets IDs
	 * of entries matching LDAP query filter and scope (or at least 
	 * candidates), and get the IDs
	 */
	srch_info.bsi_n_candidates =
		( op->ors_limit == NULL	/* isroot == FALSE */ ? -2 : 
		( op->ors_limit->lms_s_unchecked == -1 ? -2 :
		( op->ors_limit->lms_s_unchecked ) ) );
	avl_apply( bi->oc_by_oc, backsql_oc_get_candidates,
			&srch_info, BACKSQL_AVL_STOP, AVL_INORDER );
	if ( op->ors_limit != NULL	/* isroot == TRUE */
			&& op->ors_limit->lms_s_unchecked != -1
			&& srch_info.bsi_n_candidates == -1 )
	{
		rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
		send_ldap_result( op, rs );
		goto done;
	}
	
	/*
	 * now we load candidate entries (only those attributes 
	 * mentioned in attrs and filter), test it against full filter 
	 * and then send to client
	 */
	for ( eid = srch_info.bsi_id_list;
			eid != NULL; 
			eid = backsql_free_entryID( eid, 1 ) )
	{
		int		rc;
		Attribute	*hasSubordinate = NULL,
				*a = NULL;

		/* check for abandon */
		if ( op->o_abandon ) {
			break;
		}

		/* check time limit */
		if ( op->ors_tlimit != SLAP_NO_LIMIT
				&& slap_get_time() > stoptime )
		{
			rs->sr_err = LDAP_TIMELIMIT_EXCEEDED;
			rs->sr_ctrls = NULL;
			rs->sr_ref = rs->sr_v2ref;
			rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS
				: LDAP_REFERRAL;
			send_ldap_result( op, rs );
			goto end_of_search;
		}

#ifdef BACKSQL_ARBITRARY_KEY
		Debug(LDAP_DEBUG_TRACE, "backsql_search(): loading data "
			"for entry id=%s, oc_id=%ld, keyval=%s\n",
			eid->eid_id.bv_val, eid->eid_oc_id,
			eid->eid_keyval.bv_val );
#else /* ! BACKSQL_ARBITRARY_KEY */
		Debug(LDAP_DEBUG_TRACE, "backsql_search(): loading data "
			"for entry id=%ld, oc_id=%ld, keyval=%ld\n",
			eid->eid_id, eid->eid_oc_id, eid->eid_keyval );
#endif /* ! BACKSQL_ARBITRARY_KEY */

		srch_info.bsi_e = &user_entry;
		rc = backsql_id2entry( &srch_info, eid );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE, "backsql_search(): "
				"error %d in backsql_id2entry() "
				"- skipping\n", rc, 0, 0 );
			continue;
		}

		if ( !manageDSAit &&
				op->ors_scope != LDAP_SCOPE_BASE &&
				op->ors_scope != BACKSQL_SCOPE_BASE_LIKE &&
				is_entry_referral( &user_entry ) )
		{
			BerVarray refs;
			struct berval matched_dn;

			ber_dupbv( &matched_dn, &user_entry.e_name );
			refs = get_entry_referrals( op, &user_entry );
			if ( refs ) {
				rs->sr_ref = referral_rewrite( refs,
						&matched_dn, &op->o_req_dn,
						op->ors_scope );
				ber_bvarray_free( refs );
			}

			if ( !rs->sr_ref ) {
				rs->sr_text = "bad_referral object";
			}

			rs->sr_err = LDAP_REFERRAL;
			rs->sr_matched = matched_dn.bv_val;
			send_search_reference( op, rs );

			ber_bvarray_free( rs->sr_ref );
			rs->sr_ref = NULL;
			ber_memfree( matched_dn.bv_val );
			rs->sr_matched = NULL;

			continue;
		}

		/*
		 * We use this flag since we need to parse the filter
		 * anyway; we should have used the frontend API function
		 * filter_has_subordinates()
		 */
		if ( srch_info.bsi_flags & BSQL_SF_FILTER_HASSUBORDINATE ) {
			rc = backsql_has_children( bi, dbh, &user_entry.e_nname );

			switch ( rc ) {
			case LDAP_COMPARE_TRUE:
			case LDAP_COMPARE_FALSE:
				hasSubordinate = slap_operational_hasSubordinate( rc == LDAP_COMPARE_TRUE );
				if ( hasSubordinate != NULL ) {
					for ( a = user_entry.e_attrs; 
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

		if ( test_filter( op, &user_entry, op->ors_filter )
				== LDAP_COMPARE_TRUE ) {
			if ( hasSubordinate && !( srch_info.bsi_flags & BSQL_SF_ALL_OPER ) 
					&& !ad_inlist( slap_schema.si_ad_hasSubordinates, op->ors_attrs ) ) {
				a->a_next = NULL;
				attr_free( hasSubordinate );
				hasSubordinate = NULL;
			}

#if 0	/* noop is masked SLAP_CTRL_UPDATE */
			if ( op->o_noop ) {
				sres = 0;
			} else
#endif
			{
				rs->sr_attrs = op->ors_attrs;
				rs->sr_operational_attrs = NULL;
				rs->sr_entry = &user_entry;
				rs->sr_flags = REP_ENTRY_MODIFIABLE;
				sres = send_search_entry( op, rs );
				rs->sr_entry = NULL;
				rs->sr_attrs = NULL;
				rs->sr_operational_attrs = NULL;
			}

			switch ( sres ) {
			case 0:
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
		entry_clean( &user_entry );

		if ( op->ors_slimit != SLAP_NO_LIMIT
				&& rs->sr_nentries >= op->ors_slimit )
		{
			rs->sr_err = LDAP_SIZELIMIT_EXCEEDED;
			send_ldap_result( op, rs );
			goto end_of_search;
		}
	}

end_of_search:;
	/* in case we got here accidentally */
	entry_clean( &user_entry );

	if ( rs->sr_nentries > 0 ) {
		rs->sr_ref = rs->sr_v2ref;
		rs->sr_err = (rs->sr_v2ref == NULL) ? LDAP_SUCCESS
			: LDAP_REFERRAL;

	} else {
		rs->sr_err = srch_info.bsi_status;
	}
	send_ldap_result( op, rs );

	if ( rs->sr_v2ref ) {
		ber_bvarray_free( rs->sr_v2ref );
		rs->sr_v2ref = NULL;
	}

done:;
	ch_free( srch_info.bsi_attrs );
	if ( base.bv_val != op->o_req_ndn.bv_val ) {
		ch_free( base.bv_val );
	}

	Debug( LDAP_DEBUG_TRACE, "<==backsql_search()\n", 0, 0, 0 );
	return 0;
}

#endif /* SLAPD_SQL */

