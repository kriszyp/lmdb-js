/* filterentry.c - apply a filter to an entry */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>


#include "slap.h"

static int	test_filter_and( Operation *op, Entry *e, Filter *flist );
static int	test_filter_or( Operation *op, Entry *e, Filter *flist );
static int	test_substrings_filter( Operation *op, Entry *e, Filter *f);
static int	test_ava_filter( Operation *op, Entry *e, AttributeAssertion *ava, int type );
static int	test_mra_filter( Operation *op, Entry *e, MatchingRuleAssertion *mra );
static int	test_presence_filter( Operation *op, Entry *e, AttributeDescription *desc );


/*
 * test_filter - test a filter against a single entry.
 * returns:
 *		LDAP_COMPARE_TRUE		filter matched
 *		LDAP_COMPARE_FALSE		filter did not match
 *		SLAPD_COMPARE_UNDEFINED	filter is undefined
 *	or an ldap result code indicating error
 */

int
test_filter(
    Operation	*op,
    Entry	*e,
    Filter	*f )
{
	int	rc;
#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_filter: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter\n", 0, 0, 0 );
#endif

	switch ( f->f_choice ) {
	case SLAPD_FILTER_COMPUTED:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1,
			"test_filter:   COMPUTED %s (%d)\n",
			f->f_result == LDAP_COMPARE_FALSE ? "false" :
			f->f_result == LDAP_COMPARE_TRUE	 ? "true"  :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "undefined" :
			"error", f->f_result, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    COMPUTED %s (%d)\n",
			f->f_result == LDAP_COMPARE_FALSE ? "false" :
			f->f_result == LDAP_COMPARE_TRUE ? "true" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "undefined" : "error",
			f->f_result, 0 );
#endif

		rc = f->f_result;
		break;

	case LDAP_FILTER_EQUALITY:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:   EQUALITY\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    EQUALITY\n", 0, 0, 0 );
#endif

		rc = test_ava_filter( op, e, f->f_ava, LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter  SUBSTRINGS\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    SUBSTRINGS\n", 0, 0, 0 );
#endif

		rc = test_substrings_filter( op, e, f );
		break;

	case LDAP_FILTER_GE:
		rc = test_ava_filter( op, e, f->f_ava, LDAP_FILTER_GE );
		break;

	case LDAP_FILTER_LE:
		rc = test_ava_filter( op, e, f->f_ava, LDAP_FILTER_LE );
		break;

	case LDAP_FILTER_PRESENT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:	PRESENT\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    PRESENT\n", 0, 0, 0 );
#endif
		rc = test_presence_filter( op, e, f->f_desc );
		break;

	case LDAP_FILTER_APPROX:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter: APPROX\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    APPROX\n", 0, 0, 0 );
#endif
		rc = test_ava_filter( op, e, f->f_ava, LDAP_FILTER_APPROX );
		break;

	case LDAP_FILTER_AND:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:  AND\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    AND\n", 0, 0, 0 );
#endif
		rc = test_filter_and( op, e, f->f_and );
		break;

	case LDAP_FILTER_OR:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:	OR\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    OR\n", 0, 0, 0 );
#endif
		rc = test_filter_or( op, e, f->f_or );
		break;

	case LDAP_FILTER_NOT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:	NOT\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    NOT\n", 0, 0, 0 );
#endif
		rc = test_filter( op, e, f->f_not );

		/* Flip true to false and false to true
		 * but leave Undefined alone.
		 */
		switch( rc ) {
		case LDAP_COMPARE_TRUE:
			rc = LDAP_COMPARE_FALSE;
			break;
		case LDAP_COMPARE_FALSE:
			rc = LDAP_COMPARE_TRUE;
			break;
		}
		break;

	case LDAP_FILTER_EXT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, "test_filter:	EXT\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "    EXT\n", 0, 0, 0 );
#endif
		rc = test_mra_filter( op, e, f->f_mra );
		break;

	default:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, INFO, 
			"test_filter:  unknown filter type %lu\n", f->f_choice, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "    unknown filter type %lu\n",
		    f->f_choice, 0, 0 );
#endif
		rc = LDAP_PROTOCOL_ERROR;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, RESULTS, "test_filter:  return=%d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter %d\n", rc, 0, 0 );
#endif
	return( rc );
}

static int test_mra_filter(
	Operation *op,
	Entry *e,
	MatchingRuleAssertion *mra )
{
	Attribute	*a;
	void		*memctx;
	BER_MEMFREE_FN	*memfree;

	if ( op == NULL ) {
		memctx = NULL;
		memfree = slap_sl_free;
	} else {
		memctx = op->o_tmpmemctx;
		memfree = op->o_tmpfree;
	}

	if ( mra->ma_desc ) {
		/*
		 * if ma_desc is available, then we're filtering for
		 * one attribute, and SEARCH permissions can be checked
		 * directly.
		 */
		if( !access_allowed( op, e,
			mra->ma_desc, &mra->ma_value, ACL_SEARCH, NULL ) )
		{
			return LDAP_INSUFFICIENT_ACCESS;
		}

		for(a = attrs_find( e->e_attrs, mra->ma_desc );
			a != NULL;
			a = attrs_find( a->a_next, mra->ma_desc ) )
		{
			struct berval *bv;
			/* If ma_rule is not the same as the attribute's
			 * normal rule, then we can't use the a_nvals.
			 */
			if (mra->ma_rule == a->a_desc->ad_type->sat_equality) {
				bv = a->a_nvals;
			} else {
				bv = a->a_vals;
			}

			for ( ; bv->bv_val != NULL; bv++ ) {
				int ret;
				int rc;
				const char *text;
	
				rc = value_match( &ret, a->a_desc, mra->ma_rule, 0,
					bv, &mra->ma_value, &text );
	
				if( rc != LDAP_SUCCESS ) return rc;
				if ( ret == 0 ) return LDAP_COMPARE_TRUE;
			}
		}

	} else {
		/*
		 * No attribute description: test all
		 */
		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
			struct berval	*bv, value;
			const char	*text = NULL;
			int		rc;

			/* check if matching is appropriate */
			if ( !mr_usable_with_at( mra->ma_rule, a->a_desc->ad_type )) {
				continue;
			}

			/* normalize for equality */
			rc = asserted_value_validate_normalize( a->a_desc, mra->ma_rule,
				SLAP_MR_EXT|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
				&mra->ma_value, &value, &text, memctx );
			if ( rc != LDAP_SUCCESS ) continue;

			/* check search access */
			if ( !access_allowed( op, e,
				a->a_desc, &value, ACL_SEARCH, NULL ) ) {
				memfree( value.bv_val, memctx );
				continue;
			}

			/* check match */
			if (mra->ma_rule == a->a_desc->ad_type->sat_equality) {
				bv = a->a_nvals;
			} else {
				bv = a->a_vals;
			}

			for ( ; bv->bv_val != NULL; bv++ ) {
				int ret;
	
				rc = value_match( &ret, a->a_desc, mra->ma_rule, 0,
					bv, &value, &text );
	
				if( rc != LDAP_SUCCESS ) break;
	
				if ( ret == 0 ) {
					rc = LDAP_COMPARE_TRUE;
					break;
				}
			}
			memfree( value.bv_val, memctx );
			if ( rc != LDAP_SUCCESS ) return rc;
		}
	}

	/* check attrs in DN AVAs if required */
	if ( mra->ma_dnattrs ) {
		LDAPDN		dn = NULL;
		int		iRDN, iAVA;
		int		rc;

		/* parse and pretty the dn */
		rc = dnPrettyDN( NULL, &e->e_name, &dn, memctx );
		if ( rc != LDAP_SUCCESS ) {
			return LDAP_INVALID_SYNTAX;
		}

		/* for each AVA of each RDN ... */
		for ( iRDN = 0; dn[ iRDN ]; iRDN++ ) {
			LDAPRDN		rdn = dn[ iRDN ];

			for ( iAVA = 0; rdn[ iAVA ]; iAVA++ ) {
				LDAPAVA		*ava = rdn[ iAVA ];
				struct berval	*bv = &ava->la_value, value;
				AttributeDescription *ad =
					(AttributeDescription *)ava->la_private;
				int ret;
				const char *text;

				assert( ad );

				if ( mra->ma_desc ) {
					/* have a mra type? check for subtype */
					if ( !is_ad_subtype( ad, mra->ma_desc ) ) {
						continue;
					}
					value = mra->ma_value;

				} else {
					const char	*text = NULL;

					/* check if matching is appropriate */
					if ( !mr_usable_with_at( mra->ma_rule, ad->ad_type )) {
						continue;
					}

					/* normalize for equality */
					rc = asserted_value_validate_normalize( ad,
						mra->ma_rule,
						SLAP_MR_EXT|SLAP_MR_VALUE_OF_ASSERTION_SYNTAX,
						&mra->ma_value, &value, &text, memctx );
					if ( rc != LDAP_SUCCESS ) continue;

					/* check search access */
					if ( !access_allowed( op, e,
						ad, &value, ACL_SEARCH, NULL ) )
					{
						memfree( value.bv_val, memctx );
						continue;
					}
				}

				/* check match */
				rc = value_match( &ret, ad, mra->ma_rule, 0,
					bv, &value, &text );

				if ( value.bv_val != mra->ma_value.bv_val ) {
					memfree( value.bv_val, memctx );
				}

				if ( rc == LDAP_SUCCESS && ret == 0 ) rc = LDAP_COMPARE_TRUE;

				if( rc != LDAP_SUCCESS ) {
					ldap_dnfree_x( dn, memctx );
					return rc;
				}
			}
		}
		ldap_dnfree_x( dn, memctx );
	}

	return LDAP_COMPARE_FALSE;
}

static int
test_ava_filter(
	Operation	*op,
	Entry		*e,
	AttributeAssertion *ava,
	int		type )
{
	Attribute	*a;

	if ( !access_allowed( op, e,
		ava->aa_desc, &ava->aa_value, ACL_SEARCH, NULL ) )
	{
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, ava->aa_desc ) )
	{
		MatchingRule *mr;
		struct berval *bv;

		switch ( type ) {
		case LDAP_FILTER_APPROX:
			mr = a->a_desc->ad_type->sat_approx;
			if( mr != NULL ) break;

			/* use EQUALITY matching rule if no APPROX rule */

		case LDAP_FILTER_EQUALITY:
			mr = a->a_desc->ad_type->sat_equality;
			break;

		case LDAP_FILTER_GE:
		case LDAP_FILTER_LE:
			mr = a->a_desc->ad_type->sat_ordering;
			break;

		default:
			mr = NULL;
		}

		if( mr == NULL ) {
			continue;
		}

		for ( bv = a->a_nvals; bv->bv_val != NULL; bv++ ) {
			int ret;
			int rc;
			const char *text;

			rc = value_match( &ret, a->a_desc, mr, 0,
				bv, &ava->aa_value, &text );

			if( rc != LDAP_SUCCESS ) return rc;

			switch ( type ) {
			case LDAP_FILTER_EQUALITY:
			case LDAP_FILTER_APPROX:
				if ( ret == 0 ) return LDAP_COMPARE_TRUE;
				break;

			case LDAP_FILTER_GE:
				if ( ret >= 0 ) return LDAP_COMPARE_TRUE;
				break;

			case LDAP_FILTER_LE:
				if ( ret <= 0 ) return LDAP_COMPARE_TRUE;
				break;
			}
		}
	}

	if ( ava->aa_desc == slap_schema.si_ad_hasSubordinates 
		&& op && op->o_bd && op->o_bd->be_has_subordinates )
	{
		int		hasSubordinates;
		struct berval	hs;

		/*
		 * No other match should be allowed ...
		 */
		assert( type == LDAP_FILTER_EQUALITY );
		
		if ( op->o_bd->be_has_subordinates( op, e, &hasSubordinates ) !=
			LDAP_SUCCESS )
		{
			return LDAP_OTHER;
		}

		if ( hasSubordinates == LDAP_COMPARE_TRUE ) {
			hs = slap_true_bv;

		} else if ( hasSubordinates == LDAP_COMPARE_FALSE ) {
			hs = slap_false_bv;

		} else {
			return LDAP_OTHER;
		}

		if ( bvmatch( &ava->aa_value, &hs ) ) return LDAP_COMPARE_TRUE;
		return LDAP_COMPARE_FALSE;
	}

	return( LDAP_COMPARE_FALSE );
}


static int
test_presence_filter(
	Operation	*op,
	Entry		*e,
	AttributeDescription *desc )
{
	Attribute	*a;

	if ( !access_allowed( op, e, desc, NULL, ACL_SEARCH, NULL ) ) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	a = attrs_find( e->e_attrs, desc );
	if ( a == NULL && desc == slap_schema.si_ad_hasSubordinates ) {

		/*
		 * XXX: fairly optimistic: if the function is defined,
		 * then PRESENCE must succeed, because hasSubordinate
		 * is boolean-valued; I think we may live with this 
		 * simplification by now
		 */
		if ( op && op->o_bd && op->o_bd->be_has_subordinates ) {
			return LDAP_COMPARE_TRUE;
		}

		return LDAP_COMPARE_FALSE;
	}

	return a != NULL ? LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE;
}


static int
test_filter_and(
	Operation	*op,
	Entry	*e,
	Filter	*flist )
{
	Filter	*f;
	int rtn = LDAP_COMPARE_TRUE; /* True if empty */

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_filter_and: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter_and\n", 0, 0, 0 );
#endif


	for ( f = flist; f != NULL; f = f->f_next ) {
		int rc = test_filter( op, e, f );

		if ( rc == LDAP_COMPARE_FALSE ) {
			/* filter is False */
			rtn = rc;
			break;
		}

		if ( rc != LDAP_COMPARE_TRUE ) {
			/* filter is Undefined unless later elements are False */
			rtn = rc;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, RESULTS, "test_filter_and:  rc=%d\n", rtn, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter_and %d\n", rtn, 0, 0 );
#endif

	return rtn;
}

static int
test_filter_or(
	Operation	*op,
	Entry	*e,
	Filter	*flist
)
{
	Filter	*f;
	int rtn = LDAP_COMPARE_FALSE; /* False if empty */

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_filter_or: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter_or\n", 0, 0, 0 );
#endif

	for ( f = flist; f != NULL; f = f->f_next ) {
		int rc = test_filter( op, e, f );

		if ( rc == LDAP_COMPARE_TRUE ) {
			/* filter is True */
			rtn = rc;
			break;
		}

		if ( rc != LDAP_COMPARE_FALSE ) {
			/* filter is Undefined unless later elements are True */
			rtn = rc;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_filter_or: result=%d\n", rtn, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter_or %d\n", rtn, 0, 0 );
#endif
	return rtn;
}


static int
test_substrings_filter(
	Operation	*op,
	Entry	*e,
	Filter	*f )
{
	Attribute	*a;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_substrings_filter: begin\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin test_substrings_filter\n", 0, 0, 0 );
#endif

	if ( !access_allowed( op, e,
		f->f_sub_desc, NULL, ACL_SEARCH, NULL ) )
	{
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, f->f_sub_desc );
		a != NULL;
		a = attrs_find( a->a_next, f->f_sub_desc ) )
	{
		MatchingRule *mr = a->a_desc->ad_type->sat_substr;
		struct berval *bv;

		if( mr == NULL ) continue;

		for ( bv = a->a_nvals; bv->bv_val != NULL; bv++ ) {
			int ret;
			int rc;
			const char *text;

			rc = value_match( &ret, a->a_desc, mr, 0,
				bv, f->f_sub, &text );

			if( rc != LDAP_SUCCESS ) return rc;
			if ( ret == 0 ) return LDAP_COMPARE_TRUE;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "test_substrings_filter: return FALSE\n",
		0, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end test_substrings_filter 1\n",
		0, 0, 0 );
#endif
	return LDAP_COMPARE_FALSE;
}
