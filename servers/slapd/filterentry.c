/* filterentry.c - apply a filter to an entry */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>


#include "slap.h"

static int	test_filter_and( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, Filter *flist );
static int	test_filter_or( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, Filter *flist );
static int	test_substring_filter( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, Filter *f);
static int	test_ava_filter( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, AttributeAssertion *ava, int type );
static int	test_mra_filter( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, MatchingRuleAssertion *mra );
static int	test_presence_filter( Backend *be,
	Connection *conn, Operation *op,
	Entry *e, AttributeDescription *desc );


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
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*f
)
{
	int	rc;

	Debug( LDAP_DEBUG_FILTER, "=> test_filter\n", 0, 0, 0 );

	switch ( f->f_choice ) {
	case SLAPD_FILTER_COMPUTED:
		Debug( LDAP_DEBUG_FILTER, "    COMPUTED %s (%d)\n",
			f->f_result == LDAP_COMPARE_FALSE ? "false" :
			f->f_result == LDAP_COMPARE_TRUE ? "true" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "undefined" : "error",
			f->f_result, 0 );
		rc = f->f_result;
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "    EQUALITY\n", 0, 0, 0 );
		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "    SUBSTRINGS\n", 0, 0, 0 );
		rc = test_substring_filter( be, conn, op, e, f );
		break;

	case LDAP_FILTER_GE:
		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_GE );
		break;

	case LDAP_FILTER_LE:
		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_LE );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "    PRESENT\n", 0, 0, 0 );
		rc = test_presence_filter( be, conn, op, e, f->f_desc );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "    APPROX\n", 0, 0, 0 );
		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_APPROX );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "    AND\n", 0, 0, 0 );
		rc = test_filter_and( be, conn, op, e, f->f_and );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "    OR\n", 0, 0, 0 );
		rc = test_filter_or( be, conn, op, e, f->f_or );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "    NOT\n", 0, 0, 0 );
		rc = test_filter( be, conn, op, e, f->f_not );

		switch( rc ) {
		case LDAP_COMPARE_TRUE:
			rc = LDAP_COMPARE_FALSE;
			break;
		case LDAP_COMPARE_FALSE:
			rc = LDAP_COMPARE_TRUE;
			break;
		}
		break;

#ifdef SLAPD_EXT_FILTERS
	case LDAP_FILTER_EXT:
		Debug( LDAP_DEBUG_FILTER, "    EXT\n", 0, 0, 0 );
#if SLAPD_SCHEMA_NOT_COMPAT
		rc = test_mra_filter( be, conn, op, e, f->f_mra );
#else
		rc = LDAP_UNWILLING_TO_PERFORM;
#endif
		break;
#endif

	default:
		Debug( LDAP_DEBUG_ANY, "    unknown filter type %lu\n",
		    f->f_choice, 0, 0 );
		rc = LDAP_PROTOCOL_ERROR;
	}

	Debug( LDAP_DEBUG_FILTER, "<= test_filter %d\n", rc, 0, 0 );
	return( rc );
}


static int
test_ava_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
	AttributeAssertion *ava,
    int		type
)
{
	int		i;
	Attribute	*a;

	if ( be != NULL && ! access_allowed( be, conn, op, e,
		ava->aa_desc, ava->aa_value, ACL_SEARCH ) )
	{
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, ava->aa_desc );
		a != NULL;
		a = attrs_find( a->a_next, ava->aa_desc ) )
	{
		MatchingRule *mr;

		switch ( type ) {
		case LDAP_FILTER_APPROX:
			mr = a->a_desc->ad_type->sat_approx;
			if( mr != NULL ) break;

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

		for ( i = 0; a->a_vals[i] != NULL; i++ ) {
			int ret;
			int rc;
			const char *text;

			rc = value_match( &ret, a->a_desc, mr,
				a->a_vals[i], ava->aa_value,
				&text );

			if( rc != LDAP_SUCCESS ) {
				return rc;
			}

			switch ( type ) {
			case LDAP_FILTER_EQUALITY:
			case LDAP_FILTER_APPROX:
				if ( ret == 0 ) {
					return LDAP_COMPARE_TRUE;
				}
				break;

			case LDAP_FILTER_GE:
				if ( ret >= 0 ) {
					return LDAP_COMPARE_TRUE;
				}
				break;

			case LDAP_FILTER_LE:
				if ( ret <= 0 ) {
					return LDAP_COMPARE_TRUE;
				}
				break;
			}
		}
	}

	return( LDAP_COMPARE_FALSE );
}


static int
test_presence_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
	AttributeDescription *desc
)
{
	if ( be != NULL && ! access_allowed( be, conn, op, e,
		desc, NULL, ACL_SEARCH ) )
	{
		return LDAP_INSUFFICIENT_ACCESS;
	}

	return attrs_find( e->e_attrs, desc ) != NULL
		? LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE;
}


static int
test_filter_and(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*flist
)
{
	Filter	*f;
	int rtn = LDAP_COMPARE_TRUE;

	Debug( LDAP_DEBUG_FILTER, "=> test_filter_and\n", 0, 0, 0 );

	for ( f = flist; f != NULL; f = f->f_next ) {
		int rc = test_filter( be, conn, op, e, f );

		if ( rc == LDAP_COMPARE_FALSE ) {
			rtn = LDAP_COMPARE_FALSE;
			break;
		}
		if ( rc != LDAP_COMPARE_TRUE ) {
			rtn = rc;
		}
	}

	Debug( LDAP_DEBUG_FILTER, "<= test_filter_and %d\n", rtn, 0, 0 );
	return rtn;
}

static int
test_filter_or(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*flist
)
{
	Filter	*f;
	int rtn = LDAP_COMPARE_FALSE;

	Debug( LDAP_DEBUG_FILTER, "=> test_filter_or\n", 0, 0, 0 );

	for ( f = flist; f != NULL; f = f->f_next ) {
		int rc = test_filter( be, conn, op, e, f );

		if ( rc == LDAP_COMPARE_TRUE ) {
			rtn = LDAP_COMPARE_TRUE;
			break;
		}
		if ( rc != LDAP_COMPARE_TRUE ) {
			rtn = rc;
		}
	}

	Debug( LDAP_DEBUG_FILTER, "<= test_filter_or %d\n", rtn, 0, 0 );
	return rtn;
}


static int
test_substring_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*f
)
{
	Attribute	*a;

	Debug( LDAP_DEBUG_FILTER, "begin test_substring_filter\n", 0, 0, 0 );

	if ( be != NULL && ! access_allowed( be, conn, op, e,
		f->f_sub_desc, NULL, ACL_SEARCH ) )
	{
		return LDAP_INSUFFICIENT_ACCESS;
	}

	for(a = attrs_find( e->e_attrs, f->f_sub_desc );
		a != NULL;
		a = attrs_find( a->a_next, f->f_sub_desc ) )
	{
		int i;
		MatchingRule *mr = a->a_desc->ad_type->sat_substr;

		if( mr == NULL ) {
			continue;
		}

		for ( i = 0; a->a_vals[i] != NULL; i++ ) {
			int ret;
			int rc;
			const char *text;

			rc = value_match( &ret, a->a_desc, mr,
				a->a_vals[i], f->f_sub,
				&text );

			if( rc != LDAP_SUCCESS ) {
				return rc;
			}

			if ( ret == 0 ) {
				return LDAP_COMPARE_TRUE;
			}
		}
	}

	Debug( LDAP_DEBUG_FILTER, "end test_substring_filter 1\n", 0, 0, 0 );
	return LDAP_COMPARE_FALSE;
}
