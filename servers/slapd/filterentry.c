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
static int	test_substrings_filter( Backend *be,
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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter: begin\n" ));
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter\n", 0, 0, 0 );
#endif


	switch ( f->f_choice ) {
	case SLAPD_FILTER_COMPUTED:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:   COMPUTED %s (%d)\n",
			   f->f_result == LDAP_COMPARE_FALSE ? "false" :
			   f->f_result == LDAP_COMPARE_TRUE	 ? "true"  :
			   f->f_result == SLAPD_COMPARE_UNDEFINED ? "undefined" :
			   "error",
			   f->f_result ));
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
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:   EQUALITY\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    EQUALITY\n", 0, 0, 0 );
#endif

		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter  SUBSTRINGS\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    SUBSTRINGS\n", 0, 0, 0 );
#endif

		rc = test_substrings_filter( be, conn, op, e, f );
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
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:	PRESENT\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    PRESENT\n", 0, 0, 0 );
#endif

		rc = test_presence_filter( be, conn, op, e, f->f_desc );
		break;

	case LDAP_FILTER_APPROX:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter: APPROX\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    APPROX\n", 0, 0, 0 );
#endif
		rc = test_ava_filter( be, conn, op, e, f->f_ava,
		    LDAP_FILTER_APPROX );
		break;

	case LDAP_FILTER_AND:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:  AND\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    AND\n", 0, 0, 0 );
#endif

		rc = test_filter_and( be, conn, op, e, f->f_and );
		break;

	case LDAP_FILTER_OR:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:	OR\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    OR\n", 0, 0, 0 );
#endif

		rc = test_filter_or( be, conn, op, e, f->f_or );
		break;

	case LDAP_FILTER_NOT:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:	NOT\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    NOT\n", 0, 0, 0 );
#endif

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
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_DETAIL1,
			   "test_filter:	EXT\n" ));
#else
		Debug( LDAP_DEBUG_FILTER, "    EXT\n", 0, 0, 0 );
#endif

		rc = test_mra_filter( be, conn, op, e, f->f_mra );
		break;
#endif

	default:
#ifdef NEW_LOGGING
		LDAP_LOG(( "filter", LDAP_LEVEL_INFO,
			   "test_filter:  unknown filter type %lu\n", 
		       f->f_choice ));
#else
		Debug( LDAP_DEBUG_ANY, "    unknown filter type %lu\n",
		    f->f_choice, 0, 0 );
#endif

		rc = LDAP_PROTOCOL_ERROR;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter:  return=%d\n", rc ));
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter %d\n", rc, 0, 0 );
#endif

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

		for ( i = 0; a->a_vals[i] != NULL; i++ ) {
			int ret;
			int rc;
			const char *text;

			rc = value_match( &ret, a->a_desc, mr, 0,
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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter_and: begin\n" ));
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter_and\n", 0, 0, 0 );
#endif


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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter_and:  rc=%d\n", rtn ));
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter_and %d\n", rtn, 0, 0 );
#endif

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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter_or: begin\n" ));
#else
	Debug( LDAP_DEBUG_FILTER, "=> test_filter_or\n", 0, 0, 0 );
#endif


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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_filter_or: result=%d\n", rtn ));
#else
	Debug( LDAP_DEBUG_FILTER, "<= test_filter_or %d\n", rtn, 0, 0 );
#endif

	return rtn;
}


static int
test_substrings_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*f
)
{
	Attribute	*a;

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_substrings_filter: begin\n" ));
#else
	Debug( LDAP_DEBUG_FILTER, "begin test_substrings_filter\n", 0, 0, 0 );
#endif


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

			rc = value_match( &ret, a->a_desc, mr, 0,
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

#ifdef NEW_LOGGING
	LDAP_LOG(( "filter", LDAP_LEVEL_ENTRY,
		   "test_substrings_filter: return FALSE\n" ));
#else
	Debug( LDAP_DEBUG_FILTER, "end test_substrings_filter 1\n", 0, 0, 0 );
#endif

	return LDAP_COMPARE_FALSE;
}
