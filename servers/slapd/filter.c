/* filter.c - routines for parsing and dealing with filters */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"

static int	get_filter_list(
	Connection *conn,
	BerElement *ber,
	Filter **f,
	const char **text );

static int	get_substring_filter(
	Connection *conn,
	BerElement *ber,
	Filter *f,
	const char **text );

static int filter_escape_value(
	struct berval *in,
	struct berval *out );

static void simple_vrFilter2bv(
	ValuesReturnFilter *f,
	struct berval *fstr );

static int	get_simple_vrFilter(
	Connection *conn,
	BerElement *ber,
	ValuesReturnFilter **f,
	const char **text );


int
get_filter(
	Connection *conn,
	BerElement *ber,
	Filter **filt,
	const char **text )
{
	ber_tag_t	tag;
	ber_len_t	len;
	int		err;
	Filter		*f;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, "get_filter: conn %d\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_filter\n", 0, 0, 0 );
#endif
	/*
	 * A filter looks like this coming in:
	 *	Filter ::= CHOICE {
	 *		and		[0]	SET OF Filter,
	 *		or		[1]	SET OF Filter,
	 *		not		[2]	Filter,
	 *		equalityMatch	[3]	AttributeValueAssertion,
	 *		substrings	[4]	SubstringFilter,
	 *		greaterOrEqual	[5]	AttributeValueAssertion,
	 *		lessOrEqual	[6]	AttributeValueAssertion,
	 *		present		[7]	AttributeType,,
	 *		approxMatch	[8]	AttributeValueAssertion
	 *		extensibleMatch [9]	MatchingRuleAssertion
	 *	}
	 *
	 *	SubstringFilter ::= SEQUENCE {
	 *		type		   AttributeType,
	 *		SEQUENCE OF CHOICE {
	 *			initial		 [0] IA5String,
	 *			any		 [1] IA5String,
	 *			final		 [2] IA5String
	 *		}
	 *	}
	 *
	 *	MatchingRuleAssertion ::= SEQUENCE {
	 *		matchingRule	[1] MatchingRuleId OPTIONAL,
	 *		type		[2] AttributeDescription OPTIONAL,
	 *		matchValue	[3] AssertionValue,
	 *		dnAttributes	[4] BOOLEAN DEFAULT FALSE
	 *	}
	 *
	 */

	tag = ber_peek_tag( ber, &len );

	if( tag == LBER_ERROR ) {
		*text = "error decoding filter";
		return SLAPD_DISCONNECT;
	}

	f = (Filter *) ch_malloc( sizeof(Filter) );
	f->f_next = NULL;

	err = LDAP_SUCCESS;
	f->f_choice = tag; 

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL2, 
			"get_filter: conn %d  EQUALITY\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "EQUALITY\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_ava != NULL );
		break;

	case LDAP_FILTER_SUBSTRINGS:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  SUBSTRINGS\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "SUBSTRINGS\n", 0, 0, 0 );
#endif
		err = get_substring_filter( conn, ber, f, text );
		break;

	case LDAP_FILTER_GE:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  GE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "GE\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_LE:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  LE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "LE\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_PRESENT: {
		struct berval type;

#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d PRESENT\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "PRESENT\n", 0, 0, 0 );
#endif
		if ( ber_scanf( ber, "m", &type ) == LBER_ERROR ) {
			err = SLAPD_DISCONNECT;
			*text = "error decoding filter";
			break;
		}

		f->f_desc = NULL;
		err = slap_bv2ad( &type, &f->f_desc, text );

		if( err != LDAP_SUCCESS ) {
			/* unrecognized attribute description or other error */
			f->f_choice = SLAPD_FILTER_COMPUTED;
			f->f_result = LDAP_COMPARE_FALSE;
			err = LDAP_SUCCESS;
			break;
		}
		} break;

	case LDAP_FILTER_APPROX:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  APPROX\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "APPROX\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY_APPROX, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_AND:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  AND\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "AND\n", 0, 0, 0 );
#endif
		err = get_filter_list( conn, ber, &f->f_and, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_OR:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  OR\n", conn->c_connid, 0, 0  );
#else
		Debug( LDAP_DEBUG_FILTER, "OR\n", 0, 0, 0 );
#endif
		err = get_filter_list( conn, ber, &f->f_or, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_NOT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  NOT\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "NOT\n", 0, 0, 0 );
#endif
		(void) ber_skip_tag( ber, &len );
		err = get_filter( conn, ber, &f->f_not, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_EXT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_filter: conn %d  EXTENSIBLE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "EXTENSIBLE\n", 0, 0, 0 );
#endif

		err = get_mra( ber, &f->f_mra, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_mra != NULL );
		break;

	default:
		(void) ber_scanf( ber, "x" ); /* skip the element */
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, ERR, 
			"get_filter: conn %d unknown filter type=%lu\n",
			conn->c_connid, f->f_choice, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "get_filter: unknown filter type=%lu\n",
			f->f_choice, 0, 0 );
#endif
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		break;
	}

	if ( err != LDAP_SUCCESS ) {
		if( err != SLAPD_DISCONNECT ) {
			/* ignore error */
			f->f_choice = SLAPD_FILTER_COMPUTED;
			f->f_result = SLAPD_COMPARE_UNDEFINED;
			err = LDAP_SUCCESS;
			*filt = f;

		} else {
			free(f);
		}

	} else {
		*filt = f;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, DETAIL2, 
		"get_filter: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_filter %d\n", err, 0, 0 );
#endif
	return( err );
}

static int
get_filter_list( Connection *conn, BerElement *ber,
	Filter **f,
	const char **text )
{
	Filter		**new;
	int		err;
	ber_tag_t	tag;
	ber_len_t	len;
	char		*last;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_filter_list: conn %d start\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_filter_list\n", 0, 0, 0 );
#endif
	new = f;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
	{
		err = get_filter( conn, ber, new, text );
		if ( err != LDAP_SUCCESS )
			return( err );
		new = &(*new)->f_next;
	}
	*new = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_filter_list: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_filter_list\n", 0, 0, 0 );
#endif
	return( LDAP_SUCCESS );
}

static int
get_substring_filter(
	Connection	*conn,
	BerElement	*ber,
	Filter	*f,
	const char	**text )
{
	ber_tag_t	tag;
	ber_len_t	len;
	ber_tag_t	rc;
	struct berval value;
	char		*last;
	struct berval bv;
	*text = "error decoding filter";

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_substring_filter: conn %d  begin\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_substring_filter\n", 0, 0, 0 );
#endif
	if ( ber_scanf( ber, "{m" /*}*/, &bv ) == LBER_ERROR ) {
		return SLAPD_DISCONNECT;
	}

	f->f_sub = ch_calloc( 1, sizeof(SubstringsAssertion) );
	f->f_sub_desc = NULL;
	rc = slap_bv2ad( &bv, &f->f_sub_desc, text );

	if( rc != LDAP_SUCCESS ) {
		text = NULL;
		ch_free( f->f_sub );
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		return LDAP_SUCCESS;
	}

	f->f_sub_initial.bv_val = NULL;
	f->f_sub_any = NULL;
	f->f_sub_final.bv_val = NULL;

	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
	{
		unsigned usage;

		rc = ber_scanf( ber, "m", &value );
		if ( rc == LBER_ERROR ) {
			rc = SLAPD_DISCONNECT;
			goto return_error;
		}

		if ( value.bv_val == NULL || value.bv_len == 0 ) {
			rc = LDAP_INVALID_SYNTAX;
			goto return_error;
		} 

		switch ( tag ) {
		case LDAP_SUBSTRING_INITIAL:
			usage = SLAP_MR_SUBSTR_INITIAL;
			break;

		case LDAP_SUBSTRING_ANY:
			usage = SLAP_MR_SUBSTR_ANY;
			break;

		case LDAP_SUBSTRING_FINAL:
			usage = SLAP_MR_SUBSTR_FINAL;
			break;

		default:
			rc = LDAP_PROTOCOL_ERROR;

#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, ERR,
				"get_filter_substring: conn %d  unknown substring choice=%ld\n",
				conn->c_connid, (long)tag, 0 );
#else
			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring choice=%ld\n",
				(long) tag, 0, 0 );
#endif
			goto return_error;
		}

		/* valiate using equality matching rule validator! */
		rc = value_validate( f->f_sub_desc->ad_type->sat_equality,
			&value, text );
		if( rc != LDAP_SUCCESS ) {
			goto return_error;
		}

		rc = value_normalize( f->f_sub_desc, usage,
			&value, &bv, text );
		if( rc != LDAP_SUCCESS ) {
			goto return_error;
		}

		value = bv;

		rc = LDAP_PROTOCOL_ERROR;

		switch ( tag ) {
		case LDAP_SUBSTRING_INITIAL:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1,
				"get_substring_filter: conn %d  INITIAL\n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  INITIAL\n", 0, 0, 0 );
#endif

			if ( f->f_sub_initial.bv_val != NULL
				|| f->f_sub_any != NULL 
				|| f->f_sub_final.bv_val != NULL )
			{
				free( value.bv_val );
				goto return_error;
			}

			f->f_sub_initial = value;
			break;

		case LDAP_SUBSTRING_ANY:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1,
				"get_substring_filter: conn %d  ANY\n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  ANY\n", 0, 0, 0 );
#endif

			if ( f->f_sub_final.bv_val != NULL ) {
				free( value.bv_val );
				goto return_error;
			}

			ber_bvarray_add( &f->f_sub_any, &value );
			break;

		case LDAP_SUBSTRING_FINAL:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1, 
				"get_substring_filter: conn %d  FINAL\n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  FINAL\n", 0, 0, 0 );
#endif

			if ( f->f_sub_final.bv_val != NULL ) {
				free( value.bv_val );
				goto return_error;
			}

			f->f_sub_final = value;
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, INFO, 
				"get_substring_filter: conn %d  unknown substring type %ld\n",
				conn->c_connid, (long)tag, 0 );
#else
			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring type=%ld\n",
				(long) tag, 0, 0 );
#endif

			free( value.bv_val );

return_error:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, INFO, 
				"get_substring_filter: conn %d  error %ld\n",
				conn->c_connid, (long)rc, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  error=%ld\n",
				(long) rc, 0, 0 );
#endif
			free( f->f_sub_initial.bv_val );
			ber_bvarray_free( f->f_sub_any );
			free( f->f_sub_final.bv_val );
			ch_free( f->f_sub );
			return rc;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_substring_filter: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_substring_filter\n", 0, 0, 0 );
#endif
	return( LDAP_SUCCESS );
}

void
filter_free( Filter *f )
{
	Filter	*p, *next;

	if ( f == NULL ) {
		return;
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_PRESENT:
		break;

	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_APPROX:
		ava_free( f->f_ava, 1 );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		if ( f->f_sub_initial.bv_val != NULL ) {
			free( f->f_sub_initial.bv_val );
		}
		ber_bvarray_free( f->f_sub_any );
		if ( f->f_sub_final.bv_val != NULL ) {
			free( f->f_sub_final.bv_val );
		}
		ch_free( f->f_sub );
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		for ( p = f->f_list; p != NULL; p = next ) {
			next = p->f_next;
			filter_free( p );
		}
		break;

	case LDAP_FILTER_EXT:
		mra_free( f->f_mra, 1 );
		break;

	case SLAPD_FILTER_COMPUTED:
		break;

	default:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, ERR, 
			"filter_free: unknown filter type %lu\n", f->f_choice, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "filter_free: unknown filter type=%lu\n",
			f->f_choice, 0, 0 );
#endif
		break;
	}

	free( f );
}

void
filter2bv( Filter *f, struct berval *fstr )
{
	int	i;
	Filter	*p;
	struct berval tmp;
	ber_len_t len;

	if ( f == NULL ) {
		ber_str2bv( "No filter!", sizeof("No filter!")-1, 1, fstr );
		return;
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_GE:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(>=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s>=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_LE:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(<=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s<=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_APPROX:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(~=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s~=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );
		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		fstr->bv_len = f->f_sub_desc->ad_cname.bv_len +
			( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			f->f_sub_desc->ad_cname.bv_val );

		if ( f->f_sub_initial.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_initial, &tmp );

			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-2], tmp.bv_len+3,
				/* "(attr=" */ "%s*)",
				tmp.bv_val );

			ber_memfree( tmp.bv_val );
		}

		if ( f->f_sub_any != NULL ) {
			for ( i = 0; f->f_sub_any[i].bv_val != NULL; i++ ) {
				len = fstr->bv_len;
				filter_escape_value( &f->f_sub_any[i], &tmp );

				fstr->bv_len += tmp.bv_len + 1;
				fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

				snprintf( &fstr->bv_val[len-1], tmp.bv_len+3,
					/* "(attr=[init]*[any*]" */ "%s*)",
					tmp.bv_val );
				ber_memfree( tmp.bv_val );
			}
		}

		if ( f->f_sub_final.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_final, &tmp );

			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-1], tmp.bv_len+3,
				/* "(attr=[init*][any*]" */ "%s)",
				tmp.bv_val );

			ber_memfree( tmp.bv_val );
		}

		break;

	case LDAP_FILTER_PRESENT:
		fstr->bv_len = f->f_desc->ad_cname.bv_len +
			( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			f->f_desc->ad_cname.bv_val );
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		fstr->bv_len = sizeof("(%)") - 1;
		fstr->bv_val = malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%c)",
			f->f_choice == LDAP_FILTER_AND ? '&' :
			f->f_choice == LDAP_FILTER_OR ? '|' : '!' );

		for ( p = f->f_list; p != NULL; p = p->f_next ) {
			len = fstr->bv_len;

			filter2bv( p, &tmp );
			
			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-1], tmp.bv_len + 2, 
				/*"("*/ "%s)", tmp.bv_val );

			ch_free( tmp.bv_val );
		}

		break;

	case LDAP_FILTER_EXT:
		filter_escape_value( &f->f_mr_value, &tmp );
#ifndef SLAP_X_MRA_MATCH_DNATTRS
		fstr->bv_len = f->f_mr_desc->ad_cname.bv_len +
			( f->f_mr_dnattrs ? sizeof(":dn")-1 : 0 ) +
			( f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_len+1 : 0 ) +
			tmp.bv_len + ( sizeof("(:=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s%s%s%s:=%s)",
			f->f_mr_desc->ad_cname.bv_val,
			f->f_mr_dnattrs ? ":dn" : "",
			f->f_mr_rule_text.bv_len ? ":" : "",
			f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_val : "",
			tmp.bv_val );
#else /* SLAP_X_MRA_MATCH_DNATTRS */
		{
		struct berval ad;

		if ( f->f_mr_desc ) {
			ad = f->f_mr_desc->ad_cname;
		} else {
			ad.bv_len = 0;
			ad.bv_val = "";
		}
			
		fstr->bv_len = ad.bv_len +
			( f->f_mr_dnattrs ? sizeof(":dn")-1 : 0 ) +
			( f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_len+1 : 0 ) +
			tmp.bv_len + ( sizeof("(:=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s%s%s%s:=%s)",
			ad.bv_val,
			f->f_mr_dnattrs ? ":dn" : "",
			f->f_mr_rule_text.bv_len ? ":" : "",
			f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_val : "",
			tmp.bv_val );
		}
#endif /* SLAP_X_MRA_MATCH_DNATTRS */
		ber_memfree( tmp.bv_val );
		break;

	case SLAPD_FILTER_COMPUTED:
		ber_str2bv(
			f->f_result == LDAP_COMPARE_FALSE ? "(?=false)" :
			f->f_result == LDAP_COMPARE_TRUE ? "(?=true)" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "(?=undefined)" :
			"(?=error)",
			f->f_result == LDAP_COMPARE_FALSE ? sizeof("(?=false)")-1 :
			f->f_result == LDAP_COMPARE_TRUE ? sizeof("(?=true)")-1 :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? sizeof("(?=undefined)")-1 :
			sizeof("(?=error)")-1,
			1, fstr );
		break;

	default:
		ber_str2bv( "(?=unknown)", sizeof("(?=unknown)")-1, 1, fstr );
		break;
	}
}

static int filter_escape_value(
	struct berval *in,
	struct berval *out )
{
	ber_len_t i;
	assert( in );
	assert( out );

	out->bv_val = (char *) ch_malloc( ( in->bv_len * 3 ) + 1 );
	out->bv_len = 0;

	for( i=0; i < in->bv_len ; i++ ) {
		if( FILTER_ESCAPE(in->bv_val[i]) ) {
			out->bv_val[out->bv_len++] = SLAP_ESCAPE_CHAR;
			out->bv_val[out->bv_len++] = SLAP_ESCAPE_HI( in->bv_val[i] );
			out->bv_val[out->bv_len++] = SLAP_ESCAPE_LO( in->bv_val[i] );
		} else {
			out->bv_val[out->bv_len++] = in->bv_val[i];
		}
	}

	out->bv_val[out->bv_len] = '\0';
	return LDAP_SUCCESS;
}

static int
get_simple_vrFilter(
	Connection *conn,
	BerElement *ber,
	ValuesReturnFilter **filt,
	const char **text )
{
	ber_tag_t	tag;
	ber_len_t	len;
	int		err;
	ValuesReturnFilter *f;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_simple_vrFilter: conn %d\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_simple_vrFilter\n", 0, 0, 0 );
#endif

	tag = ber_peek_tag( ber, &len );

	if( tag == LBER_ERROR ) {
		*text = "error decoding filter";
		return SLAPD_DISCONNECT;
	}

	f = (ValuesReturnFilter *) ch_malloc( sizeof(ValuesReturnFilter) );
	f->f_next = NULL;

	err = LDAP_SUCCESS;
	f->f_choice = tag; 

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL2, 
			"get_simple_vrFilter: conn %d  EQUALITY\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "EQUALITY\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_ava != NULL );
		break;

	case LDAP_FILTER_SUBSTRINGS:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d  SUBSTRINGS\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "SUBSTRINGS\n", 0, 0, 0 );
#endif
		err = get_substring_filter( conn, ber, (Filter *)f, text );
		break;

	case LDAP_FILTER_GE:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d  GE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "GE\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_LE:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d  LE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "LE\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_PRESENT: {
		struct berval type;

#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d PRESENT\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "PRESENT\n", 0, 0, 0 );
#endif
		if ( ber_scanf( ber, "m", &type ) == LBER_ERROR ) {
			err = SLAPD_DISCONNECT;
			*text = "error decoding filter";
			break;
		}

		f->f_desc = NULL;
		err = slap_bv2ad( &type, &f->f_desc, text );

		if( err != LDAP_SUCCESS ) {
			/* unrecognized attribute description or other error */
			f->f_choice = SLAPD_FILTER_COMPUTED;
			f->f_result = LDAP_COMPARE_FALSE;
			err = LDAP_SUCCESS;
			break;
		}
		} break;

	case LDAP_FILTER_APPROX:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d  APPROX\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "APPROX\n", 0, 0, 0 );
#endif
		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY_APPROX, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		break;

	case LDAP_FILTER_EXT:
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, DETAIL1, 
			"get_simple_vrFilter: conn %d  EXTENSIBLE\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_FILTER, "EXTENSIBLE\n", 0, 0, 0 );
#endif

		err = get_mra( ber, &f->f_mra, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_mra != NULL );
		break;

	default:
		(void) ber_scanf( ber, "x" ); /* skip the element */
#ifdef NEW_LOGGING
		LDAP_LOG( FILTER, ERR, 
			"get_simple_vrFilter: conn %d unknown filter type=%lu\n",
			conn->c_connid, f->f_choice, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "get_simple_vrFilter: unknown filter type=%lu\n",
			f->f_choice, 0, 0 );
#endif
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		break;
	}

	if ( err != LDAP_SUCCESS ) {
		if( err != SLAPD_DISCONNECT ) {
			/* ignore error */
			f->f_choice = SLAPD_FILTER_COMPUTED;
			f->f_result = SLAPD_COMPARE_UNDEFINED;
			err = LDAP_SUCCESS;
			*filt = f;

		} else {
			free(f);
		}

	} else {
		*filt = f;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, DETAIL2, 
		"get_simple_vrFilter: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_simple_vrFilter %d\n", err, 0, 0 );
#endif
	return( err );
}

int
get_vrFilter( Connection *conn, BerElement *ber,
	ValuesReturnFilter **f,
	const char **text )
{
	/*
	 * A ValuesReturnFilter looks like this:
	 *
	 *	ValuesReturnFilter ::= SEQUENCE OF SimpleFilterItem
	 *      SimpleFilterItem ::= CHOICE {
	 *              equalityMatch   [3]     AttributeValueAssertion,
	 *              substrings      [4]     SubstringFilter,
	 *              greaterOrEqual  [5]     AttributeValueAssertion,
	 *              lessOrEqual     [6]     AttributeValueAssertion,
	 *              present         [7]     AttributeType,
	 *              approxMatch     [8]     AttributeValueAssertion,
	 *		extensibleMatch [9]	SimpleMatchingAssertion -- LDAPv3
	 *      }
	 *
	 *      SubstringFilter ::= SEQUENCE {
	 *              type               AttributeType,
	 *              SEQUENCE OF CHOICE {
	 *                      initial          [0] IA5String,
	 *                      any              [1] IA5String,
	 *                      final            [2] IA5String
	 *              }
	 *      }
	 *
	 *	SimpleMatchingAssertion ::= SEQUENCE {	-- LDAPv3
	 *		matchingRule    [1] MatchingRuleId OPTIONAL,
	 *		type            [2] AttributeDescription OPTIONAL,
	 *		matchValue      [3] AssertionValue }
	 */

	ValuesReturnFilter **new;
	ber_tag_t	tag;
	ber_len_t	len;
	char		*last;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_vrFilter: conn %d start\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_vrFilter\n", 0, 0, 0 );
#endif

	tag = ber_peek_tag( ber, &len );

	if( tag == LBER_ERROR ) {
		*text = "error decoding vrFilter";
		return SLAPD_DISCONNECT;
	}

	if( tag != LBER_SEQUENCE ) {
		*text = "error decoding vrFilter, expect SEQUENCE tag";
		return SLAPD_DISCONNECT;
	}

	new = f;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
	{
		int err = get_simple_vrFilter( conn, ber, new, text );
		if ( err != LDAP_SUCCESS )
			return( err );
		new = &(*new)->f_next;
	}
	*new = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_vrFilter: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_vrFilter\n", 0, 0, 0 );
#endif
	return( LDAP_SUCCESS );
}

void
vrFilter_free( ValuesReturnFilter *f )
{
	ValuesReturnFilter	*p, *next;

	if ( f == NULL ) {
		return;
	}

	for ( p = f; p != NULL; p = next ) {
		next = p->f_next;

		switch ( f->f_choice ) {
		case LDAP_FILTER_PRESENT:
			break;

		case LDAP_FILTER_EQUALITY:
		case LDAP_FILTER_GE:
		case LDAP_FILTER_LE:
		case LDAP_FILTER_APPROX:
			ava_free( f->f_ava, 1 );
			break;

		case LDAP_FILTER_SUBSTRINGS:
			if ( f->f_sub_initial.bv_val != NULL ) {
				free( f->f_sub_initial.bv_val );
			}
			ber_bvarray_free( f->f_sub_any );
			if ( f->f_sub_final.bv_val != NULL ) {
				free( f->f_sub_final.bv_val );
			}
			ch_free( f->f_sub );
			break;

		case LDAP_FILTER_EXT:
			mra_free( f->f_mra, 1 );
			break;

		case SLAPD_FILTER_COMPUTED:
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, ERR, 
				"filter_free: unknown filter type %lu\n", f->f_choice, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "filter_free: unknown filter type=%lu\n",
				f->f_choice, 0, 0 );
#endif
			break;
		}

		free( f );
	}
}


void
vrFilter2bv( ValuesReturnFilter *f, struct berval *fstr )
{
	ValuesReturnFilter	*p;
	struct berval tmp;
	ber_len_t len;

	if ( f == NULL ) {
		ber_str2bv( "No filter!", sizeof("No filter!")-1, 1, fstr );
		return;
	}

	fstr->bv_len = sizeof("()") - 1;
	fstr->bv_val = malloc( fstr->bv_len + 128 );

	snprintf( fstr->bv_val, fstr->bv_len + 1, "()");

	for ( p = f; p != NULL; p = p->f_next ) {
		len = fstr->bv_len;

		simple_vrFilter2bv( p, &tmp );
			
		fstr->bv_len += tmp.bv_len;
		fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

		snprintf( &fstr->bv_val[len-1], tmp.bv_len + 2, 
			/*"("*/ "%s)", tmp.bv_val );

		ch_free( tmp.bv_val );
	}
}

static void
simple_vrFilter2bv( ValuesReturnFilter *f, struct berval *fstr )
{
	struct berval tmp;
	ber_len_t len;

	if ( f == NULL ) {
		ber_str2bv( "No filter!", sizeof("No filter!")-1, 1, fstr );
		return;
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_GE:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(>=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s>=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_LE:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(<=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s<=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );

		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_APPROX:
		filter_escape_value( &f->f_av_value, &tmp );

		fstr->bv_len = f->f_av_desc->ad_cname.bv_len +
			tmp.bv_len + ( sizeof("(~=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s~=%s)",
			f->f_av_desc->ad_cname.bv_val,
			tmp.bv_val );
		ber_memfree( tmp.bv_val );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		fstr->bv_len = f->f_sub_desc->ad_cname.bv_len +
			( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 128 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			f->f_sub_desc->ad_cname.bv_val );

		if ( f->f_sub_initial.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_initial, &tmp );

			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-2], tmp.bv_len+3,
				/* "(attr=" */ "%s*)",
				tmp.bv_val );

			ber_memfree( tmp.bv_val );
		}

		if ( f->f_sub_any != NULL ) {
			int i;
			for ( i = 0; f->f_sub_any[i].bv_val != NULL; i++ ) {
				len = fstr->bv_len;
				filter_escape_value( &f->f_sub_any[i], &tmp );

				fstr->bv_len += tmp.bv_len + 1;
				fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

				snprintf( &fstr->bv_val[len-1], tmp.bv_len+3,
					/* "(attr=[init]*[any*]" */ "%s*)",
					tmp.bv_val );
				ber_memfree( tmp.bv_val );
			}
		}

		if ( f->f_sub_final.bv_val != NULL ) {
			len = fstr->bv_len;

			filter_escape_value( &f->f_sub_final, &tmp );

			fstr->bv_len += tmp.bv_len;
			fstr->bv_val = ch_realloc( fstr->bv_val, fstr->bv_len + 1 );

			snprintf( &fstr->bv_val[len-1], tmp.bv_len+3,
				/* "(attr=[init*][any*]" */ "%s)",
				tmp.bv_val );

			ber_memfree( tmp.bv_val );
		}

		break;

	case LDAP_FILTER_PRESENT:
		fstr->bv_len = f->f_desc->ad_cname.bv_len +
			( sizeof("(=*)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s=*)",
			f->f_desc->ad_cname.bv_val );
		break;

	case LDAP_FILTER_EXT:
		filter_escape_value( &f->f_mr_value, &tmp );

#ifndef SLAP_X_MRA_MATCH_DNATTRS
		fstr->bv_len = f->f_mr_desc->ad_cname.bv_len +
			( f->f_mr_dnattrs ? sizeof(":dn")-1 : 0 ) +
			( f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_len+1 : 0 ) +
			tmp.bv_len + ( sizeof("(:=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s%s%s%s:=%s)",
			f->f_mr_desc->ad_cname.bv_val,
			f->f_mr_dnattrs ? ":dn" : "",
			f->f_mr_rule_text.bv_len ? ":" : "",
			f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_val : "",
			tmp.bv_val );
#else /* SLAP_X_MRA_MATCH_DNATTRS */
		{
		struct berval ad;

		if ( f->f_mr_desc ) {
			ad = f->f_mr_desc->ad_cname;
		} else {
			ad.bv_len = 0;
			ad.bv_val = "";
		}
			
		fstr->bv_len = ad.bv_len +
			( f->f_mr_dnattrs ? sizeof(":dn")-1 : 0 ) +
			( f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_len+1 : 0 ) +
			tmp.bv_len + ( sizeof("(:=)") - 1 );
		fstr->bv_val = malloc( fstr->bv_len + 1 );

		snprintf( fstr->bv_val, fstr->bv_len + 1, "(%s%s%s%s:=%s)",
			ad.bv_val,
			f->f_mr_dnattrs ? ":dn" : "",
			f->f_mr_rule_text.bv_len ? ":" : "",
			f->f_mr_rule_text.bv_len ? f->f_mr_rule_text.bv_val : "",
			tmp.bv_val );
		}
#endif /* SLAP_X_MRA_MATCH_DNATTRS */

		ber_memfree( tmp.bv_val );
		break;

	case SLAPD_FILTER_COMPUTED:
		ber_str2bv(
			f->f_result == LDAP_COMPARE_FALSE ? "(?=false)" :
			f->f_result == LDAP_COMPARE_TRUE ? "(?=true)" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "(?=undefined)" :
			"(?=error)",
			f->f_result == LDAP_COMPARE_FALSE ? sizeof("(?=false)")-1 :
			f->f_result == LDAP_COMPARE_TRUE ? sizeof("(?=true)")-1 :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? sizeof("(?=undefined)")-1 :
			sizeof("(?=error)")-1,
			1, fstr );
		break;

	default:
		ber_str2bv( "(?=unknown)", sizeof("(?=unknown)")-1, 1, fstr );
		break;
	}
}

static int
get_substring_vrFilter(
	Connection	*conn,
	BerElement	*ber,
	ValuesReturnFilter	*f,
	const char	**text )
{
	ber_tag_t	tag;
	ber_len_t	len;
	ber_tag_t	rc;
	struct berval value;
	char		*last;
	struct berval bv;
	*text = "error decoding filter";

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_substring_filter: conn %d  begin\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "begin get_substring_filter\n", 0, 0, 0 );
#endif
	if ( ber_scanf( ber, "{m" /*}*/, &bv ) == LBER_ERROR ) {
		return SLAPD_DISCONNECT;
	}

	f->f_sub = ch_calloc( 1, sizeof(SubstringsAssertion) );
	f->f_sub_desc = NULL;
	rc = slap_bv2ad( &bv, &f->f_sub_desc, text );

	if( rc != LDAP_SUCCESS ) {
		text = NULL;
		ch_free( f->f_sub );
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		return LDAP_SUCCESS;
	}

	f->f_sub_initial.bv_val = NULL;
	f->f_sub_any = NULL;
	f->f_sub_final.bv_val = NULL;

	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
	{
		unsigned usage;

		rc = ber_scanf( ber, "m", &value );
		if ( rc == LBER_ERROR ) {
			rc = SLAPD_DISCONNECT;
			goto return_error;
		}

		if ( value.bv_val == NULL || value.bv_len == 0 ) {
			rc = LDAP_INVALID_SYNTAX;
			goto return_error;
		} 

		switch ( tag ) {
		case LDAP_SUBSTRING_INITIAL:
			usage = SLAP_MR_SUBSTR_INITIAL;
			break;

		case LDAP_SUBSTRING_ANY:
			usage = SLAP_MR_SUBSTR_ANY;
			break;

		case LDAP_SUBSTRING_FINAL:
			usage = SLAP_MR_SUBSTR_FINAL;
			break;

		default:
			rc = LDAP_PROTOCOL_ERROR;

#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, ERR, 
				"get_filter_substring: conn %d  unknown substring choice=%ld\n",
				conn->c_connid, (long)tag, 0 );
#else
			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring choice=%ld\n",
				(long) tag, 0, 0 );
#endif
			goto return_error;
		}

		/* valiate using equality matching rule validator! */
		rc = value_validate( f->f_sub_desc->ad_type->sat_equality,
			&value, text );
		if( rc != LDAP_SUCCESS ) {
			goto return_error;
		}

		rc = value_normalize( f->f_sub_desc, usage,
			&value, &bv, text );
		if( rc != LDAP_SUCCESS ) {
			goto return_error;
		}

		value = bv;

		rc = LDAP_PROTOCOL_ERROR;

		switch ( tag ) {
		case LDAP_SUBSTRING_INITIAL:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1, 
				"get_substring_filter: conn %d  INITIAL\n", 
				conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  INITIAL\n", 0, 0, 0 );
#endif

			if ( f->f_sub_initial.bv_val != NULL
				|| f->f_sub_any != NULL 
				|| f->f_sub_final.bv_val != NULL )
			{
				free( value.bv_val );
				goto return_error;
			}

			f->f_sub_initial = value;
			break;

		case LDAP_SUBSTRING_ANY:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1, 
				"get_substring_filter: conn %d  ANY\n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  ANY\n", 0, 0, 0 );
#endif

			if ( f->f_sub_final.bv_val != NULL ) {
				free( value.bv_val );
				goto return_error;
			}

			ber_bvarray_add( &f->f_sub_any, &value );
			break;

		case LDAP_SUBSTRING_FINAL:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, DETAIL1, 
				"get_substring_filter: conn %d  FINAL\n", conn->c_connid, 0, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  FINAL\n", 0, 0, 0 );
#endif

			if ( f->f_sub_final.bv_val != NULL ) {
				free( value.bv_val );
				goto return_error;
			}

			f->f_sub_final = value;
			break;

		default:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, INFO, 
				"get_substring_filter: conn %d  unknown substring type %ld\n",
				conn->c_connid, (long)tag, 0 );
#else
			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring type=%ld\n",
				(long) tag, 0, 0 );
#endif

			free( value.bv_val );

return_error:
#ifdef NEW_LOGGING
			LDAP_LOG( FILTER, INFO, 
				"get_substring_filter: conn %d  error %ld\n",
				conn->c_connid, (long)rc, 0 );
#else
			Debug( LDAP_DEBUG_FILTER, "  error=%ld\n",
				(long) rc, 0, 0 );
#endif
			free( f->f_sub_initial.bv_val );
			ber_bvarray_free( f->f_sub_any );
			free( f->f_sub_final.bv_val );
			ch_free( f->f_sub );
			return rc;
		}
	}

#ifdef NEW_LOGGING
	LDAP_LOG( FILTER, ENTRY, 
		"get_substring_filter: conn %d exit\n", conn->c_connid, 0, 0 );
#else
	Debug( LDAP_DEBUG_FILTER, "end get_substring_filter\n", 0, 0, 0 );
#endif
	return( LDAP_SUCCESS );
}

#ifdef SLAP_X_FILTER_HASSUBORDINATES
static int filter_has_subordinates_list(
	Filter		*filter );

/*
 * FIXME: we could detect the need to filter
 * for hasSubordinates when parsing the filter ...
 */

static int
filter_has_subordinates_list(
	Filter		*fl )
{
	Filter			*f;

	for ( f = fl; f != NULL; f = f->f_next ) {
		int	rc;

		rc = filter_has_subordinates( f );

		if ( rc ) {
			return rc;
		}
	}

	return 0;
}

int
filter_has_subordinates(
	Filter		*f )
{
	AttributeDescription	*ad = NULL;

	switch ( f->f_choice ) {
	case LDAP_FILTER_PRESENT:
		ad = f->f_desc;
		break;

	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_APPROX:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
		ad = f->f_ava->aa_desc;
		break;

	case LDAP_FILTER_SUBSTRINGS:
		ad = f->f_sub_desc;
		break;

	case LDAP_FILTER_EXT:
		/* could be null; however here it is harmless */
		ad = f->f_mra->ma_desc;
		break;

	case LDAP_FILTER_NOT:
		return filter_has_subordinates( f->f_not );

	case LDAP_FILTER_AND:
		return filter_has_subordinates_list( f->f_and );

	case LDAP_FILTER_OR:
		return filter_has_subordinates_list( f->f_or );

	case SLAPD_FILTER_COMPUTED:
		/*
		 * something wrong?
		 */
		return 0;

	default:
		/*
		 * this means a new type of filter has been implemented,
		 * which is not handled yet in this function; we should
		 * issue a developer's warning, e.g. an assertion
		 */
		assert( 0 );
		return -1;
	}

	if ( ad == slap_schema.si_ad_hasSubordinates ) {
		return 1;
	}

	return 0;
}

#endif /* SLAP_X_FILTER_HASSUBORDINATES */

