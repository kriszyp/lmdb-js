/* filter.c - routines for parsing and dealing with filters */
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

static int	get_filter_list(
	Connection *conn,
	BerElement *ber,
	Filter **f,
	char **fstr,
	const char **text );

static int	get_substring_filter(
	Connection *conn,
	BerElement *ber,
	Filter *f,
	char **fstr,
	const char **text );

static int filter_escape_value(
	struct berval *in,
	struct berval *out );

int
get_filter(
	Connection *conn,
	BerElement *ber,
	Filter **filt,
	char **fstr,
	const char **text )
{
	ber_tag_t	tag;
	ber_len_t	len;
	int		err;
	Filter		*f;
	char		*ftmp = NULL;
	struct berval escaped;

	Debug( LDAP_DEBUG_FILTER, "begin get_filter\n", 0, 0, 0 );

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
	 *		extensibleMatch [9] MatchingRuleAssertion
	 *	}
	 *
	 *	SubstringFilter ::= SEQUENCE {
	 *		type               AttributeType,
	 *		SEQUENCE OF CHOICE {
	 *			initial          [0] IA5String,
	 *			any              [1] IA5String,
	 *			final            [2] IA5String
	 *		}
	 *	}
	 *
     *  MatchingRuleAssertion ::= SEQUENCE {
     *          matchingRule    [1] MatchingRuleId OPTIONAL,
     *          type            [2] AttributeDescription OPTIONAL,
     *          matchValue      [3] AssertionValue,
     *          dnAttributes    [4] BOOLEAN DEFAULT FALSE
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
	*fstr = NULL;
	f->f_choice = tag; 

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "EQUALITY\n", 0, 0, 0 );

		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_ava != NULL );

		filter_escape_value( f->f_av_value, &escaped );

		*fstr = ch_malloc( sizeof("(=)")
			+ f->f_av_desc->ad_cname->bv_len
			+ escaped.bv_len );

		sprintf( *fstr, "(%s=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );

		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "SUBSTRINGS\n", 0, 0, 0 );
		err = get_substring_filter( conn, ber, f, fstr, text );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "GE\n", 0, 0, 0 );

		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		filter_escape_value( f->f_av_value, &escaped );

		*fstr = ch_malloc( sizeof("(>=)")
			+ f->f_av_desc->ad_cname->bv_len
			+ escaped.bv_len );

		sprintf( *fstr, "(%s>=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );

		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "LE\n", 0, 0, 0 );

		err = get_ava( ber, &f->f_ava, SLAP_MR_ORDERING, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}


		filter_escape_value( f->f_av_value, &escaped );

		*fstr = ch_malloc( sizeof("(<=)")
			+ f->f_av_desc->ad_cname->bv_len
			+ escaped.bv_len );

		sprintf( *fstr, "(%s<=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );

		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_PRESENT: {
		struct berval type;

		Debug( LDAP_DEBUG_FILTER, "PRESENT\n", 0, 0, 0 );

		if ( ber_scanf( ber, "o", &type ) == LBER_ERROR ) {
			err = SLAPD_DISCONNECT;
			*text = "error decoding filter";
			break;
		}

		f->f_desc = NULL;
		err = slap_bv2ad( &type, &f->f_desc, text );

		if( err != LDAP_SUCCESS ) {
			ch_free( type.bv_val );
			break;
		}

		ch_free( type.bv_val );

		*fstr = ch_malloc( sizeof("(=*)")
			+ f->f_desc->ad_cname->bv_len );
		sprintf( *fstr, "(%s=*)",
			f->f_desc->ad_cname->bv_val );

		} break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "APPROX\n", 0, 0, 0 );

		err = get_ava( ber, &f->f_ava, SLAP_MR_EQUALITY_APPROX, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		filter_escape_value( f->f_av_value, &escaped );

		*fstr = ch_malloc( sizeof("(~=)")
			+ f->f_av_desc->ad_cname->bv_len
			+ escaped.bv_len );

		sprintf( *fstr, "(%s~=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );

		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "AND\n", 0, 0, 0 );
		err = get_filter_list( conn, ber, &f->f_and, &ftmp, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		*fstr = ch_malloc( sizeof("(&)")
			+ ( ftmp == NULL ? 0 : strlen( ftmp ) ) );
		sprintf( *fstr, "(&%s)",
			ftmp == NULL ? "" : ftmp );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "OR\n", 0, 0, 0 );
		err = get_filter_list( conn, ber, &f->f_and, &ftmp, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		*fstr = ch_malloc( sizeof("(!)")
			+ ( ftmp == NULL ? 0 : strlen( ftmp ) ) );
		sprintf( *fstr, "(|%s)",
			ftmp == NULL ? "" : ftmp );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "NOT\n", 0, 0, 0 );
		(void) ber_skip_tag( ber, &len );
		err = get_filter( conn, ber, &f->f_not, &ftmp, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}
		*fstr = ch_malloc( sizeof("(!)")
			+ ( ftmp == NULL ? 0 : strlen( ftmp ) ) );
		sprintf( *fstr, "(!%s)",
			ftmp == NULL ? "" : ftmp );
		break;

	case LDAP_FILTER_EXT:
		Debug( LDAP_DEBUG_FILTER, "EXTENSIBLE\n", 0, 0, 0 );

		err = get_mra( ber, &f->f_mra, text );
		if ( err != LDAP_SUCCESS ) {
			break;
		}

		assert( f->f_mra != NULL );

		filter_escape_value( f->f_mr_value, &escaped );

		*fstr = ch_malloc( sizeof("(:dn::=)")
			+ (f->f_mr_desc ? f->f_mr_desc->ad_cname->bv_len : 0)
			+ (f->f_mr_rule_text ? strlen(f->f_mr_rule_text) : 0)
			+ escaped.bv_len );

		sprintf( *fstr, "(%s%s%s%s:=%s)",
			 (f->f_mr_desc ? f->f_mr_desc->ad_cname->bv_val : ""),
			 (f->f_mr_dnattrs ? ":dn" : ""),
			 (f->f_mr_rule_text ? ":" : ""),
			 (f->f_mr_rule_text ? f->f_mr_rule_text : ""),
			 escaped.bv_val );

		ber_memfree( escaped.bv_val );
		break;

	default:
		(void) ber_skip_tag( ber, &len );
		Debug( LDAP_DEBUG_ANY, "get_filter: unknown filter type=%lu\n",
		       f->f_choice, 0, 0 );
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		*fstr = ch_strdup( "(undefined)" );
		break;
	}

	free( ftmp );

	if ( err != LDAP_SUCCESS ) {
		if ( *fstr != NULL ) {
			free( *fstr );
		}

		if( err != SLAPD_DISCONNECT ) {
			/* ignore error */
			f->f_choice = SLAPD_FILTER_COMPUTED;
			f->f_result = SLAPD_COMPARE_UNDEFINED;
			*fstr = ch_strdup( "(badfilter)" );
			err = LDAP_SUCCESS;
			*filt = f;

		} else {
			free(f);
		}
	} else {
		*filt = f;
	}

	Debug( LDAP_DEBUG_FILTER, "end get_filter %d\n", err, 0, 0 );
	return( err );
}

static int
get_filter_list( Connection *conn, BerElement *ber,
	Filter **f, char **fstr,
	const char **text )
{
	Filter		**new;
	int		err;
	ber_tag_t	tag;
	ber_len_t	len;
	char		*last, *ftmp;

	Debug( LDAP_DEBUG_FILTER, "begin get_filter_list\n", 0, 0, 0 );

	*fstr = NULL;
	new = f;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		err = get_filter( conn, ber, new, &ftmp, text );
		if ( err != LDAP_SUCCESS )
			return( err );

		if ( *fstr == NULL ) {
			*fstr = ftmp;
		} else {
			*fstr = ch_realloc( *fstr, strlen( *fstr ) +
			    strlen( ftmp ) + 1 );
			strcat( *fstr, ftmp );
			free( ftmp );
		}
		new = &(*new)->f_next;
	}
	*new = NULL;

	Debug( LDAP_DEBUG_FILTER, "end get_filter_list\n", 0, 0, 0 );
	return( LDAP_SUCCESS );
}

static int
get_substring_filter(
    Connection	*conn,
    BerElement	*ber,
    Filter	*f,
    char	**fstr,
	const char	**text
)
{
	ber_tag_t	tag;
	ber_len_t	len;
	ber_tag_t	rc;
	struct berval *value;
	struct berval escaped;
	char		*last;
	struct berval type;
	struct berval *nvalue;
	*text = "error decoding filter";

	Debug( LDAP_DEBUG_FILTER, "begin get_substring_filter\n", 0, 0, 0 );

	if ( ber_scanf( ber, "{o" /*}*/, &type ) == LBER_ERROR ) {
		return SLAPD_DISCONNECT;
	}

	f->f_sub = ch_calloc( 1, sizeof(SubstringsAssertion) );
	f->f_sub_desc = NULL;
	rc = slap_bv2ad( &type, &f->f_sub_desc, text );

	ch_free( type.bv_val );

	if( rc != LDAP_SUCCESS ) {
		text = NULL;
		ch_free( f->f_sub );
		f->f_choice = SLAPD_FILTER_COMPUTED;
		f->f_result = SLAPD_COMPARE_UNDEFINED;
		*fstr = ch_strdup( "(undefined)" );
		return LDAP_SUCCESS;
	}

	f->f_sub_initial = NULL;
	f->f_sub_any = NULL;
	f->f_sub_final = NULL;

	if( fstr ) {
		*fstr = ch_malloc( sizeof("(=" /*)*/) +
			f->f_sub_desc->ad_cname->bv_len );
		sprintf( *fstr, "(%s=" /*)*/, f->f_sub_desc->ad_cname->bv_val );
	}

	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		unsigned usage;

		rc = ber_scanf( ber, "O", &value );
		if ( rc == LBER_ERROR ) {
			rc = SLAPD_DISCONNECT;
			goto return_error;
		}

		if ( value == NULL || value->bv_len == 0 ) {
			ber_bvfree( value );
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

			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring choice=%ld\n",
				(long) tag, 0, 0 );

			ber_bvfree( value );
			goto return_error;
		}

		rc = value_normalize( f->f_sub_desc, usage, value, &nvalue, text );
		ber_bvfree( value );

		if( rc != LDAP_SUCCESS ) {
			goto return_error;
		}

		value = nvalue;

		rc = LDAP_PROTOCOL_ERROR;

		switch ( tag ) {
		case LDAP_SUBSTRING_INITIAL:
			Debug( LDAP_DEBUG_FILTER, "  INITIAL\n", 0, 0, 0 );
			if ( f->f_sub_initial != NULL ) {
				ber_bvfree( value );
				goto return_error;
			}

			f->f_sub_initial = value;

			if( fstr ) {
				filter_escape_value( value, &escaped );
				*fstr = ch_realloc( *fstr,
					strlen( *fstr ) + escaped.bv_len + 1 );
				strcat( *fstr, escaped.bv_val );
				ber_memfree( escaped.bv_val );
			}
			break;

		case LDAP_SUBSTRING_ANY:
			Debug( LDAP_DEBUG_FILTER, "  ANY\n", 0, 0, 0 );
			if( ber_bvecadd( &f->f_sub_any, value ) < 0 ) {
				ber_bvfree( value );
				goto return_error;
			}

			if( fstr ) {
				filter_escape_value( value, &escaped );
				*fstr = ch_realloc( *fstr,
					strlen( *fstr ) + escaped.bv_len + 2 );
				strcat( *fstr, "*" );
				strcat( *fstr, escaped.bv_val );
				ber_memfree( escaped.bv_val );
			}
			break;

		case LDAP_SUBSTRING_FINAL:
			Debug( LDAP_DEBUG_FILTER, "  FINAL\n", 0, 0, 0 );
			if ( f->f_sub_final != NULL ) {
				ber_bvfree( value );
				goto return_error;
			}
			f->f_sub_final = value;

			if( fstr ) {
				filter_escape_value( value, &escaped );
				*fstr = ch_realloc( *fstr,
					strlen( *fstr ) + escaped.bv_len + 2 );
				strcat( *fstr, "*" );
				strcat( *fstr, escaped.bv_val );
				ber_memfree( escaped.bv_val );
			}
			break;

		default:
			Debug( LDAP_DEBUG_FILTER,
				"  unknown substring type=%ld\n",
				(long) tag, 0, 0 );

			ber_bvfree( value );

return_error:
			Debug( LDAP_DEBUG_FILTER, "  error=%ld\n",
				(long) rc, 0, 0 );

			if( fstr ) {
				free( *fstr );
				*fstr = NULL;
			}

			ad_free( f->f_sub_desc, 1 );
			ber_bvfree( f->f_sub_initial );
			ber_bvecfree( f->f_sub_any );
			ber_bvfree( f->f_sub_final );
			ch_free( f->f_sub );
			return rc;
		}
	}

	if( fstr ) {
		*fstr = ch_realloc( *fstr, strlen( *fstr ) + 3 );
		if ( f->f_sub_final == NULL ) {
			strcat( *fstr, "*" );
		}
		strcat( *fstr, /*(*/ ")" );
	}

	Debug( LDAP_DEBUG_FILTER, "end get_substring_filter\n", 0, 0, 0 );
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
		ad_free( f->f_desc, 1 );
		break;

	case LDAP_FILTER_EQUALITY:
	case LDAP_FILTER_GE:
	case LDAP_FILTER_LE:
	case LDAP_FILTER_APPROX:
		ava_free( f->f_ava, 1 );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		ad_free( f->f_sub_desc, 1 );
		if ( f->f_sub_initial != NULL ) {
			ber_bvfree( f->f_sub_initial );
		}
		ber_bvecfree( f->f_sub_any );
		if ( f->f_sub_final != NULL ) {
			ber_bvfree( f->f_sub_final );
		}
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		for ( p = f->f_list; p != NULL; p = next ) {
			next = p->f_next;
			filter_free( p );
		}
		break;

	case SLAPD_FILTER_COMPUTED:
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "filter_free: unknown filter type=%lu\n",
		       f->f_choice, 0, 0 );
		break;
	}

	free( f );
}

#ifdef LDAP_DEBUG
void
filter_print( Filter *f )
{
	int	i;
	Filter	*p;
	struct berval escaped;

	if ( f == NULL ) {
		fprintf( stderr, "No filter!" );
	}

	switch ( f->f_choice ) {
	case LDAP_FILTER_EQUALITY:
		filter_escape_value( f->f_av_value, &escaped );
		fprintf( stderr, "(%s=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );
		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_GE:
		filter_escape_value( f->f_av_value, &escaped );
		fprintf( stderr, "(%s>=%s)",
			f->f_av_desc->ad_cname->bv_val,
		    escaped.bv_val );
		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_LE:
		filter_escape_value( f->f_av_value, &escaped );
		fprintf( stderr, "(%s<=%s)",
			f->f_ava->aa_desc->ad_cname->bv_val,
		    escaped.bv_val );
		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_APPROX:
		filter_escape_value( f->f_av_value, &escaped );
		fprintf( stderr, "(%s~=%s)",
			f->f_ava->aa_desc->ad_cname->bv_val,
		    escaped.bv_val );
		ber_memfree( escaped.bv_val );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		fprintf( stderr, "(%s=" /*)*/,
			f->f_sub_desc->ad_cname->bv_val );
		if ( f->f_sub_initial != NULL ) {
			filter_escape_value( f->f_sub_initial, &escaped );
			fprintf( stderr, "%s",
				escaped.bv_val );
			ber_memfree( escaped.bv_val );
		}
		if ( f->f_sub_any != NULL ) {
			for ( i = 0; f->f_sub_any[i] != NULL; i++ ) {
				filter_escape_value( f->f_sub_any[i], &escaped );
				fprintf( stderr, "*%s",
					escaped.bv_val );
				ber_memfree( escaped.bv_val );
			}
		}
		if ( f->f_sub_final != NULL ) {
			filter_escape_value( f->f_sub_final, &escaped );
			fprintf( stderr,
				"*%s", escaped.bv_val );
			ber_memfree( escaped.bv_val );
		}
		fprintf( stderr, /*(*/ ")" );
		break;

	case LDAP_FILTER_PRESENT:
		fprintf( stderr, "(%s=*)",
			f->f_desc->ad_cname->bv_val );
		break;

	case LDAP_FILTER_AND:
	case LDAP_FILTER_OR:
	case LDAP_FILTER_NOT:
		fprintf( stderr, "(%c" /*)*/,
			f->f_choice == LDAP_FILTER_AND ? '&' :
		    f->f_choice == LDAP_FILTER_OR ? '|' : '!' );
		for ( p = f->f_list; p != NULL; p = p->f_next ) {
			filter_print( p );
		}
		fprintf( stderr, /*(*/ ")" );
		break;

	case SLAPD_FILTER_COMPUTED:
		fprintf( stderr, "(?=%s)",
			f->f_result == LDAP_COMPARE_FALSE ? "false" :
			f->f_result == LDAP_COMPARE_TRUE ? "true" :
			f->f_result == SLAPD_COMPARE_UNDEFINED ? "undefined" :
			"error" );
		break;

	default:
		fprintf( stderr, "(unknown-filter=%lu)", f->f_choice );
		break;
	}
}

#endif /* ldap_debug */

int filter_escape_value(
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
