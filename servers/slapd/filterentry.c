/* filterentry.c - apply a filter to an entry */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/regex.h>

#include "slap.h"

static int	test_filter_list(Backend *be, Connection *conn, Operation *op, Entry *e, Filter *flist, int ftype);
static int	test_substring_filter(Backend *be, Connection *conn, Operation *op, Entry *e, Filter *f);
static int	test_ava_filter(Backend *be, Connection *conn, Operation *op, Entry *e, Ava *ava, int type);
static int	test_approx_filter(Backend *be, Connection *conn, Operation *op, Entry *e, Ava *ava);
static int	test_presence_filter(Backend *be, Connection *conn, Operation *op, Entry *e, char *type);

/*
 * test_filter - test a filter against a single entry.
 * returns	0	filter matched
 *		-1	filter did not match
 *		>0	an ldap error code
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
	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "    EQUALITY\n", 0, 0, 0 );
		rc = test_ava_filter( be, conn, op, e, &f->f_ava,
		    LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "    SUBSTRINGS\n", 0, 0, 0 );
		rc = test_substring_filter( be, conn, op, e, f );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "    GE\n", 0, 0, 0 );
		rc = test_ava_filter( be, conn, op, e, &f->f_ava,
		    LDAP_FILTER_GE );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "    LE\n", 0, 0, 0 );
		rc = test_ava_filter( be, conn, op, e, &f->f_ava,
		    LDAP_FILTER_LE );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "    PRESENT\n", 0, 0, 0 );
		rc = test_presence_filter( be, conn, op, e, f->f_type );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "    APPROX\n", 0, 0, 0 );
		rc = test_approx_filter( be, conn, op, e, &f->f_ava );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "    AND\n", 0, 0, 0 );
		rc = test_filter_list( be, conn, op, e, f->f_and,
		    LDAP_FILTER_AND );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "    OR\n", 0, 0, 0 );
		rc = test_filter_list( be, conn, op, e, f->f_or,
		    LDAP_FILTER_OR );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "    NOT\n", 0, 0, 0 );
		rc = (! test_filter( be, conn, op, e, f->f_not ) );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "    unknown filter type %lu\n",
		    f->f_choice, 0, 0 );
		rc = -1;
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
    Ava		*ava,
    int		type
)
{
	int		i, rc;
	Attribute	*a;

	if ( be != NULL && ! access_allowed( be, conn, op, e,
		ava->ava_type, &ava->ava_value, ACL_SEARCH ) )
	{
		return( -2 );
	}

	if ( (a = attr_find( e->e_attrs, ava->ava_type )) == NULL ) {
		return( -1 );
	}

#ifdef SLAPD_SCHEMA_COMPAT
	if ( a->a_syntax == 0 ) {
		a->a_syntax = attr_syntax( ava->ava_type );
	}
#endif

	for ( i = 0; a->a_vals[i] != NULL; i++ ) {
#ifdef SLAPD_SCHEMA_COMPAT
		rc = value_cmp( a->a_vals[i], &ava->ava_value, a->a_syntax,
		    3 );
#else
		rc = 0;
#endif

		switch ( type ) {
		case LDAP_FILTER_EQUALITY:
			if ( rc == 0 ) {
				return( 0 );
			}
			break;

		case LDAP_FILTER_GE:
			if ( rc >= 0 ) {
				return( 0 );
			}
			break;

		case LDAP_FILTER_LE:
			if ( rc <= 0 ) {
				return( 0 );
			}
			break;
		}
	}

	return( 1 );
}

static int
test_presence_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    char	*type
)
{
	if ( be != NULL && ! access_allowed( be, conn, op, e,
		type, NULL, ACL_SEARCH ) )
	{
		return( -2 );
	}

	return( attr_find( e->e_attrs, type ) != NULL ? 0 : -1 );
}

static int
test_approx_filter(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Ava		*ava
)
{
	char		*w1, *w2, *c1, *c2;
	int		i;
	Attribute	*a;

	if ( be != NULL && ! access_allowed( be, conn, op, e,
		ava->ava_type, NULL, ACL_SEARCH ) )
	{
		return( -2 );
	}

	if ( (a = attr_find( e->e_attrs, ava->ava_type )) == NULL ) {
		return( -1 );
	}

	/* for each value in the attribute */
	for ( i = 0; a->a_vals[i] != NULL; i++ ) {
		/*
		 * try to match words in the filter value in order
		 * in the attribute value.
		 */

		w2 = a->a_vals[i]->bv_val;
		/* for each word in the filter value */
		for ( w1 = first_word( ava->ava_value.bv_val ); w1 != NULL;
		    w1 = next_word( w1 ) ) {
			if ( (c1 = phonetic( w1 )) == NULL ) {
				break;
			}

			/*
			 * for each word in the attribute value from
			 * where we left off...
			 */
			for ( w2 = first_word( w2 ); w2 != NULL;
			    w2 = next_word( w2 ) ) {
				c2 = phonetic( w2 );
				if ( strcmp( c1, c2 ) == 0 ) {
					free( c2 );
					break;
				}
				free( c2 );
			}
			free( c1 );

			/*
			 * if we stopped because we ran out of words
			 * before making a match, go on to the next
			 * value.  otherwise try to keep matching
			 * words in this value from where we left off.
			 */
			if ( w2 == NULL ) {
				break;
			} else {
				w2 = next_word( w2 );
			}
		}
		/*
		 * if we stopped because we ran out of words we
		 * have a match.
		 */
		if ( w1 == NULL ) {
			return( 0 );
		}
	}

	return( 1 );
}

static int
test_filter_list(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Filter	*flist,
    int		ftype
)
{
	int	nomatch;
	Filter	*f;

	Debug( LDAP_DEBUG_FILTER, "=> test_filter_list\n", 0, 0, 0 );

	nomatch = 1;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( test_filter( be, conn, op, e, f ) != 0 ) {
			if ( ftype == LDAP_FILTER_AND ) {
				Debug( LDAP_DEBUG_FILTER,
				    "<= test_filter_list 1\n", 0, 0, 0 );
				return( 1 );
			}
		} else {
			nomatch = 0;
		}
	}

	Debug( LDAP_DEBUG_FILTER, "<= test_filter_list %d\n", nomatch, 0, 0 );
	return( nomatch );
}

static void
strcpy_regex( char *d, char *s )
{
	for ( ; *s; s++ ) {
		switch ( *s ) {
		case '^':
		case '.':
		case '[':
		case ']': /* ? */
		case '$':
		case '(':
		case ')': /* ? */
		case '|':
		case '*':
		case '+':
		case '?':
		case '{':
		case '}': /* ? */
		case '\\':
			*d++ = '\\';
			/* FALL */
		default:
			*d++ = *s;
		}
	}
	*d = '\0';
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
	int		i, rc;
	char		*p, *end, *realval, *tmp;
	char		pat[BUFSIZ];
	char		buf[BUFSIZ];
	struct berval	*val;
	regex_t		re;

	Debug( LDAP_DEBUG_FILTER, "begin test_substring_filter\n", 0, 0, 0 );

	if ( be != NULL && ! access_allowed( be, conn, op, e,
		f->f_sub_type, NULL, ACL_SEARCH ) )
	{
		return( -2 );
	}

	if ( (a = attr_find( e->e_attrs, f->f_sub_type )) == NULL ) {
		return( -1 );
	}

#ifdef SLAPD_SCHEMA_COMPAT
	if ( a->a_syntax & SYNTAX_BIN ) {
		Debug( LDAP_DEBUG_FILTER, "test_substring_filter bin attr\n",
		    0, 0, 0 );
		return( -1 );
	}
#endif

	/*
	 * construct a regular expression corresponding to the
	 * filter and let regex do the work
	 */

	pat[0] = '\0';
	p = pat;
	end = pat + sizeof(pat) - 2;	/* leave room for null */
	if ( f->f_sub_initial != NULL ) {
		strcpy( p, "^" );
		p = strchr( p, '\0' );
		/* 2 * in case every char is special */
		if ( p + 2 * f->f_sub_initial->bv_len > end ) {
			Debug( LDAP_DEBUG_ANY, "not enough pattern space\n",
			    0, 0, 0 );
			return( -1 );
		}
		strcpy_regex( p, f->f_sub_initial->bv_val );
		p = strchr( p, '\0' );
	}
	if ( f->f_sub_any != NULL ) {
		for ( i = 0; f->f_sub_any[i] != NULL; i++ ) {
			/* ".*" + value */
			if ( p + 2 * f->f_sub_any[i]->bv_len + 2 > end ) {
				Debug( LDAP_DEBUG_ANY,
				    "not enough pattern space\n", 0, 0, 0 );
				return( -1 );
			}
			strcpy( p, ".*" );
			p = strchr( p, '\0' );
			strcpy_regex( p, f->f_sub_any[i]->bv_val );
			p = strchr( p, '\0' );
		}
	}
	if ( f->f_sub_final != NULL ) {
		/* ".*" + value */
		if ( p + 2 * f->f_sub_final->bv_len + 2 > end ) {
			Debug( LDAP_DEBUG_ANY, "not enough pattern space\n",
			    0, 0, 0 );
			return( -1 );
		}
		strcpy( p, ".*" );
		p = strchr( p, '\0' );
		strcpy_regex( p, f->f_sub_final->bv_val );
		p = strchr( p, '\0' );
		strcpy( p, "$" );
	}

	/* compile the regex */
	Debug( LDAP_DEBUG_FILTER, "test_substring_filter: regcomp pat: %s\n",
		pat, 0, 0 );
	if ((rc = regcomp(&re, pat, REG_EXTENDED|REG_NOSUB))) {
		char error[512];

		regerror(rc, &re, error, sizeof(error));
		Debug( LDAP_DEBUG_ANY, "regcomp failed (%s) %s\n",
			p, error, 0 );
		return( -1 );
	}

	/* for each value in the attribute see if regex matches */
	for ( i = 0; a->a_vals[i] != NULL; i++ ) {
		val = a->a_vals[i];
		tmp = NULL;
		if ( val->bv_len < sizeof(buf) ) {
			strcpy( buf, val->bv_val );
			realval = buf;
		} else {
			tmp = (char *) ch_malloc( val->bv_len + 1 );
			strcpy( tmp, val->bv_val );
			realval = tmp;
		}

#ifdef SLAPD_SCHEMA_COMPAT
		value_normalize( realval, a->a_syntax );
#endif

		rc = !regexec(&re, realval, 0, NULL, 0);

		if ( tmp != NULL ) {
			free( tmp );
		}
		if ( rc == 1 ) {
			regfree(&re);
			return( 0 );
		}
	}

	regfree(&re);

	Debug( LDAP_DEBUG_FILTER, "end test_substring_filter 1\n", 0, 0, 0 );
	return( 1 );
}
