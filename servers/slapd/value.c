/* value.c - routines for dealing with values */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include <sys/stat.h>

#include "slap.h"

int
value_add_fast( 
    struct berval	***vals,
    struct berval	**addvals,
    int			nvals,
    int			naddvals,
    int			*maxvals
)
{
	int	need, i, j;

	if ( *maxvals == 0 ) {
		*maxvals = 1;
	}
	need = nvals + naddvals + 1;
	while ( *maxvals < need ) {
		*maxvals *= 2;
		*vals = (struct berval **) ch_realloc( (char *) *vals,
		    *maxvals * sizeof(struct berval *) );
	}

	for ( i = 0, j = 0; i < naddvals; i++, j++ ) {
		if ( addvals[i]->bv_len > 0 ) {
			(*vals)[nvals + j] = ber_bvdup( addvals[i] );
		}
	}
	(*vals)[nvals + j] = NULL;

	return( 0 );
}

int
value_add( 
    struct berval	***vals,
    struct berval	**addvals
)
{
	int	n, nn, i, j;

	for ( nn = 0; addvals != NULL && addvals[nn] != NULL; nn++ )
		;	/* NULL */

	if ( *vals == NULL ) {
		*vals = (struct berval **) ch_malloc( (nn + 1)
		    * sizeof(struct berval *) );
		n = 0;
	} else {
		for ( n = 0; (*vals)[n] != NULL; n++ )
			;	/* NULL */
		*vals = (struct berval **) ch_realloc( (char *) *vals,
		    (n + nn + 1) * sizeof(struct berval *) );
	}

	for ( i = 0, j = 0; i < nn; i++ ) {
		if ( addvals[i]->bv_len > 0 ) {
			(*vals)[n + j++] = ber_bvdup( addvals[i] );
		}
	}
	(*vals)[n + j] = NULL;

	return( 0 );
}

void
value_normalize(
    char	*s,
    int		syntax
)
{
	char	*d;

	if ( syntax & SYNTAX_DN ) {
		(void) dn_normalize_case( s );
		return;
	}
	if ( ! (syntax & SYNTAX_CIS) ) {
		return;
	}

	for ( d = s; *s; s++ ) {
		if ( (syntax & SYNTAX_TEL) && (*s == ' ' || *s == '-') ) {
			continue;
		}
		*d++ = TOUPPER( (unsigned char) *s );
	}
	*d = '\0';
}

int
value_cmp(
    struct berval	*v1,
    struct berval	*v2,
    int			syntax,
    int			normalize	/* 1 => arg 1; 2 => arg 2; 3 => both */
)
{
	int		rc;
	unsigned char	*s1, *s2;

	if ( syntax & SYNTAX_DN )	/* #### TEST ### */
		normalize = 3;

    if ( normalize ) {
	if ( ! (syntax & ~(SYNTAX_CIS | SYNTAX_CES | SYNTAX_BIN)) )
		/* Normalization not needed,
		 * in SYNTAX_CIS's case because it's handled by strcascmp */
		normalize = 0;
	if ( normalize & 1 ) {
		v1 = ber_bvdup( v1 );
		value_normalize( v1->bv_val, syntax );
	}
	if ( normalize & 2 ) {
		v2 = ber_bvdup( v2 );
		value_normalize( v2->bv_val, syntax );
	}
    }

	switch ( syntax ) {
	case SYNTAX_CIS:
	case (SYNTAX_CIS | SYNTAX_TEL):
		rc = strcasecmp( v1->bv_val, v2->bv_val );
		break;

	case SYNTAX_DN:
	case SYNTAX_CES:
		rc = strcmp( v1->bv_val, v2->bv_val );
		break;

	default:
		Debug( LDAP_DEBUG_ANY, "value_cmp: unknown syntax %d.\n", syntax, 0, 0);
		/* Fall through */
	case SYNTAX_BIN:
		rc = (v1->bv_len == v2->bv_len
		      ? memcmp( v1->bv_val, v2->bv_val, v1->bv_len )
		      : v1->bv_len > v2->bv_len ? 1 : -1);
		break;
	}

	if ( normalize & 1 ) {
		ber_bvfree( v1 );
	}
	if ( normalize & 2 ) {
		ber_bvfree( v2 );
	}

	return( rc );
}

int
value_find(
    struct berval	**vals,
    struct berval	*v,
    int			syntax,
    int			normalize
)
{
	int	i;

	for ( i = 0; vals[i] != NULL; i++ ) {
		if ( value_cmp( vals[i], v, syntax, normalize ) == 0 ) {
			return( 0 );
		}
	}

	return( 1 );
}
