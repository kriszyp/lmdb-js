/* filterindex.c - generate the list of candidate entries from a filter */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"

static ID_BLOCK	*ava_candidates( BackendDB *be, Ava *ava, int type );
static ID_BLOCK	*presence_candidates( BackendDB *be, char *type );
static ID_BLOCK	*approx_candidates( BackendDB *be, Ava *ava );
static ID_BLOCK	*list_candidates( BackendDB *be, Filter *flist, int ftype );
static ID_BLOCK	*substring_candidates( BackendDB *be, Filter *f );
static ID_BLOCK	*substring_comp_candidates( BackendDB *be, char *type, char *val, int prepost );

ID_BLOCK *
bdb2i_filter_candidates(
    BackendDB	*be,
    Filter	*f
)
{
	ID_BLOCK	*result, *tmp1, *tmp2;

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_filter_candidates\n", 0, 0, 0 );

	result = NULL;
	switch ( f->f_choice ) {
	case SLAPD_FILTER_DN_ONE:
		Debug( LDAP_DEBUG_FILTER, "\tDN ONE\n", 0, 0, 0 );
		result = bdb2i_dn2idl( be, f->f_dn, DN_SUBTREE_PREFIX );
		break;

	case SLAPD_FILTER_DN_SUBTREE:
		Debug( LDAP_DEBUG_FILTER, "\tDN SUBTREE\n", 0, 0, 0 );
		result = bdb2i_dn2idl( be, f->f_dn, DN_SUBTREE_PREFIX );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_EQUALITY );
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		result = substring_candidates( be, f );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_GE );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		result = ava_candidates( be, &f->f_ava, LDAP_FILTER_LE );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		result = presence_candidates( be, f->f_type );
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
		result = approx_candidates( be, &f->f_ava );
		break;

	case LDAP_FILTER_AND:
		Debug( LDAP_DEBUG_FILTER, "\tAND\n", 0, 0, 0 );
		result = list_candidates( be, f->f_and, LDAP_FILTER_AND );
		break;

	case LDAP_FILTER_OR:
		Debug( LDAP_DEBUG_FILTER, "\tOR\n", 0, 0, 0 );
		result = list_candidates( be, f->f_or, LDAP_FILTER_OR );
		break;

	case LDAP_FILTER_NOT:
		Debug( LDAP_DEBUG_FILTER, "\tNOT\n", 0, 0, 0 );
		tmp1 = bdb2i_idl_allids( be );
		tmp2 = bdb2i_filter_candidates( be, f->f_not );
		result = bdb2i_idl_notin( be, tmp1, tmp2 );
		bdb2i_idl_free( tmp2 );
		bdb2i_idl_free( tmp1 );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_filter_candidates %ld\n",
	    result ? ID_BLOCK_NIDS(result) : 0, 0, 0 );
	return( result );
}

static ID_BLOCK *
ava_candidates(
    BackendDB	*be,
    Ava		*ava,
    int		type
)
{
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> ava_candidates 0x%x\n", type, 0, 0 );

	switch ( type ) {
	case LDAP_FILTER_EQUALITY:
		idl = bdb2i_index_read( be, ava->ava_type, INDEX_EQUALITY,
		    ava->ava_value.bv_val );
		break;

	case LDAP_FILTER_GE:
		idl = bdb2i_idl_allids( be );
		break;

	case LDAP_FILTER_LE:
		idl = bdb2i_idl_allids( be );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= ava_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
presence_candidates(
    BackendDB	*be,
    char	*type
)
{
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> presence_candidates\n", 0, 0, 0 );

	idl = bdb2i_index_read( be, type, INDEX_PRESENCE, "*" );

	Debug( LDAP_DEBUG_TRACE, "<= presence_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
approx_candidates(
    BackendDB	*be,
    Ava		*ava
)
{
	char	*w, *c;
	ID_BLOCK	*idl, *tmp;

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );

	idl = NULL;
	for ( w = first_word( ava->ava_value.bv_val ); w != NULL;
	    w = next_word( w ) ) {
		c = phonetic( w );
		if ( (tmp = bdb2i_index_read( be, ava->ava_type, INDEX_APPROX, c ))
		    == NULL ) {
			free( c );
			bdb2i_idl_free( idl );
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates NULL\n",
			    0, 0, 0 );
			return( NULL );
		}
		free( c );

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			idl = bdb2i_idl_intersection( be, idl, tmp );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
list_candidates(
    BackendDB	*be,
    Filter	*flist,
    int		ftype
)
{
	ID_BLOCK	*idl, *tmp, *tmp2;
	Filter	*f;

	Debug( LDAP_DEBUG_TRACE, "=> list_candidates 0x%x\n", ftype, 0, 0 );

	idl = NULL;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( (tmp = bdb2i_filter_candidates( be, f )) == NULL &&
		    ftype == LDAP_FILTER_AND ) {
				Debug( LDAP_DEBUG_TRACE,
				    "<= list_candidates NULL\n", 0, 0, 0 );
				bdb2i_idl_free( idl );
				return( NULL );
		}

		tmp2 = idl;
		if ( idl == NULL ) {
			idl = tmp;
		} else if ( ftype == LDAP_FILTER_AND ) {
			idl = bdb2i_idl_intersection( be, idl, tmp );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
		} else {
			idl = bdb2i_idl_union( be, idl, tmp );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= list_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
substring_candidates(
    BackendDB	*be,
    Filter	*f
)
{
	int	i;
	ID_BLOCK	*idl, *tmp, *tmp2;

	Debug( LDAP_DEBUG_TRACE, "=> substring_candidates\n", 0, 0, 0 );

	idl = NULL;

	/* initial */
	if ( f->f_sub_initial != NULL ) {
		if ( (int) strlen( f->f_sub_initial ) < SUBLEN - 1 ) {
			idl = bdb2i_idl_allids( be );
		} else if ( (idl = substring_comp_candidates( be, f->f_sub_type,
		    f->f_sub_initial, '^' )) == NULL ) {
			return( NULL );
		}
	}

	/* final */
	if ( f->f_sub_final != NULL ) {
		if ( (int) strlen( f->f_sub_final ) < SUBLEN - 1 ) {
			tmp = bdb2i_idl_allids( be );
		} else if ( (tmp = substring_comp_candidates( be, f->f_sub_type,
		    f->f_sub_final, '$' )) == NULL ) {
			bdb2i_idl_free( idl );
			return( NULL );
		}

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			tmp2 = idl;
			idl = bdb2i_idl_intersection( be, idl, tmp );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
		}
	}

	for ( i = 0; f->f_sub_any != NULL && f->f_sub_any[i] != NULL; i++ ) {
		if ( (int) strlen( f->f_sub_any[i] ) < SUBLEN ) {
			tmp = bdb2i_idl_allids( be );
		} else if ( (tmp = substring_comp_candidates( be, f->f_sub_type,
		    f->f_sub_any[i], 0 )) == NULL ) {
			bdb2i_idl_free( idl );
			return( NULL );
		}

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			tmp2 = idl;
			idl = bdb2i_idl_intersection( be, idl, tmp );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= substring_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
substring_comp_candidates(
    BackendDB	*be,
    char	*type,
    char	*val,
    int		prepost
)
{
	int	i, len;
	ID_BLOCK	*idl, *tmp, *tmp2;
	char	*p;
	char	buf[SUBLEN + 1];

	Debug( LDAP_DEBUG_TRACE, "=> substring_comp_candidates\n", 0, 0, 0 );

	len = strlen( val );
	idl = NULL;

	/* prepend ^ for initial substring */
	if ( prepost == '^' ) {
		buf[0] = '^';
		for ( i = 0; i < SUBLEN - 1; i++ ) {
			buf[i + 1] = val[i];
		}
		buf[SUBLEN] = '\0';

		if ( (idl = bdb2i_index_read( be, type, INDEX_SUB, buf )) == NULL ) {
			return( NULL );
		}
	} else if ( prepost == '$' ) {
		p = val + len - SUBLEN + 1;
		for ( i = 0; i < SUBLEN - 1; i++ ) {
			buf[i] = p[i];
		}
		buf[SUBLEN - 1] = '$';
		buf[SUBLEN] = '\0';

		if ( (idl = bdb2i_index_read( be, type, INDEX_SUB, buf )) == NULL ) {
			return( NULL );
		}
	}

	for ( p = val; p < (val + len - SUBLEN + 1); p++ ) {
		for ( i = 0; i < SUBLEN; i++ ) {
			buf[i] = p[i];
		}
		buf[SUBLEN] = '\0';

		if ( (tmp = bdb2i_index_read( be, type, INDEX_SUB, buf )) == NULL ) {
			bdb2i_idl_free( idl );
			return( NULL );
		}

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			tmp2 = idl;
			idl = bdb2i_idl_intersection( be, idl, tmp );
			bdb2i_idl_free( tmp );
			bdb2i_idl_free( tmp2 );
		}

		/* break if no candidates */
		if( idl == NULL ) {
			break;
		}

		/* if we're down to two (or less) matches, stop searching */
		if( ID_BLOCK_NIDS(idl) < 3 ) {
			Debug( LDAP_DEBUG_TRACE, "substring_comp_candidates: "
				"down to a %ld matches, stopped search\n",
					(long) ID_BLOCK_NIDS(idl), 0, 0 );
			break;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= substring_comp_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}
