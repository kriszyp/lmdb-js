/* filterindex.c - generate the list of candidate entries from a filter */
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
#include "back-ldbm.h"

#ifdef SLAPD_SCHEMA_NOT_COMPAT
static ID_BLOCK	*presence_candidates(
	Backend *be,
	AttributeDescription *desc );
static ID_BLOCK	*equality_candidates(
	Backend *be, AttributeAssertion *ava );
static ID_BLOCK	*approx_candidates(
	Backend *be, AttributeAssertion *ava );
static ID_BLOCK	*substring_candidates(
	Backend *be,
	Filter *f );
static ID_BLOCK	*list_candidates(
	Backend *be,
	Filter *flist,
	int ftype );
#else
static ID_BLOCK	*presence_candidates( Backend *be, char *type );
static ID_BLOCK	*equality_candidates( Backend *be, Ava *ava );
static ID_BLOCK	*approx_candidates( Backend *be, Ava *ava );
static ID_BLOCK	*list_candidates( Backend *be, Filter *flist, int ftype );
static ID_BLOCK	*substring_candidates( Backend *be, Filter *f );
static ID_BLOCK	*substring_comp_candidates( Backend *be, char *type,
	struct berval *val, int prepost );
#endif

ID_BLOCK *
filter_candidates(
    Backend	*be,
    Filter	*f
)
{
	ID_BLOCK	*result, *tmp1, *tmp2;

	Debug( LDAP_DEBUG_TRACE, "=> filter_candidates\n", 0, 0, 0 );

	result = NULL;
	switch ( f->f_choice ) {
	case SLAPD_FILTER_DN_ONE:
		Debug( LDAP_DEBUG_FILTER, "\tDN ONE\n", 0, 0, 0 );
		result = dn2idl( be, f->f_dn, DN_ONE_PREFIX );
		break;

	case SLAPD_FILTER_DN_SUBTREE:
		Debug( LDAP_DEBUG_FILTER, "\tDN SUBTREE\n", 0, 0, 0 );
		result = dn2idl( be, f->f_dn, DN_SUBTREE_PREFIX );
		break;

	case LDAP_FILTER_PRESENT:
		Debug( LDAP_DEBUG_FILTER, "\tPRESENT\n", 0, 0, 0 );
		result = presence_candidates( be, f->f_desc );
		break;

	case LDAP_FILTER_EQUALITY:
		Debug( LDAP_DEBUG_FILTER, "\tEQUALITY\n", 0, 0, 0 );
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		result = equality_candidates( be, f->f_ava );
#else
		result = equality_candidates( be, &f->f_ava );
#endif
		break;

	case LDAP_FILTER_APPROX:
		Debug( LDAP_DEBUG_FILTER, "\tAPPROX\n", 0, 0, 0 );
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		result = approx_candidates( be, f->f_ava );
#else
		result = approx_candidates( be, &f->f_ava );
#endif
		break;

	case LDAP_FILTER_SUBSTRINGS:
		Debug( LDAP_DEBUG_FILTER, "\tSUBSTRINGS\n", 0, 0, 0 );
		result = substring_candidates( be, f );
		break;

	case LDAP_FILTER_GE:
		Debug( LDAP_DEBUG_FILTER, "\tGE\n", 0, 0, 0 );
		result = idl_allids( be );
		break;

	case LDAP_FILTER_LE:
		Debug( LDAP_DEBUG_FILTER, "\tLE\n", 0, 0, 0 );
		result = idl_allids( be );
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
		tmp1 = idl_allids( be );
		tmp2 = filter_candidates( be, f->f_not );
		result = idl_notin( be, tmp1, tmp2 );
		idl_free( tmp2 );
		idl_free( tmp1 );
		break;
	}

	Debug( LDAP_DEBUG_TRACE, "<= filter_candidates %ld\n",
	    result ? ID_BLOCK_NIDS(result) : 0, 0, 0 );
	return( result );
}

static ID_BLOCK *
presence_candidates(
    Backend	*be,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc
#else
    char	*desc
#endif
)
{
	ID_BLOCK	*idl;

	Debug( LDAP_DEBUG_TRACE, "=> presence_candidates\n", 0, 0, 0 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	idl = idl_allids( be );
#else
	idl = index_read( be, desc, SLAP_INDEX_PRESENT, NULL );
#endif

	Debug( LDAP_DEBUG_TRACE, "<= presence_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
equality_candidates(
    Backend	*be,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeAssertion *ava
#else
    Ava		*ava
#endif
)
{
	ID_BLOCK	*idl;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_index mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;
#endif

	Debug( LDAP_DEBUG_TRACE, "=> equality_candidates\n", 0, 0, 0 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	idl = idl_allids( be );

	rc = index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_equality;
	if( !mr ) {
		/* return LDAP_INAPPROPRIATE_MATCHING; */
		return idl;
	}

	if( !mr->smr_filter ) {
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= equality_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		return idl;
	}

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "<= equality_candidates open failed (%d)\n",
		    rc, 0, 0 );
		return idl;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( be, db, keys[i], &tmp );

		if( rc != LDAP_SUCCESS ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= equality_candidates key read failed (%d)\n",
			    rc, 0, 0 );
			break;
		}

		if( tmp == NULL ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= equality_candidates NULL\n",
			    0, 0, 0 );
			break;
		}

		save = idl;
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	ldbm_cache_close( be, db );

#else
	idl = index_read( be, ava->ava_type, SLAP_INDEX_EQUALITY,
	    ava->ava_value.bv_val );
#endif

	Debug( LDAP_DEBUG_TRACE, "<= equality_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
approx_candidates(
    Backend	*be,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeAssertion *ava
#else
    Ava		*ava
#endif
)
{
	ID_BLOCK *idl;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	DBCache	*db;
	int i;
	int rc;
	char *dbname;
	slap_index mask;
	struct berval *prefix;
	struct berval **keys = NULL;
	MatchingRule *mr;
#else
	char *w, *c;
	ID_BLOCK *tmp;
#endif

	Debug( LDAP_DEBUG_TRACE, "=> approx_candidates\n", 0, 0, 0 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	idl = idl_allids( be );

	rc = index_param( be, ava->aa_desc, LDAP_FILTER_EQUALITY,
		&dbname, &mask, &prefix );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	if( dbname == NULL ) {
		/* not indexed */
		return idl;
	}

	mr = ava->aa_desc->ad_type->sat_approx;
	if( mr == NULL ) {
		/* no approx matching rule, try equality matching rule */
		mr = ava->aa_desc->ad_type->sat_equality;
	}

	if( !mr ) {
		/* return LDAP_INAPPROPRIATE_MATCHING; */
		return idl;
	}

	if( !mr->smr_filter ) {
		return idl;
	}

	rc = (mr->smr_filter)(
		LDAP_FILTER_EQUALITY,
		ava->aa_desc->ad_type->sat_syntax,
		mr,
		prefix,
		ava->aa_value,
		&keys );

	if( rc != LDAP_SUCCESS ) {
		return idl;
	}

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_READER );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= approx_candidates db open failed (%s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		return idl;
	}

	if( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_TRACE, "<= approx_candidates open failed (%d)\n",
		    rc, 0, 0 );
		return idl;
	}

	for ( i= 0; keys[i] != NULL; i++ ) {
		ID_BLOCK *save;
		ID_BLOCK *tmp;

		rc = key_read( be, db, keys[i], &tmp );

		if( rc != LDAP_SUCCESS ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates key read failed (%d)\n",
			    rc, 0, 0 );
			break;
		}

		if( tmp == NULL ) {
			idl_free( idl );
			idl = NULL;
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates NULL\n",
			    0, 0, 0 );
			break;
		}

		save = idl;
		idl = idl_intersection( be, idl, tmp );
		idl_free( save );

		if( idl == NULL ) break;
	}

	ber_bvecfree( keys );

	ldbm_cache_close( be, db );

#else
	idl = NULL;
	for ( w = first_word( ava->ava_value.bv_val );
		w != NULL;
	    w = next_word( w ) )
	{
		c = phonetic( w );
		if ( (tmp = index_read( be, ava->ava_type, SLAP_INDEX_APPROX, c ))
		    == NULL ) {
			free( c );
			idl_free( idl );
			Debug( LDAP_DEBUG_TRACE, "<= approx_candidates NULL\n",
			    0, 0, 0 );
			return( NULL );
		}
		free( c );

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			idl = idl_intersection( be, idl, tmp );
		}
	}

#endif
	Debug( LDAP_DEBUG_TRACE, "<= approx_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
list_candidates(
    Backend	*be,
    Filter	*flist,
    int		ftype
)
{
	ID_BLOCK	*idl, *tmp, *tmp2;
	Filter	*f;

	Debug( LDAP_DEBUG_TRACE, "=> list_candidates 0x%x\n", ftype, 0, 0 );

	idl = NULL;
	for ( f = flist; f != NULL; f = f->f_next ) {
		if ( (tmp = filter_candidates( be, f )) == NULL &&
		    ftype == LDAP_FILTER_AND ) {
				Debug( LDAP_DEBUG_TRACE,
				    "<= list_candidates NULL\n", 0, 0, 0 );
				idl_free( idl );
				return( NULL );
		}

		tmp2 = idl;
		if ( idl == NULL ) {
			idl = tmp;
		} else if ( ftype == LDAP_FILTER_AND ) {
			idl = idl_intersection( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		} else {
			idl = idl_union( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= list_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static ID_BLOCK *
substring_candidates(
    Backend	*be,
    Filter	*f
)
{
	ID_BLOCK *idl;
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	int	i;
	ID_BLOCK *tmp, *tmp2;
#endif

	Debug( LDAP_DEBUG_TRACE, "=> substring_candidates\n", 0, 0, 0 );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	idl = idl_allids( be );
#else
	idl = NULL;

	/* initial */
	if ( f->f_sub_initial != NULL ) {
		if ( f->f_sub_initial->bv_len < SUBLEN - 1 ) {
			idl = idl_allids( be );
		} else if ( (idl = substring_comp_candidates( be, f->f_sub_type,
		    f->f_sub_initial, '^' )) == NULL ) {
			return( NULL );
		}
	}

	/* final */
	if ( f->f_sub_final != NULL ) {
		if ( f->f_sub_final->bv_len < SUBLEN - 1 ) {
			tmp = idl_allids( be );
		} else if ( (tmp = substring_comp_candidates( be, f->f_sub_type,
		    f->f_sub_final, '$' )) == NULL ) {
			idl_free( idl );
			return( NULL );
		}

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			tmp2 = idl;
			idl = idl_intersection( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		}
	}

	if( f->f_sub_any != NULL ) {
		for ( i = 0; f->f_sub_any[i] != NULL; i++ ) {
			if ( f->f_sub_any[i]->bv_len < SUBLEN ) {
				tmp = idl_allids( be );
			} else if ( (tmp = substring_comp_candidates( be, f->f_sub_type,
				f->f_sub_any[i], 0 )) == NULL ) {
				idl_free( idl );
				return( NULL );
			}

			if ( idl == NULL ) {
				idl = tmp;
			} else {
				tmp2 = idl;
				idl = idl_intersection( be, idl, tmp );
				idl_free( tmp );
				idl_free( tmp2 );
			}
		}
	}
#endif
	Debug( LDAP_DEBUG_TRACE, "<= substring_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static ID_BLOCK *
substring_comp_candidates(
    Backend	*be,
    char	*type,
    struct berval	*bv,
    int		prepost
)
{
	int	i, len;
	ID_BLOCK	*idl, *tmp, *tmp2;
	char	*p;
	char	buf[SUBLEN + 1];
	char	*val;

	Debug( LDAP_DEBUG_TRACE, "=> substring_comp_candidates\n", 0, 0, 0 );

	val = bv->bv_val;
	len = bv->bv_len;
	idl = NULL;

	/* prepend ^ for initial substring */
	if ( prepost == '^' ) {
		buf[0] = '^';
		for ( i = 0; i < SUBLEN - 1; i++ ) {
			buf[i + 1] = val[i];
		}
		buf[SUBLEN] = '\0';

		if ( (idl = index_read( be, type, SLAP_INDEX_SUBSTR, buf )) == NULL ) {
			return( NULL );
		}
	} else if ( prepost == '$' ) {
		p = val + len - SUBLEN + 1;
		for ( i = 0; i < SUBLEN - 1; i++ ) {
			buf[i] = p[i];
		}
		buf[SUBLEN - 1] = '$';
		buf[SUBLEN] = '\0';

		if ( (idl = index_read( be, type, SLAP_INDEX_SUBSTR, buf )) == NULL ) {
			return( NULL );
		}
	}

	for ( p = val; p < (val + len - SUBLEN + 1); p++ ) {
		for ( i = 0; i < SUBLEN; i++ ) {
			buf[i] = p[i];
		}
		buf[SUBLEN] = '\0';

		if ( (tmp = index_read( be, type, SLAP_INDEX_SUBSTR, buf )) == NULL ) {
			idl_free( idl );
			return( NULL );
		}

		if ( idl == NULL ) {
			idl = tmp;
		} else {
			tmp2 = idl;
			idl = idl_intersection( be, idl, tmp );
			idl_free( tmp );
			idl_free( tmp2 );
		}

		/* break if no candidates */
		if( idl == NULL ) {
			break;
		}

		/* if we're down to two (or less) matches, stop searching */
		if( ID_BLOCK_NIDS(idl) < 3 ) {
			Debug( LDAP_DEBUG_TRACE, "substring_comp_candiates: "
				"down to a %ld matches, stopped search\n",
					(long) ID_BLOCK_NIDS(idl), 0, 0 );
			break;
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= substring_comp_candidates %ld\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}
#endif
