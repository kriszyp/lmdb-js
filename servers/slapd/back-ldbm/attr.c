/* attr.c - backend routines for dealing with attributes */
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


/* for the cache of attribute information (which are indexed, etc.) */
typedef struct ldbm_attrinfo {
#ifdef SLAPD_USE_AD
	AttributeDescription *ai_desc; /* attribute description cn;lang-en	*/
#else
	char *ai_desc;
#endif
	slap_index ai_indexmask;	/* how the attr is indexed	*/
} AttrInfo;

static int
ainfo_type_cmp(
#ifdef SLAPD_USE_AD
	AttributeDescription *desc,
#else
    char		*desc,
#endif
    AttrInfo	*a
)
{
#ifdef SLAPD_USE_AD
	return ad_cmp( desc, a->ai_desc );
#else
	return( strcasecmp( desc, a->ai_desc ) );
#endif
}

static int
ainfo_cmp(
    AttrInfo	*a,
    AttrInfo	*b
)
{
#ifdef SLAPD_USE_AD
	return ad_cmp( a->ai_desc, b->ai_desc );
#else
	return( strcasecmp( a->ai_desc, b->ai_desc ) );
#endif
}

void
attr_mask(
    struct ldbminfo	*li,
#ifdef SLAPD_USE_AD
	AttributeDescription *desc,
#else
    const char *desc,
#endif
    slap_index *indexmask )
{
	AttrInfo	*a;

	a = (AttrInfo *) avl_find( li->li_attrs, desc,
	    (AVL_CMP) ainfo_type_cmp );
	
	*indexmask = a != NULL ? a->ai_indexmask : 0;
}

int
attr_index_config(
    struct ldbminfo	*li,
    const char		*fname,
    int			lineno,
    int			argc,
    char		**argv,
	int init )
{
	int rc;
	int	i;
	slap_index mask;
	char **attrs;
	char **indexes = NULL;

	attrs = str2charray( argv[0], "," );

	if( attrs == NULL ) {
		fprintf( stderr, "%s: line %d: "
			"no attributes specified: %s\n",
			fname, lineno, argv[0] );
		return LDAP_PARAM_ERROR;
	}

	if ( argc > 1 ) {
		indexes = str2charray( argv[1], "," );

		if( indexes == NULL ) {
			fprintf( stderr, "%s: line %d: "
				"no indexes specified: %s\n",
				fname, lineno, argv[1] );
			return LDAP_PARAM_ERROR;
		}
	}

	if( indexes == NULL ) {
		mask = li->li_defaultmask;

	} else {
		mask = 0;

		for ( i = 0; indexes[i] != NULL; i++ ) {
			slap_index index;
			rc = slap_str2index( indexes[i], &index );

			if( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "%s: line %d: "
					"index type \"%s\" undefined\n",
					fname, lineno, indexes[i] );
				return LDAP_PARAM_ERROR;
			}

			mask |= index;
		}
	}

    if( !mask ) {
		fprintf( stderr, "%s: line %d: "
			"no indexes selected\n",
			fname, lineno );
		return LDAP_PARAM_ERROR;
	}

	for ( i = 0; attrs[i] != NULL; i++ ) {
		AttrInfo	*a;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		AttributeDescription *ad;
		const char *text;
#endif

		if( strcasecmp( attrs[i], "default" ) == 0 ) {
			li->li_defaultmask = mask;
			continue;
		}

		a = (AttrInfo *) ch_malloc( sizeof(AttrInfo) );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		ad = NULL;
		rc = slap_str2ad( attrs[i], &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: line %d: "
				"index attribute \"%s\" undefined\n",
				fname, lineno, attrs[i] );
			return rc;
		}

		if( slap_ad_is_binary( ad ) ) {
			fprintf( stderr, "%s: line %d: "
				"index of attribute \"%s\" disallowed\n",
				fname, lineno, attrs[i] );
			return LDAP_UNWILLING_TO_PERFORM;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) && !(
			( ad->ad_type->sat_approx
				&& ad->ad_type->sat_approx->smr_indexer
				&& ad->ad_type->sat_approx->smr_filter )
			&& ( ad->ad_type->sat_equality
				&& ad->ad_type->sat_equality->smr_indexer
				&& ad->ad_type->sat_equality->smr_filter ) ) )
		{
			fprintf( stderr, "%s: line %d: "
				"approx index of attribute \"%s\" disallowed\n",
				fname, lineno, attrs[i] );
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) && !(
			ad->ad_type->sat_equality
				&& ad->ad_type->sat_equality->smr_indexer
				&& ad->ad_type->sat_equality->smr_filter ) )
		{
			fprintf( stderr, "%s: line %d: "
				"equality index of attribute \"%s\" disallowed\n",
				fname, lineno, attrs[i] );
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) && !(
			ad->ad_type->sat_substr
				&& ad->ad_type->sat_substr->smr_indexer
				&& ad->ad_type->sat_substr->smr_filter ) )
		{
			fprintf( stderr, "%s: line %d: "
				"substr index of attribute \"%s\" disallowed\n",
				fname, lineno, attrs[i] );
			return LDAP_INAPPROPRIATE_MATCHING;
		}

		Debug( LDAP_DEBUG_CONFIG, "index %s 0x%04x\n",
			ad->ad_cname->bv_val, mask, 0 ); 

#ifdef SLAPD_USE_AD
		a->ai_desc = ad;
#else
		a->ai_desc = ch_strdup( ad->ad_cname->bv_val );
		ad_free( ad, 1 );
#endif
#else
		a->ai_desc = ch_strdup( attrs[i] );
#endif

		a->ai_indexmask = mask;

		rc = avl_insert( &li->li_attrs, (caddr_t) a,
			(AVL_CMP) ainfo_cmp, (AVL_DUP) avl_dup_error );

		if( rc && !init ) {
			fprintf( stderr, "%s: line %d: duplicate index definition "
				"for attr \"%s\" (ignored)\n",
			    fname, lineno, attrs[i] );

			return LDAP_PARAM_ERROR;
		}
	}

	charray_free( attrs );
	if ( indexes != NULL ) charray_free( indexes );

	return LDAP_SUCCESS;
}


static void
ainfo_free( void *attr )
{
	AttrInfo *ai = attr;
#ifdef SLAPD_USE_AD
	ad_free( ai->ai_desc, 1 );
#else
	free( ai->ai_desc );
#endif
	free( ai );
}

void
attr_index_destroy( Avlnode *tree )
{
	avl_free( tree, ainfo_free );
}

