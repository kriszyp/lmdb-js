/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldbm.h"

static index_mask(
	Backend *be,
	AttributeDescription *desc,
	char **dbname,
	char **atname )
{
	AttributeType *at;
	slap_mask_t mask = 0;

	/* we do support indexing of binary attributes */
	if( slap_ad_is_binary( desc ) ) return 0;

	attr_mask( be->be_private, desc->ad_cname->bv_val, &mask );

	if( mask ) {
		*atname = desc->ad_cname->bv_val;
		*dbname = desc->ad_cname->bv_val;
		return mask;
	}

	if( slap_ad_is_lang( desc ) ) {
		/* has language tag */
		attr_mask( be->be_private, desc->ad_type->sat_cname, &mask );

		if( mask & SLAP_INDEX_AUTO_LANG ) {
			*atname = desc->ad_cname->bv_val;
			*dbname = desc->ad_type->sat_cname;
			return mask;
		}
		if( mask & SLAP_INDEX_LANG ) {
			*atname = desc->ad_type->sat_cname;
			*dbname = desc->ad_type->sat_cname;
			return mask;
		}
	}

	/* see if supertype defined mask for its subtypes */
	for( at = desc->ad_type; at != NULL ; at = at->sat_sup ) {
		attr_mask( be->be_private, at->sat_cname, &mask );

		if( mask & SLAP_INDEX_AUTO_SUBTYPES ) {
			*atname = desc->ad_type->sat_cname;
			*dbname = at->sat_cname;
			return mask;
		}
		if( mask & SLAP_INDEX_SUBTYPES ) {
			*atname = at->sat_cname;
			*dbname = at->sat_cname;
			return mask;
		}

		if( mask ) break;
	}

	return 0;
}

int index_param(
	Backend *be,
	AttributeDescription *desc,
	int ftype,
	char **dbnamep,
	slap_mask_t *maskp,
	struct berval **prefixp )
{
	slap_mask_t mask;
	char *dbname;
	char *atname;

	mask = index_mask( be, desc, &dbname, &atname );

	if( mask == 0 ) {
		return LDAP_INAPPROPRIATE_MATCHING;
	}

	switch(ftype) {
	case LDAP_FILTER_PRESENT:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_PRESENT ) ) {
			goto done;
		}
		break;

	case LDAP_FILTER_APPROX:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) ) {
			goto done;
		}
		/* fall thru */

	case LDAP_FILTER_EQUALITY:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) ) {
			goto done;
		}
		break;

	case LDAP_FILTER_SUBSTRINGS:
		if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) ) {
			goto done;
		}
		break;

	default:
		return LDAP_OTHER;
	}

	return LDAP_INAPPROPRIATE_MATCHING;

done:
	*dbnamep = dbname;
	*prefixp = ber_bvstrdup( atname );
	*maskp = mask;
	return LDAP_SUCCESS;
}

static int indexer(
	Backend *be,
	char *dbname,
	char *atname,
	struct berval **vals,
	ID id,
	int op,
	slap_mask_t mask )
{
	int rc, i;
	const char *text;
    DBCache	*db;
	AttributeDescription *ad = NULL;
	struct berval **keys;
	struct berval prefix;

	assert( mask );

	rc = slap_str2ad( atname, &ad, &text );

	if( rc != LDAP_SUCCESS ) return rc;

	prefix.bv_val = atname;
	prefix.bv_len = strlen( atname );

	db = ldbm_cache_open( be, dbname, LDBM_SUFFIX, LDBM_WRCREAT );
	
	if ( db == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= index_read NULL (could not open %s%s)\n",
			dbname, LDBM_SUFFIX, 0 );
		ad_free( ad, 1 );
		return LDAP_OTHER;
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_PRESENT ) ) {
		key_change( be, db, &prefix, id, op );
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_EQUALITY ) ) {
		rc = ad->ad_type->sat_equality->smr_indexer(
			LDAP_FILTER_EQUALITY,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_equality,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
			ber_bvecfree( keys );
		}
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) ) {
		rc = ad->ad_type->sat_approx->smr_indexer(
			LDAP_FILTER_APPROX,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_approx,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
			ber_bvecfree( keys );
		}
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) ) {
		rc = ad->ad_type->sat_substr->smr_indexer(
			LDAP_FILTER_SUBSTRINGS,
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_substr,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS && keys != NULL ) {
			for( i=0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
			ber_bvecfree( keys );
		}
	}

	ldbm_cache_close( be, db );
	ad_free( ad, 1 );
	return LDAP_SUCCESS;
}

static int index_at_values(
	Backend *be,
	AttributeType *type,
	const char *lang,
	struct berval **vals,
	ID id,
	int op,
	char ** dbnamep,
	slap_mask_t *maskp )
{
	slap_mask_t mask;
	slap_mask_t tmpmask = 0;
	int lindex = 0;

	if( type->sat_sup ) {
		/* recurse */
		(void) index_at_values( be,
			type->sat_sup, lang,
			vals, id, op,
			dbnamep, &tmpmask );
	}

	attr_mask( be->be_private, type->sat_cname, &mask );

	if( mask ) {
		*dbnamep = type->sat_cname;
	} else if ( tmpmask & SLAP_INDEX_AUTO_SUBTYPES ) {
		mask = tmpmask;
	}

	if( mask ) {
		indexer( be, *dbnamep,
			type->sat_cname,
			vals, id, op,
			mask );
	}

	if( lang ) {
		char *dbname = NULL;
		size_t tlen = strlen( type->sat_cname );
		size_t llen = strlen( lang );
		char *lname = ch_malloc( tlen + llen + sizeof(";") );

		sprintf( lname, "%s;%s", type->sat_cname, lang );

		attr_mask( be->be_private, lname, &tmpmask );

		if( tmpmask ) {
			dbname = lname;
		} else if ( mask & SLAP_INDEX_AUTO_LANG ) {
			dbname = *dbnamep;
			tmpmask = mask;
		}

		if( dbname != NULL ) {
			indexer( be, dbname, lname,
				vals, id, op,
				tmpmask );
		}

		ch_free( lname );
	}

	return LDAP_SUCCESS;
}

int index_values(
	Backend *be,
	AttributeDescription *desc,
	struct berval **vals,
	ID id,
	int op )
{
	char *dbname = NULL;
	slap_mask_t mask;

	if( slap_ad_is_binary( desc ) ) {
		/* binary attributes have no index capabilities */
		return LDAP_SUCCESS;
	}

	(void) index_at_values( be,
		desc->ad_type, desc->ad_lang,
		vals, id, op,
		&dbname, &mask );

	return LDAP_SUCCESS;
}


int
index_entry(
    Backend	*be,
	int op,
    Entry	*e,
	Attribute *ap
)
{

	Debug( LDAP_DEBUG_TRACE, "=> index_entry_%s( %ld, \"%s\" )\n",
		op == SLAP_INDEX_ADD_OP ? "add" : "del",
		e->e_id, e->e_dn );


	/* add each attribute to the indexes */
	for ( ap; ap != NULL; ap = ap->a_next ) {
		index_values( be, ap->a_desc, ap->a_vals, e->e_id, op );
	}

	Debug( LDAP_DEBUG_TRACE, "<= index_entry_%s( %ld, \"%s\" ) success\n",
	    op == SLAP_INDEX_ADD_OP ? "add" : "del",
		e->e_id, e->e_dn );

	return LDAP_SUCCESS;
}

