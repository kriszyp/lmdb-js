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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
static index_mask(
	Backend *be,
	AttributeDescription *desc,
	char **dbname,
	char **atname )
{
	AttributeType *at;
	slap_index mask = 0;

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
	slap_index *maskp,
	struct berval **prefixp )
{
	slap_index mask;
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
	slap_index mask )
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
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_equality,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS ) {
			for( i= 0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
		}
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_APPROX ) ) {
		rc = ad->ad_type->sat_approx->smr_indexer(
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_approx,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS ) {
			for( i= 0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
		}
	}

	if( IS_SLAP_INDEX( mask, SLAP_INDEX_SUBSTR ) ) {
		rc = ad->ad_type->sat_substr->smr_indexer(
			mask,
			ad->ad_type->sat_syntax,
			ad->ad_type->sat_substr,
			&prefix, vals, &keys );

		if( rc == LDAP_SUCCESS ) {
			for( i= 0; keys[i] != NULL; i++ ) {
				key_change( be, db, keys[i], id, op );
 			}
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
	slap_index *maskp )
{
	slap_index mask;
	slap_index tmpmask = 0;
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
	slap_index mask;

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

#else
int index_change_values(
    Backend		*be,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc,
#else
    char		*desc,
#endif
    struct berval	**vals,
    ID			id,
    unsigned int	op
);

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static int	change_value(Backend *be,
	DBCache *db,
	char *type,
	int indextype,
	char *val,
	ID id,
	int
	(*idl_func)(Backend *, DBCache *, Datum, ID));
#endif
#endif

int
index_entry(
    Backend	*be,
	int op,
    Entry	*e,
	Attribute *ap
)
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	struct berval	bv;
	struct berval	*bvals[2];
#endif

	Debug( LDAP_DEBUG_TRACE, "=> index_entry_%s( %ld, \"%s\" )\n",
		op == SLAP_INDEX_ADD_OP ? "add" : "del",
		e->e_id, e->e_dn );

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	/*
	 * dn index entry - make it look like an attribute so it works
	 * with index_change_values() call
	 */

	bv.bv_val = ch_strdup( e->e_ndn );
	bv.bv_len = strlen( bv.bv_val );
	bvals[0] = &bv;
	bvals[1] = NULL;

	/* add the dn to the indexes */
	{
		char *dn = ch_strdup("dn");
		index_change_values( be, dn, bvals, e->e_id, op );
		free( dn );
	}

	free( bv.bv_val );
#endif

	/* add each attribute to the indexes */
	for ( ap; ap != NULL; ap = ap->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		index_values( be, ap->a_desc, ap->a_vals, e->e_id, op );
#else
		index_change_values( be, ap->a_type, ap->a_vals, e->e_id, op );
#endif
	}

	Debug( LDAP_DEBUG_TRACE, "<= index_entry_%s( %ld, \"%s\" ) success\n",
	    op == SLAP_INDEX_ADD_OP ? "add" : "del",
		e->e_id, e->e_dn );

	return LDAP_SUCCESS;
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT

ID_BLOCK *
index_read(
    Backend	*be,
    char	*type,
    int		indextype,
    char *val
)
{
	DBCache	*db;
	Datum   	key;
	ID_BLOCK		*idl;
	int		indexmask;
	char		prefix;
	char		*realval, *tmpval;
	char		buf[BUFSIZ];

	char		*at_cn;

	ldbm_datum_init( key );

	prefix = slap_index2prefix( indextype );
	Debug( LDAP_DEBUG_TRACE, "=> index_read(\"%c%s\"->\"%s\")\n",
	    prefix, type, val );

	attr_mask( be->be_private, type, &indexmask );
	if ( ! (indextype & indexmask) ) {
		idl =  idl_allids( be );
		Debug( LDAP_DEBUG_TRACE,
		    "<= index_read %ld candidates (allids - not indexed)\n",
		    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
		return( idl );
	}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	at_cn = at_canonical_name( at_find( type ) );
#else
	attr_normalize( type );
	at_cn = at_canonical_name( type );
#endif

	if ( at_cn == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= index_read no canonical name for type \"%s\"\n",
			type != NULL ? type : "(NULL)", 0, 0 );
		return( NULL );
	}

	if ( (db = ldbm_cache_open( be, at_cn, LDBM_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= index_read NULL (could not open %s%s)\n",
			at_cn, LDBM_SUFFIX, 0 );
		return( NULL );
	}

	realval = val;
	tmpval = NULL;
	if ( prefix != UNKNOWN_PREFIX ) {
		unsigned int	len = strlen( val );

		if ( (len + 2) < sizeof(buf) ) {
			realval = buf;
		} else {
			/* value + prefix + null */
			tmpval = (char *) ch_malloc( len + 2 );
			realval = tmpval;
		}

		realval[0] = prefix;
		strcpy( &realval[1], val );
	}

	key.dptr = realval;
	key.dsize = strlen( realval ) + 1;

	idl = idl_fetch( be, db, key );
	if ( tmpval != NULL ) {
              free( tmpval );
	}

	ldbm_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= index_read %ld candidates\n",
	       idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

/* Add or remove stuff from index files */

static int
change_value(
    Backend		*be,
    DBCache	*db,
    char		*type,
    int			indextype,
    char		*val,
    ID			id,
    int			(*idl_func)(Backend *, DBCache *, Datum, ID)
)
{
	int	rc;
	Datum   key;
	char	*tmpval = NULL;
	char	*realval = val;
	char	buf[BUFSIZ];

	char	prefix = slap_index2prefix( indextype );

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE,
	       "=> change_value( \"%c%s\", op=%s )\n",
	       prefix, val, (idl_func == idl_insert_key ? "ADD":"DELETE") );

	if ( prefix != UNKNOWN_PREFIX ) {
              unsigned int     len = strlen( val );

              if ( (len + 2) < sizeof(buf) ) {
			realval = buf;
	      } else {
			/* value + prefix + null */
			tmpval = (char *) ch_malloc( len + 2 );
			realval = tmpval;
	      }
              realval[0] = prefix;
              strcpy( &realval[1], val );
	}

	key.dptr = realval;
	key.dsize = strlen( realval ) + 1;

	rc = idl_func( be, db, key, id );

	if ( tmpval != NULL ) {
		free( tmpval );
	}

	ldap_pvt_thread_yield();

	Debug( LDAP_DEBUG_TRACE, "<= change_value %d\n", rc, 0, 0 );

	return( rc );

}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
static
#endif
int
index_change_values(
    Backend		*be,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc,
#else
    char		*desc,
#endif
    struct berval	**vals,
    ID			id,
    unsigned int	op
)
{
	char		*val, *p, *code, *w;
	unsigned	i, j, len;
	int		indexmask, syntax;
	char		buf[SUBLEN + 1];
	char		vbuf[BUFSIZ];
	char		*bigbuf;
	DBCache	*db;

	int		(*idl_funct)(Backend *,
				    DBCache *,
				    Datum, ID);
	char		*at_cn;	/* Attribute canonical name */
	int		mode;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	char *type = desc->ad_cname->bv_val;
#else
	char *type = desc;
#endif

	if( vals == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"=> index_change_values( %s, NULL, %ld, op=%s )\n", 
			type, id, ((op == SLAP_INDEX_ADD_OP) ? "ADD" : "DELETE" ) );
		return 0;
	}

	Debug( LDAP_DEBUG_TRACE,
	       "=> index_change_values( \"%s\", %ld, op=%s )\n", 
	       type, id, ((op == SLAP_INDEX_ADD_OP) ? "ADD" : "DELETE" ) );

	
	if (op == SLAP_INDEX_ADD_OP) {
	    /* Add values */
	    idl_funct =  idl_insert_key;
	    mode = LDBM_WRCREAT;

	} else {
	    /* Delete values */
	    idl_funct = idl_delete_key;
	    mode = LDBM_WRITER;
	}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	attr_normalize(type);
#endif
	attr_mask( be->be_private, desc, &indexmask );

	if ( indexmask == 0 ) {
		return( 0 );
	}

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	at_cn = at_canonical_name( at_find( type ) );
#else
	syntax = attr_syntax( type );
	at_cn = at_canonical_name( type );
#endif

	if ( at_cn == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= index_change_values no canonical name for type \"%s\"\n",
			type != NULL ? type : "(NULL)", 0, 0 );
		return( -1 );
	}

	if ( (db = ldbm_cache_open( be, at_cn, LDBM_SUFFIX, mode ))
	     == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		       "<= index_change_values (couldn't open(%s%s),md=%s)\n",
		       at_cn, LDBM_SUFFIX,
		       ((mode==LDBM_WRCREAT)?"LDBM_WRCREAT":"LDBM_WRITER") );
		return( -1 );
	}

	/*
	 * presence index entry
	 */
	if ( indexmask & SLAP_INDEX_PRESENT ) {
		change_value( be, db, at_cn, SLAP_INDEX_PRESENT,
			"*", id, idl_funct );
	}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	if ( syntax & SYNTAX_BIN ) {
		goto done;
	}
#endif

	for ( i = 0; vals[i] != NULL; i++ ) {
		Debug( LDAP_DEBUG_TRACE,
		       "index_change_values syntax 0x%x\n",
		       syntax, 0, 0 );

		bigbuf = NULL;
		len = vals[i]->bv_len;

		/* value + null */
		if ( len + 2 > sizeof(vbuf) ) {
			bigbuf = (char *) ch_malloc( len + 1 );
			val = bigbuf;
		} else {
			val = vbuf;
		}
		(void) memcpy( val, vals[i]->bv_val, len );
		val[len] = '\0';

#ifndef SLAPD_SCHEMA_NOT_COMPAT
		value_normalize( val, syntax );
#endif

		/* value_normalize could change the length of val */
		len = strlen( val );

		/*
		 * equality index entry
		 */
		if ( indexmask & SLAP_INDEX_EQUALITY ) {
			change_value( be, db, at_cn, SLAP_INDEX_EQUALITY,
				      val, id, idl_funct);
		}

		/*
		 * approximate index entry
		 */
		if ( indexmask & SLAP_INDEX_APPROX ) {
			for ( w = first_word( val ); w != NULL;
			    w = next_word( w ) ) {
				if ( (code = phonetic( w )) != NULL ) {
					change_value( be,
						      db,
						      at_cn,
						      SLAP_INDEX_APPROX,
						      code,
						      id,
						      idl_funct );
					free( code );
				}
			}
		}

		/*
		 * substrings index entry
		 */
		if ( indexmask & SLAP_INDEX_SUBSTR ) {
			/* leading and trailing */
			if ( len > SUBLEN - 2 ) {
				buf[0] = '^';
				for ( j = 0; j < SUBLEN - 1; j++ ) {
					buf[j + 1] = val[j];
				}
				buf[SUBLEN] = '\0';

				change_value( be, db, at_cn, SLAP_INDEX_SUBSTR,
					      buf, id, idl_funct );

				p = val + len - SUBLEN + 1;
				for ( j = 0; j < SUBLEN - 1; j++ ) {
					buf[j] = p[j];
				}
				buf[SUBLEN - 1] = '$';
				buf[SUBLEN] = '\0';

				change_value( be, db, at_cn, SLAP_INDEX_SUBSTR,
					      buf, id, idl_funct );
			}

			/* any */
			for ( p = val; p < (val + len - SUBLEN + 1); p++ ) {
				for ( j = 0; j < SUBLEN; j++ ) {
					buf[j] = p[j];
				}
				buf[SUBLEN] = '\0';

				change_value( be, db, at_cn, SLAP_INDEX_SUBSTR,
					      buf, id, idl_funct );
			}
		}

		if ( bigbuf != NULL ) {
			free( bigbuf );
		}
	}
#ifndef SLAPD_SCHEMA_NOT_COMPAT
done:
#endif
	ldbm_cache_close( be, db );
	return LDAP_SUCCESS;
}
#endif
