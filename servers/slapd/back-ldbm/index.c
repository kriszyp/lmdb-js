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

#ifndef SLAPD_SCHEMA_NOT_COMPAT

static int	change_value(Backend *be,
			  DBCache *db,
			  char *type,
			  int indextype,
			  char *val,
			  ID id,
			  int
			  (*idl_func)(Backend *, DBCache *, Datum, ID));
static int	index2prefix(int indextype);
#endif

int
index_add_entry(
    Backend	*be,
    Entry	*e
)
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	Attribute	*ap;
	struct berval	bv;
	struct berval	*bvals[2];

	Debug( LDAP_DEBUG_TRACE, "=> index_add( %ld, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

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
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		index_change_values( be, dn, bvals, e->e_id, SLAP_INDEX_ADD_OP );
#endif
		free( dn );
	}

	free( bv.bv_val );

	/* add each attribute to the indexes */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* index_change_values( be, SLAP_INDEX_ADD_OP, e->e_id, ap ); */
#else
		index_change_values( be, ap->a_type, ap->a_vals, e->e_id,
				     SLAP_INDEX_ADD_OP );
#endif
	}

	Debug( LDAP_DEBUG_TRACE, "<= index_add( %ld, \"%s\" ) 0\n", e->e_id,
	    e->e_ndn, 0 );
#endif
	return( 0 );
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
ID_BLOCK *
index_read(
    Backend	*be,
    char	*type,
    int		indextype,
    char	*val
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

	prefix = index2prefix( indextype );
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

	char	prefix = index2prefix( indextype );

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
#endif

int
index_change_values(
    Backend		*be,
    char		*type,
    struct berval	**vals,
    ID			id,
    unsigned int	op
)
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
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
	attr_mask( be->be_private, type, &indexmask );

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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
	/*
	 * presence index entry
	 */
	if ( indexmask & SLAP_INDEX_PRESENCE ) {
		change_value( be, db, at_cn, SLAP_INDEX_PRESENCE,
			"*", id, idl_funct );
	}

	if ( syntax & SYNTAX_BIN ) {
		goto done;
	}

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

		value_normalize( val, syntax );

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
#endif

done:
	ldbm_cache_close( be, db );
#endif
	return( 0 );
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static int
index2prefix( int indextype )
{
	int	prefix;

	switch ( indextype ) {
	case SLAP_INDEX_EQUALITY:
		prefix = EQ_PREFIX;
		break;
	case SLAP_INDEX_APPROX:
		prefix = APPROX_PREFIX;
		break;
	case SLAP_INDEX_SUBSTR:
		prefix = SUB_PREFIX;
		break;
	default:
		prefix = UNKNOWN_PREFIX;
		break;
	}

	return( prefix );
}
#endif