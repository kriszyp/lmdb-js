/* index.c - routines for dealing with attribute indexes */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-bdb2.h"

static int	add_value(BackendDB *be, struct dbcache *db, char *type, int indextype, char *val, ID id);
static int	index2prefix(int indextype);

int
bdb2i_index_add_entry(
    BackendDB	*be,
    Entry	*e
)
{
	Attribute	*ap;
	struct berval	bv;
	struct berval	*bvals[2];

	Debug( LDAP_DEBUG_TRACE, "=> index_add( %ld, \"%s\" )\n", e->e_id,
	    e->e_dn, 0 );

	/*
	 * dn index entry - make it look like an attribute so it works
	 * with bdb2i_index_add_values() call
	 */

	bv.bv_val = ch_strdup( e->e_ndn );
	bv.bv_len = strlen( bv.bv_val );
	bvals[0] = &bv;
	bvals[1] = NULL;

	/* add the dn to the indexes */
	{
		char *dn = ch_strdup( "dn" );
		bdb2i_index_add_values( be, dn, bvals, e->e_id );
		free( dn );
	}

	free( bv.bv_val );

	/* add each attribute to the indexes */
	for ( ap = e->e_attrs; ap != NULL; ap = ap->a_next ) {
		bdb2i_index_add_values( be, ap->a_type, ap->a_vals, e->e_id );
	}

	Debug( LDAP_DEBUG_TRACE, "<= index_add( %ld, \"%s\" ) 0\n", e->e_id,
	    e->e_ndn, 0 );
	return( 0 );
}

int
bdb2i_index_add_mods(
    BackendDB	*be,
    LDAPModList	*ml,
    ID		id
)
{
	int	rc;

	for ( ; ml != NULL; ml = ml->ml_next ) {
		LDAPMod *mod = &ml->ml_mod;

		switch ( mod->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_ADD:
		case LDAP_MOD_REPLACE:
			rc = bdb2i_index_add_values( be, mod->mod_type,
			    mod->mod_bvalues, id );
			break;
		case LDAP_MOD_SOFTADD:
		case LDAP_MOD_DELETE:
			rc = 0;
			break;
		}

		if ( rc != 0 ) {
			return( rc );
		}
	}

	return( 0 );
}

ID_BLOCK *
bdb2i_index_read(
    BackendDB	*be,
    char	*type,
    int		indextype,
    char	*val
)
{
	struct dbcache	*db;
	Datum   	key;
	ID_BLOCK		*idl;
	int		indexmask, syntax;
	char		prefix;
	char		*realval, *tmpval;
	char		buf[BUFSIZ];

	char		*at_cn;

	ldbm_datum_init( key );

	prefix = index2prefix( indextype );
	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_index_read( \"%c%s\" -> \"%s\" )\n",
	    prefix, type, val );

	bdb2i_attr_masks( be->be_private, type, &indexmask, &syntax );
	if ( ! (indextype & indexmask) ) {
		idl =  bdb2i_idl_allids( be );
		Debug( LDAP_DEBUG_TRACE,
		    "<= bdb2i_index_read %ld candidates (allids - not indexed)\n",
		    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
		return( idl );
	}

	attr_normalize( type );
	at_cn = at_canonical_name(type);

	if ( (db = bdb2i_cache_open( be, at_cn, BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_index_read NULL (could not open %s%s)\n", at_cn,
		    BDB2_SUFFIX, 0 );
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

	idl = bdb2i_idl_fetch( be, db, key );
    if ( tmpval != NULL ) {
        free( tmpval );
    }

	bdb2i_cache_close( be, db );

	Debug( LDAP_DEBUG_TRACE, "<= bdb2i_index_read %ld candidates\n",
	    idl ? ID_BLOCK_NIDS(idl) : 0, 0, 0 );
	return( idl );
}

static int
add_value(
    BackendDB		*be,
    struct dbcache	*db,
    char		*type,
    int			indextype,
    char		*val,
    ID			id
)
{
	int	rc;
	Datum   key;
	char	*tmpval = NULL;
	char	*realval = val;
	char	buf[BUFSIZ];

	char	prefix = index2prefix( indextype );

	ldbm_datum_init( key );

	Debug( LDAP_DEBUG_TRACE, "=> add_value( \"%c%s\" )\n", prefix, val, 0 );

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

	rc = bdb2i_idl_insert_key( be, db, key, id );

	if ( tmpval != NULL ) {
		free( tmpval );
	}

	ldap_pvt_thread_yield();

	/* Debug( LDAP_DEBUG_TRACE, "<= add_value %d\n", rc, 0, 0 ); */
	return( rc );
}

int
bdb2i_index_add_values(
    BackendDB		*be,
    char		*type,
    struct berval	**vals,
    ID			id
)
{
	char		*val, *p, *code, *w;
	unsigned	i, j, len;
	int		indexmask, syntax;
	char		buf[SUBLEN + 1];
	char		vbuf[BUFSIZ];
	char		*bigbuf;
	struct dbcache	*db;

	char		*at_cn;

	if( vals == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
			"=> bdb2i_index_add_values( \"%s\", NULL, %ld )\n",
			type, id, 0 );
		return 0;
	}

	Debug( LDAP_DEBUG_TRACE, "=> bdb2i_index_add_values( \"%s\", %ld )\n",
		type, id, 0 );
	attr_normalize( type );
	bdb2i_attr_masks( be->be_private, type, &indexmask, &syntax );
	if ( indexmask == 0 ) {
		return( 0 );
	}
	at_cn = at_canonical_name(type);

	if ( (db = bdb2i_cache_open( be, at_cn, BDB2_SUFFIX, LDBM_WRCREAT ))
	    == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= bdb2i_index_add_values -1 (could not open/create %s%s)\n",
		    at_cn, BDB2_SUFFIX, 0 );
		return( -1 );
	}

	for ( i = 0; vals[i] != NULL; i++ ) {
		/*
		 * presence index entry
		 */
		if ( indexmask & INDEX_PRESENCE ) {
			add_value( be, db, at_cn, INDEX_PRESENCE, "*", id );
		}

		Debug( LDAP_DEBUG_TRACE, "*** bdb2i_index_add_values syntax 0x%x syntax bin 0x%x\n",
		    syntax, SYNTAX_BIN, 0 );
		if ( syntax & SYNTAX_BIN ) {
			bdb2i_cache_close( be, db );
			return( 0 );
		}

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
		if ( indexmask & INDEX_EQUALITY ) {
			add_value( be, db, at_cn, INDEX_EQUALITY, val, id );
		}

		/*
		 * approximate index entry
		 */
		if ( indexmask & INDEX_APPROX ) {
			for ( w = first_word( val ); w != NULL;
			    w = next_word( w ) ) {
				if ( (code = phonetic( w )) != NULL ) {
					add_value( be, db, at_cn, INDEX_APPROX,
					    code, id );
					free( code );
				}
			}
		}

		/*
		 * substrings index entry
		 */
		if ( indexmask & INDEX_SUB ) {
			/* leading and trailing */
			if ( len > SUBLEN - 2 ) {
				buf[0] = '^';
				for ( j = 0; j < SUBLEN - 1; j++ ) {
					buf[j + 1] = val[j];
				}
				buf[SUBLEN] = '\0';

				add_value( be, db, at_cn, INDEX_SUB, buf, id );

				p = val + len - SUBLEN + 1;
				for ( j = 0; j < SUBLEN - 1; j++ ) {
					buf[j] = p[j];
				}
				buf[SUBLEN - 1] = '$';
				buf[SUBLEN] = '\0';

				add_value( be, db, at_cn, INDEX_SUB, buf, id );
			}

			/* any */
			for ( p = val; p < (val + len - SUBLEN + 1); p++ ) {
				for ( j = 0; j < SUBLEN; j++ ) {
					buf[j] = p[j];
				}
				buf[SUBLEN] = '\0';

				add_value( be, db, at_cn, INDEX_SUB, buf, id );
			}
		}

		if ( bigbuf != NULL ) {
			free( bigbuf );
		}
	}
	bdb2i_cache_close( be, db );

	return( 0 );
}

static int
index2prefix( int indextype )
{
	int	prefix;

	switch ( indextype ) {
	case INDEX_EQUALITY:
		prefix = EQ_PREFIX;
		break;
	case INDEX_APPROX:
		prefix = APPROX_PREFIX;
		break;
	case INDEX_SUB:
		prefix = SUB_PREFIX;
		break;
	default:
		prefix = UNKNOWN_PREFIX;
		break;
	}

	return( prefix );
}
