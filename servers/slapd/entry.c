/* entry.c - routines for dealing with entries */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"

static unsigned char	*ebuf;	/* buf returned by entry2str 		 */
static unsigned char	*ecur;	/* pointer to end of currently used ebuf */
static int		emaxsize;/* max size of ebuf	     		 */

int entry_destroy(void)
{
	free( ebuf );
	ebuf = NULL;
	ecur = NULL;
	emaxsize = 0;
	return 0;
}

Entry *
str2entry( char *s )
{
	Entry		*e;
	Attribute	**a = NULL;
	char		*type;
	char		*value;
	char		*next;
	ber_len_t	vlen;
	int		nvals = 0;
	int		maxvals = 0;
	struct berval	bval;
	struct berval	*vals[2];
	char		ptype[64];

	/*
	 * LDIF is used as the string format.
	 * An entry looks like this:
	 *
	 *	dn: <dn>\n
	 *	[<attr>:[:] <value>\n]
	 *	[<tab><continuedvalue>\n]*
	 *	...
	 *
	 * If a double colon is used after a type, it means the
	 * following value is encoded as a base 64 string.  This
	 * happens if the value contains a non-printing character
	 * or newline.
	 */

	Debug( LDAP_DEBUG_TRACE, "=> str2entry\n",
		s ? s : "NULL", 0, 0 );

	next = s;

	/* initialize reader/writer lock */
	e = (Entry *) ch_malloc( sizeof(Entry) );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= str2entry NULL (entry allocation failed)\n",
		    0, 0, 0 );
		return( NULL );
	}

	/* initialize entry */
	e->e_id = NOID;
	e->e_dn = NULL;
	e->e_ndn = NULL;
	e->e_attrs = NULL;
	e->e_private = NULL;

	/* dn + attributes */
	vals[0] = &bval;
	vals[1] = NULL;
	ptype[0] = '\0';

	while ( (s = ldif_getline( &next )) != NULL ) {
		if ( *s == '\n' || *s == '\0' ) {
			break;
		}

		if ( ldif_parse_line( s, &type, &value, &vlen ) != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (parse_line)\n", 0, 0, 0 );
			continue;
		}

		if ( strcasecmp( type, ptype ) != 0 ) {
			strncpy( ptype, type, sizeof(ptype) - 1 );
			nvals = 0;
			maxvals = 0;
			a = NULL;
		}

		if ( strcasecmp( type, "dn" ) == 0 ) {
			free( type );

			if ( e->e_dn != NULL ) {
				Debug( LDAP_DEBUG_ANY,
 "str2entry: entry %ld has multiple dns \"%s\" and \"%s\" (second ignored)\n",
				    e->e_id, e->e_dn,
					value != NULL ? value : NULL );
				if( value != NULL ) free( value );
				continue;
			}
			e->e_dn = value != NULL ? value : ch_strdup( "" );
			continue;
		}

		bval.bv_val = value;
		bval.bv_len = vlen;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		/* not yet implemented */
#else
		if ( attr_merge_fast( e, type, vals, nvals, 1, &maxvals, &a )
		    != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (attr_merge)\n", 0, 0, 0 );
			entry_free( e );
			free( value );
			free( type );
			return( NULL );
		}
#endif

		free( value );
		free( type );
		nvals++;
	}

	/* check to make sure there was a dn: line */
	if ( e->e_dn == NULL ) {
		Debug( LDAP_DEBUG_ANY, "str2entry: entry %ld has no dn\n",
		    e->e_id, 0, 0 );
		entry_free( e );
		return( NULL );
	}

	/* generate normalized dn */
	e->e_ndn = ch_strdup( e->e_dn );
	(void) dn_normalize( e->e_ndn );

	Debug(LDAP_DEBUG_TRACE, "<= str2entry(%s) -> %ld (0x%lx)\n",
		e->e_dn, e->e_id, (unsigned long)e );

	return( e );
}

#define GRABSIZE	BUFSIZ

#define MAKE_SPACE( n )	{ \
		while ( ecur + (n) > ebuf + emaxsize ) { \
			ptrdiff_t	offset; \
			offset = (int) (ecur - ebuf); \
			ebuf = (unsigned char *) ch_realloc( (char *) ebuf, \
			    emaxsize + GRABSIZE ); \
			emaxsize += GRABSIZE; \
			ecur = ebuf + offset; \
		} \
	}

char *
entry2str(
    Entry	*e,
    int		*len )
{
	Attribute	*a;
	struct berval	*bv;
	int		i, tmplen;

	/*
	 * In string format, an entry looks like this:
	 *	dn: <dn>\n
	 *	[<attr>: <value>\n]*
	 */

	ecur = ebuf;

	/* put the dn */
	if ( e->e_dn != NULL ) {
		/* put "dn: <dn>" */
		tmplen = strlen( e->e_dn );
		MAKE_SPACE( LDIF_SIZE_NEEDED( 2, tmplen ));
		ldif_sput( (char **) &ecur, LDIF_PUT_VALUE, "dn", e->e_dn, tmplen );
	}

	/* put the attributes */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		/* put "<type>:[:] <value>" line for each value */
		for ( i = 0; a->a_vals[i] != NULL; i++ ) {
			bv = a->a_vals[i];
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			tmplen = a->a_desc->ad_cname->bv_len;
#else
			tmplen = strlen( a->a_type );
#endif
			MAKE_SPACE( LDIF_SIZE_NEEDED( tmplen, bv->bv_len ));
			ldif_sput( (char **) &ecur, LDIF_PUT_VALUE,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				a->a_desc->ad_cname->bv_val,
#else
				a->a_type,
#endif
			    bv->bv_val, bv->bv_len );
		}
	}
	MAKE_SPACE( 1 );
	*ecur = '\0';
	*len = ecur - ebuf;

	return( (char *) ebuf );
}

void
entry_free( Entry *e )
{
	Attribute	*a, *next;

	if ( e->e_dn != NULL ) {
		free( e->e_dn );
		e->e_dn = NULL;
	}
	if ( e->e_ndn != NULL ) {
		free( e->e_ndn );
		e->e_ndn = NULL;
	}
	for ( a = e->e_attrs; a != NULL; a = next ) {
		next = a->a_next;
		attr_free( a );
	}
	e->e_attrs = NULL;
	e->e_private = NULL;
	free( e );
}

/*
 * These routines are used only by Backend.
 *
 * the Entry has three entry points (ways to find things):
 *
 * 	by entry	e.g., if you already have an entry from the cache
 *			and want to delete it. (really by entry ptr)
 *	by dn		e.g., when looking for the base object of a search
 *	by id		e.g., for search candidates
 *
 * these correspond to three different avl trees that are maintained.
 */

int
entry_cmp( Entry *e1, Entry *e2 )
{
	return( e1 < e2 ? -1 : (e1 > e2 ? 1 : 0) );
}

int
entry_dn_cmp( Entry *e1, Entry *e2 )
{
	/* compare their normalized UPPERCASED dn's */
	return( strcmp( e1->e_ndn, e2->e_ndn ) );
}

int
entry_id_cmp( Entry *e1, Entry *e2 )
{
	return( e1->e_id < e2->e_id ? -1 : (e1->e_id > e2->e_id ? 1 : 0) );
}

