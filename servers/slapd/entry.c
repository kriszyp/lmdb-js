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
	int rc;
	Entry		*e;
	Attribute	**a = NULL;
	char		*type;
	struct berval value;
	struct berval	*vals[2];
	AttributeDescription *ad;
	const char *text;
	char	*next;

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

	/* initialize reader/writer lock */
	e = (Entry *) ch_malloc( sizeof(Entry) );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
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
	vals[0] = &value;
	vals[1] = NULL;

	next = s;
	while ( (s = ldif_getline( &next )) != NULL ) {
		if ( *s == '\n' || *s == '\0' ) {
			break;
		}

		if ( ldif_parse_line( s, &type, &value.bv_val, &value.bv_len ) != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (parse_line)\n", 0, 0, 0 );
			continue;
		}

		if ( strcasecmp( type, "dn" ) == 0 ) {
			free( type );

			if ( e->e_dn != NULL ) {
				Debug( LDAP_DEBUG_ANY,
 "str2entry: entry %ld has multiple dns \"%s\" and \"%s\" (second ignored)\n",
				    e->e_id, e->e_dn,
					value.bv_val != NULL ? value.bv_val : "" );
				if( value.bv_val != NULL ) free( value.bv_val );
				continue;
			}

			e->e_dn = value.bv_val != NULL ? value.bv_val : ch_strdup( "" );
			continue;
		}

		ad = NULL;
		rc = slap_str2ad( type, &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			Debug( slapMode & SLAP_TOOL_MODE
				? LDAP_DEBUG_ANY : LDAP_DEBUG_TRACE,
				"<= str2entry: str2ad(%s): %s\n", type, text, 0 );

			if( slapMode & SLAP_TOOL_MODE ) {
				entry_free( e );
				free( value.bv_val );
				free( type );
				return NULL;
			}

			rc = slap_str2undef_ad( type, &ad, &text );

			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"<= str2entry: str2undef_ad(%s): %s\n",
						type, text, 0 );
				entry_free( e );
				free( value.bv_val );
				free( type );
				return NULL;
			}
		}

		if( slapMode & SLAP_TOOL_MODE ) {
			slap_syntax_validate_func *validate =
				ad->ad_type->sat_syntax->ssyn_validate;

			if( !validate ) {
				Debug( LDAP_DEBUG_ANY,
					"str2entry: no validator for syntax %s\n",
					ad->ad_type->sat_syntax->ssyn_oid, 0, 0 );
				entry_free( e );
				free( value.bv_val );
				free( type );
				return NULL;
			}

			/*
			 * validate value per syntax
			 */
			rc = validate( ad->ad_type->sat_syntax, &value );

			if( rc != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"str2entry: invalid value for syntax %s\n",
					ad->ad_type->sat_syntax->ssyn_oid, 0, 0 );
				entry_free( e );
				free( value.bv_val );
				free( type );
				return NULL;
			}
		}

		rc = attr_merge( e, ad, vals );

		ad_free( ad, 1 );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "<= str2entry NULL (attr_merge)\n", 0, 0, 0 );
			entry_free( e );
			free( value.bv_val );
			free( type );
			return( NULL );
		}

		free( type );
		free( value.bv_val );
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

	Debug(LDAP_DEBUG_TRACE, "<= str2entry(%s) -> 0x%lx\n",
		e->e_dn, (unsigned long) e, 0 );

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
			tmplen = a->a_desc->ad_cname->bv_len;
			MAKE_SPACE( LDIF_SIZE_NEEDED( tmplen, bv->bv_len ));
			ldif_sput( (char **) &ecur, LDIF_PUT_VALUE,
				a->a_desc->ad_cname->bv_val,
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

#define SLAPD_SLEEPY 1
#ifdef SLAPD_SLEEPY

/* a DER encoded entry looks like:
 *
 * entry :== SEQUENCE {
 *		dn		DistinguishedName,
 *		ndn		NormalizedDistinguishedName,
 *		attrs	SEQUENCE OF SEQUENCE {
 *			type	AttributeType,
 *			values	SET OF AttributeValue
 *		}
 * }
 *
 * Encoding/Decoding of DER should be much faster than LDIF
 */

int entry_decode( struct berval *bv, Entry **entry )
{
	int rc;
	BerElement	*ber;
	Entry		*e;
	ber_tag_t	tag;
	ber_len_t	len;
	char *last;

	ber = ber_init( bv );
	if( ber == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= entry_decode: ber_init failed\n",
		    0, 0, 0 );
		return LDAP_LOCAL_ERROR;
	}

	/* initialize reader/writer lock */
	e = (Entry *) ch_malloc( sizeof(Entry) );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "<= entry_decode: entry allocation failed\n",
		    0, 0, 0 );
		return LDAP_LOCAL_ERROR;
	}

	/* initialize entry */
	e->e_id = NOID;
	e->e_dn = NULL;
	e->e_ndn = NULL;
	e->e_attrs = NULL;
	e->e_private = NULL;

	tag = ber_scanf( ber, "{aa" /*"}"*/, &e->e_dn, &e->e_ndn );
	if( tag == LBER_ERROR ) {
		free( e );
		return LDAP_PROTOCOL_ERROR;
	}

	Debug( LDAP_DEBUG_TRACE,
	    "entry_decode: \"%s\"\n",
	    e->e_dn, 0, 0 );

	/* get the attrs */
	for ( tag = ber_first_element( ber, &len, &last );
		tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
	{
		struct berval *type;
		struct berval **vals;
		AttributeDescription *ad;
		const char *text;

		tag = ber_scanf( ber, "{O{V}}", &type, &vals );

		if ( tag == LBER_ERROR ) {
			Debug( LDAP_DEBUG_ANY, "entry_decode: decoding error\n", 0, 0, 0 );
			entry_free( e );
			return LDAP_PROTOCOL_ERROR;
		}

		if ( vals == NULL ) {
			Debug( LDAP_DEBUG_ANY, "entry_decode: no values for type %s\n",
				type, 0, 0 );
			ber_bvfree( type );
			entry_free( e );
			return LDAP_PROTOCOL_ERROR;
		}

		ad = NULL;
		rc = slap_bv2ad( type, &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_TRACE,
				"<= entry_decode: str2ad(%s): %s\n", type, text, 0 );

			rc = slap_bv2undef_ad( type, &ad, &text );

			if( rc != LDAP_SUCCESS ) {
				Debug( LDAP_DEBUG_ANY,
					"<= entry_decode: str2undef_ad(%s): %s\n",
						type, text, 0 );
				ber_bvfree( type );
				ber_bvecfree( vals );
				entry_free( e );
				return rc;
			}
		}

		rc = attr_merge( e, ad, vals );
		ad_free( ad, 1 );

		if( rc != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "<= entry_decode: attr_merge failed\n", 0, 0, 0 );
			ber_bvfree( type );
			ber_bvecfree( vals );
			entry_free( e );
			return LDAP_LOCAL_ERROR;
		}

		free( type );
		ber_bvecfree( vals );
	}

	rc = ber_scanf( ber, /*"{"*/  "}" );
	if( rc < 0 ) {
		entry_free( e );
		return LDAP_PROTOCOL_ERROR;
	}

	Debug(LDAP_DEBUG_TRACE, "<= entry_decode(%s)\n",
		e->e_dn, 0, 0 );

	*entry = e;
	return LDAP_SUCCESS;
}

int entry_encode(
	Entry *e,
	struct berval **bv )
{
	int rc = -1;
	Attribute *a;
	BerElement *ber;
	
	Debug( LDAP_DEBUG_TRACE, "=> entry_encode(0x%08lx): %s\n",
		e->e_id, e->e_dn, 0 );

	ber = ber_alloc_t( LBER_USE_DER );
	if( ber == NULL ) {
		goto done;
	}

	rc = ber_printf( ber, "{ss{" /*"}}"*/, e->e_dn, e->e_ndn );
	if( rc < 0 ) {
		goto done;
	}

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		rc = ber_printf( ber, "{O{V}}",
			a->a_desc->ad_cname,
			a->a_vals );
		if( rc < 0 ) {
			goto done;
		}
	}

	rc = ber_printf( ber, /*"{{"*/ "}}" );
	if( rc < 0 ) {
		goto done;
	}

	rc = ber_flatten( ber, bv );

done:
	ber_free( ber, 1 );
	if( rc ) {
		Debug( LDAP_DEBUG_ANY, "=> entry_encode(0x%08lx): failed (%d)\n",
			e->e_id, rc, 0 );
	}
	return rc;
}
#endif
