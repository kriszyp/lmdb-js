/* entry.c - routines for dealing with entries */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

void	entry_free();
char	*entry2str();

static unsigned char	*ebuf;	/* buf returned by entry2str 		 */
static unsigned char	*ecur;	/* pointer to end of currently used ebuf */
static int		emaxsize;/* max size of ebuf	     		 */

Entry *
str2entry( char	*s )
{
	int		i;
	Entry		*e;
	Attribute	**a;
	char		*type;
	char		*value;
	char		*next;
	int		vlen, nvals, maxvals;
	struct berval	bval;
	struct berval	*vals[2];
	char		ptype[64];

	/*
	 * In string format, an entry looks like this:
	 *
	 *	<id>\n
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

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	/* check to see if there's an id included */
	next = s;
	if ( isdigit( *s ) ) {
		e->e_id = atoi( s );
		if ( (s = str_getline( &next )) == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (missing newline after id)\n",
			    0, 0, 0 );
			return( NULL );
		}
	}

	/* dn + attributes */
	e->e_attrs = NULL;
	vals[0] = &bval;
	vals[1] = NULL;
	ptype[0] = '\0';
	while ( (s = str_getline( &next )) != NULL ) {
		if ( *s == '\n' || *s == '\0' ) {
			break;
		}

		if ( str_parse_line( s, &type, &value, &vlen ) != 0 ) {
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
			if ( e->e_dn != NULL ) {
				Debug( LDAP_DEBUG_ANY,
    "str2entry: entry %d has multiple dns \"%s\" and \"%s\" (second ignored)\n",
				    e->e_id, e->e_dn, value );
				continue;
			}
			e->e_dn = strdup( value );
			continue;
		}

		bval.bv_val = value;
		bval.bv_len = vlen;
		if ( attr_merge_fast( e, type, vals, nvals, 1, &maxvals, &a )
		    != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (attr_merge)\n", 0, 0, 0 );
			return( NULL );
		}
		nvals++;
	}

	/* check to make sure there was a dn: line */
	if ( e->e_dn == NULL ) {
		Debug( LDAP_DEBUG_ANY, "str2entry: entry %d has no dn\n",
		    e->e_id, 0, 0 );
		entry_free( e );
		return( NULL );
	}

	Debug( LDAP_DEBUG_TRACE, "<= str2entry 0x%x\n", e, 0, 0 );
	return( e );
}

#define GRABSIZE	BUFSIZ

#define MAKE_SPACE( n )	{ \
		while ( ecur + (n) > ebuf + emaxsize ) { \
			int	offset; \
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
    int		*len,
    int		printid
)
{
	Attribute	*a;
	struct berval	*bv;
	int		i, tmplen;

	/*
	 * In string format, an entry looks like this:
	 *	<id>\n
	 *	dn: <dn>\n
	 *	[<attr>: <value>\n]*
	 */

	ecur = ebuf;

	if ( printid ) {
		/* id + newline */
		MAKE_SPACE( 10 );
		sprintf( (char *) ecur, "%ld\n", e->e_id );
		ecur = (unsigned char *) strchr( (char *) ecur, '\0' );
	}

	/* put the dn */
	if ( e->e_dn != NULL ) {
		/* put "dn: <dn>" */
		tmplen = strlen( e->e_dn );
		MAKE_SPACE( LDIF_SIZE_NEEDED( 2, tmplen ));
		put_type_and_value( (char **) &ecur, "dn", e->e_dn, tmplen );
	}

	/* put the attributes */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		/* put "<type>:[:] <value>" line for each value */
		for ( i = 0; a->a_vals[i] != NULL; i++ ) {
			bv = a->a_vals[i];
			tmplen = strlen( a->a_type );
			MAKE_SPACE( LDIF_SIZE_NEEDED( tmplen, bv->bv_len ));
			put_type_and_value( (char **) &ecur, a->a_type,
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
	int		i;
	Attribute	*a, *next;

	if ( e->e_dn != NULL ) {
		free( e->e_dn );
	}
	for ( a = e->e_attrs; a != NULL; a = next ) {
		next = a->a_next;
		attr_free( a );
	}
	free( e );
}
