/* entry.c - routines for dealing with entries */

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

Entry *
str2entry( char	*s )
{
	int			id = 0;
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

	/* check to see if there's an id included */
	next = s;
	if ( isdigit( *s ) ) {
		id = atoi( s );
		if ( (s = str_getline( &next )) == NULL ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (missing newline after id)\n",
			    0, 0, 0 );
			return( NULL );
		}
	}

	/* initialize reader/writer lock */
	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	if( e == NULL ) {
		Debug( LDAP_DEBUG_TRACE,
		    "<= str2entry NULL (entry allocation failed)\n",
		    0, 0, 0 );
		return( NULL );
	}
	e->e_id = id;

	entry_rdwr_init(e);

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
 "str2entry: entry %lu has multiple dns \"%s\" and \"%s\" (second ignored)\n",
				    e->e_id, e->e_dn, value );
				continue;
			}
			e->e_dn = ch_strdup( value );

			if ( e->e_ndn != NULL ) {
				Debug( LDAP_DEBUG_ANY,
 "str2entry: entry %lu already has a normalized dn \"%s\" for \"%s\" (first ignored)\n",
				    e->e_id, e->e_ndn, value );
				free( e->e_ndn );
			}
			e->e_ndn = dn_normalize_case( ch_strdup( value ) );
			continue;
		}

		bval.bv_val = value;
		bval.bv_len = vlen;
		if ( attr_merge_fast( e, type, vals, nvals, 1, &maxvals, &a )
		    != 0 ) {
			Debug( LDAP_DEBUG_TRACE,
			    "<= str2entry NULL (attr_merge)\n", 0, 0, 0 );
			entry_free( e );
			return( NULL );
		}
		nvals++;
	}

	/* check to make sure there was a dn: line */
	if ( e->e_dn == NULL ) {
		Debug( LDAP_DEBUG_ANY, "str2entry: entry %lu has no dn\n",
		    e->e_id, 0, 0 );
		entry_free( e );
		return( NULL );
	}

	if ( e->e_ndn == NULL ) {
		Debug( LDAP_DEBUG_ANY,
			"str2entry: entry %lu (\"%s\") has no normalized dn\n",
		    e->e_id, e->e_dn, 0 );
		entry_free( e );
		return( NULL );
	}

	Debug(LDAP_DEBUG_TRACE, "<= str2entry 0x%lx\n", (unsigned long)e, 0,0);

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

	/* check that no reader/writer locks exist */

	if ( ldap_pvt_thread_rdwr_wtrylock( &e->e_rdwr ) == 
		LDAP_PVT_THREAD_EBUSY )
	{
		Debug( LDAP_DEBUG_ANY, "entry_free(%ld): active (%d, %d)\n",
			e->e_id,
			ldap_pvt_thread_rdwr_readers( &e->e_rdwr ),
			ldap_pvt_thread_rdwr_writers( &e->e_rdwr ));

#ifdef LDAP_DEBUG
		assert(!ldap_pvt_thread_rdwr_active( &e->e_rdwr ));
#endif
	}

	if ( e->e_dn != NULL ) {
		free( e->e_dn );
	}
	if ( e->e_ndn != NULL ) {
		free( e->e_ndn );
	}
	for ( a = e->e_attrs; a != NULL; a = next ) {
		next = a->a_next;
		attr_free( a );
	}
	free( e );
}

int
entry_rdwr_lock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%slock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
	if (rw)
		return ldap_pvt_thread_rdwr_wlock(&e->e_rdwr);
	else
		return ldap_pvt_thread_rdwr_rlock(&e->e_rdwr);
}

int
entry_rdwr_rlock(Entry *e)
{
	return entry_rdwr_lock( e, 0 );
}

int
entry_rdwr_wlock(Entry *e)
{
	return entry_rdwr_lock( e, 1 );
}

int
entry_rdwr_trylock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%strylock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
	if (rw)
		return ldap_pvt_thread_rdwr_wtrylock(&e->e_rdwr);
	else
		return ldap_pvt_thread_rdwr_rtrylock(&e->e_rdwr);
}

int
entry_rdwr_unlock(Entry *e, int rw)
{
	Debug( LDAP_DEBUG_ARGS, "entry_rdwr_%sunlock: ID: %ld\n",
		rw ? "w" : "r", e->e_id, 0);
	if (rw)
		return ldap_pvt_thread_rdwr_wunlock(&e->e_rdwr);
	else
		return ldap_pvt_thread_rdwr_runlock(&e->e_rdwr);
}

int
entry_rdwr_runlock(Entry *e)
{
	return entry_rdwr_unlock( e, 0 );
}

int
entry_rdwr_wunlock(Entry *e)
{
	return entry_rdwr_unlock( e, 1 );
}

int
entry_rdwr_init(Entry *e)
{
	return ldap_pvt_thread_rdwr_init( &e->e_rdwr );
}
