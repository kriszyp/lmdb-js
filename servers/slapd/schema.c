/* schema.c - routines to enforce schema definitions */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"

extern Attribute	*attr_find();
extern char		**str2charray();
extern void		charray_merge();

extern struct objclass	*global_oc;
extern int		global_schemacheck;

static struct objclass	*oc_find();
static int		oc_check_required();
static int		oc_check_allowed();

/*
 * oc_check - check that entry e conforms to the schema required by
 * its object class(es). returns 0 if so, non-zero otherwise.
 */

int
oc_schema_check( Entry *e )
{
	Attribute	*a, *aoc;
	struct objclass	*oc;
	int		i;
	int		ret = 0;

	/* find the object class attribute - could error out here */
	if ( (aoc = attr_find( e->e_attrs, "objectclass" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No object class for entry (%s)\n",
		    e->e_dn, 0, 0 );
		return( 0 );
	}

	/* check that the entry has required attrs for each oc */
	for ( i = 0; aoc->a_vals[i] != NULL; i++ ) {
		if ( oc_check_required( e, aoc->a_vals[i]->bv_val ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), required attr (%s) missing\n",
			    e->e_dn, aoc->a_vals[i]->bv_val, 0 );
			ret = 1;
		}
	}

	if ( ret != 0 ) {
	    return( ret );
	}

	/* check that each attr in the entry is allowed by some oc */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		if ( oc_check_allowed( a->a_type, aoc->a_vals ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr (%s) not allowed\n",
			    e->e_dn, a->a_type, 0 );
			ret = 1;
		}
	}

	return( ret );
}

static int
oc_check_required( Entry *e, char *ocname )
{
	struct objclass	*oc;
	int		i;
	Attribute	*a;

	/* find global oc defn. it we don't know about it assume it's ok */
	if ( (oc = oc_find( ocname )) == NULL ) {
		return( 0 );
	}

	/* check for empty oc_required */
	if(oc->oc_required == NULL) {
		return( 0 );
	}

	/* for each required attribute */
	for ( i = 0; oc->oc_required[i] != NULL; i++ ) {
		/* see if it's in the entry */
		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
			if ( strcasecmp( a->a_type, oc->oc_required[i] )
			    == 0 ) {
				break;
			}
		}

		/* not there => schema violation */
		if ( a == NULL ) {
			return( 1 );
		}
	}

	return( 0 );
}

static int
oc_check_allowed( char *type, struct berval **ocl )
{
	struct objclass	*oc;
	int		i, j;

	/* always allow objectclass attribute */
	if ( strcasecmp( type, "objectclass" ) == 0 ) {
		return( 0 );
	}

	/* check that the type appears as req or opt in at least one oc */
	for ( i = 0; ocl[i] != NULL; i++ ) {
		/* if we know about the oc */
		if ( (oc = oc_find( ocl[i]->bv_val )) != NULL ) {
			/* does it require the type? */
			for ( j = 0; oc->oc_required != NULL && 
				oc->oc_required[j] != NULL; j++ ) {
				if ( strcasecmp( oc->oc_required[j], type )
				    == 0 ) {
					return( 0 );
				}
			}
			/* does it allow the type? */
			for ( j = 0; oc->oc_allowed != NULL && 
				oc->oc_allowed[j] != NULL; j++ ) {
				if ( strcasecmp( oc->oc_allowed[j], type )
				    == 0 || strcmp( oc->oc_allowed[j], "*" )
				    == 0 )
				{
					return( 0 );
				}
			}
			/* maybe the next oc allows it */

		/* we don't know about the oc. assume it allows it */
		} else {
			return( 0 );
		}
	}

	/* not allowed by any oc */
	return( 1 );
}

static struct objclass *
oc_find( char *ocname )
{
	struct objclass	*oc;

	for ( oc = global_oc; oc != NULL; oc = oc->oc_next ) {
		if ( strcasecmp( oc->oc_name, ocname ) == 0 ) {
			return( oc );
		}
	}

	return( NULL );
}

#ifdef LDAP_DEBUG

static
oc_print( struct objclass *oc )
{
	int	i;

	printf( "objectclass %s\n", oc->oc_name );
	if ( oc->oc_required != NULL ) {
		printf( "\trequires %s", oc->oc_required[0] );
		for ( i = 1; oc->oc_required[i] != NULL; i++ ) {
			printf( ",%s", oc->oc_required[i] );
		}
		printf( "\n" );
	}
	if ( oc->oc_allowed != NULL ) {
		printf( "\tallows %s", oc->oc_allowed[0] );
		for ( i = 1; oc->oc_allowed[i] != NULL; i++ ) {
			printf( ",%s", oc->oc_allowed[i] );
		}
		printf( "\n" );
	}
}

#endif
