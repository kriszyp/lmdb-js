/* schema_check.c - routines to enforce schema definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

static char *	oc_check_required(Entry *e, char *ocname);
static int		oc_check_allowed(char *type, struct berval **ocl);

/*
 * entry_schema_check - check that entry e conforms to the schema required
 * by its object class(es).
 *
 * returns 0 if so, non-zero otherwise.
 */

int
schema_check_entry( Entry *e )
{
	Attribute	*a, *aoc;
	ObjectClass *oc;
	int		i;
	int		ret = 0;

	if( !global_schemacheck ) return 0;

	/* find the object class attribute - could error out here */
	if ( (aoc = attr_find( e->e_attrs, "objectclass" )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No object class for entry (%s)\n",
		    e->e_dn, 0, 0 );
		return( 1 );
	}

	/* check that the entry has required attrs for each oc */
	for ( i = 0; aoc->a_vals[i] != NULL; i++ ) {
		if ( (oc = oc_find( aoc->a_vals[i]->bv_val )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"Objectclass \"%s\" not defined\n",
				aoc->a_vals[i]->bv_val, 0, 0 );
		}
		else
		{
			char *s = oc_check_required( e, aoc->a_vals[i]->bv_val );

			if (s != NULL) {
				Debug( LDAP_DEBUG_ANY,
					"Entry (%s), oc \"%s\" requires attr \"%s\"\n",
					e->e_dn, aoc->a_vals[i]->bv_val, s );
				ret = 1;
			}
		}
	}

	if ( ret != 0 ) {
	    return( ret );
	}

	/* check that each attr in the entry is allowed by some oc */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		if ( oc_check_allowed( a->a_desc.ad_type, aoc->a_vals ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, a->a_desc.ad_cname->bv_val, 0 );
			ret = 1;
		}
#else
		if ( oc_check_allowed( a->a_type, aoc->a_vals ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, a->a_type, 0 );
			ret = 1;
		}
#endif
	}

	return( ret );
}

static char *
oc_check_required( Entry *e, char *ocname )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i;
	Attribute	*a;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_required entry (%s), objectclass \"%s\"\n",
	       e->e_dn, ocname, 0 );

	/* find global oc defn. it we don't know about it assume it's ok */
	if ( (oc = oc_find( ocname )) == NULL ) {
		return( 0 );
	}

	/* check for empty oc_required */
	if(oc->soc_required == NULL) {
		return( 0 );
	}

	/* for each required attribute */
	for ( i = 0; oc->soc_required[i] != NULL; i++ ) {
		at = oc->soc_required[i];
		/* see if it's in the entry */
		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			if( a->a_desc.ad_type == at ) {
				break;
			}
#else
			char		**pp;

			if ( at->sat_oid &&
			     strcmp( a->a_type, at->sat_oid ) == 0 ) {
				break;
			}
			pp = at->sat_names;
			if ( pp  == NULL ) {
				/* Empty name list => not found */
				a = NULL;
				break;
			}
			while ( *pp ) {
				if ( strcasecmp( a->a_type, *pp ) == 0 ) {
					break;
				}
				pp++;
			}
			if ( *pp ) {
				break;
			}
#endif
		}
		/* not there => schema violation */
		if ( a == NULL ) {
			if ( at->sat_names && at->sat_names[0] ) {
				return at->sat_names[0];
			} else {
				return at->sat_oid;
			}
		}
	}

	return( NULL );
}

static int
oc_check_allowed( char *type, struct berval **ocl )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i, j;
	char		**pp;
	char		*p, *t;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_allowed type \"%s\"\n", type, 0, 0 );

	/* always allow objectclass attribute */
	if ( strcasecmp( type, "objectclass" ) == 0 ) {
		return( 0 );
	}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	/* Treat any attribute type with option as an unknown attribute type */
	/*
	 * The "type" we have received is actually an AttributeDescription.
	 * Let's find out the corresponding type.
	 */
	p = strchr( type, ';' );
	if ( p ) {
		t = ch_malloc( p-type+1 );
		strncpy( t, type, p-type );
		t[p-type] = '\0';
		Debug( LDAP_DEBUG_TRACE,
		       "oc_check_allowed type \"%s\" from \"%s\"\n",
		       t, type, 0 );

	} else
#endif
	{
		t = type;
	}


	/*
	 * All operational attributions are allowed by schema rules.
	 */
	if ( oc_check_op_attr( t ) ) {
		return( 0 );
	}

	/* check that the type appears as req or opt in at least one oc */
	for ( i = 0; ocl[i] != NULL; i++ ) {
		/* if we know about the oc */
		if ( (oc = oc_find( ocl[i]->bv_val )) != NULL ) {
			/* does it require the type? */
			for ( j = 0; oc->soc_required != NULL && 
				oc->soc_required[j] != NULL; j++ ) {
				at = oc->soc_required[j];
				if ( at->sat_oid &&
				     strcmp(at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return( 0 );
					}
					pp++;
				}
			}
			/* does it allow the type? */
			for ( j = 0; oc->soc_allowed != NULL && 
				oc->soc_allowed[j] != NULL; j++ ) {
				at = oc->soc_allowed[j];
				if ( at->sat_oid &&
				     strcmp( at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ||
					     strcmp( *pp, "*" ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return( 0 );
					}
					pp++;
				}
			}
			/* maybe the next oc allows it */

#ifdef OC_UNDEFINED_IMPLES_EXTENSIBLE
		/* we don't know about the oc. assume it allows it */
		} else {
			if ( t != type )
				ldap_memfree( t );
			return( 0 );
#endif
		}
	}

	if ( t != type )
		ldap_memfree( t );
	/* not allowed by any oc */
	return( 1 );
}
