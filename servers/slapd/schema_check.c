/* schema_check.c - routines to enforce schema definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static int		oc_check_allowed(char *type, struct berval **oclist);
#endif
static char *	oc_check_required(Entry *e, struct berval *ocname);

/*
 * entry_schema_check - check that entry e conforms to the schema required
 * by its object class(es).
 *
 * returns 0 if so, non-zero otherwise.
 */

int
entry_schema_check( 
	Entry *e, Attribute *oldattrs, const char** text )
{
	Attribute	*a, *aoc;
	ObjectClass *oc;
	int		i;
	int		ret;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
#else
	static const char *ad_objectClass = "objectclass";
#endif

	if( !global_schemacheck ) return LDAP_SUCCESS;

	/* find the object class attribute - could error out here */
	if ( (aoc = attr_find( e->e_attrs, ad_objectClass )) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "No object class for entry (%s)\n",
		    e->e_dn, 0, 0 );
		*text = "no objectclass attribute";
		return oldattrs != NULL
			? LDAP_OBJECT_CLASS_VIOLATION
			: LDAP_NO_OBJECT_CLASS_MODS;
	}

	ret = LDAP_SUCCESS;

	/* check that the entry has required attrs for each oc */
	for ( i = 0; aoc->a_vals[i] != NULL; i++ ) {
		if ( (oc = oc_find( aoc->a_vals[i]->bv_val )) == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"entry_check_schema(%s): objectclass \"%s\" not defined\n",
				e->e_dn, aoc->a_vals[i]->bv_val, 0 );

		} else {
			char *s = oc_check_required( e, aoc->a_vals[i] );

			if (s != NULL) {
				Debug( LDAP_DEBUG_ANY,
					"Entry (%s), oc \"%s\" requires attr \"%s\"\n",
					e->e_dn, aoc->a_vals[i]->bv_val, s );
				*text = "missing required attribute";
				ret = LDAP_OBJECT_CLASS_VIOLATION;
				break;
			}
		}
	}

	if ( ret != LDAP_SUCCESS ) {
	    return ret;
	}

	/* check that each attr in the entry is allowed by some oc */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
		ret = oc_check_allowed( a->a_desc->ad_type, aoc->a_vals );
#else
		ret = oc_check_allowed( a->a_type, aoc->a_vals );
#endif
		if ( ret != 0 ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			char *type = a->a_desc->ad_cname->bv_val;
#else
			char *type = a->a_type;
#endif
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, type, 0 );
			*text = "attribute not allowed";
			break;
		}
	}

	return( ret );
}

static char *
oc_check_required( Entry *e, struct berval *ocname )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i;
	Attribute	*a;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_required entry (%s), objectclass \"%s\"\n",
	       e->e_dn, ocname->bv_val, 0 );

	/* find global oc defn. it we don't know about it assume it's ok */
	if ( (oc = oc_find( ocname->bv_val )) == NULL ) {
		return NULL;
	}

	/* check for empty oc_required */
	if(oc->soc_required == NULL) {
		return NULL;
	}

	/* for each required attribute */
	for ( i = 0; oc->soc_required[i] != NULL; i++ ) {
		at = oc->soc_required[i];
		/* see if it's in the entry */
		for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			if( a->a_desc->ad_type == at ) {
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
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			return at->sat_cname;
#else
			if ( at->sat_names && at->sat_names[0] ) {
				return at->sat_names[0];
			} else {
				return at->sat_oid;
			}
#endif
		}
	}

	return( NULL );
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static
#endif
int oc_check_allowed(
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeType *at,
#else
	char *type,
#endif
	struct berval **ocl )
{
	ObjectClass	*oc;
	int		i, j;

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	Debug( LDAP_DEBUG_TRACE,
		"oc_check_allowed type \"%s\"\n",
		at->sat_cname, 0, 0 );

	/* always allow objectclass attribute */
	if ( strcasecmp( at->sat_cname, "objectclass" ) == 0 ) {
		return LDAP_SUCCESS;
	}

#else
	AttributeType	*at;
	char		**pp;
	char		*p;
	char		*t;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_allowed type \"%s\"\n", type, 0, 0 );

	/* always allow objectclass attribute */
	if ( strcasecmp( type, "objectclass" ) == 0 ) {
		return LDAP_SUCCESS;
	}
#endif

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/*
	 * All operational attributions are allowed by schema rules.
	 */
	if( is_at_operational(at) ) {
		return LDAP_SUCCESS;
	}
#else
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
	{
		t = type;
	}

	/*
	 * All operational attributions are allowed by schema rules.
	 */
	if ( oc_check_op_attr( t ) ) {
		return LDAP_SUCCESS;
	}
#endif

	/* check that the type appears as req or opt in at least one oc */
	for ( i = 0; ocl[i] != NULL; i++ ) {
		/* if we know about the oc */
		if ( (oc = oc_find( ocl[i]->bv_val )) != NULL ) {
			/* does it require the type? */
			for ( j = 0; oc->soc_required != NULL && 
				oc->soc_required[j] != NULL; j++ )
			{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				if( at == oc->soc_required[j] ) {
					return LDAP_SUCCESS;
				}
#else
				at = oc->soc_required[j];
				if ( at->sat_oid &&
				     strcmp(at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return LDAP_SUCCESS;
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return LDAP_SUCCESS;
					}
					pp++;
				}
#endif
			}
			/* does it allow the type? */
			for ( j = 0; oc->soc_allowed != NULL && 
				oc->soc_allowed[j] != NULL; j++ )
			{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
				if( at == oc->soc_allowed[j] ) {
					return LDAP_SUCCESS;
				}
#else
				at = oc->soc_allowed[j];
				if ( at->sat_oid &&
				     strcmp( at->sat_oid, t ) == 0 ) {
					if ( t != type )
						ldap_memfree( t );
					return LDAP_SUCCESS;
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, t ) == 0 ||
					     strcmp( *pp, "*" ) == 0 ) {
						if ( t != type )
							ldap_memfree( t );
						return LDAP_SUCCESS;
					}
					pp++;
				}
#endif
			}
			/* maybe the next oc allows it */

#ifdef OC_UNDEFINED_IMPLES_EXTENSIBLE
		/* we don't know about the oc. assume it allows it */
		} else {
			if ( t != type )
				ldap_memfree( t );
			return LDAP_SUCCESS;
#endif
		}
	}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
	if ( t != type )
		ldap_memfree( t );
#endif

	/* not allowed by any oc */
	return LDAP_OBJECT_CLASS_VIOLATION;
}
