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
	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	int extensible = 0;

	if( !global_schemacheck ) return LDAP_SUCCESS;

	/* find the object class attribute - could error out here */
	if ( (aoc = attr_find( e->e_attrs, ad_objectClass )) == NULL ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "schema", LDAP_LEVEL_INFO,
                       "entry_schema_check: No object class for entry (%s).\n", e->e_dn ));
#else
		Debug( LDAP_DEBUG_ANY, "No object class for entry (%s)\n",
		    e->e_dn, 0, 0 );
#endif

		*text = "no objectClass attribute";
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	/* check that the entry has required attrs for each oc */
	for ( i = 0; aoc->a_vals[i] != NULL; i++ ) {
		if ( (oc = oc_find( aoc->a_vals[i]->bv_val )) == NULL ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "schema", LDAP_LEVEL_INFO,
                               "entry_schema_check: dn (%s), objectclass \"%s\" not recognized\n",
                               e->e_dn, aoc->a_vals[i]->bv_val ));
#else
			Debug( LDAP_DEBUG_ANY,
				"entry_check_schema(%s): objectclass \"%s\" not recognized\n",
				e->e_dn, aoc->a_vals[i]->bv_val, 0 );
#endif

			*text = "unrecognized object class";
			return LDAP_OBJECT_CLASS_VIOLATION;

		} else {
			char *s = oc_check_required( e, aoc->a_vals[i] );

			if (s != NULL) {
#ifdef NEW_LOGGING
                            LDAP_LOG(( "schema", LDAP_LEVEL_INFO,
                                       "entry_schema_check: dn (%s) oc \"%s\" requires att \"%s\"\n",
                                       e->e_dn, aoc->a_vals[i]->bv_val, s ));
#else
				Debug( LDAP_DEBUG_ANY,
					"Entry (%s), oc \"%s\" requires attr \"%s\"\n",
					e->e_dn, aoc->a_vals[i]->bv_val, s );
#endif

				*text = "missing required attribute";
				return LDAP_OBJECT_CLASS_VIOLATION;
			}

			if( oc == slap_schema.si_oc_extensibleObject ) {
				extensible=1;
			}

		}
	}

	if( extensible ) {
		return LDAP_SUCCESS;
	}

	/* optimistic */
	ret = LDAP_SUCCESS;

	/* check that each attr in the entry is allowed by some oc */
	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		ret = oc_check_allowed( a->a_desc->ad_type, aoc->a_vals );
		if ( ret != 0 ) {
			char *type = a->a_desc->ad_cname->bv_val;
#ifdef NEW_LOGGING
                        LDAP_LOG(( "schema", LDAP_LEVEL_INFO,
                                   "entry_schema_check: Entry (%s) attr \"%s\" not allowed.\n",
                                   e->e_dn, type ));
#else
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, type, 0 );
#endif

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

#ifdef NEW_LOGGING
        LDAP_LOG(( "schema", LDAP_LEVEL_ENTRY,
                   "oc_check_required: dn (%s), objectclass \"%s\"\n",
                   e->e_dn, ocname->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_required entry (%s), objectclass \"%s\"\n",
	       e->e_dn, ocname->bv_val, 0 );
#endif


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
			if( a->a_desc->ad_type == at ) {
				break;
			}
		}
		/* not there => schema violation */
		if ( a == NULL ) {
			return at->sat_cname;
		}
	}

	return( NULL );
}

int oc_check_allowed(
	AttributeType *at,
	struct berval **ocl )
{
	ObjectClass	*oc;
	int		i, j;

#ifdef NEW_LOGGING
        LDAP_LOG(( "schema", LDAP_LEVEL_ENTRY,
                   "oc_check_allowed: type \"%s\"\n", at->sat_cname ));
#else
	Debug( LDAP_DEBUG_TRACE,
		"oc_check_allowed type \"%s\"\n",
		at->sat_cname, 0, 0 );
#endif


	/* always allow objectclass attribute */
	if ( strcasecmp( at->sat_cname, "objectclass" ) == 0 ) {
		return LDAP_SUCCESS;
	}


	/*
	 * All operational attributions are allowed by schema rules.
	 */
	if( is_at_operational(at) ) {
		return LDAP_SUCCESS;
	}

	/* check that the type appears as req or opt in at least one oc */
	for ( i = 0; ocl[i] != NULL; i++ ) {
		/* if we know about the oc */
		if ( (oc = oc_find( ocl[i]->bv_val )) != NULL ) {
			/* does it require the type? */
			for ( j = 0; oc->soc_required != NULL && 
				oc->soc_required[j] != NULL; j++ )
			{
				if( at == oc->soc_required[j] ) {
					return LDAP_SUCCESS;
				}
			}
			/* does it allow the type? */
			for ( j = 0; oc->soc_allowed != NULL && 
				oc->soc_allowed[j] != NULL; j++ )
			{
				if( at == oc->soc_allowed[j] ) {
					return LDAP_SUCCESS;
				}
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


	/* not allowed by any oc */
	return LDAP_OBJECT_CLASS_VIOLATION;
}
