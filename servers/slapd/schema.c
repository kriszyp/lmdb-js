/* schema.c - routines to enforce schema definitions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "ldapconfig.h"
#include "slap.h"

static char *	oc_check_required(Entry *e, char *ocname);
static int		oc_check_allowed(char *type, struct berval **ocl);

/*
 * oc_check - check that entry e conforms to the schema required by
 * its object class(es). returns 0 if so, non-zero otherwise.
 */

int
oc_schema_check( Entry *e )
{
	Attribute	*a, *aoc;
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
		char *s = oc_check_required( e, aoc->a_vals[i]->bv_val );

		if (s != NULL) {
			Debug( LDAP_DEBUG_ANY,
			    "Entry (%s), oc \"%s\" requires attr \"%s\"\n",
			    e->e_dn, aoc->a_vals[i]->bv_val, s );
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
			    "Entry (%s), attr \"%s\" not allowed\n",
			    e->e_dn, a->a_type, 0 );
			ret = 1;
		}
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
	char		**pp;

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

/*
 * check to see if attribute is 'operational' or not.
 * this function should be externalized...
 */
static int
oc_check_operational( char *type )
{
	return ( strcasecmp( type, "modifiersname" ) == 0 ||
		strcasecmp( type, "modifytimestamp" ) == 0 ||
		strcasecmp( type, "creatorsname" ) == 0 ||
		strcasecmp( type, "createtimestamp" ) == 0 )
		? 1 : 0;
}

static int
oc_check_allowed( char *type, struct berval **ocl )
{
	ObjectClass	*oc;
	AttributeType	*at;
	int		i, j;
	char		**pp;

	Debug( LDAP_DEBUG_TRACE,
	       "oc_check_allowed type \"%s\"\n", type, 0, 0 );

	/* always allow objectclass attribute */
	if ( strcasecmp( type, "objectclass" ) == 0 ) {
		return( 0 );
	}

	if ( oc_check_operational( type ) ) {
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
				     strcmp(at->sat_oid, type ) == 0 ) {
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, type ) == 0 ) {
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
				     strcmp(at->sat_oid, type ) == 0 ) {
					return( 0 );
				}
				pp = at->sat_names;
				if ( pp == NULL )
					continue;
				while ( *pp ) {
					if ( strcasecmp( *pp, type ) == 0 ||
					     strcmp( *pp, "*" ) == 0 ) {
						return( 0 );
					}
					pp++;
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

struct oindexrec {
	char		*oir_name;
	ObjectClass	*oir_oc;
};

static Avlnode	*oc_index = NULL;
static ObjectClass *oc_list = NULL;

static int
oc_index_cmp(
    struct oindexrec	*oir1,
    struct oindexrec	*oir2
)
{
	return (strcasecmp( oir1->oir_name, oir2->oir_name ));
}

static int
oc_index_name_cmp(
    char 		*type,
    struct oindexrec	*oir
)
{
	return (strcasecmp( type, oir->oir_name ));
}

ObjectClass *
oc_find( char *ocname )
{
	struct oindexrec	*oir = NULL;

	if ( (oir = (struct oindexrec *) avl_find( oc_index, ocname,
            (AVL_CMP) oc_index_name_cmp )) != NULL ) {
		return( oir->oir_oc );
	}
	return( NULL );
}

static int
oc_create_required(
    ObjectClass		*soc,
    char		**attrs,
    char		**err
)
{
	char		**attrs1;
	int		nattrs;
	AttributeType	*sat;
	AttributeType	**satp;
	int		i;

	if ( attrs ) {
		attrs1 = attrs;
		while ( *attrs1 ) {
			sat = at_find(*attrs1);
			if ( !sat ) {
				*err = *attrs1;
				return SLAP_SCHERR_ATTR_NOT_FOUND;
			}
			if ( at_find_in_list(sat, soc->soc_required) < 0) {
				if ( at_append_to_list(sat, &soc->soc_required) ) {
					*err = *attrs1;
					return SLAP_SCHERR_OUTOFMEM;
				}
			}
			attrs1++;
		}
		/* Now delete duplicates from the allowed list */
		for ( satp = soc->soc_required; *satp; satp++ ) {
			i = at_find_in_list(*satp,soc->soc_allowed);
			if ( i >= 0 ) {
				at_delete_from_list(i, &soc->soc_allowed);
			}
		}
	}
	return 0;
}

static int
oc_create_allowed(
    ObjectClass		*soc,
    char		**attrs,
    char		**err
)
{
	char		**attrs1;
	int		nattrs;
	AttributeType	*sat;
	AttributeType	**satp;
	int		i;

	if ( attrs ) {
		attrs1 = attrs;
		while ( *attrs1 ) {
			sat = at_find(*attrs1);
			if ( !sat ) {
				*err = *attrs1;
				return SLAP_SCHERR_ATTR_NOT_FOUND;
			}
			if ( at_find_in_list(sat, soc->soc_required) < 0 &&
			     at_find_in_list(sat, soc->soc_allowed) < 0 ) {
				if ( at_append_to_list(sat, &soc->soc_allowed) ) {
					*err = *attrs1;
					return SLAP_SCHERR_OUTOFMEM;
				}
			}
			attrs1++;
		}
	}
	return 0;
}

static int
oc_add_sups(
    ObjectClass		*soc,
    char		**sups,
    char		**err
)
{
	int		code;
	ObjectClass	*soc1;
	int		nsups;
	char		**sups1;
	int		add_sups = 0;

	if ( sups ) {
		if ( !soc->soc_sups ) {
			/* We are at the first recursive level */
			add_sups = 1;
			nsups = 0;
			sups1 = sups;
			while ( *sups1 ) {
				nsups++;
				sups1++;
			}
			nsups++;
			soc->soc_sups = (ObjectClass **)ch_calloc(1,
					  nsups*sizeof(ObjectClass *));
		}
		nsups = 0;
		sups1 = sups;
		while ( *sups1 ) {
			soc1 = oc_find(*sups1);
			if ( !soc1 ) {
				*err = *sups1;
				return SLAP_SCHERR_CLASS_NOT_FOUND;
			}

			if ( add_sups )
				soc->soc_sups[nsups] = soc1;

			code = oc_add_sups(soc,soc1->soc_sup_oids, err);
			if ( code )
				return code;
			
			if ( code = oc_create_required(soc,
				soc1->soc_at_oids_must,err) )
				return code;
			if ( code = oc_create_allowed(soc,
				soc1->soc_at_oids_may,err) )
				return code;
			nsups++;
			sups1++;
		}
	}
	return 0;
}

static int
oc_insert(
    ObjectClass		*soc,
    char		**err
)
{
	ObjectClass	**ocp;
	struct oindexrec	*oir;
	char			**names;

	ocp = &oc_list;
	while ( *ocp != NULL ) {
		ocp = &(*ocp)->soc_next;
	}
	*ocp = soc;

	if ( soc->soc_oid ) {
		oir = (struct oindexrec *)
			ch_calloc( 1, sizeof(struct oindexrec) );
		oir->oir_name = soc->soc_oid;
		oir->oir_oc = soc;
		if ( avl_insert( &oc_index, (caddr_t) oir,
				 (AVL_CMP) oc_index_cmp,
				 (AVL_DUP) avl_dup_error ) ) {
			*err = soc->soc_oid;
			ldap_memfree(oir);
			return SLAP_SCHERR_DUP_CLASS;
		}
		/* FIX: temporal consistency check */
		oc_find(oir->oir_name);
	}
	if ( (names = soc->soc_names) ) {
		while ( *names ) {
			oir = (struct oindexrec *)
				ch_calloc( 1, sizeof(struct oindexrec) );
			oir->oir_name = ch_strdup(*names);
			oir->oir_oc = soc;
			if ( avl_insert( &oc_index, (caddr_t) oir,
					 (AVL_CMP) oc_index_cmp,
					 (AVL_DUP) avl_dup_error ) ) {
				*err = *names;
				ldap_memfree(oir);
				return SLAP_SCHERR_DUP_CLASS;
			}
			/* FIX: temporal consistency check */
			oc_find(oir->oir_name);
			names++;
		}
	}
	return 0;
}

int
oc_add(
    LDAP_OBJECT_CLASS	*oc,
    char		**err
)
{
	ObjectClass	*soc;
	int		code;

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	memcpy( &soc->soc_oclass, oc, sizeof(LDAP_OBJECT_CLASS));
	if ( code = oc_add_sups(soc,soc->soc_sup_oids,err) )
		return code;
	if ( code = oc_create_required(soc,soc->soc_at_oids_must,err) )
		return code;
	if ( code = oc_create_allowed(soc,soc->soc_at_oids_may,err) )
		return code;
	code = oc_insert(soc,err);
	return code;
}

#if defined( SLAPD_SCHEMA_DN )

static int
oc_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	ObjectClass	*oc;

	vals[0] = &val;
	vals[1] = NULL;

	for ( oc = oc_list; oc; oc = oc->soc_next ) {
		val.bv_val = ldap_objectclass2str( &oc->soc_oclass );
		if ( val.bv_val ) {
			val.bv_len = strlen( val.bv_val );
			Debug( LDAP_DEBUG_TRACE, "Merging oc [%d] %s\n",
			       val.bv_len, val.bv_val, 0 );
			attr_merge( e, "objectclasses", vals );
			ldap_memfree( val.bv_val );
		} else {
			return -1;
		}
	}
	return 0;
}

void
schema_info( Connection *conn, Operation *op, char **attrs, int attrsonly )
{
	Entry		*e;
	struct berval	val;
	struct berval	*vals[2];

	vals[0] = &val;
	vals[1] = NULL;

	e = (Entry *) ch_calloc( 1, sizeof(Entry) );

	e->e_attrs = NULL;
	e->e_dn = ch_strdup( SLAPD_SCHEMA_DN );
	e->e_ndn = dn_normalize_case( ch_strdup( SLAPD_SCHEMA_DN ));
	e->e_private = NULL;

	val.bv_val = ch_strdup( "top" );
	val.bv_len = strlen( val.bv_val );
	attr_merge( e, "objectclass", vals );
	ldap_memfree( val.bv_val );

	val.bv_val = ch_strdup( "subschema" );
	val.bv_len = strlen( val.bv_val );
	attr_merge( e, "objectclass", vals );
	ldap_memfree( val.bv_val );

	if ( at_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	if ( oc_schema_info( e ) ) {
		/* Out of memory, do something about it */
		entry_free( e );
		return;
	}
	
	send_search_entry( &backends[0], conn, op, e, attrs, attrsonly );
	send_ldap_search_result( conn, op, LDAP_SUCCESS, NULL, NULL, 1 );

	entry_free( e );
}
#endif

#ifdef LDAP_DEBUG

static void
oc_print( ObjectClass *oc )
{
	int	i;

	if ( oc->soc_names && oc->soc_names[0] ) {
		printf( "objectclass %s\n", oc->soc_names[0] );
	} else {
		printf( "objectclass %s\n", oc->soc_oid );
	}
	if ( oc->soc_required != NULL ) {
		printf( "\trequires %s", oc->soc_required[0] );
		for ( i = 1; oc->soc_required[i] != NULL; i++ ) {
			printf( ",%s", oc->soc_required[i] );
		}
		printf( "\n" );
	}
	if ( oc->soc_allowed != NULL ) {
		printf( "\tallows %s", oc->soc_allowed[0] );
		for ( i = 1; oc->soc_allowed[i] != NULL; i++ ) {
			printf( ",%s", oc->soc_allowed[i] );
		}
		printf( "\n" );
	}
}

#endif
