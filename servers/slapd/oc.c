/* oc.c - object class routines */
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

int is_object_subclass(
	ObjectClass *sub,
	ObjectClass *sup )
{
	int i;

	if( sub == NULL || sup == NULL ) return 0;

#if 0
	Debug( LDAP_DEBUG_TRACE, "is_object_subclass(%s,%s) %d\n",
		sub->soc_oid, sup->soc_oid, sup == sub );
#endif

	if( sup == sub ) {
		return 1;
	}

	if( sup->soc_sups == NULL ) {
		return 0;
	}

	for( i=0; sup->soc_sups[i] != NULL; i++ ) {
		if( is_object_subclass( sub, sup->soc_sups[i] ) ) {
			return 1;
		}
	}

	return 0;
}

int is_entry_objectclass(
	Entry*	e,
	ObjectClass *oc )
{
	Attribute *attr;
	int i;
	AttributeDescription *objectClass = slap_schema.si_ad_objectClass;
	assert(!( e == NULL || oc == NULL ));

	if( e == NULL || oc == NULL ) {
		return 0;
	}

	/*
	 * find objectClass attribute
	 */
	attr = attr_find(e->e_attrs, objectClass);

	if( attr == NULL ) {
		/* no objectClass attribute */
		Debug( LDAP_DEBUG_ANY, "is_entry_objectclass(\"%s\", \"%s\") "
			"no objectClass attribute\n",
			e->e_dn == NULL ? "" : e->e_dn,
			oc->soc_oclass.oc_oid, 0 );

		return 0;
	}

	for( i=0; attr->a_vals[i]; i++ ) {
		ObjectClass *objectClass = oc_find( attr->a_vals[i]->bv_val );

		if( objectClass == oc ) {
			return 1;
		}
	}

	return 0;

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
    struct oindexrec	*oir2 )
{
	assert( oir1->oir_name );
	assert( oir1->oir_oc );
	assert( oir2->oir_name );
	assert( oir2->oir_oc );

	return (strcasecmp( oir1->oir_name, oir2->oir_name ));
}

static int
oc_index_name_cmp(
    char 		*name,
    struct oindexrec	*oir )
{
	assert( oir->oir_name );
	assert( oir->oir_oc );

	return (strcasecmp( name, oir->oir_name ));
}

ObjectClass *
oc_find( const char *ocname )
{
	struct oindexrec	*oir;

	oir = (struct oindexrec *) avl_find( oc_index, ocname,
            (AVL_CMP) oc_index_name_cmp );

	if ( oir != NULL ) {
		assert( oir->oir_name );
		assert( oir->oir_oc );

		return( oir->oir_oc );
	}

	return( NULL );
}

static int
oc_create_required(
    ObjectClass		*soc,
    char		**attrs,
    const char		**err )
{
	char		**attrs1;
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
    const char		**err )
{
	char		**attrs1;
	AttributeType	*sat;

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
    char			**sups,
    const char		**err )
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
			soc->soc_sups = (ObjectClass **)ch_calloc(nsups,
					  sizeof(ObjectClass *));
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

			code = oc_add_sups( soc, soc1->soc_sup_oids, err );
			if ( code ) return code;

			code = oc_create_required( soc, soc1->soc_at_oids_must, err );
			if ( code ) return code;

			code = oc_create_allowed( soc, soc1->soc_at_oids_may, err );
			if ( code ) return code;

			nsups++;
			sups1++;
		}
	}
	return 0;
}

static int
oc_insert(
    ObjectClass		*soc,
    const char		**err
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

		assert( oir->oir_name );
		assert( oir->oir_oc );

		if ( avl_insert( &oc_index, (caddr_t) oir,
				 (AVL_CMP) oc_index_cmp,
				 (AVL_DUP) avl_dup_error ) )
		{
			*err = soc->soc_oid;
			ldap_memfree(oir->oir_name);
			ldap_memfree(oir);
			return SLAP_SCHERR_DUP_CLASS;
		}

		/* FIX: temporal consistency check */
		assert( oc_find(oir->oir_name) != NULL );
	}

	if ( (names = soc->soc_names) ) {
		while ( *names ) {
			oir = (struct oindexrec *)
				ch_calloc( 1, sizeof(struct oindexrec) );
			oir->oir_name = ch_strdup(*names);
			oir->oir_oc = soc;

			assert( oir->oir_name );
			assert( oir->oir_oc );

			if ( avl_insert( &oc_index, (caddr_t) oir,
					 (AVL_CMP) oc_index_cmp,
					 (AVL_DUP) avl_dup_error ) )
			{
				*err = *names;
				ldap_memfree(oir->oir_name);
				ldap_memfree(oir);
				return SLAP_SCHERR_DUP_CLASS;
			}

			/* FIX: temporal consistency check */
			assert( oc_find(oir->oir_name) != NULL );

			names++;
		}
	}

	return 0;
}

int
oc_add(
    LDAPObjectClass	*oc,
    const char		**err
)
{
	ObjectClass	*soc;
	int		code;

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	AC_MEMCPY( &soc->soc_oclass, oc, sizeof(LDAPObjectClass) );

	if( soc->soc_sup_oids == NULL &&
		soc->soc_kind == LDAP_SCHEMA_STRUCTURAL )
	{
		/* structural object classes implicitly inherit from 'top' */
		static char *top_oids[] = { SLAPD_TOP_OID, NULL };
		code = oc_add_sups( soc, top_oids, err );
	} else {
		code = oc_add_sups( soc, soc->soc_sup_oids, err );
	}
	if ( code != 0 ) return code;

	code = oc_create_required( soc, soc->soc_at_oids_must, err );
	if ( code != 0 ) return code;

	code = oc_create_allowed( soc, soc->soc_at_oids_may, err );
	if ( code != 0 ) return code;

	code = oc_insert(soc,err);
	return code;
}

#ifdef LDAP_DEBUG

static void
oc_print( ObjectClass *oc )
{
	int	i;
	const char *mid;

	printf( "objectclass %s\n", ldap_objectclass2name( &oc->soc_oclass ) );
	if ( oc->soc_required != NULL ) {
		mid = "\trequires ";
		for ( i = 0; oc->soc_required[i] != NULL; i++, mid = "," )
			printf( "%s%s", mid,
			        ldap_attributetype2name( &oc->soc_required[i]->sat_atype ) );
		printf( "\n" );
	}
	if ( oc->soc_allowed != NULL ) {
		mid = "\tallows ";
		for ( i = 0; oc->soc_allowed[i] != NULL; i++, mid = "," )
			printf( "%s%s", mid,
			        ldap_attributetype2name( &oc->soc_allowed[i]->sat_atype ) );
		printf( "\n" );
	}
}

#endif


#if defined( SLAPD_SCHEMA_DN )

int
oc_schema_info( Entry *e )
{
	struct berval	val;
	struct berval	*vals[2];
	ObjectClass	*oc;

	AttributeDescription *ad_objectClasses = slap_schema.si_ad_objectClasses;

	vals[0] = &val;
	vals[1] = NULL;

	for ( oc = oc_list; oc; oc = oc->soc_next ) {
		val.bv_val = ldap_objectclass2str( &oc->soc_oclass );
		if ( val.bv_val == NULL ) {
			return -1;
		}
		val.bv_len = strlen( val.bv_val );
#if 0
		Debug( LDAP_DEBUG_TRACE, "Merging oc [%ld] %s\n",
	       (long) val.bv_len, val.bv_val, 0 );
#endif
		attr_merge( e, ad_objectClasses, vals );
		ldap_memfree( val.bv_val );
	}
	return 0;
}

#endif
