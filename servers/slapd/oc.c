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

int is_entry_objectclass(
	Entry*	e,
	const char*	oc)
{
	Attribute *attr;
	struct berval bv;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *objectClass = slap_schema.si_ad_objectClass;
#else
	static const char *objectClass = "objectclass";
#endif

	if( e == NULL || oc == NULL || *oc == '\0' )
		return 0;

	/*
	 * find objectClass attribute
	 */
	attr = attr_find(e->e_attrs, objectClass);

	if( attr == NULL ) {
		/* no objectClass attribute */
		return 0;
	}

	bv.bv_val = (char *) oc;
	bv.bv_len = strlen( bv.bv_val );

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
	if( value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		/* entry is not of this objectclass */
		return 0;
	}
#endif

	return 1;
}


#ifndef SLAPD_SCHEMA_NOT_COMPAT
	/* these shouldn't be hardcoded */

static char *oc_op_usermod_attrs[] = {
	/*
	 * these are operational attributes which are
	 * not defined as NO-USER_MODIFICATION and
	 * which slapd supports modification of.
	 *
	 * Currently none.
	 * Likely candidate, "aci"
	 */
	NULL
};

static char *oc_op_attrs[] = {
	/*
	 * these are operational attributes 
	 * most could be user modifiable
	 */
	"objectClasses",
	"attributeTypes",
	"matchingRules",
	"matchingRuleUse",
	"dITStructureRules",
	"dITContentRules",
	"nameForms",
	"ldapSyntaxes",
	"namingContexts",
	"supportedExtension",
	"supportedControl",
	"supportedSASLMechanisms",
	"supportedLDAPversion",
	"supportedACIMechanisms",
	"subschemaSubentry",		/* NO USER MOD */
	NULL

};

/* this list should be extensible  */
static char *oc_op_no_usermod_attrs[] = {
	/*
	 * Operational and 'no user modification' attributes
	 * which are STORED in the directory server.
	 */

	/* RFC2252, 3.2.1 */
	"creatorsName",
	"createTimestamp",
	"modifiersName",
	"modifyTimestamp",

	NULL
};
#endif


/*
 * check to see if attribute is 'operational' or not.
 */
int
oc_check_op_attr( const char *type )
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	return charray_inlist( oc_op_attrs, type )
		|| charray_inlist( oc_op_usermod_attrs, type )
		|| charray_inlist( oc_op_no_usermod_attrs, type );
#else
	AttributeType *at = at_find( type );

	if( at == NULL ) return 0;

	return at->sat_usage != LDAP_SCHEMA_USER_APPLICATIONS;
#endif
}

/*
 * check to see if attribute can be user modified or not.
 */
int
oc_check_op_usermod_attr( const char *type )
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	return charray_inlist( oc_op_usermod_attrs, type );
#else
	/* not (yet) in schema */
	return 0;
#endif
}

/*
 * check to see if attribute is 'no user modification' or not.
 */
int
oc_check_op_no_usermod_attr( const char *type )
{
#ifndef SLAPD_SCHEMA_NOT_COMPAT
	return charray_inlist( oc_op_no_usermod_attrs, type );
#else
	AttributeType *at = at_find( type );

	if( at == NULL ) return 0;

	return at->sat_no_user_mod;
#endif
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
    char 		*name,
    struct oindexrec	*oir
)
{
	return (strcasecmp( name, oir->oir_name ));
}

ObjectClass *
oc_find( const char *ocname )
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
    const char		**err
)
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
    const char		**err
)
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
    char		**sups,
    const char		**err
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

			code = oc_add_sups(soc,soc1->soc_sup_oids, err);
			if ( code )
				return code;

			code = oc_create_required(soc,soc1->soc_at_oids_must,err);
			if ( code )
				return code;
			code = oc_create_allowed(soc,soc1->soc_at_oids_may,err);
			if ( code )
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
    const char		**err
)
{
	ObjectClass	*soc;
	int		code;

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	memcpy( &soc->soc_oclass, oc, sizeof(LDAP_OBJECT_CLASS));
	if ( (code = oc_add_sups(soc,soc->soc_sup_oids,err)) != 0 )
		return code;
	if ( (code = oc_create_required(soc,soc->soc_at_oids_must,err)) != 0 )
		return code;
	if ( (code = oc_create_allowed(soc,soc->soc_at_oids_may,err)) != 0 )
		return code;
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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *ad_objectClasses = slap_schema.si_ad_objectClasses;
#else
	char *ad_objectClasses = "objectClasses";
#endif

	vals[0] = &val;
	vals[1] = NULL;

	for ( oc = oc_list; oc; oc = oc->soc_next ) {
		val.bv_val = ldap_objectclass2str( &oc->soc_oclass );
		if ( val.bv_val == NULL ) {
			return -1;
		}
		val.bv_len = strlen( val.bv_val );
		Debug( LDAP_DEBUG_TRACE, "Merging oc [%ld] %s\n",
	       (long) val.bv_len, val.bv_val, 0 );
		attr_merge( e, ad_objectClasses, vals );
		ldap_memfree( val.bv_val );
	}
	return 0;
}

#endif
