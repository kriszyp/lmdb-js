/* oc.c - object class routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_pvt.h"

int is_object_subclass(
	ObjectClass *sup,
	ObjectClass *sub )
{
	int i;

	if( sub == NULL || sup == NULL ) return 0;

#if 1
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, ARGS, 
		"is_object_subclass(%s,%s) %d\n",
		sup->soc_oid, sub->soc_oid, sup == sub );
#else
	Debug( LDAP_DEBUG_TRACE, "is_object_subclass(%s,%s) %d\n",
		sup->soc_oid, sub->soc_oid, sup == sub );
#endif
#endif

	if( sup == sub ) {
		return 1;
	}

	if( sub->soc_sups == NULL ) {
		return 0;
	}

	for( i=0; sub->soc_sups[i] != NULL; i++ ) {
		if( is_object_subclass( sup, sub->soc_sups[i] ) ) {
			return 1;
		}
	}

	return 0;
}

int is_entry_objectclass(
	Entry*	e,
	ObjectClass *oc,
	int set_flags )
{
	/*
	 * set_flags should only be true if oc is one of operational
	 * object classes which we support objectClass flags for
	 * (e.g., referral, alias, ...).  See <slap.h>.
	 */

	Attribute *attr;
	struct berval *bv;
	AttributeDescription *objectClass = slap_schema.si_ad_objectClass;

	assert(!( e == NULL || oc == NULL ));

	if( e == NULL || oc == NULL ) {
		return 0;
	}

	if( set_flags && ( e->e_ocflags & SLAP_OC__END )) {
		/* flags are set, use them */
		return (e->e_ocflags & oc->soc_flags & SLAP_OC__MASK) != 0;
	}

	/*
	 * find objectClass attribute
	 */
	attr = attr_find(e->e_attrs, objectClass);
	if( attr == NULL ) {
		/* no objectClass attribute */
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"is_entry_objectclass: dn(%s), oid (%s), no objectClass "
			"attribute.\n", e->e_dn == NULL ? "" : e->e_dn,
			oc->soc_oclass.oc_oid, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "is_entry_objectclass(\"%s\", \"%s\") "
			"no objectClass attribute\n",
			e->e_dn == NULL ? "" : e->e_dn,
			oc->soc_oclass.oc_oid, 0 );
#endif

		return 0;
	}

	for( bv=attr->a_vals; bv->bv_val; bv++ ) {
		ObjectClass *objectClass = oc_bvfind( bv );

		if ( !set_flags && objectClass == oc ) {
			return 1;
		}
		
		if ( objectClass != NULL ) {
			e->e_ocflags |= objectClass->soc_flags;
		}
	}

	/* mark flags as set */
	e->e_ocflags |= SLAP_OC__END;

	return (e->e_ocflags & oc->soc_flags & SLAP_OC__MASK) != 0;
}


struct oindexrec {
	struct berval oir_name;
	ObjectClass	*oir_oc;
};

static Avlnode	*oc_index = NULL;
static LDAP_SLIST_HEAD(OCList, slap_object_class) oc_list
	= LDAP_SLIST_HEAD_INITIALIZER(&oc_list);

static int
oc_index_cmp(
	const void *v_oir1,
	const void *v_oir2 )
{
	const struct oindexrec *oir1 = v_oir1, *oir2 = v_oir2;
	int i = oir1->oir_name.bv_len - oir2->oir_name.bv_len;
	if (i)
		return i;
	return strcasecmp( oir1->oir_name.bv_val, oir2->oir_name.bv_val );
}

static int
oc_index_name_cmp(
	const void *v_name,
	const void *v_oir )
{
	const struct berval    *name = v_name;
	const struct oindexrec *oir  = v_oir;
	int i = name->bv_len - oir->oir_name.bv_len;
	if (i)
		return i;
	return strncasecmp( name->bv_val, oir->oir_name.bv_val, name->bv_len );
}

ObjectClass *
oc_find( const char *ocname )
{
	struct berval bv;

	bv.bv_val = (char *)ocname;
	bv.bv_len = strlen( ocname );

	return( oc_bvfind( &bv ) );
}

ObjectClass *
oc_bvfind( struct berval *ocname )
{
	struct oindexrec	*oir;

	oir = avl_find( oc_index, ocname, oc_index_name_cmp );

	if ( oir != NULL ) {
		return( oir->oir_oc );
	}

	return( NULL );
}

static int
oc_create_required(
    ObjectClass		*soc,
    char		**attrs,
	int			*op,
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

			if( is_at_operational( sat )) (*op)++;

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
	int			*op,
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

			if( is_at_operational( sat )) (*op)++;

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
	int			*op,
    const char		**err )
{
	int		code;
	ObjectClass	*soc1;
	int		nsups;
	char	**sups1;
	int		add_sups = 0;

	if ( sups ) {
		if ( !soc->soc_sups ) {
			/* We are at the first recursive level */
			add_sups = 1;
			nsups = 1;
			sups1 = sups;
			while ( *sups1 ) {
				nsups++;
				sups1++;
			}
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

			/* check object class usage
			 * abstract classes can only sup abstract classes 
			 * structural classes can not sup auxiliary classes
			 * auxiliary classes can not sup structural classes
			 */
			if( soc->soc_kind != soc1->soc_kind
				&& soc1->soc_kind != LDAP_SCHEMA_ABSTRACT )
			{
				*err = *sups1;
				return SLAP_SCHERR_CLASS_BAD_SUP;
			}

			if( soc1->soc_obsolete && !soc->soc_obsolete ) {
				*err = *sups1;
				return SLAP_SCHERR_CLASS_BAD_SUP;
			}

			if( soc->soc_flags & SLAP_OC_OPERATIONAL ) (*op)++;

			if ( add_sups ) {
				soc->soc_sups[nsups] = soc1;
			}

			code = oc_add_sups( soc, soc1->soc_sup_oids, op, err );
			if ( code ) return code;

			code = oc_create_required( soc, soc1->soc_at_oids_must, op, err );
			if ( code ) return code;

			code = oc_create_allowed( soc, soc1->soc_at_oids_may, op, err );
			if ( code ) return code;

			nsups++;
			sups1++;
		}
	}

	return 0;
}

void
oc_destroy( void )
{
	ObjectClass *o;

	avl_free(oc_index, ldap_memfree);
	while( !LDAP_SLIST_EMPTY(&oc_list) ) {
		o = LDAP_SLIST_FIRST(&oc_list);
		LDAP_SLIST_REMOVE_HEAD(&oc_list, soc_next);

		if (o->soc_sups) ldap_memfree(o->soc_sups);
		if (o->soc_required) ldap_memfree(o->soc_required);
		if (o->soc_allowed) ldap_memfree(o->soc_allowed);
		ldap_objectclass_free((LDAPObjectClass *)o);
	}
}

static int
oc_insert(
    ObjectClass		*soc,
    const char		**err
)
{
	struct oindexrec	*oir;
	char			**names;

	LDAP_SLIST_NEXT( soc, soc_next ) = NULL;
	LDAP_SLIST_INSERT_HEAD( &oc_list, soc, soc_next );

	if ( soc->soc_oid ) {
		oir = (struct oindexrec *)
			ch_calloc( 1, sizeof(struct oindexrec) );
		oir->oir_name.bv_val = soc->soc_oid;
		oir->oir_name.bv_len = strlen( soc->soc_oid );
		oir->oir_oc = soc;

		assert( oir->oir_name.bv_val );
		assert( oir->oir_oc );

		if ( avl_insert( &oc_index, (caddr_t) oir,
		                 oc_index_cmp, avl_dup_error ) )
		{
			*err = soc->soc_oid;
			ldap_memfree(oir);
			return SLAP_SCHERR_CLASS_DUP;
		}

		/* FIX: temporal consistency check */
		assert( oc_bvfind(&oir->oir_name) != NULL );
	}

	if ( (names = soc->soc_names) ) {
		while ( *names ) {
			oir = (struct oindexrec *)
				ch_calloc( 1, sizeof(struct oindexrec) );
			oir->oir_name.bv_val = *names;
			oir->oir_name.bv_len = strlen( *names );
			oir->oir_oc = soc;

			assert( oir->oir_name.bv_val );
			assert( oir->oir_oc );

			if ( avl_insert( &oc_index, (caddr_t) oir,
			                 oc_index_cmp, avl_dup_error ) )
			{
				*err = *names;
				ldap_memfree(oir);
				return SLAP_SCHERR_CLASS_DUP;
			}

			/* FIX: temporal consistency check */
			assert( oc_bvfind(&oir->oir_name) != NULL );

			names++;
		}
	}

	return 0;
}

int
oc_add(
    LDAPObjectClass	*oc,
	int user,
    const char		**err
)
{
	ObjectClass	*soc;
	int		code;
	int		op = 0;

	if ( oc->oc_names != NULL ) {
		int i;

		for( i=0; oc->oc_names[i]; i++ ) {
			if( !slap_valid_descr( oc->oc_names[i] ) ) {
				return SLAP_SCHERR_BAD_DESCR;
			}
		}
	}

	if ( !OID_LEADCHAR( oc->oc_oid[0] )) {
		/* Expand OID macros */
		char *oid = oidm_find( oc->oc_oid );
		if ( !oid ) {
			*err = oc->oc_oid;
			return SLAP_SCHERR_OIDM;
		}
		if ( oid != oc->oc_oid ) {
			ldap_memfree( oc->oc_oid );
			oc->oc_oid = oid;
		}
	}

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	AC_MEMCPY( &soc->soc_oclass, oc, sizeof(LDAPObjectClass) );

	if( oc->oc_names != NULL ) {
		soc->soc_cname.bv_val = soc->soc_names[0];
	} else {
		soc->soc_cname.bv_val = soc->soc_oid;
	}
	soc->soc_cname.bv_len = strlen( soc->soc_cname.bv_val );

	if( soc->soc_sup_oids == NULL &&
		soc->soc_kind == LDAP_SCHEMA_STRUCTURAL )
	{
		/* structural object classes implicitly inherit from 'top' */
		static char *top_oids[] = { SLAPD_TOP_OID, NULL };
		code = oc_add_sups( soc, top_oids, &op, err );
	} else {
		code = oc_add_sups( soc, soc->soc_sup_oids, &op, err );
	}

	if ( code != 0 ) return code;

	code = oc_create_required( soc, soc->soc_at_oids_must, &op, err );
	if ( code != 0 ) return code;

	code = oc_create_allowed( soc, soc->soc_at_oids_may, &op, err );
	if ( code != 0 ) return code;

	if( user && op ) return SLAP_SCHERR_CLASS_BAD_SUP;

	code = oc_insert(soc,err);
	return code;
}

int
oc_schema_info( Entry *e )
{
	AttributeDescription *ad_objectClasses = slap_schema.si_ad_objectClasses;
	ObjectClass	*oc;
	struct berval	val;
	struct berval	nval;

	LDAP_SLIST_FOREACH( oc, &oc_list, soc_next ) {
		if( oc->soc_flags & SLAP_OC_HIDE ) continue;

		if ( ldap_objectclass2bv( &oc->soc_oclass, &val ) == NULL ) {
			return -1;
		}

		nval.bv_val = oc->soc_oid;
		nval.bv_len = strlen(oc->soc_oid);

#if 0
		Debug( LDAP_DEBUG_TRACE, "Merging oc [%ld] %s (%s)\n",
	       (long) val.bv_len, val.bv_val, nval.bv_val );
#endif

		if( attr_merge_one( e, ad_objectClasses, &val, &nval ) )
		{
			return -1;
		}
		ldap_memfree( val.bv_val );
	}
	return 0;
}
