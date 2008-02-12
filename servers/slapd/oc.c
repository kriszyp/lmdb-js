/* oc.c - object class routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

int is_object_subclass(
	ObjectClass *sup,
	ObjectClass *sub )
{
	int i;

	if( sub == NULL || sup == NULL ) return 0;

#if 0
	Debug( LDAP_DEBUG_TRACE, "is_object_subclass(%s,%s) %d\n",
		sup->soc_oid, sub->soc_oid, sup == sub );
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
	unsigned flags )
{
	/*
	 * set_flags should only be true if oc is one of operational
	 * object classes which we support objectClass flags for
	 * (e.g., referral, alias, ...).  See <slap.h>.
	 */

	Attribute *attr;
	struct berval *bv;

	assert( !( e == NULL || oc == NULL ) );
	assert( ( flags & SLAP_OCF_MASK ) != SLAP_OCF_MASK );

	if( e == NULL || oc == NULL ) {
		return 0;
	}

	if( flags == SLAP_OCF_SET_FLAGS && ( e->e_ocflags & SLAP_OC__END ) )
	{
		/* flags are set, use them */
		return (e->e_ocflags & oc->soc_flags & SLAP_OC__MASK) != 0;
	}

	/*
	 * find objectClass attribute
	 */
	attr = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	if( attr == NULL ) {
		/* no objectClass attribute */
		Debug( LDAP_DEBUG_ANY, "is_entry_objectclass(\"%s\", \"%s\") "
			"no objectClass attribute\n",
			e->e_dn == NULL ? "" : e->e_dn,
			oc->soc_oclass.oc_oid, 0 );

		return 0;
	}

	for( bv=attr->a_vals; bv->bv_val; bv++ ) {
		ObjectClass *objectClass = oc_bvfind( bv );

		if ( objectClass == NULL ) {
			/* FIXME: is this acceptable? */
			continue;
		}

		if ( !( flags & SLAP_OCF_SET_FLAGS ) ) {
			if ( objectClass == oc ) {
				return 1;
			}

			if ( ( flags & SLAP_OCF_CHECK_SUP )
				&& is_object_subclass( oc, objectClass ) )
			{
				return 1;
			}
		}
		
		e->e_ocflags |= objectClass->soc_flags;
	}

	/* mark flags as set */
	e->e_ocflags |= SLAP_OC__END;

	return ( e->e_ocflags & oc->soc_flags & SLAP_OC__MASK ) != 0;
}


struct oindexrec {
	struct berval oir_name;
	ObjectClass	*oir_oc;
};

static Avlnode	*oc_index = NULL;
static Avlnode	*oc_cache = NULL;
static LDAP_STAILQ_HEAD(OCList, slap_object_class) oc_list
	= LDAP_STAILQ_HEAD_INITIALIZER(oc_list);

static int
oc_index_cmp(
	const void *v_oir1,
	const void *v_oir2 )
{
	const struct oindexrec *oir1 = v_oir1, *oir2 = v_oir2;
	int i = oir1->oir_name.bv_len - oir2->oir_name.bv_len;
	if (i) return i;
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
	if (i) return i;
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

	if ( oc_cache ) {
		oir = avl_find( oc_cache, ocname, oc_index_name_cmp );
		if ( oir ) return oir->oir_oc;
	}
	oir = avl_find( oc_index, ocname, oc_index_name_cmp );

	if ( oir != NULL ) {
		if ( at_oc_cache ) {
			avl_insert( &oc_cache, (caddr_t) oir,
				oc_index_cmp, avl_dup_error );
		}
		return( oir->oir_oc );
	}

	return( NULL );
}

static LDAP_STAILQ_HEAD(OCUList, slap_object_class) oc_undef_list
	= LDAP_STAILQ_HEAD_INITIALIZER(oc_undef_list);

ObjectClass *
oc_bvfind_undef( struct berval *ocname )
{
	ObjectClass	*oc = oc_bvfind( ocname );

	if ( oc ) {
		return oc;
	}

	LDAP_STAILQ_FOREACH( oc, &oc_undef_list, soc_next ) {
		int	d = oc->soc_cname.bv_len - ocname->bv_len;

		if ( d ) {
			continue;
		}

		if ( strcasecmp( oc->soc_cname.bv_val, ocname->bv_val ) == 0 ) {
			break;
		}
	}
	
	if ( oc ) {
		return oc;
	}
	
	oc = ch_malloc( sizeof( ObjectClass ) + ocname->bv_len + 1 );
	memset( oc, 0, sizeof( ObjectClass ) );

	oc->soc_cname.bv_len = ocname->bv_len;
	oc->soc_cname.bv_val = (char *)&oc[ 1 ];
	AC_MEMCPY( oc->soc_cname.bv_val, ocname->bv_val, ocname->bv_len );

	LDAP_STAILQ_NEXT( oc, soc_next ) = NULL;
	ldap_pvt_thread_mutex_lock( &oc_undef_mutex );
	LDAP_STAILQ_INSERT_HEAD( &oc_undef_list, oc, soc_next );
	ldap_pvt_thread_mutex_unlock( &oc_undef_mutex );

	return oc;
}

static int
oc_create_required(
	ObjectClass		*soc,
	char			**attrs,
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
			i = at_find_in_list(*satp, soc->soc_allowed);
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
	while( !LDAP_STAILQ_EMPTY(&oc_list) ) {
		o = LDAP_STAILQ_FIRST(&oc_list);
		LDAP_STAILQ_REMOVE_HEAD(&oc_list, soc_next);

		if (o->soc_sups) ldap_memfree(o->soc_sups);
		if (o->soc_required) ldap_memfree(o->soc_required);
		if (o->soc_allowed) ldap_memfree(o->soc_allowed);
		if (o->soc_oidmacro) ldap_memfree(o->soc_oidmacro);
		ldap_objectclass_free((LDAPObjectClass *)o);
	}
	
	while( !LDAP_STAILQ_EMPTY(&oc_undef_list) ) {
		o = LDAP_STAILQ_FIRST(&oc_undef_list);
		LDAP_STAILQ_REMOVE_HEAD(&oc_undef_list, soc_next);

		ch_free( (ObjectClass *)o );
	}
}

/*
 * check whether the two ObjectClasses actually __are__ identical,
 * or rather inconsistent
 */
static int
oc_check_dup(
	ObjectClass	*soc,
	ObjectClass	*new_soc )
{
	if ( new_soc->soc_oid != NULL ) {
		if ( soc->soc_oid == NULL ) {
			return SLAP_SCHERR_CLASS_INCONSISTENT;
		}

		if ( strcmp( soc->soc_oid, new_soc->soc_oid ) != 0 ) {
			return SLAP_SCHERR_CLASS_INCONSISTENT;
		}

	} else {
		if ( soc->soc_oid != NULL ) {
			return SLAP_SCHERR_CLASS_INCONSISTENT;
		}
	}

	if ( new_soc->soc_names ) {
		int	i;

		if ( soc->soc_names == NULL ) {
			return SLAP_SCHERR_CLASS_INCONSISTENT;
		}

		for ( i = 0; new_soc->soc_names[ i ]; i++ ) {
			if ( soc->soc_names[ i ] == NULL ) {
				return SLAP_SCHERR_CLASS_INCONSISTENT;
			}
			
			if ( strcasecmp( soc->soc_names[ i ],
					new_soc->soc_names[ i ] ) != 0 )
			{
				return SLAP_SCHERR_CLASS_INCONSISTENT;
			}
		}
	} else {
		if ( soc->soc_names != NULL ) {
			return SLAP_SCHERR_CLASS_INCONSISTENT;
		}
	}

	return SLAP_SCHERR_CLASS_DUP;
}

static int
oc_insert(
    ObjectClass		*soc,
    const char		**err )
{
	struct oindexrec	*oir;
	char			**names;

	if ( soc->soc_oid ) {
		oir = (struct oindexrec *)
			ch_calloc( 1, sizeof(struct oindexrec) );
		oir->oir_name.bv_val = soc->soc_oid;
		oir->oir_name.bv_len = strlen( soc->soc_oid );
		oir->oir_oc = soc;

		assert( oir->oir_name.bv_val != NULL );
		assert( oir->oir_oc != NULL );

		if ( avl_insert( &oc_index, (caddr_t) oir,
			oc_index_cmp, avl_dup_error ) )
		{
			ObjectClass	*old_soc;
			int		rc;

			*err = soc->soc_oid;

			old_soc = oc_bvfind( &oir->oir_name );
			assert( old_soc != NULL );
			rc = oc_check_dup( old_soc, soc );

			ldap_memfree( oir );
			return rc;
		}

		/* FIX: temporal consistency check */
		assert( oc_bvfind( &oir->oir_name ) != NULL );
	}

	if ( (names = soc->soc_names) ) {
		while ( *names ) {
			oir = (struct oindexrec *)
				ch_calloc( 1, sizeof(struct oindexrec) );
			oir->oir_name.bv_val = *names;
			oir->oir_name.bv_len = strlen( *names );
			oir->oir_oc = soc;

			assert( oir->oir_name.bv_val != NULL );
			assert( oir->oir_oc != NULL );

			if ( avl_insert( &oc_index, (caddr_t) oir,
				oc_index_cmp, avl_dup_error ) )
			{
				ObjectClass	*old_soc;
				int		rc;

				*err = *names;

				old_soc = oc_bvfind( &oir->oir_name );
				assert( old_soc != NULL );
				rc = oc_check_dup( old_soc, soc );

				ldap_memfree( oir );

				while ( names > soc->soc_names ) {
					struct oindexrec	tmpoir;

					names--;
					ber_str2bv( *names, 0, 0, &tmpoir.oir_name );
					tmpoir.oir_oc = soc;
					oir = (struct oindexrec *)avl_delete( &oc_index,
						(caddr_t)&tmpoir, oc_index_cmp );
					assert( oir != NULL );
					ldap_memfree( oir );
				}

				if ( soc->soc_oid ) {
					struct oindexrec	tmpoir;

					ber_str2bv( soc->soc_oid, 0, 0, &tmpoir.oir_name );
					tmpoir.oir_oc = soc;
					oir = (struct oindexrec *)avl_delete( &oc_index,
						(caddr_t)&tmpoir, oc_index_cmp );
					assert( oir != NULL );
					ldap_memfree( oir );
				}

				return rc;
			}

			/* FIX: temporal consistency check */
			assert( oc_bvfind(&oir->oir_name) != NULL );

			names++;
		}
	}
	LDAP_STAILQ_INSERT_TAIL( &oc_list, soc, soc_next );

	return 0;
}

int
oc_add(
    LDAPObjectClass	*oc,
	int user,
	ObjectClass		**rsoc,
    const char		**err )
{
	ObjectClass	*soc;
	int		code;
	int		op = 0;
	char	*oidm = NULL;

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
			oidm = oc->oc_oid;
			oc->oc_oid = oid;
		}
	}

	soc = (ObjectClass *) ch_calloc( 1, sizeof(ObjectClass) );
	AC_MEMCPY( &soc->soc_oclass, oc, sizeof(LDAPObjectClass) );

	soc->soc_oidmacro = oidm;
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

	if ( code != 0 ) {
		goto done;
	}

	if ( user && op ) {
		code = SLAP_SCHERR_CLASS_BAD_SUP;
		goto done;
	}

	code = oc_create_required( soc, soc->soc_at_oids_must, &op, err );
	if ( code != 0 ) {
		goto done;
	}

	code = oc_create_allowed( soc, soc->soc_at_oids_may, &op, err );
	if ( code != 0 ) {
		goto done;
	}

	if ( user && op ) {
		code = SLAP_SCHERR_CLASS_BAD_USAGE;
		goto done;
	}

	if ( !user ) {
		soc->soc_flags |= SLAP_OC_HARDCODE;
	}

	code = oc_insert(soc,err);
done:;
	if ( code != 0 ) {
		if ( soc->soc_sups ) {
			ch_free( soc->soc_sups );
		}

		if ( soc->soc_required ) {
			ch_free( soc->soc_required );
		}

		if ( soc->soc_allowed ) {
			ch_free( soc->soc_allowed );
		}

		ch_free( soc );

	} else if ( rsoc ) {
		*rsoc = soc;
	}
	return code;
}

void
oc_unparse( BerVarray *res, ObjectClass *start, ObjectClass *end, int sys )
{
	ObjectClass *oc;
	int i, num;
	struct berval bv, *bva = NULL, idx;
	char ibuf[32];

	if ( !start )
		start = LDAP_STAILQ_FIRST( &oc_list );

	/* count the result size */
	i = 0;
	for ( oc=start; oc; oc=LDAP_STAILQ_NEXT(oc, soc_next)) {
		if ( sys && !(oc->soc_flags & SLAP_OC_HARDCODE)) continue;
		i++;
		if ( oc == end ) break;
	}
	if (!i) return;

	num = i;
	bva = ch_malloc( (num+1) * sizeof(struct berval) );
	BER_BVZERO( bva );
	idx.bv_val = ibuf;
	if ( sys ) {
		idx.bv_len = 0;
		ibuf[0] = '\0';
	}
	i = 0;
	for ( oc=start; oc; oc=LDAP_STAILQ_NEXT(oc, soc_next)) {
		LDAPObjectClass loc, *locp;
		if ( sys && !(oc->soc_flags & SLAP_OC_HARDCODE)) continue;
		if ( oc->soc_oidmacro ) {
			loc = oc->soc_oclass;
			loc.oc_oid = oc->soc_oidmacro;
			locp = &loc;
		} else {
			locp = &oc->soc_oclass;
		}
		if ( ldap_objectclass2bv( locp, &bv ) == NULL ) {
			ber_bvarray_free( bva );
		}
		if ( !sys ) {
			idx.bv_len = sprintf(idx.bv_val, "{%d}", i);
		}
		bva[i].bv_len = idx.bv_len + bv.bv_len;
		bva[i].bv_val = ch_malloc( bva[i].bv_len + 1 );
		strcpy( bva[i].bv_val, ibuf );
		strcpy( bva[i].bv_val + idx.bv_len, bv.bv_val );
		i++;
		bva[i].bv_val = NULL;
		ldap_memfree( bv.bv_val );
		if ( oc == end ) break;
	}
	*res = bva;
}

int
oc_schema_info( Entry *e )
{
	AttributeDescription *ad_objectClasses = slap_schema.si_ad_objectClasses;
	ObjectClass	*oc;
	struct berval	val;
	struct berval	nval;

	LDAP_STAILQ_FOREACH( oc, &oc_list, soc_next ) {
		if( oc->soc_flags & SLAP_OC_HIDE ) continue;

		if ( ldap_objectclass2bv( &oc->soc_oclass, &val ) == NULL ) {
			return -1;
		}

		nval = oc->soc_cname;

#if 0
		Debug( LDAP_DEBUG_TRACE, "Merging oc [%ld] %s (%s)\n",
	       (long) val.bv_len, val.bv_val, nval.bv_val );
#endif

		if( attr_merge_one( e, ad_objectClasses, &val, &nval ) ) {
			return -1;
		}
		ldap_memfree( val.bv_val );
	}
	return 0;
}
