/* ndbio.cpp - get/set/del data for NDB */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2008 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software. This work was sponsored by MySQL.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>
#include <ac/errno.h>
#include <lutil.h>

#include "back-ndb.h"

/* For reference only */
typedef struct MedVar {
	Int16 len;	/* length is always little-endian */
	char buf[1024];
} MedVar;

extern "C" {
	static int ndb_name_cmp( const void *v1, const void *v2 );
	static int ndb_oc_dup_err( void *v1, void *v2 );
};

static int
ndb_name_cmp( const void *v1, const void *v2 )
{
	NdbOcInfo *oc1 = (NdbOcInfo *)v1, *oc2 = (NdbOcInfo *)v2;
	return ber_bvstrcasecmp( &oc1->no_name, &oc2->no_name );
}

static int
ndb_oc_dup_err( void *v1, void *v2 )
{
	NdbOcInfo *oc = (NdbOcInfo *)v2;

	oc->no_oc = (ObjectClass *)v1;
	return -1;
}

/* Find an existing NdbAttrInfo */
extern "C" NdbAttrInfo *
ndb_ai_find( struct ndb_info *ni, AttributeType *at )
{
	NdbAttrInfo atmp;
	atmp.na_name = at->sat_cname;

	return (NdbAttrInfo *)avl_find( ni->ni_ai_tree, &atmp, ndb_name_cmp );
}

/* Find or create an NdbAttrInfo */
extern "C" NdbAttrInfo *
ndb_ai_get( struct ndb_info *ni, struct berval *aname )
{
	NdbAttrInfo atmp, *ai;
	atmp.na_name = *aname;

	ai = (NdbAttrInfo *)avl_find( ni->ni_ai_tree, &atmp, ndb_name_cmp );
	if ( !ai ) {
		const char *text;
		AttributeDescription *ad = NULL;

		if ( slap_bv2ad( aname, &ad, &text ))
			return NULL;

		ai = (NdbAttrInfo *)ch_malloc( sizeof( NdbAttrInfo ));
		ai->na_desc = ad;
		ai->na_attr = ai->na_desc->ad_type;
		ai->na_name = ai->na_attr->sat_cname;
		ai->na_oi = NULL;
		ai->na_flag = 0;
		ai->na_ixcol = 0;
		ai->na_len = ai->na_attr->sat_atype.at_syntax_len;
		/* Reasonable default */
		if ( !ai->na_len ) {
			if ( ai->na_attr->sat_syntax == slap_schema.si_syn_distinguishedName )
				ai->na_len = 1024;
			else
				ai->na_len = 128;
		}
		/* Arbitrary limit */
		if ( ai->na_len > 1024 )
			ai->na_len = 1024;
		avl_insert( &ni->ni_ai_tree, ai, ndb_name_cmp, avl_dup_error );
	}
	return ai;
}

static int
ndb_ai_check( struct ndb_info *ni, NdbOcInfo *oci, AttributeType **attrs, char **ptr, int *col,
	int create )
{
	NdbAttrInfo *ai, atmp;
	int i;

	for ( i=0; attrs[i]; i++ ) {
		if ( attrs[i] == slap_schema.si_ad_objectClass->ad_type )
			continue;
		/* skip attrs that are in a superior */
		if ( oci->no_oc && oci->no_oc->soc_sups ) {
			int j, k, found=0;
			ObjectClass *oc;
			for ( j=0; oci->no_oc->soc_sups[j]; j++ ) {
				oc = oci->no_oc->soc_sups[j];
				if ( oc->soc_kind == LDAP_SCHEMA_ABSTRACT )
					continue;
				if ( oc->soc_required ) {
					for ( k=0; oc->soc_required[k]; k++ ) {
						if ( attrs[i] == oc->soc_required[k] ) {
							found = 1;
							break;
						}
					}
					if ( found ) break;
				}
				if ( oc->soc_allowed ) {
					for ( k=0; oc->soc_allowed[k]; k++ ) {
						if ( attrs[i] == oc->soc_allowed[k] ) {
							found = 1;
							break;
						}
					}
					if ( found ) break;
				}
			}
			if ( found )
				continue;
		}

		ai = ndb_ai_get( ni, &attrs[i]->sat_cname );
		if ( !ai ) {
			/* can never happen */
			return LDAP_OTHER;
		}

		/* An indexed attr is defined before its OC is */
		if ( !ai->na_oi ) {
			ai->na_oi = oci;
			ai->na_column = (*col)++;
		}

		oci->no_attrs[oci->no_nattrs++] = ai;

		/* An attrset attr may already be defined */
		if ( ai->na_oi != oci ) {
			int j;
			for ( j=0; j<oci->no_nsets; j++ )
				if ( oci->no_sets[j] == ai->na_oi ) break;
			if ( j >= oci->no_nsets ) {
				/* FIXME: data loss if more sets are in use */
				if ( oci->no_nsets < NDB_MAX_OCSETS ) {
					oci->no_sets[oci->no_nsets++] = ai->na_oi;
				}
			}
			continue;
		}

		if ( create ) {
			*ptr += sprintf( *ptr, ", `%s` VARCHAR(%d)", ai->na_attr->sat_cname.bv_val,
				ai->na_len );
		}
	}
	return 0;
}

static int
ndb_oc_create( struct ndb_info *ni, NdbOcInfo *oci, int create )
{
	char buf[4096], *ptr;
	int i, rc = 0, col;

	if ( create ) {
		ptr = buf + sprintf( buf,
			"CREATE TABLE `%s` (eid bigint unsigned NOT NULL PRIMARY KEY",
			oci->no_table.bv_val );
	}

	col = 0;
	if ( oci->no_oc->soc_required ) {
		for ( i=0; oci->no_oc->soc_required[i]; i++ );
		col += i;
	}
	if ( oci->no_oc->soc_allowed ) {
		for ( i=0; oci->no_oc->soc_allowed[i]; i++ );
		col += i;
	}
	/* assume all are present */
	oci->no_attrs = (struct ndb_attrinfo **)ch_malloc( col * sizeof(struct ndb_attrinfo *));

	col = 1;
	ldap_pvt_thread_rdwr_wlock( &ni->ni_ai_rwlock );
	if ( oci->no_oc->soc_required ) {
		rc = ndb_ai_check( ni, oci, oci->no_oc->soc_required, &ptr, &col, create );
	}
	if ( !rc && oci->no_oc->soc_allowed ) {
		rc = ndb_ai_check( ni, oci, oci->no_oc->soc_allowed, &ptr, &col, create );
	}
	ldap_pvt_thread_rdwr_wunlock( &ni->ni_ai_rwlock );

	/* shrink down to just the needed size */
	oci->no_attrs = (struct ndb_attrinfo **)ch_realloc( oci->no_attrs,
		oci->no_nattrs * sizeof(struct ndb_attrinfo *));

	if ( create ) {
		ptr = lutil_strcopy( ptr, " ) ENGINE=ndb" );
		rc = mysql_real_query( &ni->ni_sql, buf, ptr - buf );
		if ( rc ) {
			Debug( LDAP_DEBUG_ANY,
				"ndb_oc_create: CREATE TABLE %s failed, %s (%d)\n",
				oci->no_table.bv_val, mysql_error(&ni->ni_sql), mysql_errno(&ni->ni_sql) );
		}
	}
	return rc;
}

/* Read table definitions from the DB and populate ObjectClassInfo */
extern "C" int
ndb_oc_read( struct ndb_info *ni, const NdbDictionary::Dictionary *myDict )
{
	const NdbDictionary::Table *myTable;
	const NdbDictionary::Column *myCol;
	NdbOcInfo *oci, octmp;
	NdbAttrInfo *ai;
	ObjectClass *oc;
	NdbDictionary::Dictionary::List myList;
	struct berval bv;
	int i, j, rc, col;

	rc = myDict->listObjects( myList, NdbDictionary::Object::UserTable );
	/* Populate our objectClass structures */
	for ( i=0; i<myList.count; i++ ) {
		/* Ignore other DBs */
		if ( strcmp( myList.elements[i].database, ni->ni_dbname ))
			continue;
		/* Ignore internal tables */
		if ( !strncmp( myList.elements[i].name, "OL_", 3 ))
			continue;
		ber_str2bv( myList.elements[i].name, 0, 0, &octmp.no_name );
		oci = (NdbOcInfo *)avl_find( ni->ni_oc_tree, &octmp, ndb_name_cmp );
		if ( oci )
			continue;

		oc = oc_bvfind( &octmp.no_name );
		if ( !oc ) {
			/* undefined - shouldn't happen */
			continue;
		}
		myTable = myDict->getTable( myList.elements[i].name );
		oci = (NdbOcInfo *)ch_malloc( sizeof( NdbOcInfo )+oc->soc_cname.bv_len+1 );
		oci->no_table.bv_val = (char *)(oci+1);
		strcpy( oci->no_table.bv_val, oc->soc_cname.bv_val );
		oci->no_table.bv_len = oc->soc_cname.bv_len;
		oci->no_name = oci->no_table;
		oci->no_oc = oc;
		oci->no_flag = 0;
		oci->no_nsets = 0;
		oci->no_nattrs = 0;
		col = 0;
		/* Make space for all attrs, even tho sups will be dropped */
		if ( oci->no_oc->soc_required ) {
			for ( j=0; oci->no_oc->soc_required[j]; j++ );
			col = j;
		}
		if ( oci->no_oc->soc_allowed ) {
			for ( j=0; oci->no_oc->soc_allowed[j]; j++ );
			col += j;
		}
		oci->no_attrs = (struct ndb_attrinfo **)ch_malloc( col * sizeof(struct ndb_attrinfo *));
		avl_insert( &ni->ni_oc_tree, oci, ndb_name_cmp, avl_dup_error );

		col = myTable->getNoOfColumns();
		/* Skip 0, eid */
		for ( j = 1; j<col; j++ ) {
			myCol = myTable->getColumn( j );
			ber_str2bv( myCol->getName(), 0, 0, &bv );
			ai = ndb_ai_get( ni, &bv );
			/* shouldn't happen */
			if ( !ai )
				continue;
			ai->na_oi = oci;
			ai->na_column = j;
			ai->na_len = myCol->getLength();
		}
	}
	/* Link to any attrsets */
	for ( i=0; i<myList.count; i++ ) {
		/* Ignore other DBs */
		if ( strcmp( myList.elements[i].database, ni->ni_dbname ))
			continue;
		/* Ignore internal tables */
		if ( !strncmp( myList.elements[i].name, "OL_", 3 ))
			continue;
		ber_str2bv( myList.elements[i].name, 0, 0, &octmp.no_name );
		oci = (NdbOcInfo *)avl_find( ni->ni_oc_tree, &octmp, ndb_name_cmp );
		/* shouldn't happen */
		if ( !oci )
			continue;
		col = 1;
		if ( oci->no_oc->soc_required ) {
			rc = ndb_ai_check( ni, oci, oci->no_oc->soc_required, NULL, &col, 0 );
		}
		if ( oci->no_oc->soc_allowed ) {
			rc = ndb_ai_check( ni, oci, oci->no_oc->soc_allowed, NULL, &col, 0 );
		}
		/* shrink down to just the needed size */
		oci->no_attrs = (struct ndb_attrinfo **)ch_realloc( oci->no_attrs,
			oci->no_nattrs * sizeof(struct ndb_attrinfo *));
	}
	return 0;
}

static int
ndb_oc_get( struct ndb_info *ni, const NdbDictionary::Dictionary *myDict,
	struct berval *oname, NdbOcs *out )
{
	const NdbDictionary::Table *myTable;
	NdbOcInfo *oci, octmp;
	ObjectClass *oc;
	int i, rc;

	/* shortcut top */
	if ( ber_bvstrcasecmp( oname, &slap_schema.si_oc_top->soc_cname )) {
		octmp.no_name = *oname;
		oci = (NdbOcInfo *)avl_find( ni->ni_oc_tree, &octmp, ndb_name_cmp );
		if ( oci ) {
			oc = oci->no_oc;
		} else {
			oc = oc_bvfind( oname );
			if ( !oc ) {
				/* undefined - shouldn't happen */
				return LDAP_INVALID_SYNTAX;
			}
		}
		if ( oc->soc_sups ) {
			int i;

			for ( i=0; oc->soc_sups[i]; i++ ) {
				rc = ndb_oc_get( ni, myDict, &oc->soc_sups[i]->soc_cname, out );
				if ( rc ) return rc;
			}
		}
	} else {
		oc = slap_schema.si_oc_top;
	}
	/* Only insert once */
	for ( i=0; i<out->no_ntext; i++ )
		if ( out->no_text[i].bv_val == oc->soc_cname.bv_val )
			break;
	if ( i == out->no_ntext )
		out->no_text[out->no_ntext++] = oc->soc_cname;

	/* ignore top, etc... */
	if ( oc->soc_kind == LDAP_SCHEMA_ABSTRACT )
		return 0;

	if ( !oci ) {
		ldap_pvt_thread_rdwr_runlock( &ni->ni_oc_rwlock );
		oci = (NdbOcInfo *)ch_malloc( sizeof( NdbOcInfo )+oc->soc_cname.bv_len+1 );
		oci->no_table.bv_val = (char *)(oci+1);
		strcpy( oci->no_table.bv_val, oc->soc_cname.bv_val );
		oci->no_table.bv_len = oc->soc_cname.bv_len;
		oci->no_name = oci->no_table;
		oci->no_oc = oc;
		oci->no_flag = 0;
		oci->no_nsets = 0;
		oci->no_nattrs = 0;
		ldap_pvt_thread_rdwr_wlock( &ni->ni_oc_rwlock );
		if ( avl_insert( &ni->ni_oc_tree, oci, ndb_name_cmp, ndb_oc_dup_err )) {
			octmp.no_oc = oci->no_oc;
			ch_free( oci );
			oci = (NdbOcInfo *)octmp.no_oc;
		}
		/* see if the oc table already exists in the DB */
		myTable = myDict->getTable( oci->no_table.bv_val );
		rc = ndb_oc_create( ni, oci, myTable == NULL );
		ldap_pvt_thread_rdwr_wunlock( &ni->ni_oc_rwlock );
		ldap_pvt_thread_rdwr_rlock( &ni->ni_oc_rwlock );
		if ( rc ) return rc;
	}
	/* Only insert once */
	for ( i=0; i<out->no_ninfo; i++ )
		if ( out->no_info[i] == oci )
			break;
	if ( i == out->no_ninfo )
		out->no_info[out->no_ninfo++] = oci;
	return 0;
}

extern "C" int
ndb_aset_get( struct ndb_info *ni, struct berval *sname, struct berval *attrs, NdbOcInfo **ret )
{
	NdbOcInfo *oci, octmp;
	int i, rc;

	octmp.no_name = *sname;
	oci = (NdbOcInfo *)avl_find( ni->ni_oc_tree, &octmp, ndb_name_cmp );
	if ( oci )
		return LDAP_ALREADY_EXISTS;

	for ( i=0; !BER_BVISNULL( &attrs[i] ); i++ ) {
		if ( !at_bvfind( &attrs[i] ))
			return LDAP_NO_SUCH_ATTRIBUTE;
	}
	i++;

	oci = (NdbOcInfo *)ch_calloc( 1, sizeof( NdbOcInfo ) + sizeof( ObjectClass ) +
		i*sizeof(AttributeType *) + sname->bv_len+1 );
	oci->no_oc = (ObjectClass *)(oci+1);
	oci->no_oc->soc_required = (AttributeType **)(oci->no_oc+1);
	oci->no_table.bv_val = (char *)(oci->no_oc->soc_required+i);

	for ( i=0; !BER_BVISNULL( &attrs[i] ); i++ )
		oci->no_oc->soc_required[i] = at_bvfind( &attrs[i] );

	strcpy( oci->no_table.bv_val, sname->bv_val );
	oci->no_table.bv_len = sname->bv_len;
	oci->no_name = oci->no_table;
	oci->no_oc->soc_cname = oci->no_name;
	oci->no_flag = NDB_INFO_ATSET;

	rc = ndb_oc_create( ni, oci, 0 );
	if ( !rc )
		rc = avl_insert( &ni->ni_oc_tree, oci, ndb_name_cmp, avl_dup_error );
	if ( rc ) {
		ch_free( oci );
	} else {
		*ret = oci;
	}
	return rc;
}

extern "C" int
ndb_aset_create( struct ndb_info *ni, NdbOcInfo *oci )
{
	char buf[4096], *ptr;
	NdbAttrInfo *ai;
	int i;

	ptr = buf + sprintf( buf,
		"CREATE TABLE IF NOT EXISTS `%s` (eid bigint unsigned NOT NULL PRIMARY KEY",
		oci->no_table.bv_val );

	for ( i=0; i<oci->no_nattrs; i++ ) {
		if ( oci->no_attrs[i]->na_oi != oci )
			continue;
		ai = oci->no_attrs[i];
		ptr += sprintf( ptr, ", `%s` VARCHAR(%d)", ai->na_attr->sat_cname.bv_val,
			ai->na_len );
		if ( ai->na_flag & NDB_INFO_INDEX ) {
			ptr += sprintf( ptr, ", INDEX (`%s`)", ai->na_attr->sat_cname.bv_val );
		}
	}
	ptr = lutil_strcopy( ptr, " ) ENGINE=ndb" );
	i = mysql_real_query( &ni->ni_sql, buf, ptr - buf );
	if ( i ) {
		Debug( LDAP_DEBUG_ANY,
			"ndb_aset_create: CREATE TABLE %s failed, %s (%d)\n",
			oci->no_table.bv_val, mysql_error(&ni->ni_sql), mysql_errno(&ni->ni_sql) );
	}
	return i;
}

static int
ndb_oc_check( BackendDB *be, Ndb *ndb,
	struct berval *ocsin, NdbOcs *out )
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = ndb->getDictionary();

	int i, rc = 0;

	out->no_ninfo = 0;
	out->no_ntext = 0;

	/* Find all objectclasses and their superiors. List
	 * the superiors first.
	 */

	ldap_pvt_thread_rdwr_rlock( &ni->ni_oc_rwlock );
	for ( i=0; !BER_BVISNULL( &ocsin[i] ); i++ ) {
		rc = ndb_oc_get( ni, myDict, &ocsin[i], out );
		if ( rc ) break;
	}
	ldap_pvt_thread_rdwr_runlock( &ni->ni_oc_rwlock );
	return rc;
}

/* set all the unique attrs of this objectclass into the table
 * max row size is 8192 bytes; how do we detect if the row is too large?
 *
 * FIXME: Currently only stores the first value of any multivalued attribute.
 */
extern "C" int
ndb_oc_attrs(
	NdbTransaction *txn,
	const NdbDictionary::Table *myTable,
	Entry *e,
	NdbOcInfo *no,
	NdbAttrInfo **attrs,
	int nattrs,
	int update,
	int *num,
	NdbOperation **retop
)
{
	char buf[65538], *ptr;
	Attribute *a;
	NdbOperation *myop = retop ? *retop : NULL;
	int i;

	for ( i=0; i<nattrs; i++ ) {
		/* Skip if not in this table */
		if ( attrs[i]->na_oi != no )
			continue;
		for ( a=e->e_attrs; a; a=a->a_next ) {
			if ( a->a_desc->ad_type == attrs[i]->na_attr )
				break;
		}
		/* If we found a match, set its value. If we found no match
		 * and we're updating, delete its value.
		 */
		if ( a || update ) {
			/* objectclass is in dn_idx_table */
			if ( a && a->a_desc == slap_schema.si_ad_objectClass )
				continue;

			/* First attr, get the op, set the type and primary key */
			if ( !*num ) {
				Uint64 eid = e->e_id;
				myop = txn->getNdbOperation( myTable );
				if ( !myop )
					return LDAP_OTHER;
				if ( update ) {
					if ( myop->writeTuple())
						return LDAP_OTHER;
				} else {
					if ( myop->insertTuple())
						return LDAP_OTHER;
				}
				if ( myop->equal( EID_COLUMN, eid ))
					return LDAP_OTHER;
			}
			ptr = buf;
			if ( a ) {
				if ( a->a_vals[0].bv_len > attrs[i]->na_len ) {
					Debug( LDAP_DEBUG_ANY, "ndb_oc_attrs: attribute %s too long for column\n",
						attrs[i]->na_name.bv_val, 0, 0 );
					return LDAP_CONSTRAINT_VIOLATION;
				}
				*ptr++ = a->a_vals[0].bv_len & 0xff;
				if ( attrs[i]->na_len > 255 ) {
					/* MedVar */
					*ptr++ = a->a_vals[0].bv_len >> 8;
				}
				memcpy( ptr, a->a_vals[0].bv_val, a->a_vals[0].bv_len );
				ptr = buf;
			} else {
				ptr = NULL;
			}
			if ( myop->setValue( attrs[i]->na_column, ptr ))
				return LDAP_OTHER;
			(*num)++;
		}
	}
	if ( retop )
		*retop = myop;
	return LDAP_SUCCESS;
}

static int
ndb_oc_put(
	const NdbDictionary::Dictionary *myDict,
	NdbTransaction *txn, NdbOcInfo *no, Entry *e, int update )
{
	const NdbDictionary::Table *myTable;
	int i, rc;

	for ( i=0; i<no->no_nsets; i++ ) {
		rc = ndb_oc_put( myDict, txn, no->no_sets[i], e, update );
		if ( rc )
			return rc;
	}

	myTable = myDict->getTable( no->no_table.bv_val );
	if ( !myTable )
		return LDAP_OTHER;

	i = 0;
	return ndb_oc_attrs( txn, myTable, e, no, no->no_attrs, no->no_nattrs, update, &i, NULL );
}

extern "C" int
ndb_entry_put_data(
	BackendDB *be,
	NdbArgs *NA,
	int update
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	ObjectClass *oc;
	Attribute *aoc, *a;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable;
	NdbOperation *myop;
	NdbOcs myOcs;
	int i, rc;

	/* Get the entry's objectClass attribute */
	aoc = attr_find( NA->e->e_attrs, slap_schema.si_ad_objectClass );
	if ( !aoc )
		return LDAP_OTHER;

	ndb_oc_check( be, NA->ndb, aoc->a_nvals, &myOcs );
	myOcs.no_info[myOcs.no_ninfo++] = ni->ni_opattrs;

	/* Walk thru objectclasses, find all the attributes belonging to a class */
	for ( i=0; i<myOcs.no_ninfo; i++ ) {
		rc = ndb_oc_put( myDict, NA->txn, myOcs.no_info[i], NA->e, update );
		if ( rc ) return rc;
	}

	return 0;
}

static void
ndb_oc_get( NdbOcInfo *no, int *j, int *nocs, NdbOcInfo ***oclist )
{
	int i;
	NdbOcInfo  **ol2;

	for ( i=0; i<no->no_nsets; i++ ) {
		ndb_oc_get( no->no_sets[i], j, nocs, oclist );
	}
	if ( *j >= *nocs ) {
		*nocs *= 2;
		ol2 = (NdbOcInfo **)ch_realloc( *oclist, *nocs * sizeof(NdbOcInfo *));
		*oclist = ol2;
	}
	ol2 = *oclist;
	ol2[(*j)++] = no;
}

/* Retrieve attribute data for given entry. The entry's DN and eid should
 * already be populated.
 */
extern "C" int
ndb_entry_get_data(
	BackendDB *be,
	NdbArgs *NA,
	int update
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable;
	NdbOperation *myop;
	Uint64 eid;

	Attribute *aoc, *a;
	NdbOcs myOcs;
	NdbOcInfo *oci, **oclist = NULL;
	char abuf[65536], *ptr, **attrs = NULL;

	/* FIXME: abuf should be dynamically allocated */

	int i, j, k, nocs, nattrs, rc = LDAP_OTHER, alen;

	attr_merge( NA->e, slap_schema.si_ad_objectClass, NA->ocs, NULL );

	eid = NA->e->e_id;

	ndb_oc_check( be, NA->ndb, NA->ocs, &myOcs );
	myOcs.no_info[myOcs.no_ninfo++] = ni->ni_opattrs;
	nocs = myOcs.no_ninfo;

	oclist = (NdbOcInfo **)ch_calloc( 1, nocs * sizeof(NdbOcInfo *));

	for ( i=0, j=0; i<myOcs.no_ninfo; i++ ) {
		ndb_oc_get( myOcs.no_info[i], &j, &nocs, &oclist );
	}

	nocs = j;
	nattrs = 0;
	for ( i=0; i<nocs; i++ )
		nattrs += oclist[i]->no_nattrs;

	attrs = (char **)ch_malloc( nattrs * sizeof(char *));

	k = 0;
	ptr = abuf;
	for ( i=0; i<nocs; i++ ) {
		oci = oclist[i];
		myTable = myDict->getTable( oci->no_table.bv_val );

		myop = NA->txn->getNdbOperation( myTable );
		if ( !myop )
			goto leave;
		if ( myop->readTuple( update ? NdbOperation::LM_Exclusive : NdbOperation::LM_CommittedRead ))
			goto leave;
		if ( myop->equal( EID_COLUMN, eid ))
			goto leave;

		for ( j=0; j<oci->no_nattrs; j++ ) {
			if ( oci->no_attrs[j]->na_oi != oci )
				continue;
			attrs[k] = ptr;
			*ptr++ = 0;
			if ( oci->no_attrs[j]->na_len > 255 )
				*ptr++ = 0;
			ptr += oci->no_attrs[j]->na_len + 1;
			myop->getValue( oci->no_attrs[j]->na_column, attrs[k++] );
		}
	}
	if ( NA->txn->execute( update ? NdbTransaction::NoCommit : NdbTransaction::Commit,
		update ? NdbOperation::AO_IgnoreError : NdbOperation::AbortOnError, 1) < 0 )
		goto leave;

	/* count results */
	nattrs = 0;
	k = 0;
	for ( i=0; i<nocs; i++ ) {
		oci = oclist[i];
		for ( j=0; j<oci->no_nattrs; j++ ) {
			unsigned char *buf;
			int len;
			if ( oci->no_attrs[j]->na_oi != oci )
				continue;
			buf = (unsigned char *)attrs[k++];
			len = buf[0];
			if ( oci->no_attrs[j]->na_len > 255 ) {
				/* MedVar */
				len |= (buf[1] << 8);
			}
			if ( !len )
				continue;
			nattrs++;
		}
	}

	a = attrs_alloc( nattrs );
	NA->e->e_attrs->a_next = a;
	k = 0;
	for ( i=0; i<nocs; i++ ) {
		oci = oclist[i];
		for ( j=0; j<oci->no_nattrs; j++ ) {
			unsigned char *buf;
			struct berval bv, nbv;
			if ( oci->no_attrs[j]->na_oi != oci )
				continue;
			buf = (unsigned char *)attrs[k++];
			bv.bv_len = buf[0];
			if ( oci->no_attrs[j]->na_len > 255 ) {
				/* MedVar */
				bv.bv_len |= (buf[1] << 8);
				bv.bv_val = (char *)buf+2;
			} else {
				bv.bv_val = (char *)buf+1;
			}
			if ( bv.bv_len == 0 )
				continue;
			bv.bv_val[bv.bv_len] = '\0';
			a->a_desc = oci->no_attrs[j]->na_desc;
			attr_normalize_one( a->a_desc, &bv, &nbv, NULL );
			a->a_vals = NULL;
			a->a_nvals = NULL;
			a->a_numvals = 1;
			value_add_one( &a->a_vals, &bv );
			if ( !BER_BVISNULL( &nbv )) {
				ber_bvarray_add( &a->a_nvals, &nbv );
			} else {
				a->a_nvals = a->a_vals;
			}
			a = a->a_next;
		}
	}

	rc = 0;
leave:
	if ( attrs ) {
		ch_free( attrs );
	}
	if ( oclist ) {
		ch_free( oclist );
	}

	return rc;
}

static int
ndb_oc_del( 
	const NdbDictionary::Dictionary *myDict,
	NdbTransaction *txn, Uint64 eid, NdbOcInfo *no )
{
	const NdbDictionary::Table *myTable;
	NdbOperation *myop;
	int i, rc;

	for ( i=0; i<no->no_nsets; i++ ) {
		rc = ndb_oc_del( myDict, txn, eid, no->no_sets[i] );
		if ( rc ) rc;
	}
	myTable = myDict->getTable( no->no_table.bv_val );

	myop = txn->getNdbOperation( myTable );
	if ( !myop )
		return LDAP_OTHER;
	if ( myop->deleteTuple() )
		return LDAP_OTHER;
	if ( myop->equal( EID_COLUMN, eid ))
		return LDAP_OTHER;

	return 0;
}

extern "C" int
ndb_entry_del_data(
	BackendDB *be,
	NdbArgs *NA
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable;
	NdbOperation *myop;
	Uint64 eid = NA->e->e_id;
	int i;
	NdbOcs myOcs;

	ndb_oc_check( be, NA->ndb, NA->ocs, &myOcs );
	myOcs.no_info[myOcs.no_ninfo++] = ni->ni_opattrs;

	for ( i=0; i<myOcs.no_ninfo; i++ ) {
		if ( ndb_oc_del( myDict, NA->txn, eid, myOcs.no_info[i] ))
			return LDAP_OTHER;
	}

	return 0;
}

extern "C" int
ndb_dn2rdns(
	struct berval *dn,
	NdbRdns *rdns
)
{
	char *beg, *end;
	int i, len;

	/* Walk thru RDNs */
	end = dn->bv_val + dn->bv_len;
	for ( i=0; i<NDB_MAX_RDNS; i++ ) {
		for ( beg = end-1; beg > dn->bv_val; beg-- ) {
			if (*beg == ',') {
				beg++;
				break;
			}
		}
		if ( beg >= dn->bv_val ) {
			len = end - beg;
			/* RDN is too long */
			if ( len > NDB_RDN_LEN )
				return LDAP_CONSTRAINT_VIOLATION;
			memcpy( rdns->nr_buf[i]+1, beg, len );
		} else {
			break;
		}
		rdns->nr_buf[i][0] = len;
		end = beg - 1;
	}
	/* Too many RDNs in DN */
	if ( i == NDB_MAX_RDNS && beg > dn->bv_val ) {
			return LDAP_CONSTRAINT_VIOLATION;
	}
	rdns->nr_num = i;
	return 0;
}

static int
ndb_rdns2keys(
	NdbOperation *myop,
	NdbRdns *rdns
)
{
	int i;
	char dummy[2] = {0,0};

	/* Walk thru RDNs */
	for ( i=0; i<rdns->nr_num; i++ ) {
		if ( myop->equal( i+RDN_COLUMN, rdns->nr_buf[i] ))
			return LDAP_OTHER;
	}
	for ( ; i<NDB_MAX_RDNS; i++ ) {
		if ( myop->equal( i+RDN_COLUMN, dummy ))
			return LDAP_OTHER;
	}
	return 0;
}

/* Store the DN2ID_TABLE fields */
extern "C" int
ndb_entry_put_info(
	BackendDB *be,
	NdbArgs *NA,
	int update
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable = myDict->getTable( DN2ID_TABLE );
	NdbOperation *myop;
	NdbAttrInfo *ai;
	Attribute *aoc, *a;

	/* Get the entry's objectClass attribute; it's ok to be
	 * absent on a fresh insert
	 */
	aoc = attr_find( NA->e->e_attrs, slap_schema.si_ad_objectClass );
	if ( update && !aoc )
		return LDAP_OBJECT_CLASS_VIOLATION;

	myop = NA->txn->getNdbOperation( myTable );
	if ( !myop )
		return LDAP_OTHER;
	if ( update ) {
		if ( myop->updateTuple())
			return LDAP_OTHER;
	} else {
		if ( myop->insertTuple())
			return LDAP_OTHER;
	}

	if ( ndb_rdns2keys( myop, NA->rdns ))
		return LDAP_OTHER;

	/* Set entry ID */
	{
		Uint64 eid = NA->e->e_id;
		if ( myop->setValue( EID_COLUMN, eid ))
			return LDAP_OTHER;
	}

	/* Set list of objectClasses */
	if ( aoc ) {
		char *ptr, buf[sizeof(MedVar)];
		NdbOcs myOcs;
		int i;

		ndb_oc_check( be, NA->ndb, aoc->a_nvals, &myOcs );
		ptr = buf+2;
		for ( i=0; i<myOcs.no_ntext; i++ ) {
			/* data loss... */
			if ( ptr + myOcs.no_text[i].bv_len >= &buf[sizeof(buf)] )
				break;
			if ( i ) *ptr++ = ' ';
			ptr = lutil_strcopy( ptr, myOcs.no_text[i].bv_val );
		}
		i = ptr - buf - 2;
		buf[0] = i & 0xff;
		buf[1] = i >> 8;
		if ( myop->setValue( OCS_COLUMN, buf ))
			return LDAP_OTHER;
	}

	/* Set any indexed attrs */
	for ( a = NA->e->e_attrs; a; a=a->a_next ) {
		ai = ndb_ai_find( ni, a->a_desc->ad_type );
		if ( ai && ( ai->na_flag & NDB_INFO_INDEX )) {
			char *ptr, buf[sizeof(MedVar)];
			int len;

			ptr = buf+1;
			len = a->a_vals[0].bv_len;
			/* FIXME: data loss */
			if ( len > ai->na_len )
				len = ai->na_len;
			buf[0] = len & 0xff;
			if ( ai->na_len > 255 ) {
				*ptr++ = len >> 8;
			}
			memcpy( ptr, a->a_vals[0].bv_val, len );
			if ( myop->setValue( ai->na_ixcol, buf ))
				return LDAP_OTHER;
		}
	}

	return 0;
}

extern "C" struct berval *
ndb_str2bvarray(
	char *str,
	int len,
	char delim
)
{
	struct berval *list, tmp;
	char *beg;
	int i, num;

	for ( i = 1, beg = str;; i++ ) {
		beg = strchr( beg, delim );
		if ( !beg )
			break;
		beg++;
	}

	num = i;
	list = (struct berval *)ch_malloc( (num+1)*sizeof(struct berval));

	for ( i = 0, beg = str; i<num; i++ ) {
		tmp.bv_val = beg;
		beg = strchr( beg, delim );
		if ( beg ) {
			tmp.bv_len = beg - tmp.bv_val;
		} else {
			tmp.bv_len = len - (tmp.bv_val - str);
		}
		ber_dupbv( &list[i], &tmp );
		beg++;
	}

	BER_BVZERO( &list[i] );
	return list;
}

extern "C" struct berval *
ndb_ref2oclist(
	const char *ref
)
{
	/* MedVar */
	int len = ref[0] | (ref[1] << 8);
	return ndb_str2bvarray( (char *)ref+2, len, ' ' );
}

/* Retrieve the DN2ID_TABLE fields. Can call with NULL ocs if just verifying
 * the existence of a DN.
 */
extern "C" int
ndb_entry_get_info(
	BackendDB *be,
	NdbArgs *NA,
	int update,
	struct berval *matched
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable = myDict->getTable( DN2ID_TABLE );
	NdbOperation *myop;
	NdbRecAttr *attr1, *attr2;
	char idbuf[2*sizeof(ID)];
	char ocbuf[NDB_OC_BUFLEN];

	if ( matched ) {
		BER_BVZERO( matched );
	}
	if ( !myTable ) {
		return LDAP_OTHER;
	}

	myop = NA->txn->getNdbOperation( myTable );
	if ( !myop ) {
		return LDAP_OTHER;
	}

	if ( myop->readTuple( update ? NdbOperation::LM_Exclusive : NdbOperation::LM_CommittedRead )) {
		return LDAP_OTHER;
	}

	if ( !NA->rdns->nr_num && ndb_dn2rdns( &NA->e->e_name, NA->rdns )) {
		return LDAP_NO_SUCH_OBJECT;
	}

	if ( ndb_rdns2keys( myop, NA->rdns )) {
		return LDAP_OTHER;
	}

	attr1 = myop->getValue( EID_COLUMN, idbuf );
	if ( !attr1 ) {
		return LDAP_OTHER;
	}

	ocbuf[0] = 0;
	ocbuf[1] = 0;
	if ( !NA->ocs ) {
		attr2 = myop->getValue( OCS_COLUMN, ocbuf );
		if ( !attr2 ) {
			return LDAP_OTHER;
		}
	}

	if ( NA->txn->execute(NdbTransaction::NoCommit, NdbOperation::AO_IgnoreError, 1) < 0 ) {
		return LDAP_OTHER;
	}

	switch( myop->getNdbError().code ) {
	case 0:
		if ( !attr1->isNULL() && ( NA->e->e_id = attr1->u_64_value() )) {
			/* If we didn't care about OCs, or we got them */
			if ( NA->ocs || ocbuf[0] || ocbuf[1] ) {
				/* If wanted, return them */
				if ( !NA->ocs )
					NA->ocs = ndb_ref2oclist( ocbuf );
				break;
			}
		}
		/* FALLTHRU */
	case NDB_NO_SUCH_OBJECT:	/* no such tuple: look for closest parent */
		if ( matched ) {
			NdbOperation *ops[NDB_MAX_RDNS];
			int i, j, k;
			char dummy[2] = {0,0};

			/* get to last RDN, then back up 1 */
			k = NA->rdns->nr_num - 1;

			for ( i=0; i<k; i++ ) {
				ops[i] = NA->txn->getNdbOperation( myTable );
				if ( !ops[i] )
					return LDAP_OTHER;
				if ( ops[i]->readTuple( NdbOperation::LM_CommittedRead ))
					return LDAP_OTHER;
				for ( j=0; j<=i; j++ ) {
					if ( ops[i]->equal( j+RDN_COLUMN, NA->rdns->nr_buf[j] ))
						return LDAP_OTHER;
				}
				for ( ;j<NDB_MAX_RDNS; j++ ) {
					if ( ops[i]->equal( j+RDN_COLUMN, dummy ))
						return LDAP_OTHER;
				}
			}
			if ( NA->txn->execute(NdbTransaction::NoCommit, NdbOperation::AO_IgnoreError, 1) < 0 ) {
				return LDAP_OTHER;
			}
			for ( --i; i>=0; i-- ) {
				if ( ops[i]->getNdbError().code == 0 ) {
					for ( j=0; j<=i; j++ )
						matched->bv_len += NA->rdns->nr_buf[j][0];
					matched->bv_len += i;
					matched->bv_val = NA->e->e_name.bv_val +
						NA->e->e_name.bv_len - matched->bv_len;
					break;
				}
			}
		}
		return LDAP_NO_SUCH_OBJECT;
	default:
		return LDAP_OTHER;
	}

	return 0;
}

extern "C" int
ndb_entry_del_info(
	BackendDB *be,
	NdbArgs *NA
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = NA->ndb->getDictionary();
	const NdbDictionary::Table *myTable = myDict->getTable( DN2ID_TABLE );
	NdbOperation *myop;

	myop = NA->txn->getNdbOperation( myTable );
	if ( !myop )
		return LDAP_OTHER;
	if ( myop->deleteTuple())
		return LDAP_OTHER;

	if ( ndb_rdns2keys( myop, NA->rdns ))
		return LDAP_OTHER;

	/* Let caller invoke the roundtrip */
	/* return txn->execute(NoCommit); */
	return 0;
}

extern "C" int
ndb_next_id(
	BackendDB *be,
	Ndb *ndb,
	ID *id
)
{
	struct ndb_info *ni = (struct ndb_info *) be->be_private;
	const NdbDictionary::Dictionary *myDict = ndb->getDictionary();
	const NdbDictionary::Table *myTable = myDict->getTable( NEXTID_TABLE );
	Uint64 nid = 0;
	int rc;

	if ( !myTable ) {
		Debug( LDAP_DEBUG_ANY, "ndb_next_id: " NEXTID_TABLE " table is missing\n",
			0, 0, 0 );
		return LDAP_OTHER;
	}

	rc = ndb->getAutoIncrementValue( myTable, nid, 1000 );
	if ( !rc )
		*id = nid;
	return rc;
}

extern "C" { static void ndb_thread_hfree( void *key, void *data ); };
static void
ndb_thread_hfree( void *key, void *data )
{
	Ndb *ndb = (Ndb *)data;
	delete ndb;
}

extern "C" int
ndb_thread_handle(
	Operation *op,
	Ndb **ndb )
{
	struct ndb_info *ni = (struct ndb_info *) op->o_bd->be_private;
	void *data;

	if ( ldap_pvt_thread_pool_getkey( op->o_threadctx, ni, &data, NULL )) {
		Ndb *myNdb;
		int rc;
		ldap_pvt_thread_mutex_lock( &ni->ni_conn_mutex );
		myNdb = new Ndb( ni->ni_cluster[ni->ni_nextconn++], ni->ni_dbname );
		if ( ni->ni_nextconn >= ni->ni_nconns )
			ni->ni_nextconn = 0;
		ldap_pvt_thread_mutex_unlock( &ni->ni_conn_mutex );
		if ( !myNdb ) {
			return LDAP_OTHER;
		}
		rc = myNdb->init(1024);
		if ( rc ) {
			delete myNdb;
			Debug( LDAP_DEBUG_ANY, "ndb_thread_handle: err %d\n",
				rc, 0, 0 );
			return rc;
		}
		data = (void *)myNdb;
		if (( rc = ldap_pvt_thread_pool_setkey( op->o_threadctx, ni,
			data, ndb_thread_hfree, NULL, NULL ))) {
			delete myNdb;
			Debug( LDAP_DEBUG_ANY, "ndb_thread_handle: err %d\n",
				rc, 0, 0 );
			return rc;
		}
	}
	*ndb = (Ndb *)data;
	return 0;
}

extern "C" int
ndb_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *ad,
	int rw,
	Entry **ent )
{
	struct ndb_info *ni = (struct ndb_info *) op->o_bd->be_private;
	NdbArgs NA;
	Entry e = {0};
	int rc;

	/* Get our NDB handle */
	rc = ndb_thread_handle( op, &NA.ndb );

	NA.txn = NA.ndb->startTransaction();
	if( !NA.txn ) {
		Debug( LDAP_DEBUG_TRACE,
			LDAP_XSTRING(ndb_entry_get) ": startTransaction failed: %s (%d)\n",
			NA.ndb->getNdbError().message, NA.ndb->getNdbError().code, 0 );
		return 1;
	}

	e.e_name = *ndn;
	NA.e = &e;
	/* get entry */
	{
		NdbRdns rdns;
		rdns.nr_num = 0;
		NA.ocs = NULL;
		NA.rdns = &rdns;
		rc = ndb_entry_get_info( op->o_bd, &NA, rw, NULL );
	}
	if ( rc == 0 ) {
		e.e_name = *ndn;
		e.e_nname = *ndn;
		rc = ndb_entry_get_data( op->o_bd, &NA, 0 );
		ber_bvarray_free( NA.ocs );
		if ( rc == 0 ) {
			if ( oc && !is_entry_objectclass_or_sub( &e, oc )) {
				attrs_free( e.e_attrs );
				rc = 1;
			}
		}
	}
	if ( rc == 0 ) {
		*ent = entry_alloc();
		**ent = e;
		ber_dupbv( &(*ent)->e_name, ndn );
		ber_dupbv( &(*ent)->e_nname, ndn );
	} else {
		rc = 1;
	}
	NA.txn->close();
	return rc;
}

/* Congestion avoidance code
 * for Deadlock Rollback
 */

extern "C" void
ndb_trans_backoff( int num_retries )
{
	int i;
	int delay = 0;
	int pow_retries = 1;
	unsigned long key = 0;
	unsigned long max_key = -1;
	struct timeval timeout;

	lutil_entropy( (unsigned char *) &key, sizeof( unsigned long ));

	for ( i = 0; i < num_retries; i++ ) {
		if ( i >= 5 ) break;
		pow_retries *= 4;
	}

	delay = 16384 * (key * (double) pow_retries / (double) max_key);
	delay = delay ? delay : 1;

	Debug( LDAP_DEBUG_TRACE,  "delay = %d, num_retries = %d\n", delay, num_retries, 0 );

	timeout.tv_sec = delay / 1000000;
	timeout.tv_usec = delay % 1000000;
	select( 0, NULL, NULL, NULL, &timeout );
}
