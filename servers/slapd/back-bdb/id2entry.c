/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "back-bdb.h"

#ifdef BDB_USE_BINARY_RW

/* A cache of every AttributeDescription we ever see. We don't want
 * to churn thru malloc/free on them all the time since most will be
 * encountered repeatedly.
 */
static Avlnode *adcache;

static int
ad_type_cmp(
	char *desc,
	AttributeDescription *ad
)
{
	return strcasecmp(desc, ad->ad_cname.bv_val);
}

static int
ad_info_cmp(
	AttributeDescription *a1,
	AttributeDescription *a2
)
{
	return strcasecmp(a1->ad_cname.bv_val, a2->ad_cname.bv_val);
}

AttributeDescription *
bdb_str2ad(const char *desc)
{
	AttributeDescription *a;

	a = (AttributeDescription *) avl_find(adcache, desc,
		(AVL_CMP) ad_type_cmp);
	if (!a) {
		int rc;
		const char *text;

		rc = slap_str2ad(desc, &a, &text);
		if (rc != LDAP_SUCCESS) {
			return NULL;
		}
		rc = avl_insert(&adcache, (caddr_t)a, (AVL_CMP) ad_info_cmp,
			(AVL_DUP) avl_dup_error);
	}
	return a;
}

/* Flatten an Entry into a buffer. The buffer contents become a direct
 * copy of the entry, with all pointers converted to offsets from the
 * beginning of the buffer. We do this by first walking through all
 * the fields of the Entry, adding up their sizes. Then a single chunk
 * of memory is malloc'd and the entry is copied. We differentiate between
 * fixed size fields and variable-length content when tallying up the
 * entry size, so that we can stick all of the variable-length stuff
 * into the back half of the buffer.
 */
int bdb_encode(Entry *e, struct berval **bv)
{
	int siz = sizeof(Entry);
	int len, dnlen;
	int i, j;
	Entry *f;
	Attribute *a, *b;
	struct berval **bvl, *bz;
	char *ptr, *base, *data;

	*bv = ch_malloc(sizeof(struct berval));
	/* Compress any white space in the DN */
	dn_validate(e->e_dn);
	dnlen = strlen(e->e_dn);
	/* The dn and ndn are always the same length */
	len = dnlen + dnlen + 2;	/* two trailing NUL bytes */
	for (a=e->e_attrs; a; a=a->a_next) {
		/* For AttributeDesc, we only store the attr name */
		siz += sizeof(Attribute);
		len += a->a_desc->ad_cname.bv_len+1;
		for (i=0; a->a_vals[i]; i++) {
			siz += sizeof(struct berval *);
			siz += sizeof(struct berval);
			len += a->a_vals[i]->bv_len + 1;
		}
		siz += sizeof(struct berval *);	/* NULL pointer at end */
	}
	(*bv)->bv_len = siz + len;
	(*bv)->bv_val = ch_malloc(siz+len);
	base = (*bv)->bv_val;
	ptr = base + siz;
	f = (Entry *)base;
	data = (char *)(f+1);
	f->e_id = e->e_id;
	f->e_dn = (char *)(ptr-base);
	memcpy(ptr, e->e_dn, dnlen);
	ptr += dnlen;
	*ptr++ = '\0';
	f->e_ndn = (char *)(ptr-base);
	memcpy(ptr, e->e_ndn, dnlen);
	ptr += dnlen;
	*ptr++ = '\0';
	f->e_attrs = e->e_attrs ? (Attribute *)sizeof(Entry) : NULL;
	f->e_private = NULL;
	for (a=e->e_attrs; a; a=a->a_next) {
		b = (Attribute *)data;
		data = (char *)(b+1);
		b->a_desc = (AttributeDescription *)(ptr-base);
		memcpy(ptr, a->a_desc->ad_cname.bv_val,
			a->a_desc->ad_cname.bv_len);
		ptr += a->a_desc->ad_cname.bv_len;
		*ptr++ = '\0';
		if (a->a_vals) {
		    bvl = (struct berval **)data;
		    b->a_vals = (struct berval **)(data-base);
		    for (i=0; a->a_vals[i]; i++);
		    data = (char *)(bvl+i+1);
		    bz = (struct berval *)data;
		    for (j=0; j<i; j++) {
			    bz->bv_len = a->a_vals[j]->bv_len;
			    if (a->a_vals[j]->bv_val) {
				bz->bv_val = (char *)(ptr-base);
				memcpy(ptr, a->a_vals[j]->bv_val, bz->bv_len);
			    } else {
			    	bz->bv_val = NULL;
			    }
			    ptr += bz->bv_len;
			    *ptr++ = '\0';
			    bvl[j] = (struct berval *)(data-base);
			    bz++;
			    data = (char *)bz;
		    }
		    bvl[j] = NULL;
		} else {
		    b->a_vals = NULL;
		}

		if (a->a_next)
		    b->a_next = (Attribute *)(data-base);
		else
		    b->a_next = NULL;
	}
	return 0;
}

/* Retrieve an Entry that was stored using bdb_encode above.
 * All we have to do is add the buffer address to all of the
 * stored offsets. We also use the stored attribute names to
 * pull AttributeDescriptions from our ad_cache. To detect if
 * the attributes of an Entry are later modified, we also store
 * the address of the end of this block in e_private. Since
 * modify_internal always allocs a new list of attrs to work
 * with, we need to free that separately.
 */
int bdb_decode(struct berval *bv, Entry **e)
{
	int i;
	long base;
	Attribute *a;
	Entry *x = (Entry *)bv->bv_val;

	base = (long)bv->bv_val;
	x->e_dn += base;
	x->e_ndn += base;
	x->e_private = bv->bv_val + bv->bv_len;
	if (x->e_attrs)
		x->e_attrs = (Attribute *)((long)x->e_attrs+base);
	for (a=x->e_attrs; a; a=a->a_next) {
		if (a->a_next)
			a->a_next = (Attribute *)((long)a->a_next+base);
		a->a_desc=bdb_str2ad((char *)a->a_desc+base);
		if (!a->a_desc) return -1;
		if (a->a_vals) {
			a->a_vals = (struct berval **)((long)a->a_vals+base);
			for (i=0; a->a_vals[i]; i++) {
				a->a_vals[i] = (struct berval *)
					((long)a->a_vals[i]+base);
				if (a->a_vals[i]->bv_val)
				    a->a_vals[i]->bv_val += base;
			}
		}
	}
	*e = x;
	return 0;
}

#define	entry_encode(a, b)	bdb_encode(a,b)
#define	entry_decode(a, b)	bdb_decode(a,b)

#endif	/* BDB_USE_BINARY_RW */

int bdb_id2entry_add(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( bv, &data );

	rc = db->put( db, tid, &key, &data, DB_NOOVERWRITE );

	ber_bvfree( bv );
	return rc;
}

int bdb_id2entry_update(
	BackendDB *be,
	DB_TXN *tid,
	Entry *e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &e->e_id;
	key.size = sizeof(ID);

	rc = entry_encode( e, &bv );
	if( rc != LDAP_SUCCESS ) {
		return -1;
	}

	DBTzero( &data );
	bv2DBT( bv, &data );

	rc = db->put( db, tid, &key, &data, 0 );

	ber_bvfree( bv );
	return rc;
}

int bdb_id2entry(
	BackendDB *be,
	DB_TXN *tid,
	ID id,
	Entry **e )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key, data;
	struct berval bv;
	int rc;

	*e = NULL;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	DBTzero( &data );
	data.flags = DB_DBT_MALLOC;

	/* fetch it */
	rc = db->get( db, tid, &key, &data, 0 );

	if( rc != 0 ) {
		return rc;
	}

	DBT2bv( &data, &bv );

	rc = entry_decode( &bv, e );

	if( rc == 0 ) {
		(*e)->e_id = id;
	}

#ifndef BDB_USE_BINARY_RW
	ch_free( data.data );
#endif
	return rc;
}

int bdb_id2entry_delete(
	BackendDB *be,
	DB_TXN *tid,
	ID id )
{
	struct bdb_info *bdb = (struct bdb_info *) be->be_private;
	DB *db = bdb->bi_id2entry->bdi_db;
	DBT key;
	struct berval *bv;
	int rc;

	DBTzero( &key );
	key.data = (char *) &id;
	key.size = sizeof(ID);

	rc = db->del( db, tid, &key, 0 );

	ber_bvfree( bv );
	return rc;
}

int bdb_entry_return(
	BackendDB *be,
	Entry *e )
{
#ifdef BDB_USE_BINARY_RW
	/* bdb_modify_internal always operates on a dup'd set of attrs. */
	if ((void *)e->e_attrs < (void *)e  ||
		(void *)e->e_attrs > e->e_private)
	    attrs_free(e->e_attrs);
	ch_free(e);
#else
	entry_free( e );
#endif
	return 0;
}
