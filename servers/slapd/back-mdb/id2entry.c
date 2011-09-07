/* id2entry.c - routines to deal with the id2entry database */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2011 The OpenLDAP Foundation.
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
#include <ac/string.h>
#include <ac/errno.h>

#include "back-mdb.h"

static int mdb_entry_encode(Operation *op, MDB_txn *txn, Entry *e, MDB_val *data);

static int mdb_id2entry_put(
	Operation *op,
	MDB_txn *tid,
	Entry *e,
	int flag )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key, data;
	int rc;

	/* We only store rdns, and they go in the dn2id database. */

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	rc = mdb_entry_encode( op, tid, e, &data );
	if( rc != LDAP_SUCCESS ) {
		return LDAP_OTHER;
	}

	rc = mdb_put( tid, dbi, &key, &data, flag );
	op->o_tmpfree( data.mv_data, op->o_tmpmemctx );
	if (rc) {
		Debug( LDAP_DEBUG_ANY,
			"mdb_id2entry_put: mdb_put failed: %s(%d) \"%s\"\n",
			mdb_strerror(rc), rc,
			e->e_nname.bv_val );
		rc = LDAP_OTHER;
	}
	return rc;
}

/*
 * This routine adds (or updates) an entry on disk.
 * The cache should be already be updated.
 */


int mdb_id2entry_add(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, MDB_NOOVERWRITE);
}

int mdb_id2entry_update(
	Operation *op,
	MDB_txn *tid,
	Entry *e )
{
	return mdb_id2entry_put(op, tid, e, 0);
}

int mdb_id2entry(
	Operation *op,
	MDB_txn *tid,
	ID id,
	Entry **e )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key, data;
	int rc = 0;

	*e = NULL;

	key.mv_data = &id;
	key.mv_size = sizeof(ID);

	/* fetch it */
	rc = mdb_get( tid, dbi, &key, &data );
	if ( rc == MDB_NOTFOUND ) {
		/* Looking for root entry on an empty-dn suffix? */
		if ( !id && BER_BVISEMPTY( &op->o_bd->be_nsuffix[0] )) {
			struct berval gluebv = BER_BVC("glue");
			Entry *r = entry_alloc();

			r->e_id = 0;
			attr_merge_one( r, slap_schema.si_ad_objectClass, &gluebv, NULL );
			attr_merge_one( r, slap_schema.si_ad_structuralObjectClass, &gluebv, NULL );
			r->e_ocflags = SLAP_OC_GLUE|SLAP_OC__END;
			*e = r;
			return MDB_SUCCESS;
		}
	}
	if ( rc ) return rc;

	rc = mdb_entry_decode( op, &data, e );
	if ( rc ) return rc;

	(*e)->e_id = id;
	(*e)->e_name.bv_val = NULL;
	(*e)->e_nname.bv_val = NULL;

	return rc;
}

int mdb_id2entry_delete(
	BackendDB *be,
	MDB_txn *tid,
	Entry *e )
{
	struct mdb_info *mdb = (struct mdb_info *) be->be_private;
	MDB_dbi dbi = mdb->mi_id2entry;
	MDB_val key;
	int rc;

	key.mv_data = &e->e_id;
	key.mv_size = sizeof(ID);

	/* delete from database */
	rc = mdb_del( tid, dbi, &key, NULL );

	return rc;
}

int mdb_entry_return(
	Entry *e
)
{
	entry_free( e );
	return 0;
}

int mdb_entry_release(
	Operation *op,
	Entry *e,
	int rw )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *moi = NULL;
	int rc;
 
	/* slapMode : SLAP_SERVER_MODE, SLAP_TOOL_MODE,
			SLAP_TRUNCATE_MODE, SLAP_UNDEFINED_MODE */
 
	mdb_entry_return ( e );
	if ( slapMode == SLAP_SERVER_MODE ) {
		OpExtra *oex;
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) {
				moi = (mdb_op_info *)oex;
				/* If it was setup by entry_get we should probably free it */
				if ( moi->moi_flag & MOI_FREEIT ) {
					moi->moi_ref--;
					if ( moi->moi_ref < 1 ) {
						mdb_txn_reset( moi->moi_txn );
						moi->moi_ref = 0;
						LDAP_SLIST_REMOVE( &op->o_extra, &moi->moi_oe, OpExtra, oe_next );
						op->o_tmpfree( moi, op->o_tmpmemctx );
					}
				}
				break;
			}
		}
	}
 
	return 0;
}

/* return LDAP_SUCCESS IFF we can retrieve the specified entry.
 */
int mdb_entry_get(
	Operation *op,
	struct berval *ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent )
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	struct mdb_op_info *moi = NULL;
	MDB_txn *txn = NULL;
	Entry *e = NULL;
	int	rc;
	const char *at_name = at ? at->ad_cname.bv_val : "(null)";

	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: ndn: \"%s\"\n", ndn->bv_val, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> mdb_entry_get: oc: \"%s\", at: \"%s\"\n",
		oc ? oc->soc_cname.bv_val : "(null)", at_name, 0);

	rc = mdb_opinfo_get( op, mdb, rw == 0, &moi );
	if ( rc )
		return LDAP_OTHER;
	txn = moi->moi_txn;

	/* can we find entry */
	rc = mdb_dn2entry( op, txn, ndn, &e, 0 );
	switch( rc ) {
	case MDB_NOTFOUND:
	case 0:
		break;
	default:
		return (rc != LDAP_BUSY) ? LDAP_OTHER : LDAP_BUSY;
	}
	if (e == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"=> mdb_entry_get: cannot find entry: \"%s\"\n",
				ndn->bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_OBJECT;
		goto return_results;
	}
	
	Debug( LDAP_DEBUG_ACL,
		"=> mdb_entry_get: found entry: \"%s\"\n",
		ndn->bv_val, 0, 0 ); 

	if ( oc && !is_entry_objectclass( e, oc, 0 )) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find objectClass %s\n",
			oc->soc_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

	/* NOTE: attr_find() or attrs_find()? */
	if ( at && attr_find( e->e_attrs, at ) == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"<= mdb_entry_get: failed to find attribute %s\n",
			at->ad_cname.bv_val, 0, 0 ); 
		rc = LDAP_NO_SUCH_ATTRIBUTE;
		goto return_results;
	}

return_results:
	if( rc != LDAP_SUCCESS ) {
		/* free entry */
		if ( e )
			mdb_entry_return( e );

		if (moi->moi_ref == 1) {
			LDAP_SLIST_REMOVE( &op->o_extra, &moi->moi_oe, OpExtra, oe_next );
			mdb_txn_reset( txn );
			op->o_tmpfree( moi, op->o_tmpmemctx );
		}
	} else {
		*ent = e;
	}

	Debug( LDAP_DEBUG_TRACE,
		"mdb_entry_get: rc=%d\n",
		rc, 0, 0 ); 
	return(rc);
}

static void
mdb_reader_free( void *key, void *data )
{
	MDB_txn *txn = data;

	if ( txn ) mdb_txn_abort( txn );
}

/* free up any keys used by the main thread */
void
mdb_reader_flush( MDB_env *env )
{
	void *data;
	void *ctx = ldap_pvt_thread_pool_context();

	if ( !ldap_pvt_thread_pool_getkey( ctx, env, &data, NULL ) ) {
		ldap_pvt_thread_pool_setkey( ctx, env, NULL, 0, NULL, NULL );
		mdb_reader_free( env, data );
	}
}

int
mdb_opinfo_get( Operation *op, struct mdb_info *mdb, int rdonly, mdb_op_info **moip )
{
	int rc, renew = 0;
	void *data;
	void *ctx;
	mdb_op_info *moi = NULL;
	OpExtra *oex;

	assert( op != NULL );

	if ( !mdb || !moip ) return -1;

	/* If no op was provided, try to find the ctx anyway... */
	if ( op ) {
		ctx = op->o_threadctx;
	} else {
		ctx = ldap_pvt_thread_pool_context();
	}

	if ( op ) {
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == mdb ) break;
		}
		moi = (mdb_op_info *)oex;
	}

	if ( !moi ) {
		moi = *moip;

		if ( !moi ) {
			if ( op ) {
				moi = op->o_tmpalloc(sizeof(struct mdb_op_info),op->o_tmpmemctx);
			} else {
				moi = ch_malloc(sizeof(mdb_op_info));
			}
			moi->moi_flag = MOI_FREEIT;
			*moip = moi;
		}
		LDAP_SLIST_INSERT_HEAD( &op->o_extra, &moi->moi_oe, oe_next );
		moi->moi_oe.oe_key = mdb;
		moi->moi_ref = 0;
		moi->moi_txn = NULL;
	}

	if ( !rdonly ) {
		/* This op started as a reader, but now wants to write. */
		if ( moi->moi_flag & MOI_READER ) {
			moi = *moip;
			LDAP_SLIST_INSERT_HEAD( &op->o_extra, &moi->moi_oe, oe_next );
		} else {
		/* This op is continuing an existing write txn */
			*moip = moi;
		}
		moi->moi_ref++;
		if ( !moi->moi_txn ) {
			rc = mdb_txn_begin( mdb->mi_dbenv, 0, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
			}
			return rc;
		}
		return 0;
	}

	/* OK, this is a reader */
	if ( !moi->moi_txn ) {
		if ( !ctx ) {
			/* Shouldn't happen unless we're single-threaded */
			rc = mdb_txn_begin( mdb->mi_dbenv, MDB_RDONLY, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
			}
			return rc;
		}
		if ( ldap_pvt_thread_pool_getkey( ctx, mdb->mi_dbenv, &data, NULL ) ) {
			rc = mdb_txn_begin( mdb->mi_dbenv, MDB_RDONLY, &moi->moi_txn );
			if (rc) {
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: err %s(%d)\n",
					mdb_strerror(rc), rc, 0 );
				return rc;
			}
			data = moi->moi_txn;
			if ( ( rc = ldap_pvt_thread_pool_setkey( ctx, mdb->mi_dbenv,
				data, mdb_reader_free, NULL, NULL ) ) ) {
				mdb_txn_abort( moi->moi_txn );
				moi->moi_txn = NULL;
				Debug( LDAP_DEBUG_ANY, "mdb_opinfo_get: thread_pool_setkey failed err (%d)\n",
					rc, 0, 0 );
				return rc;
			}
		} else {
			moi->moi_txn = data;
			renew = 1;
		}
		moi->moi_flag |= MOI_READER;
	}
	if ( moi->moi_ref < 1 ) {
		moi->moi_ref = 0;
	}
	if ( renew ) {
		mdb_txn_renew( moi->moi_txn );
	}
	moi->moi_ref++;
	if ( *moip != moi )
		*moip = moi;

	return 0;
}

/* This is like a ber_len */
#define entry_lenlen(l)	(((l) < 0x80) ? 1 : ((l) < 0x100) ? 2 : \
	((l) < 0x10000) ? 3 : ((l) < 0x1000000) ? 4 : 5)

static void
mdb_entry_putlen(unsigned char **buf, ber_len_t len)
{
	ber_len_t lenlen = entry_lenlen(len);

	if (lenlen == 1) {
		**buf = (unsigned char) len;
	} else {
		int i;
		**buf = 0x80 | ((unsigned char) lenlen - 1);
		for (i=lenlen-1; i>0; i--) {
			(*buf)[i] = (unsigned char) len;
			len >>= 8;
		}
	}
	*buf += lenlen;
}

static ber_len_t
mdb_entry_getlen(unsigned char **buf)
{
	ber_len_t len;
	int i;

	len = *(*buf)++;
	if (len <= 0x7f)
		return len;
	i = len & 0x7f;
	len = 0;
	for (;i > 0; i--) {
		len <<= 8;
		len |= *(*buf)++;
	}
	return len;
}

/* Count up the sizes of the components of an entry */
static int mdb_entry_partsize(struct mdb_info *mdb, MDB_txn *txn, Entry *e,
	EntryHeader *eh)
{
	ber_len_t len = 0;
	int i, nat = 0, nval = 0;
	Attribute *a;

	for (a=e->e_attrs; a; a=a->a_next) {
		/* For AttributeDesc, we only store the attr index */
		nat++;
		if (!mdb->mi_adxs[a->a_desc->ad_index]) {
			int rc = mdb_ad_get(mdb, txn, a->a_desc);
			if (rc)
				return rc;
		}
		len += entry_lenlen(mdb->mi_adxs[a->a_desc->ad_index]);
		for (i=0; a->a_vals[i].bv_val; i++) {
			nval++;
			len += a->a_vals[i].bv_len + 1;
			len += entry_lenlen(a->a_vals[i].bv_len);
		}
		len += entry_lenlen(i);
		nval++;	/* empty berval at end */
		if (a->a_nvals != a->a_vals) {
			for (i=0; a->a_nvals[i].bv_val; i++) {
				nval++;
				len += a->a_nvals[i].bv_len + 1;
				len += entry_lenlen(a->a_nvals[i].bv_len);
			}
			len += entry_lenlen(i);	/* i nvals */
			nval++;
		} else {
			len += entry_lenlen(0);	/* 0 nvals */
		}
	}
	len += entry_lenlen(e->e_ocflags);
	len += entry_lenlen(nat);
	len += entry_lenlen(nval);
	eh->bv.bv_len = len;
	eh->nattrs = nat;
	eh->nvals = nval;
	return 0;
}

/* Flatten an Entry into a buffer. The buffer is filled with just the
 * strings/bervals of all the entry components. Each field is preceded
 * by its length, encoded the way ber_put_len works. Every field is NUL
 * terminated.  The entire buffer size is precomputed so that a single
 * malloc can be performed. The entry size is also recorded,
 * to aid in entry_decode.
 */
static int mdb_entry_encode(Operation *op, MDB_txn *txn, Entry *e, MDB_val *data)
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	ber_len_t len, dnlen, ndnlen, i;
	EntryHeader eh;
	int rc;
	Attribute *a;
	unsigned char *ptr;

	Debug( LDAP_DEBUG_TRACE, "=> mdb_entry_encode(0x%08lx): %s\n",
		(long) e->e_id, e->e_dn, 0 );

	if (is_entry_referral(e))
		;	/* empty */

	rc = mdb_entry_partsize( mdb, txn, e, &eh );
	if (rc) return rc;

	data->mv_size = eh.bv.bv_len;
	data->mv_data = op->o_tmpalloc(data->mv_size, op->o_tmpmemctx);
	ptr = (unsigned char *)data->mv_data;
	mdb_entry_putlen(&ptr, eh.nattrs);
	mdb_entry_putlen(&ptr, eh.nvals);
	mdb_entry_putlen(&ptr, e->e_ocflags);

	for (a=e->e_attrs; a; a=a->a_next) {
		mdb_entry_putlen(&ptr, mdb->mi_adxs[a->a_desc->ad_index]);
		if (a->a_vals) {
			for (i=0; a->a_vals[i].bv_val; i++);
			assert( i == a->a_numvals );
			mdb_entry_putlen(&ptr, i);
			for (i=0; a->a_vals[i].bv_val; i++) {
				mdb_entry_putlen(&ptr, a->a_vals[i].bv_len);
				AC_MEMCPY(ptr, a->a_vals[i].bv_val,
					a->a_vals[i].bv_len);
				ptr += a->a_vals[i].bv_len;
				*ptr++ = '\0';
			}
			if (a->a_nvals != a->a_vals) {
				mdb_entry_putlen(&ptr, i);
				for (i=0; a->a_nvals[i].bv_val; i++) {
					mdb_entry_putlen(&ptr, a->a_nvals[i].bv_len);
					AC_MEMCPY(ptr, a->a_nvals[i].bv_val,
					a->a_nvals[i].bv_len);
					ptr += a->a_nvals[i].bv_len;
					*ptr++ = '\0';
				}
			} else {
				mdb_entry_putlen(&ptr, 0);
			}
		}
	}

	Debug( LDAP_DEBUG_TRACE, "<= mdb_entry_encode(0x%08lx): %s\n",
		(long) e->e_id, e->e_dn, 0 );

	return 0;
}

/* Retrieve an Entry that was stored using entry_encode above.
 *
 * Note: everything is stored in a single contiguous block, so
 * you can not free individual attributes or names from this
 * structure. Attempting to do so will likely corrupt memory.
 */

int mdb_entry_decode(Operation *op, MDB_val *data, Entry **e)
{
	struct mdb_info *mdb = (struct mdb_info *) op->o_bd->be_private;
	int i, j, nattrs, nvals;
	int rc;
	Attribute *a;
	Entry *x;
	const char *text;
	AttributeDescription *ad;
	unsigned char *ptr = (unsigned char *)data->mv_data;
	BerVarray bptr;

	Debug( LDAP_DEBUG_TRACE,
		"=> mdb_entry_decode:\n",
		0, 0, 0 );

	nattrs = mdb_entry_getlen(&ptr);
	nvals = mdb_entry_getlen(&ptr);
	x = entry_alloc();
	x->e_ocflags = mdb_entry_getlen(&ptr);
	x->e_attrs = attrs_alloc( nattrs );
	x->e_bv.bv_len = nvals * sizeof(struct berval);
	x->e_bv.bv_val = op->o_tmpalloc(x->e_bv.bv_len, op->o_tmpmemctx);
	bptr = (BerVarray) x->e_bv.bv_val;

	a = x->e_attrs;

	while ((i = mdb_entry_getlen(&ptr))) {
		a->a_desc = mdb->mi_ads[i];
		a->a_flags = SLAP_ATTR_DONT_FREE_DATA | SLAP_ATTR_DONT_FREE_VALS;
		j = mdb_entry_getlen(&ptr);
		a->a_numvals = j;
		a->a_vals = bptr;

		while (j) {
			i = mdb_entry_getlen(&ptr);
			bptr->bv_len = i;
			bptr->bv_val = (char *)ptr;
			ptr += i+1;
			bptr++;
			j--;
		}
		bptr->bv_val = NULL;
		bptr->bv_len = 0;
		bptr++;

		j = mdb_entry_getlen(&ptr);
		if (j) {
			a->a_nvals = bptr;
			while (j) {
				i = mdb_entry_getlen(&ptr);
				bptr->bv_len = i;
				bptr->bv_val = (char *)ptr;
				ptr += i+1;
				bptr++;
				j--;
			}
			bptr->bv_val = NULL;
			bptr->bv_len = 0;
			bptr++;
		} else {
			a->a_nvals = a->a_vals;
		}
		/* FIXME: This is redundant once a sorted entry is saved into the DB */
		if ( a->a_desc->ad_type->sat_flags & SLAP_AT_SORTED_VAL ) {
			rc = slap_sort_vals( (Modifications *)a, &text, &j, NULL );
			if ( rc == LDAP_SUCCESS ) {
				a->a_flags |= SLAP_ATTR_SORTED_VALS;
			} else if ( rc == LDAP_TYPE_OR_VALUE_EXISTS ) {
				/* should never happen */
				Debug( LDAP_DEBUG_ANY,
					"mdb_entry_decode: attributeType %s value #%d provided more than once\n",
					a->a_desc->ad_cname.bv_val, j, 0 );
				return rc;
			}
		}
		a = a->a_next;
		nattrs--;
		if ( !nattrs )
			break;
	}

	Debug(LDAP_DEBUG_TRACE, "<= mdb_entry_decode\n",
		0, 0, 0 );
	*e = x;
	return 0;
}
