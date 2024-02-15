/**	@file midl.c
 *	@brief ldap bdb back-end ID List functions */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2021 The OpenLDAP Foundation.
 * Portions Copyright 2001-2021 Howard Chu, Symas Corp.
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

#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include "midl.h"

/** @defgroup internal	LMDB Internals
 *	@{
 */
/** @defgroup idls	ID List Management
 *	@{
 */
#define CMP(x,y)	 ( (x) < (y) ? -1 : (x) > (y) )

unsigned mdb_midl_search( MDB_IDL ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned end = ids[0];

	while( base + 1 < end ) {
		cursor = (base + end + 1) >> 1;
		ssize_t entry;
		while((entry = ids[cursor]) == 0) {
			if (++cursor > end) {
				// we went past the end, search other direction
				cursor = (base + end) >> 1;
				while((entry = ids[cursor]) == 0) {
					if (--cursor <= base) {
						// completely empty section
						return (base + end + 1) >> 1;
					}
				}
			}
		}
		if (entry < 0) entry = ids[cursor + 1]; // block length, skip past and compare actual id
		val = CMP( entry, id );

		if( val < 0 ) {
			if (cursor == end) return cursor;
			end = cursor;
		} else if ( val > 0 ) {
			if (cursor == base) return cursor + 1;
			base = cursor;
		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

	/* superseded by append/sort */
int mdb_midl_insert( MDB_IDL* ids_ref, MDB_ID id )
{
	MDB_IDL ids = *ids_ref;
	unsigned x, i;

	x = mdb_midl_search( ids, id );
	//assert( x > 0 );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0] && ids[x] == id ) {
		/* duplicate */
		//assert(0);
		return -1;
	}

	if ( ids[0] >= MDB_IDL_DB_MAX ) {
		/* no room */
		--ids[0];
		return -2;

	} else {
		if (x > ids[0]) return -3; // at the end
		ssize_t next_id = ids[x];
		unsigned next_count = 1;
		if (next_id < 0) {
			next_count = -next_id;
			next_id = ids[x + 1];
		}
		unsigned before = x; // this will end up pointing to an entry or zero right before a block of empty space
		while (!ids[--before] && before > 0) {
			// move past empty entries
		}
		if (id - next_count == next_id && next_id > 0) {
			// connected to next entry
			ssize_t count = next_count + 1;
			// ids[x + 1] = id; // no need to adjust id, so since we are adding to the end of the block

			if (before > 0) {
				MDB_ID previous_id = before > 0 ? ids[before] : 0;
				int previous_count = before > 1 ? -ids[before - 1] : 0;
				if (previous_count < 1) previous_count = 1;
				if (previous_id - 1 == id) {
					// the block we just added to can now be connected to previous entry
					count += previous_count;
					if (previous_count > 1) {
						ids[before - 1] = 0; // remove previous length
					}
					ids[before] = 0; // remove previous id
					if (next_count == 1) {
						// we can safely add the new count to the empty space
						ids[x - 1] = -count; // update the count
						return 0;
					}
				}
			}
			if (next_count > 1) {
				ids[x] = -count; // update the count
			} else if (ids[x - 1] == 0) {
				ids[x - 1] = -2;
			} else {
				id = -2; // switching a single entry to a block size of 2
				x--;
				goto insert_id;
			}
			return 0;
		}
		if (before > 0) {
			MDB_ID previous_id = before > 0 ? ids[before] : 0;
			int count = before > 1 ? -ids[before - 1] : 0;
			if (count < 1) count = 1;
			if (previous_id - 1 == id) {
				// connected to previous entry
				ids[before]--; // adjust the starting block to include this
				if (count > 1) {
					ids[before - 1]--; // can just update the count to include this id
					return 0;
				} else {
					id = -2; // switching a single entry to a block size of 2
					x = before;
					goto insert_id;
				}
			}
		}
		if (x == 1 && ids[0] > 2 && ids[1] == 0 && ids[2] == 0 && ids[3] == 0) {
			// this occurs when we have an empty list
			ids[2] = id;
			return 0;
		}
		if (before + 1 < x) {
			// there is an empty slot we can use, find a place in the middle
			ids[before + 3 < x ? (before + 2) : (before + 1)] = id;
			i = 0;
			goto check_full;
		}
		insert_id:
		// move items to try to make room
		ssize_t last_id = id;
		i = x;
		do {
			next_id = ids[i];
			ids[i++] = last_id;
			last_id = next_id;
		} while(next_id);
		check_full:
		if (x == ids[0] || // if it is full
			i > 0 && (i - x > ids[0] >> 3)) { // or too many moves. TODO: This threshold should actually be more like the square root of the length
			// grow the ids (this will replace the reference too)
			mdb_midl_need(ids_ref, 1);
		}
	}

	return 0;
}

MDB_IDL mdb_midl_alloc(int num)
{
	MDB_IDL ids = calloc((num+2), sizeof(MDB_ID));
	if (ids) {
		*ids++ = num;
		*ids = num;
	}
	return ids;
}

void mdb_midl_free(MDB_IDL ids)
{
	if (ids)
		free(ids-1);
}

void mdb_midl_shrink( MDB_IDL *idp )
{
	MDB_IDL ids = *idp;
	if (*(--ids) > MDB_IDL_UM_MAX &&
		(ids = realloc(ids, (MDB_IDL_UM_MAX+2) * sizeof(MDB_ID))))
	{
		*ids++ = MDB_IDL_UM_MAX;
		*idp = ids;
	}
}

static int mdb_midl_grow( MDB_IDL *idp, int num )
{
	MDB_IDL idn = *idp-1;
	/* grow it */
	idn = realloc(idn, (*idn + num + 2) * sizeof(MDB_ID));
	if (!idn)
		return ENOMEM;
	*idn++ += num;
	*idp = idn;
	return 0;
}

int mdb_midl_need( MDB_IDL *idp, unsigned num )
{
	MDB_IDL ids = *idp;
	num += ids[0];
	if (num > ids[-1]) {
		num = (num + num + (256 + 2)) & -256;
		MDB_IDL new_ids; 
		if (!(new_ids = calloc(num, sizeof(MDB_ID))))
			return ENOMEM;
		fprintf(stderr, "Created new id list of size %u\n", num);
		*new_ids++ = num - 2;
		*new_ids = num - 2;
		unsigned j = 1;
		// re-spread out the entries with gaps for growth
		for (unsigned i = 1; i <= ids[0]; i++) {
			new_ids[j++] = 0; // empty slot for growth
			ssize_t entry;
			while (!(entry = ids[i])) {
				if (++i > ids[0]) break;
			}
			new_ids[j++] = entry;
			if (entry < 0) new_ids[j++] = ids[++i]; // this was a block with a length
		}
		mdb_midl_free(ids);
		// now shrink (or grow) back to appropriate size
		num = (j + (j >> 3) + 22) & -16;
		if (num > new_ids[0]) num = new_ids[0];
		new_ids = realloc(new_ids - 1, (num + 2) * sizeof(MDB_ID));
		*new_ids++ = num;
		*new_ids = num;
		*idp = new_ids;
	}
	return 0;
}

int mdb_midl_print( FILE *fp, MDB_IDL ids )
{
	if (ids == NULL) {
		fprintf(fp, "freelist: NULL\n");
		return 0;
	}
	unsigned i;
	fprintf(fp, "freelist: %u: ", ids[0]);
	for (i=1; i<=ids[0]; i++) {
		ssize_t entry = ids[i];
		if (entry < 0) {
			fprintf(fp, "%li-%li ", ids[i+1], ids[i+1] - entry - 1);
			i++;
		} else if (ids[i] == 0) {
			fprintf(fp, "_");
		} else {
			fprintf(fp, "%lu ", (unsigned long)ids[i]);
		}
	}
	fprintf(fp, "\n");
	return 0;
}
int mdb_midl_append( MDB_IDL *idp, MDB_ID id )
{
	MDB_IDL ids = *idp;
	/* Too big? */
	if (ids[0] >= ids[-1]) {
		if (mdb_midl_grow(idp, MDB_IDL_UM_MAX))
			return ENOMEM;
		ids = *idp;
	}
	ids[0]++;
	ids[ids[0]] = id;
	return 0;
}

int mdb_midl_append_list( MDB_IDL *idp, MDB_IDL app )
{
	MDB_IDL ids = *idp;
	/* Too big? */
	if (ids[0] + app[0] >= ids[-1]) {
		if (mdb_midl_grow(idp, app[0]))
			return ENOMEM;
		ids = *idp;
	}
	memcpy(&ids[ids[0]+1], &app[1], app[0] * sizeof(MDB_ID));
	ids[0] += app[0];
	return 0;
}

int mdb_midl_append_range( MDB_IDL *idp, MDB_ID id, unsigned n )
{
	MDB_ID *ids = *idp, len = ids[0];
	/* Too big? */
	if (len + n > ids[-1]) {
		if (mdb_midl_grow(idp, n | MDB_IDL_UM_MAX))
			return ENOMEM;
		ids = *idp;
	}
	ids[0] = len + n;
	ids += len;
	while (n)
		ids[n--] = id++;
	return 0;
}

void mdb_midl_xmerge( MDB_IDL idl, MDB_IDL merge )
{
	MDB_ID old_id, merge_id, i = merge[0], j = idl[0], k = i+j, total = k;
	idl[0] = (MDB_ID)-1;		/* delimiter for idl scan below */
	old_id = idl[j];
	while (i) {
		merge_id = merge[i--];
		for (; old_id < merge_id; old_id = idl[--j])
			idl[k--] = old_id;
		idl[k--] = merge_id;
	}
	idl[0] = total;
}

/* Quicksort + Insertion sort for small arrays */

#define SMALL	8
#define	MIDL_SWAP(a,b)	{ itmp=(a); (a)=(b); (b)=itmp; }

void
mdb_midl_sort( MDB_IDL ids )
{
	/* Max possible depth of int-indexed tree * 2 items/level */
	int istack[sizeof(int)*CHAR_BIT * 2];
	int i,j,k,l,ir,jstack;
	MDB_ID a, itmp;

	ir = (int)ids[0];
	l = 1;
	jstack = 0;
	for(;;) {
		if (ir - l < SMALL) {	/* Insertion sort */
			for (j=l+1;j<=ir;j++) {
				a = ids[j];
				for (i=j-1;i>=1;i--) {
					if (ids[i] >= a) break;
					ids[i+1] = ids[i];
				}
				ids[i+1] = a;
			}
			if (jstack == 0) break;
			ir = istack[jstack--];
			l = istack[jstack--];
		} else {
			k = (l + ir) >> 1;	/* Choose median of left, center, right */
			MIDL_SWAP(ids[k], ids[l+1]);
			if (ids[l] < ids[ir]) {
				MIDL_SWAP(ids[l], ids[ir]);
			}
			if (ids[l+1] < ids[ir]) {
				MIDL_SWAP(ids[l+1], ids[ir]);
			}
			if (ids[l] < ids[l+1]) {
				MIDL_SWAP(ids[l], ids[l+1]);
			}
			i = l+1;
			j = ir;
			a = ids[l+1];
			for(;;) {
				do i++; while(ids[i] > a);
				do j--; while(ids[j] < a);
				if (j < i) break;
				MIDL_SWAP(ids[i],ids[j]);
			}
			ids[l+1] = ids[j];
			ids[j] = a;
			jstack += 2;
			if (ir-i+1 >= j-l) {
				istack[jstack] = ir;
				istack[jstack-1] = i;
				ir = j-1;
			} else {
				istack[jstack] = j-1;
				istack[jstack-1] = l;
				l = i;
			}
		}
	}
}

unsigned mdb_mid2l_search( MDB_ID2L ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned n = (unsigned)ids[0].mid;

	while( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot + 1;
		val = CMP( id, ids[cursor].mid );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor;
			n -= pivot + 1;

		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

int mdb_mid2l_insert( MDB_ID2L ids, MDB_ID2 *id )
{
	unsigned x, i;

	x = mdb_mid2l_search( ids, id->mid );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0].mid && ids[x].mid == id->mid ) {
		/* duplicate */
		return -1;
	}

	if ( ids[0].mid >= MDB_IDL_UM_MAX ) {
		/* too big */
		return -2;

	} else {
		/* insert id */
		ids[0].mid++;
		for (i=(unsigned)ids[0].mid; i>x; i--)
			ids[i] = ids[i-1];
		ids[x] = *id;
	}

	return 0;
}

int mdb_mid2l_append( MDB_ID2L ids, MDB_ID2 *id )
{
	/* Too big? */
	if (ids[0].mid >= MDB_IDL_UM_MAX) {
		return -2;
	}
	ids[0].mid++;
	ids[ids[0].mid] = *id;
	return 0;
}

MDB_ID2L mdb_mid2l_alloc(int num)
{
	MDB_ID2L ids = malloc((num+2) * sizeof(MDB_ID2));
	if (ids) {
		ids->mid = num;
		ids++;
		ids->mid = 0;
	}
	return ids;
}

void mdb_mid2l_free(MDB_ID2L ids)
{
	if (ids)
		free(ids-1);
}

int mdb_mid2l_need( MDB_ID2L *idp, unsigned num )
{
	MDB_ID2L ids = *idp;
	num += ids[0].mid;
	if (num > ids[-1].mid) {
		num = (num + num/4 + (256 + 2)) & -256;
		if (!(ids = realloc(ids-1, num * sizeof(MDB_ID2))))
			return ENOMEM;
		ids[0].mid = num - 2;
		*idp = ids+1;
	}
	return 0;
}

#if MDB_RPAGE_CACHE
unsigned mdb_mid3l_search( MDB_ID3L ids, MDB_ID id )
{
	/*
	 * binary search of id in ids
	 * if found, returns position of id
	 * if not found, returns first position greater than id
	 */
	unsigned base = 0;
	unsigned cursor = 1;
	int val = 0;
	unsigned n = (unsigned)ids[0].mid;

	while( 0 < n ) {
		unsigned pivot = n >> 1;
		cursor = base + pivot + 1;
		val = CMP( id, ids[cursor].mid );

		if( val < 0 ) {
			n = pivot;

		} else if ( val > 0 ) {
			base = cursor;
			n -= pivot + 1;

		} else {
			return cursor;
		}
	}

	if( val > 0 ) {
		++cursor;
	}
	return cursor;
}

int mdb_mid3l_insert( MDB_ID3L ids, MDB_ID3 *id )
{
	unsigned x, i;

	x = mdb_mid3l_search( ids, id->mid );

	if( x < 1 ) {
		/* internal error */
		return -2;
	}

	if ( x <= ids[0].mid && ids[x].mid == id->mid ) {
		/* duplicate */
		return -1;
	}

	/* insert id */
	ids[0].mid++;
	for (i=(unsigned)ids[0].mid; i>x; i--)
		ids[i] = ids[i-1];
	ids[x] = *id;

	return 0;
}
#endif /* MDB_RPAGE_CACHE */

/** @} */
/** @} */
