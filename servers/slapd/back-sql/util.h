/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
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
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */

#ifndef __BACKSQL_UTIL_H__
#define __BACKSQL_UTIL_H__


#include "entry-id.h"
#include "schema-map.h"

#define BACKSQL_CONCAT

typedef struct berbuf {
	struct berval	bb_val;
	ber_len_t	bb_len;
} BerBuffer;
#define BB_NULL		{ { 0, NULL }, 0 }

struct berbuf * backsql_strcat( struct berbuf *dest, ... );
struct berbuf * backsql_strfcat( struct berbuf *dest, const char *fmt, ... );

int backsql_entry_addattr( Entry *e, struct berval *at_name, 
		struct berval *at_val, void *memctx );

typedef struct backsql_srch_info {
	Operation		*op;

	int			bsi_flags;
#define	BSQL_SF_ALL_OPER		0x0001
#define BSQL_SF_FILTER_HASSUBORDINATE	0x0002

	struct berval		*base_dn;
	int			scope;
	Filter			*filter;
	int			slimit, tlimit;
	time_t			stoptime;

	backsql_entryID		*id_list, *c_eid;
	int			n_candidates;
	int			abandon;
	int			status;

	backsql_oc_map_rec	*oc;
	struct berbuf		sel, from, join_where, flt_where;
	SQLHDBC			dbh;
	AttributeName		*attrs;

	Entry			*e;
} backsql_srch_info;

void backsql_init_search( backsql_srch_info *bsi, 
		struct berval *nbase, int scope, int slimit, int tlimit,
		time_t stoptime, Filter *filter, SQLHDBC dbh,
		Operation *op, AttributeName *attrs );
Entry *backsql_id2entry( backsql_srch_info *bsi, Entry *e, 
		backsql_entryID *id );

extern char 
	backsql_def_oc_query[],
	backsql_def_needs_select_oc_query[],
	backsql_def_at_query[],
	backsql_def_delentry_query[],
	backsql_def_insentry_query[],
	backsql_def_subtree_cond[],
	backsql_def_upper_subtree_cond[],
	backsql_id_query[],
	backsql_def_concat_func[];
extern char 
	backsql_check_dn_ru_query[];

int backsql_merge_from_clause( struct berbuf *dest_from, 
		struct berval *src_from );

int backsql_split_pattern( const char *pattern, BerVarray *split_pattern,
		int expected );
int backsql_prepare_pattern( BerVarray split_pattern, BerVarray values,
		struct berval *res );

#endif /* __BACKSQL_UTIL_H__ */

