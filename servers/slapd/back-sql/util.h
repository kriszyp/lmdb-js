#ifndef __BACKSQL_UTIL_H__
#define __BACKSQL_UTIL_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */


#include "entry-id.h"
#include "schema-map.h"

#define BACKSQL_CONCAT

struct berval * backsql_strcat( struct berval *dest, ber_len_t *buflen, ... );
struct berval * backsql_strfcat( struct berval *dest, ber_len_t *buflen,
		const char *fmt, ... );

int backsql_entry_addattr( Entry *e, struct berval *at_name, 
		struct berval *at_val );

typedef struct backsql_srch_info {
	struct berval		*base_dn;
	int			scope;
	Filter			*filter;
	int			slimit, tlimit;
	time_t			stoptime;
	backsql_entryID		*id_list, *c_eid;
	int			n_candidates;
	int			abandon;
	backsql_info		*bi;
	backsql_oc_map_rec	*oc;
	struct berval		sel, from, join_where, flt_where;
	ber_len_t		sel_len, from_len, jwhere_len, fwhere_len;
	SQLHDBC			dbh;
	int			status;
	Backend			*be;
	Connection		*conn;
	Operation		*op;
	AttributeName		*attrs;
	int			bsi_flags;
#define	BSQL_SF_ALL_OPER		0x0001
#define BSQL_SF_FILTER_HASSUBORDINATE	0x0002
	Entry			*e;
	/* 1 if the db is TimesTen; 0 if it's not */
	int			use_reverse_dn; 
} backsql_srch_info;

void backsql_init_search( backsql_srch_info *bsi, backsql_info *bi,
		struct berval *nbase, int scope, int slimit, int tlimit,
		time_t stoptime, Filter *filter, SQLHDBC dbh,
		BackendDB *be, Connection *conn, Operation *op,
		AttributeName *attrs );
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

int backsql_merge_from_clause( struct berval *dest_from, ber_len_t *dest_len, 
		struct berval *src_from );

int backsql_split_pattern( const char *pattern, BerVarray *split_pattern,
		int expected );
int backsql_prepare_pattern( BerVarray split_pattern, BerVarray values,
		struct berval *res );

#endif /* __BACKSQL_UTIL_H__ */

