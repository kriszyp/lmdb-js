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

#define BACKSQL_MAX(a,b) ((a)>(b)?(a):(b))
#define BACKSQL_MIN(a,b) ((a)<(b)?(a):(b))

#define BACKSQL_STR_GROW 64

char* backsql_strcat(char* dest,int *buflen, ...);

int backsql_entry_addattr(Entry *e,char *at_name,char *at_val,unsigned int at_val_len);

typedef struct __backsql_srch_info
{
 char *base_dn;
 int scope;
 Filter *filter;
 int slimit,tlimit;
 time_t	stoptime;
 backsql_entryID *id_list,*c_eid;
 int abandon;
 backsql_info *bi;
 backsql_oc_map_rec *oc;
 char *sel,*from,*join_where,*flt_where;
 int sel_len,from_len,jwhere_len,fwhere_len;
 SQLHDBC dbh;
 int status;
 Backend *be;
 Connection *conn;
 Operation *op;
 char **attrs;
 Entry *e;
 int isTimesTen; /* 1 if the db is TimesTen; 0 if it's not */
}backsql_srch_info;

int backsql_process_filter(backsql_srch_info *bsi,Filter *f);
void backsql_init_search(backsql_srch_info *bsi,backsql_info *bi,char *nbase,int scope,
						 int slimit,int tlimit,time_t stoptime,Filter *filter,
						 SQLHDBC dbh,Backend *be,Connection *conn,Operation *op,struct berval **attrs);
Entry* backsql_id2entry(backsql_srch_info *bsi,Entry* e,backsql_entryID* id);

extern char backsql_def_oc_query[],backsql_def_at_query[],
			backsql_def_delentry_query[],backsql_def_insentry_query[],
			backsql_def_subtree_cond[],backsql_id_query[];
extern char backsql_check_dn_ru_query[];

int backsql_merge_from_clause(char **dest_from,int *dest_len,char *src_from);


#endif

