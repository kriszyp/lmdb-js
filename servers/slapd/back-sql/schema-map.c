/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "util.h"

int backsql_dummy(void *,void *);

int backsql_cmp_oc_name(backsql_oc_map_rec *m1,backsql_oc_map_rec *m2)
{
 return strcasecmp(m1->name,m2->name);
}

int backsql_cmp_oc_id(backsql_oc_map_rec *m1,backsql_oc_map_rec *m2)
{
 if (m1->id < m2->id)
  return -1;
 if (m1->id > m2->id)
  return 1;
 return 0;
}

int backsql_cmp_attr(backsql_at_map_rec *m1,backsql_at_map_rec *m2)
{
 return strcasecmp(m1->name,m2->name);
}

char* backsql_make_attr_query(backsql_oc_map_rec *oc_map,backsql_at_map_rec *at_map)
{
 char *tmps;
 int tmpslen;

 tmps=NULL;tmpslen=0;
 tmps=backsql_strcat(tmps,&tmpslen,"SELECT ",at_map->sel_expr," AS ",at_map->name,
			" FROM ",at_map->from_tbls,
			" WHERE ",oc_map->keytbl,".",oc_map->keycol,"=?",NULL);
 if (at_map->join_where!=NULL && at_map->join_where[0]!='\0')
  tmps=backsql_strcat(tmps,&tmpslen," AND ",at_map->join_where,NULL);
 at_map->query=ch_strdup(tmps);
 ch_free(tmps);
 return at_map->query;
}


int backsql_add_sysmaps(backsql_oc_map_rec *oc_map)
{
 backsql_at_map_rec *at_map;
 int len;
 char s[30]; 

 sprintf(s,"%d",oc_map->id);
 at_map=(backsql_at_map_rec*)ch_calloc(1,sizeof(backsql_at_map_rec));
 at_map->name=ch_strdup("objectClass");
 at_map->sel_expr=ch_strdup("ldap_entry_objclasses.oc_name");
 at_map->from_tbls=ch_strdup("ldap_entry_objclasses,ldap_entries");
 len=strlen(at_map->from_tbls);
 backsql_merge_from_clause(&at_map->from_tbls,&len,oc_map->keytbl);
 at_map->join_where=NULL; len=0;
 at_map->join_where=backsql_strcat(at_map->join_where,&len,
			"ldap_entries.id=ldap_entry_objclasses.entry_id and ldap_entries.keyval=",
			oc_map->keytbl,".",oc_map->keycol," and ldap_entries.oc_map_id=",s,NULL);
 at_map->add_proc=NULL;
 at_map->delete_proc=NULL;
 at_map->param_order=0;
 at_map->expect_return=0;
 backsql_make_attr_query(oc_map,at_map);
 avl_insert(&oc_map->attrs,at_map,(AVL_CMP)backsql_cmp_attr,backsql_dummy);

 at_map=(backsql_at_map_rec*)ch_calloc(1,sizeof(backsql_at_map_rec));
 at_map->name=ch_strdup("ref");
 at_map->sel_expr=ch_strdup("ldap_referrals.url");
 at_map->from_tbls=ch_strdup("ldap_referrals,ldap_entries");
 len=strlen(at_map->from_tbls);
 backsql_merge_from_clause(&at_map->from_tbls,&len,oc_map->keytbl);
 at_map->join_where=NULL; len=0;
 at_map->join_where=backsql_strcat(at_map->join_where,&len,
			"ldap_entries.id=ldap_referrals.entry_id and ldap_entries.keyval=",
			oc_map->keytbl,".",oc_map->keycol," and ldap_entries.oc_map_id=",s,NULL);
 at_map->add_proc=NULL;
 at_map->delete_proc=NULL;
 at_map->param_order=0;
 at_map->expect_return=0;
 backsql_make_attr_query(oc_map,at_map);
 avl_insert(&oc_map->attrs,at_map,(AVL_CMP)backsql_cmp_attr,backsql_dummy);

 return 1;
}

int backsql_load_schema_map(backsql_info *si,SQLHDBC dbh)
{
 SQLHSTMT oc_sth,at_sth;
 RETCODE rc;
 BACKSQL_ROW_NTS oc_row,at_row;
 unsigned long oc_id;
 backsql_oc_map_rec *oc_map;
 backsql_at_map_rec *at_map;
 char *tmps;
 int tmpslen;

 Debug(LDAP_DEBUG_TRACE,"==>load_schema_map()\n",0,0,0);

 /* TimesTen : See if the ldap_entries.dn_ru field exists in the schema. */

 rc = backsql_Prepare(dbh, &oc_sth, backsql_check_dn_ru_query, 0);
 if (rc == SQL_SUCCESS) {
   si->has_ldapinfo_dn_ru = 1;  /* Yes, the field exists */
   Debug(LDAP_DEBUG_TRACE, "ldapinfo.dn_ru field exists in the schema\n", 0, 0,0);
 }
 else {
   si->has_ldapinfo_dn_ru = 0;  /* No such field exists */
 }

 SQLFreeStmt(oc_sth, SQL_DROP);

 rc=backsql_Prepare(dbh,&oc_sth,si->oc_query,0);
 if (rc != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): error preparing oc_query: '%s'\n",si->oc_query,0,0);
   backsql_PrintErrors(si->db_env,dbh,oc_sth,rc);
   return -1;
  }
  Debug(LDAP_DEBUG_TRACE, "load_schema_map(): at_query '%s'\n", si->at_query,0,0);

 rc=backsql_Prepare(dbh,&at_sth,si->at_query,0);
 if (rc != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): error preparing at_query: '%s'\n",si->at_query,0,0);
   backsql_PrintErrors(si->db_env,dbh,at_sth,rc);
   return -1;
  }
 if ((rc=backsql_BindParamID(at_sth,1,&oc_id)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): error binding param for at_query: \n",0,0,0);
   backsql_PrintErrors(si->db_env,dbh,at_sth,rc);
   return -1;
  }
 if ((rc=SQLExecute(oc_sth)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): error executing oc_query: \n",0,0,0);
   backsql_PrintErrors(si->db_env,dbh,oc_sth,rc);
   return -1;
  }
 backsql_BindRowAsStrings(oc_sth,&oc_row);
 while ((rc=SQLFetch(oc_sth)) == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)
  {
   oc_map=(backsql_oc_map_rec*)ch_calloc(1,sizeof(backsql_oc_map_rec));
   oc_map->id=atoi(oc_row.cols[0]);
   oc_map->name=ch_strdup(oc_row.cols[1]);
   oc_map->keytbl=ch_strdup(oc_row.cols[2]);
   oc_map->keycol=ch_strdup(oc_row.cols[3]);
   oc_map->create_proc=(oc_row.is_null[4]<0)?NULL:ch_strdup(oc_row.cols[4]);
   oc_map->delete_proc=(oc_row.is_null[5]<0)?NULL:ch_strdup(oc_row.cols[5]);
   oc_map->expect_return=atoi(oc_row.cols[6]);

   oc_map->attrs=NULL;
   avl_insert(&si->oc_by_name,oc_map,(AVL_CMP)backsql_cmp_oc_name,backsql_dummy);
   avl_insert(&si->oc_by_id,oc_map,(AVL_CMP)backsql_cmp_oc_id,backsql_dummy);
   oc_id=oc_map->id;
   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): objectclass '%s': keytbl='%s' keycol='%s' ",
	   oc_map->name,oc_map->keytbl,oc_map->keycol);
   if (oc_map->delete_proc) {
     Debug(LDAP_DEBUG_TRACE,"delete_proc='%s'\n", oc_map->delete_proc, 0, 0);
   }
   if (oc_map->create_proc) {
     Debug(LDAP_DEBUG_TRACE,"create_proc='%s'\n", oc_map->create_proc, 0, 0);
   }
   Debug(LDAP_DEBUG_TRACE,"expect_return=%d; attributes:\n",
       oc_map->expect_return, 0, 0);

   Debug(LDAP_DEBUG_TRACE,"load_schema_map(): autoadding 'objectClass' and 'ref' mappings\n",0,0,0);
   backsql_add_sysmaps(oc_map);
   if ((rc=SQLExecute(at_sth)) != SQL_SUCCESS)
    {
     Debug(LDAP_DEBUG_TRACE,"load_schema_map(): error executing at_query: \n",0,0,0);
     backsql_PrintErrors(SQL_NULL_HENV,dbh,at_sth,rc);
     return -1;
    }
   backsql_BindRowAsStrings(at_sth,&at_row);
   while ((rc=SQLFetch(at_sth)) == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)
    {
     Debug(LDAP_DEBUG_TRACE,"********'%s'\n",at_row.cols[0],0,0);
     Debug(LDAP_DEBUG_TRACE,"name='%s',sel_expr='%s' from='%s' ",at_row.cols[0],
             at_row.cols[1],at_row.cols[2]);
	 Debug(LDAP_DEBUG_TRACE,"join_where='%s',add_proc='%s' ",at_row.cols[3],
             at_row.cols[4],0);
	 Debug(LDAP_DEBUG_TRACE,"delete_proc='%s'\n",at_row.cols[5],0,0);
	 Debug(LDAP_DEBUG_TRACE,"sel_expr_u='%s'\n", at_row.cols[8],0,0); /* TimesTen*/
     at_map=(backsql_at_map_rec*)ch_calloc(1,sizeof(backsql_at_map_rec));
     at_map->name=ch_strdup(at_row.cols[0]);
     at_map->sel_expr=ch_strdup(at_row.cols[1]);
	 at_map->sel_expr_u = (at_row.is_null[8]<0)?NULL:ch_strdup(at_row.cols[8
]);
	 tmps=NULL;tmpslen=0;
	 backsql_merge_from_clause(&tmps,&tmpslen,at_row.cols[2]);
     at_map->from_tbls=ch_strdup(tmps);
	 ch_free(tmps);
	 at_map->join_where=ch_strdup((at_row.is_null[3]<0)?"":at_row.cols[3]);
	 at_map->add_proc=(at_row.is_null[4]<0)?NULL:ch_strdup(at_row.cols[4]);
	 at_map->delete_proc=(at_row.is_null[5]<0)?NULL:ch_strdup(at_row.cols[5]);
	 at_map->param_order=atoi(at_row.cols[6]);
	 at_map->expect_return=atoi(at_row.cols[7]);
	 backsql_make_attr_query(oc_map,at_map);
	 Debug(LDAP_DEBUG_TRACE,"load_schema_map(): preconstructed query '%s'\n",at_map->query,0,0);
     avl_insert(&oc_map->attrs,at_map,(AVL_CMP)backsql_cmp_attr,backsql_dummy);
    }
   backsql_FreeRow(&at_row);
   SQLFreeStmt(at_sth,SQL_CLOSE);
  }
 backsql_FreeRow(&oc_row);
 SQLFreeStmt(at_sth,SQL_DROP);
 SQLFreeStmt(oc_sth,SQL_DROP);
 si->schema_loaded=1;
 Debug(LDAP_DEBUG_TRACE,"<==load_schema_map()\n",0,0,0);
 return 1;
}

backsql_oc_map_rec* backsql_oc_with_name(backsql_info *si,char* objclass)
{
 backsql_oc_map_rec tmp,*res;
 
/* Debug(LDAP_DEBUG_TRACE,"==>oc_with_name(): searching for objectclass with name='%s'\n",objclass,0,0);*/
 tmp.name=objclass;
 res=(backsql_oc_map_rec*)avl_find(si->oc_by_name,&tmp,(AVL_CMP)backsql_cmp_oc_name);
/* if (res!=NULL)
  Debug(LDAP_DEBUG_TRACE,"<==oc_with_name(): found name='%s', id=%d\n",res->name,res->id,0);
 else
  Debug(LDAP_DEBUG_TRACE,"<==oc_with_name(): not found\n",0,0,0);
*/
 return res;
}

backsql_oc_map_rec* backsql_oc_with_id(backsql_info *si,unsigned long id)
{
 backsql_oc_map_rec tmp,*res;
 
/* Debug(LDAP_DEBUG_TRACE,"==>oc_with_id(): searching for objectclass with id='%d'\n",id,0,0);*/
 tmp.id=id;
 res=(backsql_oc_map_rec*)avl_find(si->oc_by_id,&tmp,(AVL_CMP)backsql_cmp_oc_id);
/* if (res!=NULL)
  Debug(LDAP_DEBUG_TRACE,"<==oc_with_name(): found name='%s', id=%d\n",res->name,res->id,0);
 else
  Debug(LDAP_DEBUG_TRACE,"<==oc_with_name(): not found\n",0,0,0);
*/
 return res;
}

backsql_at_map_rec* backsql_at_with_name(backsql_oc_map_rec* objclass,char* attr)
{
 backsql_at_map_rec tmp,*res;
 
 /*Debug(LDAP_DEBUG_TRACE,"==>at_with_name(): searching for attribute with name='%s' (for objectclass '%s')\n",
                 attr,objclass->name,0);
*/
 tmp.name=attr;
 res=(backsql_at_map_rec*)avl_find(objclass->attrs,&tmp,(AVL_CMP)backsql_cmp_attr);
 /*if (res!=NULL)
  Debug(LDAP_DEBUG_TRACE,"<==at_with_name(): found name='%s', sel_expr='%s'\n",
              res->name,res->sel_expr,0);
 else
  Debug(LDAP_DEBUG_TRACE,"<==at_with_name(): not found\n",0,0,0);
*/
 return res;
}

int backsql_free_attr(backsql_at_map_rec *at)
{
 Debug(LDAP_DEBUG_TRACE,"==>free_attr(): '%s'\n",at->name,0,0);
 ch_free(at->name);
 ch_free(at->sel_expr);
 if (at->from_tbls!=NULL)
  ch_free(at->from_tbls);
 if (at->join_where!=NULL)
  ch_free(at->join_where);
 if (at->add_proc!=NULL)
  ch_free(at->add_proc);
 if (at->delete_proc!=NULL)
  ch_free(at->delete_proc);
 if (at->query)
  ch_free(at->query);
 ch_free(at);
 if (at->sel_expr_u)
   ch_free(at->sel_expr_u); /* TimesTen */
 Debug(LDAP_DEBUG_TRACE,"<==free_attr()\n",0,0,0);
 return 1;
}

int backsql_free_oc(backsql_oc_map_rec *oc)
{
 Debug(LDAP_DEBUG_TRACE,"==>free_oc(): '%s'\n",oc->name,0,0);
 avl_free(oc->attrs,(AVL_FREE)backsql_free_attr);
 ch_free(oc->name);
 ch_free(oc->keytbl);
 ch_free(oc->keycol);
 if (oc->create_proc!=NULL)
  ch_free(oc->create_proc);
 if (oc->delete_proc!=NULL)
  ch_free(oc->delete_proc);
 ch_free(oc);
 Debug(LDAP_DEBUG_TRACE,"<==free_oc()\n",0,0,0);
 return 1;
}

int backsql_destroy_schema_map(backsql_info *si)
{
 Debug(LDAP_DEBUG_TRACE,"==>destroy_schema_map()\n",0,0,0);
 avl_free(si->oc_by_id,(AVL_FREE)backsql_free_oc);
 avl_free(si->oc_by_name,(AVL_FREE)backsql_dummy);
 Debug(LDAP_DEBUG_TRACE,"<==destroy_schema_map()\n",0,0,0);
 return 0;
}

#endif /* SLAPD_SQL */
