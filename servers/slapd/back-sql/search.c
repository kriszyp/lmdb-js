/*
 *	 Copyright 1999, Dmitry Kovalev (zmit@mail.ru), All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "entry-id.h"
#include "util.h"

int backsql_attrlist_add(backsql_srch_info *bsi,char *at_name)
{
 char **p=bsi->attrs;
 int n_attrs=0;

 if (bsi->attrs==NULL)
  return 1;

 while(*p)
 {
  Debug(LDAP_DEBUG_TRACE,"==>backsql_attrlist_add(): attribute '%s' is in list\n",*p,0,0);
  if (!strcasecmp(*p,at_name))
   return 1;
  n_attrs++;
  p++;
 }
 Debug(LDAP_DEBUG_TRACE,"==>backsql_attrlist_add(): adding '%s' to list\n",at_name,0,0);
 bsi->attrs=(char**)ch_realloc(bsi->attrs,(n_attrs+2)*sizeof(char*));
 bsi->attrs[n_attrs]=strdup(at_name);
 bsi->attrs[n_attrs+1]=NULL;
 return 1;
}

void backsql_init_search(backsql_srch_info *bsi,backsql_info *bi,char *nbase,int scope,
						 int slimit,int tlimit,time_t stoptime,Filter *filter,
						 SQLHDBC dbh,Backend *be,Connection *conn,Operation *op,char **attrs)
{
 char **p;
 bsi->base_dn=nbase;
 bsi->scope=scope;
 bsi->slimit=slimit;
 bsi->tlimit=tlimit;
 bsi->filter=filter;
 bsi->dbh=dbh;
 bsi->be=be;
 bsi->conn=conn;
 bsi->op=op;
 if (attrs!=NULL)
 {
  bsi->attrs=(char**)ch_calloc(1,sizeof(char*));
  bsi->attrs[0]=NULL;
  for(p=attrs;*p!=NULL;p++)
   backsql_attrlist_add(bsi,*p);
 }
 else
  bsi->attrs=attrs;
 bsi->abandon=0;
 bsi->id_list=NULL;
 bsi->stoptime=stoptime;
 bsi->bi=bi;
 bsi->sel=NULL; bsi->from=NULL; bsi->join_where=NULL; bsi->flt_where=NULL;
 bsi->sel_len=0; bsi->from_len=0; bsi->jwhere_len=0; bsi->fwhere_len=0;
}

int backsql_process_filter_list(backsql_srch_info *bsi,Filter *f,int op)
{
 char *sub_clause=NULL;
 int len=0,res;

 bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"(",NULL);
 while(1)
 {
  res=backsql_process_filter(bsi,f);
  
  if (res==-1)
	bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len," 1=0 ",NULL);

  f=f->f_next;
  if (f==NULL)
   break;

  switch (op)
  {
   case LDAP_FILTER_AND:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len," AND ",NULL);
			break;
   case LDAP_FILTER_OR:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len," OR ",NULL);
			break;
  }
 }

 
 bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,")",NULL);
 return 1;
}

int backsql_process_sub_filter(backsql_srch_info *bsi,Filter *f)
{
 int i;

 backsql_at_map_rec *at=backsql_at_with_name(bsi->oc,f->f_sub_type);

 bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"(",at->sel_expr,
				" LIKE '",NULL);
 if (f->f_sub_initial!=NULL)
  bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,f->f_sub_initial,NULL);

 bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"%",NULL);

 if (f->f_sub_any!=NULL)
  for(i=0;f->f_sub_any[i]!=NULL;i++)
   bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,f->f_sub_any[i],"%",NULL);

 if (f->f_sub_final!=NULL)
  bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,f->f_sub_final,NULL);

 bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"')",NULL);
 
 return 1;
}

int backsql_process_filter(backsql_srch_info *bsi,Filter *f)
{
 backsql_at_map_rec *at;
 backsql_at_map_rec oc_attr={"objectClass","","",NULL,NULL,NULL,NULL};
 char *at_name=NULL;
 int done=0,len=0;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_process_filter()\n",0,0,0);
 switch(f->f_choice)
 {
  case LDAP_FILTER_OR:
			backsql_process_filter_list(bsi,f->f_or,LDAP_FILTER_OR);
			done=1;
			break;
  case LDAP_FILTER_AND:
			backsql_process_filter_list(bsi,f->f_and,LDAP_FILTER_AND);
			done=1;
			break;
  case LDAP_FILTER_NOT:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"NOT (",NULL);
			backsql_process_filter(bsi,f->f_not);
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,")",NULL);
			done=1;
			break;
  case LDAP_FILTER_PRESENT:
			at_name=f->f_type;
			break;
  default:
			at_name=f->f_avtype;
			break;
 }
 
 if (done)
  goto done;

 if (strcasecmp(at_name,"objectclass"))
  at=backsql_at_with_name(bsi->oc,at_name);
 else
 {
  at=&oc_attr;
  at->sel_expr=backsql_strcat(at->sel_expr,&len,"'",bsi->oc->name,"'",NULL);
 }
 if (at==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_process_filter(): attribute '%s' is not defined for objectclass '%s'\n",
                      at_name,bsi->oc->name,0);
  return -1;
 }
			
 backsql_merge_from_clause(&bsi->from,&bsi->from_len,at->from_tbls);
 //need to add this attribute to list of attrs to load, so that we could do test_filter() later
 backsql_attrlist_add(bsi,at_name);

 if (at->join_where != NULL && strstr(bsi->join_where,at->join_where)==NULL)
  bsi->join_where=backsql_strcat(bsi->join_where,&bsi->jwhere_len," AND ",at->join_where,NULL);

 //if (at!=&oc_attr)
 // bsi->sel=backsql_strcat(bsi->sel,&bsi->sel_len,",",at->sel_expr," AS ",at->name,NULL);

 switch(f->f_choice)
 {
  case LDAP_FILTER_EQUALITY:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"(",at->sel_expr,"='",
															f->f_avvalue.bv_val,"')",NULL);
			break;
  case LDAP_FILTER_GE:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"(",at->sel_expr,">=",
															f->f_avvalue.bv_val,")",NULL);
			break;
  case LDAP_FILTER_LE:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"(",at->sel_expr,"<=",
															f->f_avvalue.bv_val,")",NULL);
			break;
  case LDAP_FILTER_PRESENT:
			bsi->flt_where=backsql_strcat(bsi->flt_where,&bsi->fwhere_len,"NOT (",at->sel_expr,
						" IS NULL)",NULL);
			break;
  case LDAP_FILTER_SUBSTRINGS:
			backsql_process_sub_filter(bsi,f);
			break;
 }

done:
 if (oc_attr.sel_expr!=NULL)
  free(oc_attr.sel_expr);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_process_filter()\n",0,0,0);
 return 1;
}

char* backsql_srch_query(backsql_srch_info *bsi)
{
 char *query=NULL;
 int q_len=0;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_srch_query()\n",0,0,0);
 bsi->sel=NULL;
 bsi->from=NULL;
 bsi->join_where=NULL;
 bsi->flt_where=NULL;
 bsi->sel_len=bsi->from_len=bsi->jwhere_len=bsi->fwhere_len=0;

 bsi->sel=backsql_strcat(bsi->sel,&bsi->sel_len,
				"SELECT ldap_entries.id,",bsi->oc->keytbl,".",bsi->oc->keycol,
				", '",bsi->oc->name,"' AS objectClass",
				", ldap_entries.dn AS dn",
				NULL);
 bsi->from=backsql_strcat(bsi->from,&bsi->from_len," FROM ldap_entries,",bsi->oc->keytbl,NULL);
 bsi->join_where=backsql_strcat(bsi->join_where,&bsi->jwhere_len," WHERE ",
	 bsi->oc->keytbl,".",bsi->oc->keycol,"=ldap_entries.keyval AND ",
	 "ldap_entries.objclass=? AND ",NULL);

 switch(bsi->scope)
 {
  case LDAP_SCOPE_BASE:
		bsi->join_where=backsql_strcat(bsi->join_where,&bsi->jwhere_len,
				"ldap_entries.dn=?",NULL);
		break;
  case LDAP_SCOPE_ONELEVEL:
		bsi->join_where=backsql_strcat(bsi->join_where,&bsi->jwhere_len,
				"ldap_entries.parent=?",NULL);
		break;
  case LDAP_SCOPE_SUBTREE:
		bsi->join_where=backsql_strcat(bsi->join_where,&bsi->jwhere_len,
				bsi->bi->subtree_cond,NULL);
		break;
 }
 if (backsql_process_filter(bsi,bsi->filter))
  query=backsql_strcat(query,&q_len,bsi->sel,bsi->from,bsi->join_where," AND ",bsi->flt_where,NULL);

 
 free(bsi->sel);
 free(bsi->from);
 free(bsi->join_where);
 free(bsi->flt_where);
 bsi->sel_len=bsi->from_len=bsi->jwhere_len=bsi->fwhere_len=0;
 Debug(LDAP_DEBUG_TRACE,"<==backsql_srch_query()\n",0,0,0);
 return query;
}

int backsql_oc_get_candidates(backsql_oc_map_rec *oc,backsql_srch_info *bsi)
{
 char *query=NULL;
 SQLHSTMT sth;
 RETCODE rc;
 backsql_entryID base_id,*res,*c_id;
 //Entry *e;
 BACKSQL_ROW_NTS row;
 //int i;
 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_oc_get_candidates(): oc='%s'\n",oc->name,0,0);
 bsi->oc=oc;
 query=backsql_srch_query(bsi);
 if (query==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): could not construct query for objectclass\n",0,0,0);
  return 1;
 }

 Debug(LDAP_DEBUG_TRACE,"Constructed query: %s\n",query,0,0);
 if ((rc=backsql_Prepare(bsi->dbh,&sth,query,0)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): error preparing query\n",0,0,0);
   backsql_PrintErrors(bsi->bi->db_env,bsi->dbh,sth,rc);
   free(query);
   return 1;
  }
 free(query);

 if (backsql_BindParamID(sth,1,&bsi->oc->id) != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): error binding objectclass id parameter\n",0,0,0);
  return 1;
 }
 switch(bsi->scope)
 {
  case LDAP_SCOPE_BASE:
  case LDAP_SCOPE_SUBTREE:
		if ((rc=backsql_BindParamStr(sth,2,bsi->base_dn,BACKSQL_MAX_DN_LEN)) != SQL_SUCCESS)
		{
         Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): error binding base_dn parameter\n",0,0,0);
		 backsql_PrintErrors(bsi->bi->db_env,bsi->dbh,sth,rc);
         return 1;
		}
		break;
  case LDAP_SCOPE_ONELEVEL:
		res=backsql_dn2id(&base_id,bsi->dbh,bsi->base_dn);
		if (res==NULL)
		{
		 Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): could not retrieve base_dn id - no such entry\n",0,0,0);
		 bsi->status=LDAP_NO_SUCH_OBJECT;
		 return 0;
		}
		if (backsql_BindParamID(sth,2,&base_id.id) != SQL_SUCCESS)
		{
		 Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): error binding base id parameter\n",0,0,0);
		 free(base_id.dn);
		 return 1;
		}		
		free(base_id.dn);
		break;
 }
 
 if ((rc=SQLExecute(sth)) != SQL_SUCCESS && rc!= SQL_SUCCESS_WITH_INFO)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): error executing query\n",0,0,0);
   backsql_PrintErrors(bsi->bi->db_env,bsi->dbh,sth,rc);
   SQLFreeStmt(sth,SQL_DROP);
   return 1;
  }

 backsql_BindRowAsStrings(sth,&row);
 while ((rc=SQLFetch(sth)) == SQL_SUCCESS || rc==SQL_SUCCESS_WITH_INFO)
  {
   /*
   e=(Entry*)ch_calloc(1,sizeof(Entry)); 
   for (i=1;i<row.ncols;i++)
    {
     if (row.is_null[i]>0)
      {
       backsql_entry_addattr(e,row.col_names[i],row.cols[i],row.col_prec[i]);
//       Debug(LDAP_DEBUG_TRACE,"prec=%d\n",(int)row.col_prec[i],0,0);
      }
    // else
    //  Debug(LDAP_DEBUG_TRACE,"NULL value in this row for attribute '%s'\n",row.col_names[i],0,0);
    }
   */

   Debug(LDAP_DEBUG_TRACE,"backsql_oc_get_candidates(): adding entry id=%s, keyval=%s dn='%s'\n",
		row.cols[0],row.cols[1],row.cols[3]);
   c_id=(backsql_entryID*)ch_calloc(1,sizeof(backsql_entryID));
   c_id->id=atoi(row.cols[0]);
   c_id->keyval=atoi(row.cols[1]);
   c_id->oc_id=bsi->oc->id;
   c_id->dn=strdup(row.cols[3]);
   c_id->next=bsi->id_list;
   bsi->id_list=c_id;
  }
 backsql_FreeRow(&row);
 SQLFreeStmt(sth,SQL_DROP);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_oc_get_candidates()\n",0,0,0);
 return 1;
}


int backsql_search(Backend *be,Connection *conn,Operation *op,
	char *base, char *nbase, int scope,int deref,int slimit,int tlimit,
	Filter *filter, char *filterstr,char **attrs,int attrsonly)
{
 backsql_info *bi=(backsql_info*)be->be_private;
 SQLHDBC dbh;
 int sres;
 int nentries;
 Entry entry,*res;
 int manageDSAit = get_manageDSAit( op );
 struct berval **v2refs = NULL;
 time_t	stoptime;
 backsql_srch_info srch_info;
 backsql_entryID *eid=NULL;

 base=dn_validate(base);
 Debug(LDAP_DEBUG_TRACE,"==>backsql_search(): base='%s', filter='%s', scope=%d,",
                     base,filterstr,scope);
 Debug(LDAP_DEBUG_TRACE," deref=%d, attrsonly=%d, attributes to load: %s\n",
	 deref,attrsonly,attrs==NULL?"all":"custom list");
 dbh=backsql_get_db_conn(be,conn);

 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_search(): could not get connection handle - exiting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 
 if (tlimit == 0 && be_isroot(be,op->o_dn))
  {
   tlimit = -1;	/* allow root to set no limit */
  } 
 else
  {
   tlimit = (tlimit > be->be_timelimit || tlimit < 1) ?
		    be->be_timelimit : tlimit;
   stoptime = op->o_time + tlimit;
  }
  
 if (slimit == 0 && be_isroot(be,op->o_dn))
  {
   slimit = -1;	/* allow root to set no limit */
  }
 else
  {
   slimit = (slimit > be->be_sizelimit || slimit < 1) ?
		    be->be_sizelimit : slimit;
  }

 //backsql_init_search(&srch_info,bi,nbase/*!!!!!!!!*/,scope,slimit,tlimit,stoptime,filter,dbh,
//		 be,conn,op,attrs);
 backsql_init_search(&srch_info,bi,base/*don't know so far how to make Oracle do CIS search on VARCHAR2*/,
			scope,slimit,tlimit,stoptime,filter,dbh,
	 be,conn,op,attrs);

 //for each objectclass we try to construct query which gets IDs
 //of entries matching LDAP query filter and scope (or at least candidates),
 //and get the IDs
 avl_apply(bi->oc_by_name,(AVL_APPLY)backsql_oc_get_candidates,&srch_info,0,AVL_INORDER);
	     
 nentries=0;
 //now we load candidate entries (only those attrubutes mentioned in attrs and filter),
 //test it against full filter and then send to client
 for(eid=srch_info.id_list;eid!=NULL;eid=eid->next)
  {
   /* check for abandon */
   ldap_pvt_thread_mutex_lock(&op->o_abandonmutex);
   if (op->o_abandon)
    {
     ldap_pvt_thread_mutex_unlock(&op->o_abandonmutex);
     break;
    }
   ldap_pvt_thread_mutex_unlock(&op->o_abandonmutex);

   /* check time limit */
   if ( tlimit != -1 && slap_get_time() > stoptime)
    {
	 send_search_result( conn, op, LDAP_TIMELIMIT_EXCEEDED,
				NULL, NULL, v2refs, NULL, nentries );
     
     break;
    }
     
   Debug(LDAP_DEBUG_TRACE,"backsql_search(): loading data for entry id=%d, oc_id=%d, keyval=%d\n",
               eid->id,eid->oc_id,eid->keyval);
   
   res=backsql_id2entry(&srch_info,&entry,eid);
   if (res==NULL)
    {
     Debug(LDAP_DEBUG_TRACE,"backsql_search(): error in backsql_id2entry() - skipping entry\n",0,0,0);
     continue;
    }

   if ( !manageDSAit && scope != LDAP_SCOPE_BASE &&
			is_entry_referral( &entry ) )
    {
     struct berval **refs = get_entry_referrals(be,conn,op,&entry);

     send_search_reference( be, conn, op, &entry, refs, scope, NULL, &v2refs );
     ber_bvecfree( refs );
     continue;
    }

  // if (test_filter(be,conn,op,&entry,filter)==0)
    {
     if ((sres=send_search_entry(be,conn,op,&entry,attrs,attrsonly,NULL))==-1)
      {
       Debug(LDAP_DEBUG_TRACE,"backsql_search(): connection lost\n",0,0,0);
       break;
      }
     nentries+=!sres;					
    }
  }

 for(eid=srch_info.id_list;eid!=NULL;eid=backsql_free_entryID(eid));

 //free bsi->attrs!!!!!!!!!!!!!!!!!!!!!!!!!!!

 if (nentries>0)
  send_search_result( conn, op,
		v2refs == NULL ? LDAP_SUCCESS : LDAP_REFERRAL,
		NULL, NULL, v2refs, NULL, nentries );
 else
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,NULL,NULL,NULL,0);
 
 Debug(LDAP_DEBUG_TRACE,"<==backsql_search()\n",0,0,0);
 return 0;
}
