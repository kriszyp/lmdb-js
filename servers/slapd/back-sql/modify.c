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
#include "entry-id.h"
#include "util.h"

int backsql_modify(BackendDB *be,Connection *conn,Operation *op,
	const char *dn,const char *ndn,Modifications *modlist)
{
 backsql_info *bi=(backsql_info*)be->be_private;
 SQLHDBC dbh;
 SQLHSTMT sth;
 RETCODE rc;
 backsql_oc_map_rec *oc=NULL;
 backsql_entryID e_id,*res;
 Modification *c_mod;
 Modifications *ml;
 backsql_at_map_rec *at=NULL;
 struct berval *at_val;
 int i;
 int pno,po;/*first parameter no, parameter order*/
 int prc; /*procedure return code*/

 Debug(LDAP_DEBUG_TRACE,"==>backsql_modify(): changing entry '%s'\n",ndn,0,0);
 dbh=backsql_get_db_conn(be,conn);
 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): could not get connection handle - exiting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 res=backsql_dn2id(bi,&e_id,dbh,(char*)ndn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): could not lookup entry id\n",0,0,0);
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,"",NULL,NULL,NULL);
  return 1;
 }

 oc=backsql_oc_with_id(bi,e_id.oc_id);
 if (oc==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): cannot determine objectclass of entry -- aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }

 SQLAllocStmt(dbh, &sth);

 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): traversing modifications list\n",0,0,0);
 for(ml=modlist;ml!=NULL;ml=ml->sml_next)
 {
  c_mod=&ml->sml_mod;
  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): attribute '%s'\n",c_mod->sm_desc->ad_cname.bv_val,0,0);
  at=backsql_at_with_name(oc,c_mod->sm_desc->ad_cname.bv_val);
  if (at==NULL)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_modify(): attribute provided is not registered in this objectclass ('%s')\n",c_mod->sm_desc->ad_cname.bv_val,0,0);
   continue;
  }
  
  switch(c_mod->sm_op)
  {
   case LDAP_MOD_REPLACE:
			{
			 SQLHSTMT asth;
			 BACKSQL_ROW_NTS row;
			 
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): replacing values for attribute '%s'\n",at->name,0,0);
             if (at->add_proc==NULL)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): add procedure is not defined for this attribute ('%s') - unable to perform replacements\n",at->name,0,0);
			  break;
			 }
del_all:
			 
			 if ((rc=backsql_Prepare(dbh,&asth,at->query,0)) != SQL_SUCCESS)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): error preparing query\n",0,0,0);
			  backsql_PrintErrors(bi->db_env,dbh,asth,rc);
			  break;
			 }

			 if (backsql_BindParamID(asth,1,&e_id.keyval) != SQL_SUCCESS)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): error binding key value parameter\n",0,0,0);
			  backsql_PrintErrors(bi->db_env,dbh,asth,rc);
			  SQLFreeStmt(asth,SQL_DROP);
			  break;
			 }

			 if ((rc=SQLExecute(asth)) != SQL_SUCCESS && rc!= SQL_SUCCESS_WITH_INFO)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): error executing attribute query\n",0,0,0);
			  backsql_PrintErrors(bi->db_env,dbh,asth,rc);
			  SQLFreeStmt(asth,SQL_DROP);
			  break;
			 }

			 backsql_BindRowAsStrings(asth,&row);
			 while ((rc=SQLFetch(asth)) == SQL_SUCCESS || rc==SQL_SUCCESS_WITH_INFO)
			 {
			  for (i=0;i<row.ncols;i++)
			  {
			   if (at->expect_return & BACKSQL_DEL)
			   {
			    pno=1;
			    SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&prc,0,0);
			   }
			   else
			    pno=0;
			   po=(at->param_order & BACKSQL_DEL)>0;
			   SQLBindParameter(sth,(SQLUSMALLINT)(pno+1+po),SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.keyval,0,0);
			   /*check for syntax needed here - maybe need binary bind?*/
			   SQLBindParameter(sth,(SQLUSMALLINT)(pno+2-po),SQL_PARAM_INPUT,SQL_C_CHAR,SQL_CHAR,0,0,row.cols[i],strlen(row.cols[i]),0);
			 
			   Debug(LDAP_DEBUG_TRACE,"backsql_modify(): executing '%s'\n",at->delete_proc,0,0);
			   rc=SQLExecDirect(sth,at->delete_proc,SQL_NTS);
			   if (rc!=SQL_SUCCESS)
				{
			     Debug(LDAP_DEBUG_TRACE,"backsql_modify(): delete_proc execution failed\n",0,0,0);
			     backsql_PrintErrors(bi->db_env,dbh,sth,rc);
				}
			  }
			 }
			 backsql_FreeRow(&row);
             SQLFreeStmt(asth,SQL_DROP);
			}
			/*PASSTHROUGH - to add new attributes -- do NOT add break*/
  case LDAP_MOD_ADD:
			if (at->add_proc==NULL)
			{
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): add procedure is not defined for this attribute ('%s')\n",at->name,0,0);
			 break;
			}
			if (c_mod->sm_bvalues==NULL)
			{
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): no values given to add for attribute '%s'\n",at->name,0,0);
			 break;
			}
			Debug(LDAP_DEBUG_TRACE,"backsql_modify(): adding new values for attribute '%s'\n",at->name,0,0);
			for(i=0,at_val=c_mod->sm_bvalues[0];at_val!=NULL;i++,at_val=c_mod->sm_bvalues[i])
			{
			 if (at->expect_return & BACKSQL_ADD)
			 {
			  pno=1;
			  SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&prc,0,0);
			 }
			 else
			  pno=0;
			 po=(at->param_order & BACKSQL_ADD)>0;
			 SQLBindParameter(sth,(SQLUSMALLINT)(pno+1+po),SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.keyval,0,0);
			 /*check for syntax needed here - maybe need binary bind?*/
			 SQLBindParameter(sth,(SQLUSMALLINT)(pno+2-po),SQL_PARAM_INPUT,SQL_C_CHAR,SQL_CHAR,0,0,at_val->bv_val,at_val->bv_len,0);
			 
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): executing '%s'\n",at->add_proc,0,0);
			 rc=SQLExecDirect(sth,at->add_proc,SQL_NTS);
			 if (rc!=SQL_SUCCESS)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): add_proc execution failed\n",0,0,0);
			  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
			 }
			}
			break;
  case LDAP_MOD_DELETE:
			if (at->delete_proc==NULL)
			{
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): delete procedure is not defined for this attribute ('%s')\n",at->name,0,0);
			 break;
			}
			if (c_mod->sm_bvalues==NULL)
			{
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): no values given to delete for attribute '%s' -- deleting all values\n",at->name,0,0);
			 goto del_all;
			}
            Debug(LDAP_DEBUG_TRACE,"backsql_modify(): deleting values for attribute '%s'\n",at->name,0,0);
			for(i=0,at_val=c_mod->sm_bvalues[0];at_val!=NULL;i++,at_val=c_mod->sm_bvalues[i])
			{
			 if (at->expect_return & BACKSQL_DEL)
			  {
			   pno=1;
			   SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&prc,0,0);
			  }
			 else
			  pno=0;
			 po=(at->param_order & BACKSQL_DEL)>0;
			 SQLBindParameter(sth,(SQLUSMALLINT)(pno+1+po),SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.keyval,0,0);
			 /*check for syntax needed here - maybe need binary bind?*/
			 SQLBindParameter(sth,(SQLUSMALLINT)(pno+2-po),SQL_PARAM_INPUT,SQL_C_CHAR,SQL_CHAR,0,0,at_val->bv_val,at_val->bv_len,0);
			   
			 Debug(LDAP_DEBUG_TRACE,"backsql_modify(): executing '%s'\n",at->delete_proc,0,0);
			 rc=SQLExecDirect(sth,at->delete_proc,SQL_NTS);
			 if (rc!=SQL_SUCCESS)
			 {
			  Debug(LDAP_DEBUG_TRACE,"backsql_modify(): delete_proc execution failed\n",0,0,0);
			  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
			 }
			}
			break;
  }
  SQLFreeStmt(sth,SQL_RESET_PARAMS);
 }

 SQLFreeStmt(sth,SQL_DROP);
 send_ldap_result(conn,op,LDAP_SUCCESS,"",NULL,NULL,NULL);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_modify()\n",0,0,0);
 return 0;
}

int backsql_modrdn(BackendDB *be,Connection *conn,Operation *op,
	const char *dn,const char *ndn,const char *newrdn,int deleteoldrdn,const char *newSuperior)
{
 backsql_info *bi=(backsql_info*)be->be_private;
 SQLHDBC dbh;
 SQLHSTMT sth;
 RETCODE rc;
 backsql_oc_map_rec *oc=NULL;
 backsql_entryID e_id,pe_id,new_pid,*res;
 backsql_at_map_rec *at=NULL;
 char *p_dn=NULL,*new_pdn=NULL, *new_dn;
 
 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_modrdn() renaming entry '%s', newrdn='%s', newSuperior='%s'\n",dn,newrdn,newSuperior);
 dbh=backsql_get_db_conn(be,conn);
 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): could not get connection handle - exiting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 res=backsql_dn2id(bi,&e_id,dbh,(char*)ndn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): could not lookup entry id\n",0,0,0);
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,"",NULL,NULL,NULL);
  return 1;
 }
 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): entry id is %d\n",e_id.id,0,0);

 p_dn=dn_parent(be,ndn);

 if (newSuperior)
  new_pdn=dn_validate(ch_strdup(newSuperior));
 else
   new_pdn=p_dn;

 SQLAllocStmt(dbh, &sth);

 if (newSuperior && !strcasecmp(p_dn,new_pdn))
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): newSuperior is equal to old parent - aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"",NULL,NULL,NULL);
  goto modrdn_return;
 }

 if (newSuperior && !strcasecmp(ndn,new_pdn))
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): newSuperior is equal to entry being moved - aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"",NULL,NULL,NULL);
  goto modrdn_return;
 }

 build_new_dn( &new_dn, dn, new_pdn, newrdn ); 
 if (!dn_validate(new_dn))
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): new dn is invalid ('%s') - aborting\n",new_dn,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"",NULL,NULL,NULL);
  goto modrdn_return;
 }
 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): new entry dn is '%s'\n",new_dn,0,0);

 res=backsql_dn2id(bi,&pe_id,dbh,(char*)p_dn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): could not lookup old parent entry id\n",0,0,0);
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,"",NULL,NULL,NULL);
  goto modrdn_return;
 }
 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): old parent entry id is %d\n",pe_id.id,0,0);

 res=backsql_dn2id(bi,&new_pid,dbh,(char*)new_pdn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): could not lookup new parent entry id\n",0,0,0);
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,"",NULL,NULL,NULL);
  goto modrdn_return;
 }
 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): new parent entry id is %d\n",new_pid.id,0,0);

 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): executing delentry_query\n",0,0,0);
 SQLBindParameter(sth,1,SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.id,0,0);
 rc=SQLExecDirect(sth,bi->delentry_query,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): failed to delete record from ldap_entries\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  goto modrdn_return;
 }

 SQLFreeStmt(sth,SQL_RESET_PARAMS);

 Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): executing insentry_query\n",0,0,0);
 backsql_BindParamStr(sth,1,new_dn,BACKSQL_MAX_DN_LEN);
 SQLBindParameter(sth,2,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&e_id.oc_id,0,0);
 SQLBindParameter(sth,3,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&new_pid.id,0,0);
 SQLBindParameter(sth,4,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&e_id.keyval,0,0);
 rc=SQLExecDirect(sth,bi->insentry_query,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_modrdn(): could not insert ldap_entries record\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  goto modrdn_return;
 }

 /*should process deleteoldrdn here...*/

 send_ldap_result(conn,op,LDAP_SUCCESS,"",NULL,NULL,NULL);
modrdn_return:
 SQLFreeStmt(sth,SQL_DROP);
 if (newSuperior && new_pdn)
  ch_free(new_pdn);
 if (new_dn)
  ch_free(new_dn);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_modrdn()\n",0,0,0);
 return 0;
}

int backsql_add(BackendDB *be,Connection *conn,Operation *op,Entry *e)
{
 backsql_info *bi=(backsql_info*)be->be_private;
 SQLHDBC dbh;
 SQLHSTMT sth;
 unsigned long new_keyval;
 long i;
 RETCODE rc;
 backsql_oc_map_rec *oc=NULL;
 backsql_at_map_rec *at_rec=NULL;
 backsql_entryID parent_id,*res;
 Attribute *at;
 struct berval *at_val;
 char *pdn;
 int pno,po;/*first parameter no, parameter order*/
 int prc; /*procedure return code*/

 Debug(LDAP_DEBUG_TRACE,"==>backsql_add(): adding entry '%s'\n",e->e_dn,0,0);
 if (dn_validate(e->e_dn)==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"==>backsql_add(): invalid dn '%s' -- aborting\n",e->e_dn,0,0);
 }
 for(at=e->e_attrs;at!=NULL;at=at->a_next)
 {
  /*Debug(LDAP_DEBUG_TRACE,"backsql_add(): scanning entry -- %s\n",at->a_type,0,0);*/
  if (!strcasecmp(at->a_desc->ad_cname.bv_val,"objectclass"))
  {
   oc=backsql_oc_with_name(bi,at->a_vals[0]->bv_val);
   break;
  }
 }

 if (oc==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): cannot determine objectclass of entry -- aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 if (oc->create_proc == NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): create procedure is not defined for this objectclass - aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }

 dbh=backsql_get_db_conn(be,conn);
 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): could not get connection handle - exiting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }

 SQLAllocStmt(dbh, &sth);
 SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&new_keyval,0,0);

 Debug(LDAP_DEBUG_TRACE,"backsql_add(): executing '%s'\n",oc->create_proc,0,0);
 rc=SQLExecDirect(sth,oc->create_proc,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): create_proc execution failed\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  SQLFreeStmt(sth,SQL_DROP);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 SQLFreeStmt(sth,SQL_RESET_PARAMS);
 Debug(LDAP_DEBUG_TRACE,"backsql_add(): create_proc returned keyval=%d\n",new_keyval,0,0);

 for(at=e->e_attrs;at!=NULL;at=at->a_next)
 {
  at_rec=backsql_at_with_name(oc,at->a_desc->ad_cname.bv_val); 
  
  if (at_rec==NULL)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_add(): attribute provided is not registered in this objectclass ('%s')\n",at->a_desc->ad_cname.bv_val,0,0);
   continue;
  }
  if (at_rec->add_proc==NULL)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_add(): add procedure is not defined for this attribute ('%s')\n",at->a_desc->ad_cname.bv_val,0,0);
   continue;
  }
  
  for(i=0,at_val=at->a_vals[0];at_val!=NULL;i++,at_val=at->a_vals[i])
  {
	if (at_rec->expect_return & BACKSQL_ADD)
	{
	 pno=1;
	 SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&prc,0,0);
	}
	else
	 pno=0;
	po=(at_rec->param_order & BACKSQL_ADD)>0;
	SQLBindParameter(sth,(SQLUSMALLINT)(pno+1+po),SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&new_keyval,0,0);
	/*check for syntax needed here - maybe need binary bind?*/
	SQLBindParameter(sth,(SQLUSMALLINT)(pno+2-po),SQL_PARAM_INPUT,SQL_C_CHAR,SQL_CHAR,0,0,at_val->bv_val,at_val->bv_len,0);
   Debug(LDAP_DEBUG_TRACE,"backsql_add(): executing '%s'\n",at_rec->add_proc,0,0);
   rc=SQLExecDirect(sth,at_rec->add_proc,SQL_NTS);
   if (rc!=SQL_SUCCESS)
   {
	Debug(LDAP_DEBUG_TRACE,"backsql_add(): add_proc execution failed\n",0,0,0);
	backsql_PrintErrors(bi->db_env,dbh,sth,rc);
   }
  }
 }
 SQLFreeStmt(sth,SQL_RESET_PARAMS); 
 pdn=dn_parent(be,e->e_dn);
 res=backsql_dn2id(bi,&parent_id,dbh,pdn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): could not lookup parent entry for new record ('%s')\n",
												pdn,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 backsql_BindParamStr(sth,1,e->e_dn,BACKSQL_MAX_DN_LEN);
 SQLBindParameter(sth,2,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&oc->id,0,0);
 SQLBindParameter(sth,3,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&parent_id.id,0,0);
 SQLBindParameter(sth,4,SQL_PARAM_INPUT,SQL_C_LONG,SQL_INTEGER,0,0,&new_keyval,0,0);
 rc=SQLExecDirect(sth,bi->insentry_query,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_add(): could not insert ldap_entries record\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  /*execute delete_proc to delete data added !!!*/
  SQLFreeStmt(sth,SQL_DROP);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 SQLFreeStmt(sth,SQL_DROP);
 send_ldap_result(conn,op,LDAP_SUCCESS,"",NULL,NULL,NULL);
 return 0;
}

int backsql_delete(BackendDB *be,Connection *conn,Operation *op,
	const char *dn,const char *ndn)
{
 backsql_info *bi=(backsql_info*)be->be_private;
 SQLHDBC dbh;
 SQLHSTMT sth;
 RETCODE rc;
 backsql_oc_map_rec *oc=NULL;
 backsql_entryID e_id,*res;
 int pno;/*first parameter no, parameter order*/

 Debug(LDAP_DEBUG_TRACE,"==>backsql_delete(): deleting entry '%s'\n",ndn,0,0);
 dbh=backsql_get_db_conn(be,conn);
 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): could not get connection handle - exiting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 res=backsql_dn2id(bi,&e_id,dbh,(char*)ndn);
 if (res==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): could not lookup entry id\n",0,0,0);
  send_ldap_result(conn,op,LDAP_NO_SUCH_OBJECT,"",NULL,NULL,NULL);
  return 1;
 }

 oc=backsql_oc_with_id(bi,e_id.oc_id);
 if (oc==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): cannot determine objectclass of entry -- aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 if (oc->delete_proc == NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): delete procedure is not defined for this objectclass - aborting\n",0,0,0);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }

 SQLAllocStmt(dbh, &sth);
 if (oc->expect_return)
 {
  pno=1;
  SQLBindParameter(sth,1,SQL_PARAM_OUTPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&rc,0,0);
 }
 else
  pno=0;
 SQLBindParameter(sth,(SQLUSMALLINT)(pno+1),SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.keyval,0,0);
 /*SQLBindParameter(sth,2,SQL_PARAM_OUTPUT,SQL_C_SLONG,SQL_INTEGER,0,0,&retcode,0,0);*/

 Debug(LDAP_DEBUG_TRACE,"backsql_delete(): executing '%s'\n",oc->delete_proc,0,0);
 rc=SQLExecDirect(sth,oc->delete_proc,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): delete_proc execution failed\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  SQLFreeStmt(sth,SQL_DROP);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 SQLFreeStmt(sth,SQL_RESET_PARAMS);

 SQLBindParameter(sth,1,SQL_PARAM_INPUT,SQL_C_ULONG,SQL_INTEGER,0,0,&e_id.id,0,0);
 rc=SQLExecDirect(sth,bi->delentry_query,SQL_NTS);
 if (rc != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_delete(): failed to delete record from ldap_entries\n",0,0,0);
  backsql_PrintErrors(bi->db_env,dbh,sth,rc);
  SQLFreeStmt(sth,SQL_DROP);
  send_ldap_result(conn,op,LDAP_OTHER,"","SQL-backend error",NULL,NULL);
  return 1;
 }
 SQLFreeStmt(sth,SQL_DROP);

 send_ldap_result(conn,op,LDAP_SUCCESS,"",NULL,NULL,NULL);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_delete()\n",0,0,0);
 return 0;
}

#endif /* SLAPD_SQL */
