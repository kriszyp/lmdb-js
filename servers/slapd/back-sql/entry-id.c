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

backsql_entryID* backsql_free_entryID(backsql_entryID* id)
{
 backsql_entryID* next=id->next;
 if (id->dn!=NULL)
  free(id->dn);
 free(id);
 return next;
}

backsql_entryID* backsql_dn2id(backsql_entryID *id,SQLHDBC dbh,char *dn)
{
 static char id_query[]="SELECT id,keyval,objclass FROM ldap_entries WHERE dn=?";
 SQLHSTMT sth; 
 BACKSQL_ROW_NTS row;
 //SQLINTEGER nrows=0;
 RETCODE rc;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_dn2id(): dn='%s'\n",dn,0,0);
 backsql_Prepare(dbh,&sth,id_query,0);
 if ((rc=backsql_BindParamStr(sth,1,dn,BACKSQL_MAX_DN_LEN)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_dn2id(): error binding dn parameter:\n",0,0,0);
   backsql_PrintErrors(SQL_NULL_HENV,dbh,sth,rc);
   SQLFreeStmt(sth,SQL_DROP);
   return NULL;
  }
 
 if ((rc=SQLExecute(sth)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_dn2id(): error executing query:\n",0,0,0);
   backsql_PrintErrors(SQL_NULL_HENV,dbh,sth,rc);
   SQLFreeStmt(sth,SQL_DROP);
   return NULL;
  }
 
 backsql_BindRowAsStrings(sth,&row);
 if ((rc=SQLFetch(sth)) == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO)
  {
   if (id==NULL)
    {
     id=(backsql_entryID*)ch_calloc(1,sizeof(backsql_entryID));
    }
   id->id=atoi(row.cols[0]);
   id->keyval=atoi(row.cols[1]);
   id->oc_id=atoi(row.cols[2]);
   id->dn=strdup(dn);
   id->next=NULL;
  }
 else
  id=NULL;
 backsql_FreeRow(&row);
 
 SQLFreeStmt(sth, SQL_DROP);
 if (id!=NULL)
  Debug(LDAP_DEBUG_TRACE,"<==backsql_dn2id(): id=%d\n",(int)id->id,0,0);
 else
  Debug(LDAP_DEBUG_TRACE,"<==backsql_dn2id(): no match\n",0,0,0);
 return id;
}


int backsql_get_attr_vals(backsql_at_map_rec *at,backsql_srch_info *bsi)
{
 RETCODE rc;
 SQLHSTMT sth;
 BACKSQL_ROW_NTS row;
 int i;
 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_get_attr_vals(): oc='%s' attr='%s' keyval=%d\n",
			bsi->oc->name,at->name,bsi->c_eid->keyval);

 if ((rc=backsql_Prepare(bsi->dbh,&sth,at->query,0)) != SQL_SUCCESS)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_get_attr_values(): error preparing query: %s\n",at->query,0,0);
   backsql_PrintErrors(bsi->bi->db_env,bsi->dbh,sth,rc);
   return 1;
  }

 if (backsql_BindParamID(sth,1,&(bsi->c_eid->keyval)) != SQL_SUCCESS)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_get_attr_values(): error binding key value parameter\n",0,0,0);
  return 1;
 }

 if ((rc=SQLExecute(sth)) != SQL_SUCCESS && rc!= SQL_SUCCESS_WITH_INFO)
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_get_attr_values(): error executing query\n",0,0,0);
   backsql_PrintErrors(bsi->bi->db_env,bsi->dbh,sth,rc);
   SQLFreeStmt(sth,SQL_DROP);
   return 1;
  }

 backsql_BindRowAsStrings(sth,&row);
 while ((rc=SQLFetch(sth)) == SQL_SUCCESS || rc==SQL_SUCCESS_WITH_INFO)
  {
   for (i=0;i<row.ncols;i++)
    {
     if (row.is_null[i]>0)
      {
       backsql_entry_addattr(bsi->e,row.col_names[i],row.cols[i],/*row.col_prec[i]*/
					strlen(row.cols[i]));
//       Debug(LDAP_DEBUG_TRACE,"prec=%d\n",(int)row.col_prec[i],0,0);
      }
    // else
    //  Debug(LDAP_DEBUG_TRACE,"NULL value in this row for attribute '%s'\n",row.col_names[i],0,0);
    }
  }
 backsql_FreeRow(&row);
 SQLFreeStmt(sth,SQL_DROP);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_get_attr_vals()\n",0,0,0);
 return 1;
}


Entry* backsql_id2entry(backsql_srch_info *bsi,Entry* e,backsql_entryID* eid)
{
 char **c_at_name;
 backsql_at_map_rec *at;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_id2entry()\n",0,0,0);

 bsi->oc=backsql_oc_with_id(bsi->bi,eid->oc_id);
 bsi->e=e;
 bsi->c_eid=eid;
 e->e_attrs=NULL;
 if (bsi->base_dn != NULL)
  e->e_dn=strdup(bsi->c_eid->dn);
 
 if (bsi->attrs!=NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_id2entry(): custom attribute list\n",0,0,0);
  for(c_at_name=bsi->attrs;*c_at_name!=NULL;c_at_name++)
  {
   if (!strcasecmp(*c_at_name,"objectclass") || !strcasecmp(*c_at_name,"0.10"))
   {
	//backsql_entry_addattr(bsi->e,"objectclass",bsi->oc->name,strlen(bsi->oc->name));
    continue;
   }
   at=backsql_at_with_name(bsi->oc,*c_at_name);
   if (at!=NULL)
    backsql_get_attr_vals(at,bsi);
   else
	Debug(LDAP_DEBUG_TRACE,"backsql_id2entry(): attribute '%s' is not defined for objectlass '%s'\n",
			*c_at_name,bsi->oc->name,0);

  }
 }
 else
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_id2entry(): retrieving all attributes\n",0,0,0);
  avl_apply(bsi->oc->attrs,(AVL_APPLY)backsql_get_attr_vals,bsi,0,AVL_INORDER);
 }
 backsql_entry_addattr(bsi->e,"objectclass",bsi->oc->name,strlen(bsi->oc->name));

 Debug(LDAP_DEBUG_TRACE,"<==backsql_id2entry()\n",0,0,0);
 return e;
}
