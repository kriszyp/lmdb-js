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
#include <stdarg.h>
#include "slap.h"
#include "back-sql.h"
#include "schema-map.h"
#include "util.h"


char backsql_def_oc_query[]="SELECT id,name,keytbl,keycol,create_proc,delete_proc,expect_return FROM ldap_oc_mappings";
char backsql_def_at_query[]="SELECT name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return,sel_expr_u FROM ldap_attr_mappings WHERE oc_map_id=?";
char backsql_def_delentry_query[]="DELETE FROM ldap_entries WHERE id=?";
char backsql_def_insentry_query[]="INSERT INTO ldap_entries (dn,oc_map_id,parent,keyval) VALUES (?,?,?,?)";
char backsql_def_subtree_cond[]="ldap_entries.dn LIKE CONCAT('%',?)";
char backsql_id_query[]="SELECT id,keyval,oc_map_id FROM ldap_entries WHERE ";

/* TimesTen*/
char backsql_check_dn_ru_query[] = "SELECT dn_ru from ldap_entries";

char* backsql_strcat(char* dest,int *buflen, ...)
{
 va_list strs;
 int cdlen,cslen,grow;
 char *cstr;
 
 /*Debug(LDAP_DEBUG_TRACE,"==>my_strcat()\n");*/
 va_start(strs,buflen);
 if (dest==NULL || *buflen<=0)
  {
   dest=(char*)ch_calloc(BACKSQL_STR_GROW,sizeof(char));
   *buflen=BACKSQL_STR_GROW;
  }
 cdlen=strlen(dest)+1;
 while ((cstr=va_arg(strs,char*)) != NULL)
  {
   cslen=strlen(cstr);
   grow=BACKSQL_MAX(BACKSQL_STR_GROW,cslen);
   if (*buflen-cdlen < cslen)
    {
     /*Debug(LDAP_DEBUG_TRACE,"my_strcat(): buflen=%d, cdlen=%d, cslen=%d -- reallocating dest\n",
                           *buflen,cdlen,cslen); */
     dest=(char*)ch_realloc(dest,(*buflen)+grow*sizeof(char));
     if (dest == NULL)
      {
       Debug(LDAP_DEBUG_ANY,"my_strcat(): could not reallocate string buffer.\n",0,0,0);
      }
     *buflen+=grow;
     /*Debug(LDAP_DEBUG_TRACE,"my_strcat(): new buflen=%d, dest=%p\n",*buflen,dest,0);*/
    }
   strcat(dest,cstr);
   cdlen+=cslen;
  }
 va_end(strs);
 /*Debug(LDAP_DEBUG_TRACE,"<==my_strcat() (dest='%s')\n",dest,0,0);*/
 return dest;
} 

int backsql_entry_addattr(Entry *e,char *at_name,char *at_val,unsigned int at_val_len)
{
 Attribute *c_at=e->e_attrs;
 struct berval* add_val[2];
 struct berval cval;
 AttributeDescription *ad;
 int rc;
 const char *text;
 
 Debug(LDAP_DEBUG_TRACE,"backsql_entry_addattr(): at_name='%s', at_val='%s'\n",at_name,at_val,0);
 cval.bv_val=at_val;
 cval.bv_len=at_val_len;
 add_val[0]=&cval;
 add_val[1]=NULL;
 
 ad=NULL;
 rc = slap_str2ad( at_name, &ad, &text );
 if( rc != LDAP_SUCCESS ) 
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_entry_addattr(): failed to find AttributeDescription for '%s'\n",at_name,0,0);
   return 0;
  }
  
 rc = attr_merge(e,ad,add_val);

 if( rc != 0 )
  {
   Debug(LDAP_DEBUG_TRACE,"backsql_entry_addattr(): failed to merge value '%s' for attribute '%s'\n",at_val,at_name,0);
   return 0;
  }
 
 Debug(LDAP_DEBUG_TRACE,"<==backsql_query_addattr()\n",0,0,0);
 return 1;
}

char* backsql_get_table_spec(char **p)
{
 char *s,*q;
 char *res=NULL;
 int res_len=0;

 s=*p;
 while(**p && **p!=',') (*p)++;
 if (**p)
  *(*p)++='\0';

#define BACKSQL_NEXT_WORD  {while (*s && isspace(*s)) s++; if (!*s) return res; q=s; while (*q && !isspace(*q)) q++; if (*q) *q++='\0';}
 BACKSQL_NEXT_WORD;
 res=backsql_strcat(res,&res_len,s,NULL);/*table name*/
 s=q;

 BACKSQL_NEXT_WORD;
 if (!strcasecmp(s,"as"))
 {
  s=q;
  BACKSQL_NEXT_WORD;
 }
 /*res=backsql_strcat(res,&res_len," AS ",s,NULL);
  *oracle doesn't understand AS :(
  */
 res=backsql_strcat(res,&res_len," ",s,NULL);/*table alias*/
 return res;
}

int backsql_merge_from_clause(char **dest_from,int *dest_len,char *src_from)
{
 char *s,*p,*srcc,*pos,e;

 /*Debug(LDAP_DEBUG_TRACE,"==>backsql_merge_from_clause(): dest_from='%s',src_from='%s'\n",
 				dest_from,src_from,0); */
 srcc=ch_strdup(src_from);
 p=srcc;
 while(*p)
 {
  s=backsql_get_table_spec(&p);
 /* Debug(LDAP_DEBUG_TRACE,"backsql_merge_from_clause(): p='%s' s='%s'\n",p,s,0);  */
  if (*dest_from==NULL)
   *dest_from=backsql_strcat(*dest_from,dest_len,s,NULL);
  else
	if((pos=strstr(*dest_from,s))==NULL)
     *dest_from=backsql_strcat(*dest_from,dest_len,",",s,NULL);
    else if((e=pos[strlen(s)])!='\0' && e!=',')
      *dest_from=backsql_strcat(*dest_from,dest_len,",",s,NULL);
  if (s)
	ch_free(s);
 }
/* Debug(LDAP_DEBUG_TRACE,"<==backsql_merge_from_clause()\n",0,0,0);*/
 free(srcc);
 return 1;
}

#endif /* SLAPD_SQL */
