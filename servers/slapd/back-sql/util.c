/*
 *	 Copyright 1999, Dmitry Kovalev (zmit@mail.ru), All rights reserved.
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
#include "util.h"


char backsql_def_oc_query[]="SELECT id,name,keytbl,keycol,create_proc,delete_proc FROM ldap_objclasses";
char backsql_def_at_query[]="SELECT name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc FROM ldap_attrs WHERE oc_id=?";
char backsql_def_delentry_query[]="DELETE FROM ldap_entries WHERE id=?";
char backsql_def_insentry_query[]="INSERT INTO ldap_entries (dn,objclass,parent,keyval) VALUES (?,?,?,?)";
char backsql_def_subtree_cond[]="ldap_entries.dn LIKE CONCAT('%',?)";


char* backsql_strcat(char* dest,int *buflen, ...)
{
 va_list strs;
 int cdlen,cslen,grow;
 char *cstr;
 
 //Debug(LDAP_DEBUG_TRACE,"==>my_strcat()\n");
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
     //Debug(LDAP_DEBUG_TRACE,"my_strcat(): buflen=%d, cdlen=%d, cslen=%d -- reallocating dest\n",
     //                     *buflen,cdlen,cslen);
     dest=(char*)ch_realloc(dest,(*buflen)+grow*sizeof(char));
     if (dest == NULL)
      {
       Debug(LDAP_DEBUG_ANY,"my_strcat(): could not reallocate string buffer.\n",0,0,0);
      }
     *buflen+=grow;
     //Debug(LDAP_DEBUG_TRACE,"my_strcat(): new buflen=%d, dest=%p\n",*buflen,dest,0);
    }
   strcat(dest,cstr);
   cdlen+=cslen;
  }
 va_end(strs);
 //Debug(LDAP_DEBUG_TRACE,"<==my_strcat() (dest='%s')\n",dest,0,0);
 return dest;
} 

int backsql_entry_addattr(Entry *e,char *at_name,char *at_val,unsigned int at_val_len)
{
 Attribute *c_at=e->e_attrs;
 struct berval **cval;
 int nvals;
 
 Debug(LDAP_DEBUG_TRACE,"backsql_entry_addattr(): at_name='%s', at_val='%s'\n",at_name,at_val,0);
 while (c_at!=NULL && strcasecmp(c_at->a_type,at_name))
  c_at=c_at->a_next;
 if (c_at == NULL)
  {
   //Debug(LDAP_DEBUG_TRACE,"backsql_addattr(): creating new attribute\n",0,0,0);
   c_at=(Attribute *)ch_calloc(sizeof(Attribute),1);
   c_at->a_type=strdup(at_name);
   c_at->a_syntax=SYNTAX_CIS;
   c_at->a_vals=(struct berval**)ch_calloc(sizeof(struct berval *),1);
   c_at->a_vals[0]=NULL;
   c_at->a_next=e->e_attrs;
   e->e_attrs=c_at;
  }
 //Debug(LDAP_DEBUG_TRACE,"backsql_addattr(): checking attribute values\n",0,0,0);
 //should use different comparison methods for different attributes
 //for now, uses memcmp
 for (cval=c_at->a_vals,nvals=0;*cval != NULL &&
      memcmp((*cval)->bv_val,at_val,BACKSQL_MIN((*cval)->bv_len,at_val_len));cval++,nvals++);
     
 if (*cval==NULL)
  {
   //Debug(LDAP_DEBUG_TRACE,"backsql_addattr(): nvals=%d; adding new value\n",nvals,0,0);
   c_at->a_vals=(struct berval **)realloc(c_at->a_vals,sizeof(struct berval *)*(nvals+2));
   c_at->a_vals[nvals]=(struct berval*)ch_calloc(sizeof(struct berval),1);
   c_at->a_vals[nvals]->bv_val=(char*)ch_calloc(sizeof(char),at_val_len);
   strncpy(c_at->a_vals[nvals]->bv_val,at_val,at_val_len);
   c_at->a_vals[nvals]->bv_len=at_val_len;
   c_at->a_vals[nvals+1]=NULL;
  }
 else
 {
  //Debug(LDAP_DEBUG_TRACE,"backsql_addattr(): value already exists\n",0,0,0);
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
 res=backsql_strcat(res,&res_len,s,NULL);//table name
 s=q;

 BACKSQL_NEXT_WORD;
 if (!strcasecmp(s,"as"))
 {
  s=q;
  BACKSQL_NEXT_WORD;
 }
 //res=backsql_strcat(res,&res_len," AS ",s,NULL);//table alias
 //oracle doesn't understand AS :(
 res=backsql_strcat(res,&res_len," ",s,NULL);//table alias
 return res;
}

int backsql_merge_from_clause(char **dest_from,int *dest_len,char *src_from)
{
 char *s,*p,*srcc,*pos,e;

 //Debug(LDAP_DEBUG_TRACE,"==>backsql_merge_from_clause(): dest_from='%s',src_from='%s'\n",
 //				dest_from,src_from,0);
 srcc=strdup(src_from);
 p=srcc;
 while(*p)
 {//4832041
  s=backsql_get_table_spec(&p);
 // Debug(LDAP_DEBUG_TRACE,"backsql_merge_from_clause(): p='%s' s='%s'\n",p,s,0);  
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
// Debug(LDAP_DEBUG_TRACE,"<==backsql_merge_from_clause()\n",0,0,0);
 free(srcc);
 return 1;
}

#endif /* SLAPD_SQL */