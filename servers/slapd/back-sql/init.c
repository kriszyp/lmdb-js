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
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"
#include "schema-map.h"
#include "util.h"

#ifdef SLAPD_SQL_DYNAMIC

int backsql_LTX_init_module(int argc, char *argv[]) {
    BackendInfo bi;

    memset( &bi, '\0', sizeof(bi) );
    bi.bi_type = "sql";
    bi.bi_init = backbacksql_initialize;

    backend_add(&bi);
    return 0;
}

#endif /* SLAPD_SHELL_DYNAMIC */

int sql_back_initialize(
    BackendInfo	*bi
)
{ 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_initialize()\n",0,0,0);
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = backsql_db_init;
	bi->bi_db_config = backsql_db_config;
	bi->bi_db_open = backsql_db_open;
	bi->bi_db_close = backsql_db_close;
	bi->bi_db_destroy = backsql_db_destroy;

#ifdef BACKSQL_ALL_DONE
	bi->bi_op_abandon = backsql_abandon;
	bi->bi_op_compare = backsql_compare;
#else
	bi->bi_op_abandon = 0;
	bi->bi_op_compare = 0;
#endif
	bi->bi_op_bind = backsql_bind;
	bi->bi_op_unbind = backsql_unbind;
	bi->bi_op_search = backsql_search;
	bi->bi_op_modify = backsql_modify;
	bi->bi_op_modrdn = backsql_modrdn;
	bi->bi_op_add = backsql_add;
	bi->bi_op_delete = backsql_delete;
	
	bi->bi_acl_group = 0;
	bi->bi_acl_attribute = 0;
	bi->bi_chk_referrals = 0;
 
	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = backsql_connection_destroy;
	
	Debug(LDAP_DEBUG_TRACE,"<==backsql_initialize()\n",0,0,0);
	return 0;
}


int backsql_destroy ( BackendInfo *bi )
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_destroy()\n",0,0,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_destroy()\n",0,0,0);
 return 0;
}

int backsql_db_init(BackendDB *bd)
{
 backsql_info *si;
 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_db_init()\n",0,0,0);
 si = (backsql_info *) ch_calloc( 1, sizeof(backsql_info) );
 ldap_pvt_thread_mutex_init(&si->dbconn_mutex);
 ldap_pvt_thread_mutex_init(&si->schema_mutex);
 backsql_init_db_env(si);
 
 bd->be_private=si;
 Debug(LDAP_DEBUG_TRACE,"<==backsql_db_init()\n",0,0,0);
 return 0;
}

int backsql_db_destroy(BackendDB *bd)
{
 backsql_info *si=(backsql_info*)bd->be_private;
 
 Debug(LDAP_DEBUG_TRACE,"==>backsql_db_destroy()\n",0,0,0);
 ldap_pvt_thread_mutex_lock(&si->dbconn_mutex);
 backsql_free_db_env(si);
 ldap_pvt_thread_mutex_unlock(&si->dbconn_mutex);
 ldap_pvt_thread_mutex_lock(&si->schema_mutex);
 backsql_destroy_schema_map(si);
 ldap_pvt_thread_mutex_unlock(&si->schema_mutex);
 ldap_pvt_thread_mutex_destroy(&si->schema_mutex);
 ldap_pvt_thread_mutex_destroy(&si->dbconn_mutex);
 free(si->dbname);
 free(si->dbuser);
 if (si->dbpasswd)
  free(si->dbpasswd);
 if (si->dbhost)
  free(si->dbhost);
 if (si->upper_func)
  free(si->upper_func);
 free(si->subtree_cond);
 free(si->oc_query);
 free(si->at_query);
 free(si->insentry_query);
 free(si->delentry_query);
 free(si);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_db_destroy()\n",0,0,0);
 return 0;
}

int backsql_db_open (BackendDB *bd)
{
 backsql_info *si=(backsql_info*)bd->be_private;
 Connection tmp;
 SQLHDBC dbh;
 int idq_len;

 Debug(LDAP_DEBUG_TRACE,"==>backsql_db_open(): testing RDBMS connection\n",0,0,0);
 if (si->dbname==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): datasource name not specified (use dbname directive in slapd.conf)\n",0,0,0);
  return 1;
 }
 if (si->dbuser==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): user name not specified (use dbuser directive in slapd.conf)\n",0,0,0);
  return 1;
 }
 if (si->subtree_cond==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): subtree search SQL condition not specified (use subtree_cond directive in slapd.conf)\n",0,0,0);
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): setting '%s' as default\n",backsql_def_subtree_cond,0,0);
  si->subtree_cond=ch_strdup(backsql_def_subtree_cond);
 }
 if (si->oc_query==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): objectclass mapping SQL statement not specified (use oc_query directive in slapd.conf)\n",0,0,0);
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): setting '%s' by default\n",backsql_def_oc_query,0,0);
  si->oc_query=ch_strdup(backsql_def_oc_query);
 }
 if (si->at_query==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): attribute mapping SQL statement not specified (use at_query directive in slapd.conf)\n",0,0,0);
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): setting '%s' by default\n",backsql_def_at_query,0,0);
  si->at_query=ch_strdup(backsql_def_at_query);
 }
 if (si->insentry_query==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): entry insertion SQL statement not specified (use insentry_query directive in slapd.conf)\n",0,0,0);
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): setting '%s' by default\n",backsql_def_insentry_query,0,0);
  si->insentry_query=ch_strdup(backsql_def_insentry_query);
 }
 if (si->delentry_query==NULL)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): entry deletion SQL statement not specified (use delentry_query directive in slapd.conf)\n",0,0,0);
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): setting '%s' by default\n",backsql_def_delentry_query,0,0);
  si->delentry_query=ch_strdup(backsql_def_delentry_query);
 }
 tmp.c_connid=-1;
 dbh=backsql_get_db_conn(bd,&tmp);
 if (!dbh)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): connection failed, exiting\n",0,0,0
);
  return 1;
 }

 si->id_query=NULL;
 idq_len=0;
 if (si->upper_func==NULL)
 {
  si->id_query=backsql_strcat(si->id_query,&idq_len,backsql_id_query,"dn=?",NULL);
 }
 else
 {
    if (si->has_ldapinfo_dn_ru) {
      si->id_query=backsql_strcat(si->id_query,&idq_len,backsql_id_query,"dn_ru=?",NULL);
    }
    else {
      if (si->isTimesTen) {
    si->id_query=backsql_strcat(si->id_query,&idq_len,backsql_id_query,si->upper_func,"(dn)=?",NULL);
      }
      else {
   		si->id_query=backsql_strcat(si->id_query,&idq_len,backsql_id_query,si->upper_func,"(dn)=",si->upper_func,"(?)",NULL);
   	  }
	}
 }
 
backsql_free_db_conn(bd,&tmp);
 if (!si->schema_loaded)
 {
  Debug(LDAP_DEBUG_TRACE,"backsql_db_open(): test failed, schema map not loaded - exiting\n",0,0,0);
  return 1;
 }
 Debug(LDAP_DEBUG_TRACE,"<==backsql_db_open(): test succeeded, schema map loaded\n",0,0,0);
 return 0;
}

int backsql_db_close(BackendDB *bd)
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_db_close()\n",0,0,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_db_close()\n",0,0,0);
 return 0;
}

int backsql_connection_destroy(BackendDB *be,Connection *conn)
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_connection_destroy()\n",0,0,0);
 backsql_free_db_conn(be,conn);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_connection_destroy()\n",0,0,0);
 return 0;
}

#endif /* SLAPD_SQL */
