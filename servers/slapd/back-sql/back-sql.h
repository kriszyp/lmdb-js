#ifndef __BACKSQL_H__
#define __BACKSQL_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */


#include "external.h"
#include "sql-types.h"
#define BACKSQL_MAX_DN_LEN 255

typedef struct
{
 char *dbhost;
 int dbport;
 char *dbuser;
 char *dbpasswd;
 char *dbname;
 /*SQL condition for subtree searches differs in syntax:
 *"LIKE CONCAT('%',?)" or "LIKE '%'+?" or smth else */
 char *subtree_cond;
 char *oc_query,*at_query;
 char *insentry_query,*delentry_query;
 char *id_query;
 char *upper_func;
 Avlnode *db_conns;
 Avlnode *oc_by_name;
 Avlnode *oc_by_id;
 int schema_loaded;
 ldap_pvt_thread_mutex_t dbconn_mutex;
 ldap_pvt_thread_mutex_t schema_mutex;
 SQLHENV db_env;
 int   isTimesTen; /* TimesTen */
 int   has_ldapinfo_dn_ru;  /* Does ldapinfo.dn_ru exist in schema? */
}backsql_info;

#endif

