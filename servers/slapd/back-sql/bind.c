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
#include "slap.h"
#include "back-sql.h"
#include "sql-wrap.h"

int backsql_bind(Backend *be,Connection *conn,Operation *op,
	char *dn,char *ndn,int method,char *mech,struct berval *cred,char** edn)
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_bind()\n",0,0,0);
 //for now, just return OK, allowing to test modify operations
 send_ldap_result(conn,op,LDAP_SUCCESS,NULL,NULL,NULL,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_bind()\n",0,0,0);
 return 0;
}
 
int backsql_unbind(Backend *be,Connection *conn,Operation *op)
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_unbind()\n",0,0,0);
 backsql_free_db_conn(be,conn);
 send_ldap_result(conn,op,LDAP_SUCCESS,NULL,NULL,NULL,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_unbind()\n",0,0,0);
 return 0;
}
