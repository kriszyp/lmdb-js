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

int backsql_dummy()
{
 return 0;
}

int backsql_compare(BackendDB *be,Connection *conn,Operation *op,
	char *dn,char *ndn,Ava *ava)
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_compare()\n",0,0,0);
 return 0;
}

int backsql_abandon( BackendDB *be,
	Connection *conn, Operation *op, int msgid )
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_abandon()\n",0,0,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_abandon()\n",0,0,0);
 return 0;
}
