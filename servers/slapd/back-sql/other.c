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

int backsql_dummy()
{
 return 0;
}

int	backsql_compare(BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	AttributeAssertion *ava )
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_compare() - not implemented\n",0,0,0);
 return 0;
}

int backsql_abandon( BackendDB *be,
	Connection *conn, Operation *op, int msgid )
{
 Debug(LDAP_DEBUG_TRACE,"==>backsql_abandon()\n",0,0,0);
 Debug(LDAP_DEBUG_TRACE,"<==backsql_abandon()\n",0,0,0);
 return 0;
}

#endif /* SLAPD_SQL */
