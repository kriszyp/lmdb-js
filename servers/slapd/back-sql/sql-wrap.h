#ifndef __BACKSQL_SQL_WRAP_H__
#define __BACKSQL_SQL_WRAP_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include "back-sql.h"
#include "sql-types.h"

RETCODE backsql_Prepare(SQLHDBC dbh,SQLHSTMT *sth,char* query,int timeout);
RETCODE backsql_BindParamStr(SQLHSTMT sth,int par_ind,char *str,int maxlen);
RETCODE backsql_BindParamID(SQLHSTMT sth,int par_ind,unsigned long *id);
RETCODE backsql_BindRowAsStrings(SQLHSTMT sth,BACKSQL_ROW_NTS *row);
RETCODE backsql_FreeRow(BACKSQL_ROW_NTS *row);
void backsql_PrintErrors(SQLHENV henv, SQLHDBC hdbc, SQLHSTMT sth,int rc);

int backsql_init_db_env(backsql_info *si);
int backsql_free_db_env(backsql_info *si);
SQLHDBC backsql_get_db_conn(Backend *be,Connection *ldapc);
int backsql_free_db_conn(Backend *be,Connection *ldapc);

#endif

