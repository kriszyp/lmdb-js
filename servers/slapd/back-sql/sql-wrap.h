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

RETCODE backsql_Prepare( SQLHDBC dbh, SQLHSTMT *sth, char* query, int timeout );

#define backsql_BindParamStr( sth, par_ind, str, maxlen ) 		\
	SQLBindParameter( (sth), (SQLUSMALLINT)(par_ind), 		\
			SQL_PARAM_INPUT,				\
			SQL_C_CHAR, SQL_VARCHAR,			\
         		(SQLUINTEGER)(maxlen), 0, (SQLPOINTER)(str),	\
			(SQLUINTEGER)(maxlen), NULL )

#define backsql_BindParamID( sth, par_ind, id )				\
	SQLBindParameter( (sth), (SQLUSMALLINT)(par_ind),		\
			SQL_PARAM_INPUT, SQL_C_ULONG, SQL_INTEGER,	\
			0, 0, (SQLPOINTER)(id), 0, (SQLINTEGER*)NULL )

RETCODE backsql_BindRowAsStrings( SQLHSTMT sth, BACKSQL_ROW_NTS *row );
RETCODE backsql_FreeRow( BACKSQL_ROW_NTS *row );
void backsql_PrintErrors( SQLHENV henv, SQLHDBC hdbc, SQLHSTMT sth, int rc );

int backsql_init_db_env( backsql_info *si );
int backsql_free_db_env( backsql_info *si );
int backsql_get_db_conn( Backend *be, Connection *ldapc, SQLHDBC *dbh );
int backsql_free_db_conn( Backend *be, Connection *ldapc );

#endif /* __BACKSQL_SQL_WRAP_H__ */

