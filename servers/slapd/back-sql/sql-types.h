#ifndef __BACKSQL_SQL_TYPES_H__
#define __BACKSQL_SQL_TYPES_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

#include <sql.h>
#include <sqlext.h>

typedef struct
{
 SWORD ncols;
 char** col_names;
 UDWORD *col_prec;
 char** cols;
 SQLINTEGER* is_null;
}BACKSQL_ROW_NTS;

#endif

