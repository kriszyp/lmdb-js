/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */
#ifndef __BACKSQL_SQL_TYPES_H__
#define __BACKSQL_SQL_TYPES_H__

#include <sql.h>
#include <sqlext.h>

typedef struct {
	SWORD		ncols;
	BerVarray	col_names;
	UDWORD		*col_prec;
	char		**cols;
	SQLINTEGER	*value_len;
} BACKSQL_ROW_NTS;

#endif /* __BACKSQL_SQL_TYPES_H__ */

