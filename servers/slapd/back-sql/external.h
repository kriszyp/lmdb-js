/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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

#ifndef _SQL_EXTERNAL_H
#define _SQL_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init		sql_back_initialize;
extern BI_destroy	backsql_destroy;

extern BI_db_init	backsql_db_init;
extern BI_db_open	backsql_db_open;
extern BI_db_close	backsql_db_close;
extern BI_db_destroy	backsql_db_destroy;

extern BI_db_config	backsql_db_config;

extern BI_op_bind	backsql_bind;
extern BI_op_search	backsql_search;
extern BI_op_compare	backsql_compare;
extern BI_op_modify	backsql_modify;
extern BI_op_modrdn	backsql_modrdn;
extern BI_op_add	backsql_add;
extern BI_op_delete	backsql_delete;

extern BI_operational	backsql_operational;

extern BI_connection_destroy	backsql_connection_destroy;

LDAP_END_DECL

#endif /* _SQL_EXTERNAL_H */
