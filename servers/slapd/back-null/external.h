/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2004 The OpenLDAP Foundation.
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
 * This work was originally developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#ifndef _NULL_EXTERNAL_H
#define _NULL_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init		null_back_initialize;

extern BI_db_init	null_back_db_init;
extern BI_db_destroy 	null_back_db_destroy;

extern BI_db_config	null_back_db_config;

extern BI_op_bind	null_back_bind;

extern BI_op_search	null_back_search;

extern BI_op_compare 	null_back_compare;

extern BI_op_modify	null_back_modify;

extern BI_op_modrdn	null_back_modrdn;

extern BI_op_add	null_back_add;

extern BI_op_delete	null_back_delete;

LDAP_END_DECL

#endif /* _NULL_EXTERNAL_H */
