/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2003 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#ifndef _MONITOR_EXTERNAL_H
#define _MONITOR_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	monitor_back_initialize;
extern BI_db_init	monitor_back_db_init;
extern BI_db_open	monitor_back_db_open;
extern BI_config	monitor_back_config;
extern BI_db_config	monitor_back_db_config;

extern BI_db_destroy	monitor_back_db_destroy;

extern BI_op_search	monitor_back_search;
extern BI_op_compare	monitor_back_compare;
extern BI_op_modify	monitor_back_modify;
extern BI_op_bind	monitor_back_bind;
extern BI_operational	monitor_back_operational;

LDAP_END_DECL

#endif /* _MONITOR_EXTERNAL_H */
