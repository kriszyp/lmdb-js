/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2001-2004 The OpenLDAP Foundation.
 * Portions Copyright 2004 Pierangelo Masarati.
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

#ifndef RELAY_EXTERNAL_H
#define RELAY_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init			relay_back_initialize;
#if 0
extern BI_config		relay_back_config;
extern BI_open			relay_back_open;
extern BI_close			relay_back_close;
extern BI_destroy		relay_back_destroy;
#endif

extern BI_db_init		relay_back_db_init;
extern BI_db_config		relay_back_db_config;
extern BI_db_open		relay_back_db_open;
extern BI_db_close		relay_back_db_close;
extern BI_db_destroy		relay_back_db_destroy;

extern BI_op_bind		relay_back_op_bind;
extern BI_op_unbind		relay_back_op_unbind;
extern BI_op_search		relay_back_op_search;
extern BI_op_compare		relay_back_op_compare;
extern BI_op_modify		relay_back_op_modify;
extern BI_op_modrdn		relay_back_op_modrdn;
extern BI_op_add		relay_back_op_add;
extern BI_op_delete		relay_back_op_delete;
extern BI_op_abandon		relay_back_op_abandon;
extern BI_op_cancel		relay_back_op_cancel;
extern BI_op_extended		relay_back_op_extended;
extern BI_entry_release_rw	relay_back_entry_release_rw;
extern BI_entry_get_rw		relay_back_entry_get_rw;
extern BI_chk_referrals		relay_back_chk_referrals;
extern BI_operational		relay_back_operational;
extern BI_has_subordinates	relay_back_has_subordinates;

extern BI_connection_init	relay_back_connection_init;
extern BI_connection_destroy	relay_back_connection_destroy;

#if 0
extern BI_tool_entry_open	relay_back_tool_entry_open;
extern BI_tool_entry_close	relay_back_tool_entry_close;
extern BI_tool_entry_first	relay_back_tool_entry_first;
extern BI_tool_entry_next	relay_back_tool_entry_next;
extern BI_tool_entry_get	relay_back_tool_entry_get;
extern BI_tool_entry_put	relay_back_tool_entry_put;
extern BI_tool_entry_reindex	relay_back_tool_entry_reindex;
extern BI_tool_sync		relay_back_tool_sync;
extern BI_tool_dn2id_get	relay_back_tool_dn2id_get;
extern BI_tool_id2entry_get	relay_back_tool_id2entry_get;
extern BI_tool_entry_modify	relay_back_tool_entry_modify;
#endif

LDAP_END_DECL

#endif /* _MONITOR_EXTERNAL_H */

