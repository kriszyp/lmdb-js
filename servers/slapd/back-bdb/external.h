/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2000-2003 The OpenLDAP Foundation.
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

#ifndef _BDB_EXTERNAL_H
#define _BDB_EXTERNAL_H

LDAP_BEGIN_DECL

#ifndef BDB_SYMBOL
#ifdef BDB_HIER
#define	BDB_SYMBOL(x)	LDAP_CONCAT(hdb_,x)
#else
#define BDB_SYMBOL(x)	LDAP_CONCAT(bdb_,x)
#endif
#endif

#define bdb_initialize				BDB_SYMBOL(initialize)
#define bdb_db_config				BDB_SYMBOL(db_config)
#define bdb_add						BDB_SYMBOL(add)
#define bdb_bind					BDB_SYMBOL(bind)
#define bdb_compare					BDB_SYMBOL(compare)
#define bdb_delete					BDB_SYMBOL(delete)
#define bdb_modify					BDB_SYMBOL(modify)
#define bdb_modrdn					BDB_SYMBOL(modrdn)
#define bdb_search					BDB_SYMBOL(search)
#define bdb_extended				BDB_SYMBOL(extended)
#define bdb_referrals				BDB_SYMBOL(referrals)
#define bdb_operational				BDB_SYMBOL(operational)
#define bdb_hasSubordinates			BDB_SYMBOL(hasSubordinates)
#define bdb_tool_entry_open			BDB_SYMBOL(tool_entry_open)
#define bdb_tool_entry_close		BDB_SYMBOL(tool_entry_close)
#define bdb_tool_entry_next			BDB_SYMBOL(tool_entry_next)
#define bdb_tool_entry_get			BDB_SYMBOL(tool_entry_get)
#define bdb_tool_entry_put			BDB_SYMBOL(tool_entry_put)
#define bdb_tool_entry_reindex		BDB_SYMBOL(tool_entry_reindex)
#define bdb_tool_dn2id_get			BDB_SYMBOL(tool_dn2id_get)
#define bdb_tool_id2entry_get		BDB_SYMBOL(tool_id2entry_get)
#define bdb_tool_entry_modify		BDB_SYMBOL(tool_entry_modify)

extern BI_init	bdb_initialize;

extern BI_db_config	bdb_db_config;

extern BI_op_add	bdb_add;

extern BI_op_bind	bdb_bind;

extern BI_op_compare	bdb_compare;

extern BI_op_delete	bdb_delete;

extern BI_op_modify	bdb_modify;

extern BI_op_modrdn	bdb_modrdn;

extern BI_op_search	bdb_search;

extern BI_op_extended	bdb_extended;

extern BI_chk_referrals	bdb_referrals;

extern BI_operational	bdb_operational;

extern BI_has_subordinates bdb_hasSubordinates;

/* tools.c */
extern BI_tool_entry_open	bdb_tool_entry_open;
extern BI_tool_entry_close	bdb_tool_entry_close;
extern BI_tool_entry_next	bdb_tool_entry_next;
extern BI_tool_entry_get	bdb_tool_entry_get;
extern BI_tool_entry_put	bdb_tool_entry_put;
extern BI_tool_entry_reindex	bdb_tool_entry_reindex;
extern BI_tool_dn2id_get	bdb_tool_dn2id_get;
extern BI_tool_id2entry_get	bdb_tool_id2entry_get;
extern BI_tool_entry_modify	bdb_tool_entry_modify;

LDAP_END_DECL

#endif /* _BDB_EXTERNAL_H */

