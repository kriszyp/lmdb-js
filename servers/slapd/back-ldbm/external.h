/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _LDBM_EXTERNAL_H
#define _LDBM_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	ldbm_back_initialize;
extern BI_open	ldbm_back_open;
extern BI_close	ldbm_back_close;
extern BI_destroy	ldbm_back_destroy;

extern BI_db_init	ldbm_back_db_init;
extern BI_db_open	ldbm_back_db_open;
extern BI_db_close	ldbm_back_db_close;
extern BI_db_destroy	ldbm_back_db_destroy;

extern BI_db_config	ldbm_back_db_config;

extern BI_op_extended	ldbm_back_extended;

extern BI_op_bind	ldbm_back_bind;

extern BI_op_search	ldbm_back_search;

extern BI_op_compare	ldbm_back_compare;

extern BI_op_modify	ldbm_back_modify;

extern BI_op_modrdn	ldbm_back_modrdn;

extern BI_op_add	ldbm_back_add;

extern BI_op_delete	ldbm_back_delete;

extern BI_acl_group	ldbm_back_group;

extern BI_acl_attribute	ldbm_back_attribute;

extern BI_operational	ldbm_back_operational;

#ifdef SLAP_X_FILTER_HASSUBORDINATES
extern BI_has_subordinates	ldbm_back_hasSubordinates;
#endif /* SLAP_X_FILTER_HASSUBORDINATES */

/* hooks for slap tools */
extern BI_tool_entry_open	ldbm_tool_entry_open;
extern BI_tool_entry_close	ldbm_tool_entry_close;
extern BI_tool_entry_first	ldbm_tool_entry_first;
extern BI_tool_entry_next	ldbm_tool_entry_next;
extern BI_tool_entry_get	ldbm_tool_entry_get;
extern BI_tool_entry_put	ldbm_tool_entry_put;

extern BI_tool_entry_reindex	ldbm_tool_entry_reindex;
extern BI_tool_sync	ldbm_tool_sync;

extern BI_chk_referrals	ldbm_back_referrals;

LDAP_END_DECL

#endif /* _LDBM_EXTERNAL_H */
