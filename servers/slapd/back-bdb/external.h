/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _BDB_EXTERNAL_H
#define _BDB_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	bdb_initialize;

extern BI_db_config	bdb_db_config;

extern BI_op_add	bdb_add;

extern BI_op_bind	bdb_bind;

extern BI_op_compare	bdb_compare;

extern BI_op_delete	bdb_delete;

extern BI_op_abandon	bdb_abandon;

extern BI_op_modify	bdb_modify;

extern BI_op_modrdn	bdb_modrdn;

extern BI_op_search	bdb_search;

extern BI_op_unbind	bdb_unbind;

extern BI_chk_referrals	bdb_referrals;

LDAP_END_DECL

#endif /* _BDB_EXTERNAL_H */

