/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _LDAP_EXTERNAL_H
#define _LDAP_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	ldap_back_initialize;
extern BI_open	ldap_back_open;
extern BI_close	ldap_back_close;
extern BI_destroy	ldap_back_destroy;

extern BI_db_init	ldap_back_db_init;
extern BI_db_destroy	ldap_back_db_destroy;

extern BI_db_config	ldap_back_db_config;

extern BI_op_bind	ldap_back_bind;

extern BI_connection_destroy	ldap_back_conn_destroy;

extern BI_op_search	ldap_back_search;

extern BI_op_compare	ldap_back_compare;

extern BI_op_modify	ldap_back_modify;

extern BI_op_modrdn	ldap_back_modrdn;

extern BI_op_add	ldap_back_add;

extern BI_op_delete	ldap_back_delete;

extern BI_op_abandon	ldap_back_abandon;

extern BI_op_extended	ldap_back_extended;

extern BI_acl_group	ldap_back_group;

extern BI_acl_attribute	ldap_back_attribute;

LDAP_END_DECL

#endif /* _LDAP_EXTERNAL_H */
