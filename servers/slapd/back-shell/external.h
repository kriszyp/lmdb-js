/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _SHELL_EXTERNAL_H
#define _SHELL_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	shell_back_initialize;
extern BI_open	shell_back_open;
extern BI_close	shell_back_close;
extern BI_destroy	shell_back_destroy;

extern BI_db_init	shell_back_db_init;
extern BI_db_destroy	shell_back_db_destroy;

extern BI_db_config	shell_back_db_config;

extern BI_op_bind	shell_back_bind;

extern BI_op_unbind	shell_back_unbind;

extern BI_op_search	shell_back_search;

extern BI_op_compare	shell_back_compare;

extern BI_op_modify	shell_back_modify;

extern BI_op_modrdn	shell_back_modrdn;

extern BI_op_add	shell_back_add;

extern BI_op_delete	shell_back_delete;

extern BI_op_abandon	shell_back_abandon;

LDAP_END_DECL

#endif /* _SHELL_EXTERNAL_H */
