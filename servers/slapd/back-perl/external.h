/* $OpenLDAP$ */
/*
 * Copyright 1999-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _PERL_EXTERNAL_H
#define _PERL_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	perl_back_initialize;
extern BI_open	perl_back_open;
extern BI_close	perl_back_close;
extern BI_destroy	perl_back_destroy;

extern BI_db_init	perl_back_db_init;
extern BI_db_open	perl_back_db_open;
extern BI_db_destroy	perl_back_db_destroy;

extern BI_db_config	perl_back_db_config;

extern BI_op_bind	perl_back_bind;

extern BI_op_search	perl_back_search;

extern BI_op_compare	perl_back_compare;

extern BI_op_modify	perl_back_modify;

extern BI_op_modrdn	perl_back_modrdn;

extern BI_op_add	perl_back_add;

extern BI_op_delete	perl_back_delete;

LDAP_END_DECL

#endif /* _PERL_EXTERNAL_H */
