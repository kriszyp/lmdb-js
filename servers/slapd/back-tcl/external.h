/* $OpenLDAP$ */

#ifndef _TCL_EXTERNAL_H
#define _TCL_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	tcl_back_initialize;
extern BI_open	tcl_back_open;
extern BI_close	tcl_back_close;
extern BI_destroy	tcl_back_destroy;

extern BI_db_init	tcl_back_db_init;
extern BI_db_open	tcl_back_db_open;
extern BI_db_close	tcl_back_db_close;
extern BI_db_destroy	tcl_back_db_destroy;

extern BI_db_config	tcl_back_db_config;

extern BI_op_bind	tcl_back_bind;

extern BI_op_unbind	tcl_back_unbind;

extern BI_op_search	tcl_back_search;

extern BI_op_compare	tcl_back_compare;

extern BI_op_modify	tcl_back_modify;

extern BI_op_modrdn	tcl_back_modrdn;

extern BI_op_add	tcl_back_add;

extern BI_op_delete	tcl_back_delete;

extern BI_op_abandon	tcl_back_abandon;

LDAP_END_DECL

#endif /* _TCL_EXTERNAL_H */
