/* $Id: external.h,v 1.7 1999/06/29 01:29:27 kdz Exp $ */

#ifndef _TCL_EXTERNAL_H
#define _TCL_EXTERNAL_H

LDAP_BEGIN_DECL

extern int tcl_back_initialize LDAP_P ((BackendInfo * bi));
extern int tcl_back_open LDAP_P ((BackendInfo * bi));
extern int tcl_back_close LDAP_P ((BackendInfo * bi));
extern int tcl_back_destroy LDAP_P ((BackendInfo * bi));

extern int tcl_back_db_init LDAP_P ((BackendDB * bd));
extern int tcl_back_db_open LDAP_P ((BackendDB * bd));
extern int tcl_back_db_close LDAP_P ((BackendDB * bd));
extern int tcl_back_db_destroy LDAP_P ((BackendDB * bd));

extern int tcl_back_db_config LDAP_P ((BackendDB * bd,
		const char *fname, int lineno, int argc, char **argv));

extern int tcl_back_bind LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		char *dn, int method, char *mech,
		struct berval * cred, char **edn));

extern int tcl_back_unbind LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op));

extern int tcl_back_search LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		char *base, int scope, int deref, int sizelimit, int timelimit,
		Filter * filter, char *filterstr, char **attrs, int attrsonly));

extern int tcl_back_compare LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		char *dn, Ava * ava));

extern int tcl_back_modify LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		char *dn, LDAPModList * ml));

extern int tcl_back_modrdn LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		char *dn, char *newrdn, int deleteoldrdn,
		char *newSuperior));

extern int tcl_back_add LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op, Entry * e));

extern int tcl_back_delete LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op, char *dn));

extern int tcl_back_abandon LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op, int msgid));

LDAP_END_DECL

#endif /* _TCL_EXTERNAL_H */
