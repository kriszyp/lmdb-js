/* $OpenLDAP$ */

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
		const char *dn, const char *ndn, int method,
		struct berval * cred, char **edn));

extern int tcl_back_unbind LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op));

extern int tcl_back_search LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		const char *base, const char *nbase,
		int scope, int deref, int sizelimit, int timelimit,
		Filter * filter, const char *filterstr,
		char **attrs, int attrsonly));

extern int tcl_back_compare LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		const char *dn, const char *ndn,
		Ava * ava));

extern int tcl_back_modify LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		const char *dn, const char *ndn,
		Modifications * ml));

extern int tcl_back_modrdn LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		const char *dn, const char *ndn,
		const char *newrdn, int deleteoldrdn,
		const char *newSuperior));

extern int tcl_back_add LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op, Entry * e));

extern int tcl_back_delete LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op,
		const char *dn, const char *ndn));

extern int tcl_back_abandon LDAP_P ((BackendDB * bd,
		Connection * conn, Operation * op, int msgid));

LDAP_END_DECL

#endif /* _TCL_EXTERNAL_H */
