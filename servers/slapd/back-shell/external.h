/* $OpenLDAP$ */
#ifndef _SHELL_EXTERNAL_H
#define _SHELL_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	shell_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	shell_back_open LDAP_P(( BackendInfo *bi ));
extern int	shell_back_close LDAP_P(( BackendInfo *bi ));
extern int	shell_back_destroy LDAP_P(( BackendInfo *bi ));

extern int	shell_back_db_init LDAP_P(( BackendDB *bd ));
extern int	shell_back_db_destroy LDAP_P(( BackendDB *bd ));

extern int	shell_back_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

extern int shell_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	shell_back_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int	shell_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *base,
	char *nbase, int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

extern int	shell_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Ava 	*ava ));

extern int	shell_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, LDAPModList *ml ));

extern int	shell_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, char*newrdn, int deleteoldrdn,
        char *newSuperior ));

extern int	shell_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	shell_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn, char *ndn ));

extern int	shell_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

LDAP_END_DECL

#endif /* _SHELL_EXTERNAL_H */

