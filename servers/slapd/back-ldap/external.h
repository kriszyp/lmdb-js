/* $OpenLDAP$ */
#ifndef _LDAP_EXTERNAL_H
#define _LDAP_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	ldap_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	ldap_back_open LDAP_P(( BackendInfo *bi ));
extern int	ldap_back_close LDAP_P(( BackendInfo *bi ));
extern int	ldap_back_destroy LDAP_P(( BackendInfo *bi ));

extern int	ldap_back_db_init LDAP_P(( BackendDB *bd ));
extern int	ldap_back_db_destroy LDAP_P(( BackendDB *bd ));

extern int	ldap_back_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

extern int ldap_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	ldap_back_conn_destroy LDAP_P(( BackendDB *bd,
	Connection *conn ));

extern int	ldap_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *base, char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

extern int	ldap_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Ava 	*ava ));

extern int	ldap_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, LDAPModList *ml ));

extern int	ldap_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, char*newrdn, int deleteoldrdn,
        char *newSuperior ));

extern int	ldap_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	ldap_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn, char *ndn ));

extern int	ldap_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

LDAP_END_DECL

#endif /* _LDAP_EXTERNAL_H */

