/* $OpenLDAP$ */
#ifndef _SQL_EXTERNAL_H
#define _SQL_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	sql_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	backsql_destroy LDAP_P(( BackendInfo *bi ));

extern int	backsql_db_init LDAP_P(( BackendDB *bd ));
extern int	backsql_db_open LDAP_P(( BackendDB *bd ));
extern int	backsql_db_close LDAP_P(( BackendDB *bd ));
extern int	backsql_db_destroy LDAP_P(( BackendDB *bd ));

extern int	backsql_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

extern int backsql_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	backsql_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int	backsql_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *base,
	char *nbase, int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

extern int	backsql_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Ava 	*ava ));

extern int	backsql_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, LDAPModList *ml ));

extern int	backsql_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, char*newrdn, int deleteoldrdn,
        char *newSuperior ));

extern int	backsql_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	backsql_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn, char *ndn ));

extern int	backsql_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

LDAP_END_DECL

#endif /* _SQL_EXTERNAL_H */

