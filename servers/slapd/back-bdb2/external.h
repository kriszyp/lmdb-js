#ifndef _BDB2_EXTERNAL_H
#define _BDB2_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	bdb2_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_open LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_close LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_destroy LDAP_P(( BackendInfo *bi ));

extern int	bdb2_back_config LDAP_P(( BackendInfo *bt,
	char *fname, int lineno, int argc, char **argv ));

extern int	bdb2_back_db_init LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_open LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_close LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_destroy LDAP_P(( BackendDB *bd ));

extern int	bdb2_back_db_config LDAP_P(( BackendDB *bd,
	char *fname, int lineno, int argc, char **argv ));

extern int bdb2_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	bdb2_back_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int	bdb2_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *base, int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

extern int	bdb2_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, Ava 	*ava ));

extern int	bdb2_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, LDAPModList *ml ));

extern int	bdb2_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char*newrdn, int deleteoldrdn,
	char *newSuperior ));

extern int	bdb2_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	bdb2_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn ));

extern int	bdb2_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

extern int	bdb2_back_group LDAP_P(( BackendDB *bd,
	Entry *target, char* gr_ndn, char* op_ndn,
	char* objectclassValue, char* groupattrName));

LDAP_END_DECL

#endif /* _BDB2_EXTERNAL_H */

