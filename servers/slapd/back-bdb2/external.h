/* $OpenLDAP$ */
#ifndef _BDB2_EXTERNAL_H
#define _BDB2_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	bdb2_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_open LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_close LDAP_P(( BackendInfo *bi ));
extern int	bdb2_back_destroy LDAP_P(( BackendInfo *bi ));

extern int	bdb2_back_config LDAP_P(( BackendInfo *bt,
	const char *fname, int lineno, int argc, char **argv ));

extern int	bdb2_back_db_init LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_open LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_close LDAP_P(( BackendDB *bd ));
extern int	bdb2_back_db_destroy LDAP_P(( BackendDB *bd ));

extern int	bdb2_back_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

extern int bdb2_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	bdb2_back_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int	bdb2_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *base,
	char *nbase, int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

extern int	bdb2_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Ava 	*ava ));

extern int	bdb2_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Modifications *ml ));

extern int	bdb2_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, char*newrdn, int deleteoldrdn,
	char *newSuperior ));

extern int	bdb2_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	bdb2_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn, char *ndn ));

extern int	bdb2_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

extern int	bdb2_back_group LDAP_P(( BackendDB *bd,
	Entry *target, const char* gr_ndn, const char* op_ndn,
	const char* objectclassValue, const char* groupattrName));

/* hooks for slap tools */
extern int bdb2_tool_entry_open LDAP_P(( BackendDB *be, int mode ));
extern int bdb2_tool_entry_close LDAP_P(( BackendDB *be ));
extern ID bdb2_tool_entry_first LDAP_P(( BackendDB *be ));
extern ID bdb2_tool_entry_next LDAP_P(( BackendDB *be ));
extern Entry* bdb2_tool_entry_get LDAP_P(( BackendDB *be, ID id ));
extern ID bdb2_tool_entry_put LDAP_P(( BackendDB *be, Entry *e ));
extern int bdb2_tool_index_attr LDAP_P(( BackendDB *be, char* type ));
extern int bdb2_tool_index_change LDAP_P(( BackendDB *be, char* type,
	struct berval **bv, ID id, int op ));
extern int bdb2_tool_sync LDAP_P(( BackendDB *be ));

LDAP_END_DECL

#endif /* _BDB2_EXTERNAL_H */

