/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

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
	const char *dn, const char *ndn, int method,
	struct berval *cred, char** edn ));

extern int	ldap_back_conn_destroy LDAP_P(( BackendDB *bd,
	Connection *conn ));

extern int	ldap_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *base, const char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, const char *filterstr,
	char **attrs, int attrsonly ));

extern int	ldap_back_compare LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	AttributeAssertion *ava ));

extern int	ldap_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, Modifications *ml ));

extern int	ldap_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	const char *newrdn, int deleteoldrdn,
	const char *newSuperior ));

extern int	ldap_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	ldap_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn ));

extern int	ldap_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

extern int	ldap_back_group LDAP_P(( BackendDB *bd,
	Connection *conn,
	Operation *op,
	Entry *target,
	const char* gr_ndn,
	const char* op_ndn,
	ObjectClass* group_oc,
	AttributeDescription* group_at));

extern int	ldap_back_attribute LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	Entry *target,
	const char* e_ndn,
	AttributeDescription* entry_at,
	struct berval ***vals));

LDAP_END_DECL

#endif /* _LDAP_EXTERNAL_H */

