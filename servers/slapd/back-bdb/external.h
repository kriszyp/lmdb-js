/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _BDB_EXTERNAL_H
#define _BDB_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	bdb_initialize LDAP_P(( BackendInfo *bi ));

extern int	bdb_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno,
	int argc, char **argv ));

extern int	bdb_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int bdb_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, int method,
	struct berval *cred, char** edn ));

extern int	bdb_compare LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	AttributeAssertion *ava ));

extern int	bdb_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn ));

extern int	bdb_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, ber_int_t msgid ));

extern int	bdb_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, Modifications *ml ));

extern int	bdb_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	const char* newrdn, int deleteoldrdn,
	const char *newSuperior ));

extern int	bdb_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *base, const char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, const char *filterstr,
	char **attrs, int attrsonly ));

extern int	bdb_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int bdb_referrals(
    BackendDB	*be,
    Connection	*conn,
    Operation	*op,
    const char *dn,
    const char *ndn,
	const char **text );

LDAP_END_DECL

#endif /* _BDB_EXTERNAL_H */

