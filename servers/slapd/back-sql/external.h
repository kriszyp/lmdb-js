/* $OpenLDAP$ */
#ifndef _SQL_EXTERNAL_H
#define _SQL_EXTERNAL_H

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */


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
	const char *dn, const char *ndn, int method,
	struct berval *cred, char** edn ));

extern int	backsql_unbind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op ));

extern int	backsql_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *base, const char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, const char *filterstr,
	char **attrs, int attrsonly ));

extern int	backsql_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	AttributeAssertion *ava ));

extern int	backsql_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	Modifications *ml ));

extern int	backsql_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	const char *newrdn, int deleteoldrdn,
	const char *newSuperior ));

extern int	backsql_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	backsql_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn ));

extern int	backsql_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, int msgid ));

extern int	backsql_connection_destroy LDAP_P(( BackendDB *bd,
	Connection *conn));

LDAP_END_DECL

#endif /* _SQL_EXTERNAL_H */

