/* $OpenLDAP$ */
/*
 *	 Copyright 2000, OpenLDAP Foundation, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */
#ifndef _DNSSRV_EXTERNAL_H
#define _DNSSRV_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	dnssrv_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	dnssrv_back_open LDAP_P(( BackendInfo *bi ));
extern int	dnssrv_back_close LDAP_P(( BackendInfo *bi ));
extern int	dnssrv_back_destroy LDAP_P(( BackendInfo *bi ));

extern int	dnssrv_back_db_init LDAP_P(( BackendDB *bd ));
extern int	dnssrv_back_db_destroy LDAP_P(( BackendDB *bd ));

extern int	dnssrv_back_db_config LDAP_P(( BackendDB *bd,
	const char *fname, int lineno, int argc, char **argv ));

extern int dnssrv_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, int method, char* mech,
	struct berval *cred, char** edn ));

extern int	dnssrv_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *base,
	char *nbase, int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, char *filterstr, char **attrs, int attrsonly ));

#ifdef SLAPD_SCHEMA_NOT_COMPAT
extern int	dnssrv_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, AttributeAssertion *ava ));
#else
extern int	dnssrv_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Ava *ava ));
#endif

extern int	dnssrv_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, Modifications *ml ));

extern int	dnssrv_back_modrdn LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	char *dn, char *ndn, char*newrdn, int deleteoldrdn,
	char *newSuperior ));

extern int	dnssrv_back_add LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, Entry *e ));

extern int	dnssrv_back_delete LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, char *dn, char *ndn ));

LDAP_END_DECL

#endif /* _DNSSRV_EXTERNAL_H */

