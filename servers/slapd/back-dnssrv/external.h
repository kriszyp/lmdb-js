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
	const char *dn, const char *ndn, int method,
	struct berval *cred, char** edn ));

extern int	dnssrv_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *base, const char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, const char *filterstr,
	char **attrs, int attrsonly ));

extern int	dnssrv_back_compare LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, AttributeAssertion *ava ));

extern int	dnssrv_back_referrals LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	const char **text ));

LDAP_END_DECL

#endif /* _DNSSRV_EXTERNAL_H */

