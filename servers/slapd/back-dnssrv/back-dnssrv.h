/* $OpenLDAP$ */
/*
 *   Copyright 2000, OpenLDAP Foundation, All rights reserved.
 *
 *   Redistribution and use in source and binary forms are permitted only
 *   as authorized by the OpenLDAP Public License.  A copy of this
 *   license is available at http://www.OpenLDAP.org/license.html or
 *   in file LICENSE in the top-level directory of the distribution.
 */

#ifndef DNSSRV_BACK_H
#define DNSSRV_BACK_H 1

#include "external.h"

LDAP_BEGIN_DECL

int dnssrv_result();
	
extern int dnssrv_back_request LDAP_P((
	BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	int scope, Filter *filter,
	char **attrs, int attrsonly ));

LDAP_END_DECL

#endif /* DNSSRV_BACK_H */
