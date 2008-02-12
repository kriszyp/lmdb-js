/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This program was orignally developed by Kurt D. Zeilenga for inclusion in
 * OpenLDAP Software.
 */

#include "portable.h"

#include <ac/stdlib.h>

#include <ac/time.h>
#include <ac/string.h>

#include "ldap-int.h"

#ifdef LDAP_GROUP_TRANSACTION

int
ldap_txn_create_s(
	LDAP *ld,
	struct berval	**cookie,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls )
{
	return LDAP_NOT_SUPPORTED;
}

int
ldap_txn_end_s(
	LDAP *ld,
	struct berval	*cookie,
	int				commit,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls )
{
	return LDAP_NOT_SUPPORTED;
}

#endif
