/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

int
ldap_extended_operation(
	LDAP			*ld,
	LDAP_CONST char	*exoid,
	struct berval	*exdata,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	int				*msgidp )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_extended_operation\n", 0, 0, 0 );
	return LDAP_NOT_SUPPORTED;
}

int
ldap_extended_operation_s(
	LDAP			*ld,
	LDAP_CONST char	*exoid,
	struct berval	*exdata,
	LDAPControl		**sctrls,
	LDAPControl		**cctrls,
	char			**retoidp,
	struct berval	**retdatap )
{
	Debug( LDAP_DEBUG_TRACE, "ldap_extended_operation_s\n", 0, 0, 0 );
	return LDAP_NOT_SUPPORTED;
}

