/* compare.c - DNS SRV backend compare function */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-dnssrv.h"

int
dnssrv_back_compare(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeAssertion *ava
#else
    Ava		*ava
#endif
)
{
	return dnssrv_back_request( be, conn, op, dn, ndn );
}
