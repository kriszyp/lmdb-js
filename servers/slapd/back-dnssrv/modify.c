/* modify.c - DNS SRV backend modify function */
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
dnssrv_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
    LDAPModList	*ml
)
{
	return -1;
}
