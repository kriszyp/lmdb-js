/* bind.c - DNS SRV backend bind function */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-dnssrv.h"

int
dnssrv_back_bind(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    char		*dn,
    char		*ndn,
    int			method,
	char		*mech,
    struct berval	*cred,
	char		**edn
)
{
	return( -1 );
}
