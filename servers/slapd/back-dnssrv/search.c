/* search.c - DNS SRV backend search function */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */


#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "back-dnssrv.h"

int
dnssrv_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*dn,
    char	*ndn,
    int		scope,
    int		deref,
    int		size,
    int		time,
    Filter	*filter,
    char	*filterstr,
    char	**attrs,
    int		attrsonly
)
{
	return dnssrv_back_request( be, conn, op, dn, ndn );
}
