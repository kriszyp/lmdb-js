/* delete.c - DNS SRV backend delete function */
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
dnssrv_back_delete(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    const char	*ndn
)
{
	return dnssrv_back_request( be, conn, op, dn, ndn,
		0, NULL, NULL, 0 );
}
