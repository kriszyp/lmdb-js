/* add.c - DNS SRV backend request handler */
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
dnssrv_back_request(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char *dn,
    const char *ndn )
{
	return -1;
}
