/* add.c - DNS SRV backend add function */
/* $OpenLDAP$ */
/*
 * Copyright 2000-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-dnssrv.h"

int
dnssrv_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	return dnssrv_back_request( be, conn, op, e->e_dn, e->e_ndn );
}
