/* unbind.c - handle an ldap unbind operation */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/socket.h>

#include "slap.h"

void
ldbm_back_unbind(
	Backend     *be,
	Connection  *conn,
	Operation   *op
)
{
}
