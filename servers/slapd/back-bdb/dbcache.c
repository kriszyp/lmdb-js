/* dbcache.c - manage cache of open databases */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <sys/stat.h>

#include "slap.h"
#include "back-bdb.h"

int
bdb_db_cache(
    Backend	*be,
    const char *name,
	DB *db )
{
	return -1;
}
