/* error.c - BDB errcall routine */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb.h"

void bdb_errcall( const char *pfx, char * msg )
{
#ifdef NEW_LOGGING
	LDAP_LOG ( OPERATION, INFO, "bdb(%s): %s\n", pfx, msg, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "bdb(%s): %s\n", pfx, msg, 0 );
#endif
}
