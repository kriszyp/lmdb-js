/* config.c - DNS SRV backend configuration file routine */
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
#include "external.h"

int
dnssrv_back_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	char *port;

	if ( li == NULL ) {
		fprintf( stderr, "%s: line %d: DNSSRV backend info is null!\n",
		    fname, lineno );
		return( 1 );
	}

	/* no configuration options (yet) */
	{
		fprintf( stderr,
"%s: line %d: unknown directive \"%s\" in DNSSRV database definition (ignored)\n",
		    fname, lineno, argv[0] );
	}
	return 0;
}
