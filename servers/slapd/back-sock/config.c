/* config.c - sock backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2007 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Brian Candler for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-sock.h"

int
sock_back_db_config(
    BackendDB	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	struct sockinfo	*si = (struct sockinfo *) be->be_private;

	if ( si == NULL ) {
		fprintf( stderr, "%s: line %d: sock backend info is null!\n",
		    fname, lineno );
		return( 1 );
	}

	/* socketpath */
	if ( strcasecmp( argv[0], "socketpath" ) == 0 ) {
		if ( argc != 2 ) {
			fprintf( stderr,
	"%s: line %d: exactly one parameter needed for \"socketpath\"\n",
			    fname, lineno );
			return( 1 );
		}
		si->si_sockpath = ch_strdup( argv[1] );

	/* extensions */
	} else if ( strcasecmp( argv[0], "extensions" ) == 0 ) {
		int i;
		for ( i=1; i<argc; i++ ) {
			if ( strcasecmp( argv[i], "binddn" ) == 0 )
				si->si_extensions |= SOCK_EXT_BINDDN;
			else if ( strcasecmp( argv[i], "peername" ) == 0 )
				si->si_extensions |= SOCK_EXT_PEERNAME;
			else if ( strcasecmp( argv[i], "ssf" ) == 0 )
				si->si_extensions |= SOCK_EXT_SSF;
			else {
				fprintf( stderr,
	"%s: line %d: unknown extension \"%s\"\n",
			    fname, lineno, argv[i] );
				return( 1 );
			}
		}

	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}
