/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004 The OpenLDAP Foundation.
 * Portions Copyright 2004 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldif.h>
#include <lutil.h>

#include "slapcommon.h"

int
slaptest( int argc, char **argv )
{
	int			rc = EXIT_SUCCESS;
	const char		*progname = "slaptest";

#ifdef NEW_LOGGING
	lutil_log_initialize( argc, argv );
#endif
	slap_tool_init( progname, SLAPTEST, argc, argv );

	fprintf( stderr, "config file testing succeeded\n");

	slap_tool_destroy();

	return rc;
}
