/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/unistd.h>
#include <ac/string.h>
#include <ac/errno.h>

#include <ldap.h>

static char progname[ BUFSIZ ];

void
tester_init( const char *pname )
{
	snprintf( progname, sizeof( progname ), "%s PID=%d", pname, getpid() );
}

char *
tester_uri( char *uri, char *host, int port )
{
	static char	uribuf[ BUFSIZ ];

	if ( uri != NULL ) {
		return uri;
	}

	snprintf( uribuf, sizeof( uribuf ), "ldap://%s:%d", host, port );

	return uribuf;
}

void
tester_ldap_error( LDAP *ld, const char *fname )
{
	int err;
	const char *text = "Success";

	ldap_get_option( ld, LDAP_OPT_RESULT_CODE, (void *)&err );
	if ( err != LDAP_SUCCESS ) {
		ldap_get_option( ld, LDAP_OPT_ERROR_STRING, (void *)&text );
	}

	fprintf( stderr, "%s: %s: (%d) %s\n",
			progname, fname, err, text == NULL ? "" : text );
}

void
tester_perror( const char *fname )
{
	int	save_errno = errno;
	char	buf[ BUFSIZ ];

	fprintf( stderr, "%s: %s: (%d) %s\n",
			progname, fname, save_errno,
			AC_STRERROR_R( save_errno, buf, sizeof( buf ) ) );
}

