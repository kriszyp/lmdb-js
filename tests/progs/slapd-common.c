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
tester_ldap_error( LDAP *ld, const char *fname, const char *msg )
{
	int		err;
	char		*text = NULL;
	LDAPControl	**ctrls = NULL;

	ldap_get_option( ld, LDAP_OPT_RESULT_CODE, (void *)&err );
	if ( err != LDAP_SUCCESS ) {
		ldap_get_option( ld, LDAP_OPT_ERROR_STRING, (void *)&text );
	}

	fprintf( stderr, "%s: %s: %s (%d) %s %s\n",
		progname, fname, ldap_err2string( err ), err,
		text == NULL ? "" : text,
		msg ? msg : "" );

	if ( text ) {
		ldap_memfree( text );
		text = NULL;
	}

	ldap_get_option( ld, LDAP_OPT_MATCHED_DN, (void *)&text );
	if ( text != NULL ) {
		if ( text[ 0 ] != '\0' ) {
			fprintf( stderr, "\tmatched: %s\n", text );
		}
		ldap_memfree( text );
		text = NULL;
	}

	ldap_get_option( ld, LDAP_OPT_SERVER_CONTROLS, (void *)&ctrls );
	if ( ctrls != NULL ) {
		int	i;

		fprintf( stderr, "\tcontrols:\n" );
		for ( i = 0; ctrls[ i ] != NULL; i++ ) {
			fprintf( stderr, "\t\t%s\n", ctrls[ i ]->ldctl_oid );
		}
		ldap_controls_free( ctrls );
		ctrls = NULL;
	}

	if ( err == LDAP_REFERRAL ) {
		char **refs = NULL;

		ldap_get_option( ld, LDAP_OPT_REFERRAL_URLS, (void *)&refs );

		if ( refs ) {
			int	i;

			fprintf( stderr, "\treferral:\n" );
			for ( i = 0; refs[ i ] != NULL; i++ ) {
				fprintf( stderr, "\t\t%s\n", refs[ i ] );
			}

			ber_memvfree( (void **)refs );
		}
	}
}

void
tester_perror( const char *fname, const char *msg )
{
	int	save_errno = errno;
	char	buf[ BUFSIZ ];

	fprintf( stderr, "%s: %s: (%d) %s %s\n",
			progname, fname, save_errno,
			AC_STRERROR_R( save_errno, buf, sizeof( buf ) ),
			msg ? msg : "" );
}

void
tester_error( const char *msg )
{
	fprintf( stderr, "%s: %s\n", progname, msg );
}

