/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
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
 * This work was initially developed by Kurt Zeilenga for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap.h>
#include <lutil.h>
#include <lutil_sha1.h>

#include "ldap_defaults.h"

static int	verbose = 0;

static void
usage(const char *s)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  -h hash\tpassword scheme\n"
		"  -s secret\tnew password\n"
		"  -c format\tcrypt(3) salt format\n"
		"  -u\t\tgenerate RFC2307 values (default)\n"
		"  -v\t\tincrease verbosity\n"
		"  -T file\tread file for new password\n"
		, s );

	exit( EXIT_FAILURE );
}

int
slappasswd( int argc, char *argv[] )
{
#ifdef LUTIL_SHA1_BYTES
	char	*scheme = "{SSHA}";
#else
	char	*scheme = "{SMD5}";
#endif

	char	*newpw = NULL;
	char	*pwfile = NULL;
	const char *text;
	const char *progname = "slappasswd";

	int		i;
	struct berval passwd;
	struct berval hash;

	while( (i = getopt( argc, argv,
		"c:d:h:s:T:vu" )) != EOF )
	{
		switch (i) {
		case 'c':	/* crypt salt format */
			scheme = "{CRYPT}";
			lutil_salt_format( optarg );
			break;

		case 'h':	/* scheme */
			scheme = strdup( optarg );
			break;

		case 's':	/* new password (secret) */
			{
				char* p;
				newpw = strdup( optarg );

				for( p = optarg; *p != '\0'; p++ ) {
					*p = '\0';
				}
			} break;

		case 'T':	/* password file */
			pwfile = optarg;
			break;

		case 'u':	/* RFC2307 userPassword */
			break;

		case 'v':	/* verbose */
			verbose++;
			break;

		default:
			usage ( progname );
		}
	}

	if( argc - optind != 0 ) {
		usage( progname );
	} 

	if( pwfile != NULL ) {
		if( lutil_get_filed_password( pwfile, &passwd )) {
			return EXIT_FAILURE;
		}
	} else {
		if( newpw == NULL ) {
			/* prompt for new password */
			char *cknewpw;
			newpw = strdup(getpassphrase("New password: "));
			cknewpw = getpassphrase("Re-enter new password: ");
	
			if( strcmp( newpw, cknewpw )) {
				fprintf( stderr, "Password values do not match\n" );
				return EXIT_FAILURE;
			}
		}

		passwd.bv_val = newpw;
		passwd.bv_len = strlen(passwd.bv_val);
	}

	lutil_passwd_hash( &passwd, scheme, &hash, &text );
	if( hash.bv_val == NULL ) {
		fprintf( stderr,
			"Password generation failed for scheme %s: %s\n",
			scheme, text ? text : "" );
		return EXIT_FAILURE;
	}

	if( lutil_passwd( &hash, &passwd, NULL, &text ) ) {
		fprintf( stderr, "Password verification failed. %s\n",
			text ? text : "" );
		return EXIT_FAILURE;
	}

	printf( "%s\n" , hash.bv_val );
	return EXIT_SUCCESS;
}
