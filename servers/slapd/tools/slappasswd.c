/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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

#include "ldap_defaults.h"

static int	verbose = 0;

static void
usage(const char *s)
{
	fprintf(stderr,
		"Usage: %s [options]\n"
		"  -h hash\tpassword scheme\n"
		"  -s secret\tnew password\n"
		"  -u\t\tgenerate RFC2307 values (default)\n"
		"  -v\t\tincrease verbosity\n"
		, s );

	exit( EXIT_FAILURE );
}

int
main( int argc, char *argv[] )
{
	int rc;
	char	*scheme = "{SSHA}";
	char	*newpw = NULL;

	int		i;
	int		version = -1;
	struct berval passwd;
	struct berval *hash = NULL;

	while( (i = getopt( argc, argv,
		"d:h:s:vu" )) != EOF )
	{
		switch (i) {
		case 'h':	/* scheme */
			scheme = strdup (optarg);
			break;

		case 's':	/* new password (secret) */
			newpw = strdup (optarg);

			{
				char* p;

				for( p = optarg; *p != '\0'; p++ ) {
					*p = '\0';
				}
			}
			break;

		case 'u':	/* RFC2307 userPassword */
			break;

		case 'v':	/* verbose */
			verbose++;
			break;

		default:
			usage (argv[0]);
		}
	}

	if( argc - optind != 0 ) {
		usage( argv[0] );
	} 

	if( newpw == NULL ) {
		/* prompt for new password */
		char *cknewpw;
		newpw = strdup(getpassphrase("New password: "));
		cknewpw = getpassphrase("Re-enter new password: ");

		if( strncmp( newpw, cknewpw, strlen(newpw) )) {
			fprintf( stderr, "Password values do not match\n" );
			return EXIT_FAILURE;
		}
	}

	passwd.bv_val = newpw;
	passwd.bv_len = strlen(passwd.bv_val);

	hash = lutil_passwd_hash( &passwd, scheme );

	if( hash == NULL || hash->bv_val == NULL ) {
		fprintf( stderr, "Password generation failed.\n");
		return EXIT_FAILURE;
	}

	if( lutil_passwd( hash, &passwd, NULL ) ) {
		fprintf( stderr, "Password verification failed.\n");
		return EXIT_FAILURE;
	}

	printf( "%s\n" , hash->bv_val );
	return EXIT_SUCCESS;
}
