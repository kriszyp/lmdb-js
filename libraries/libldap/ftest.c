/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* OpenLDAP Filter API Test */

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <stdio.h>

#include <ldap.h>

#include "ldap-int.h"

#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

static int filter2ber( const char *filter );

int usage()
{
	fprintf( stderr, "usage:\n"
		"	ftest [filter]" );
	return EXIT_FAILURE;
}

int
main( int argc, char *argv[] )
{
	int i, debug=0, ber=0;
	char *filter=NULL;

    while( (i = getopt( argc, argv, "Aa:Ss:"
        "bd:" )) != EOF )
    {
		switch ( i ) {
		case 'b':
			ber++;
			break;
		case 'd':
			debug = atoi( optarg );
			break;
		default:
			fprintf( stderr, "ftest: unrecognized option -%c\n",
				optopt );
			return usage();
		}
	}

	if ( debug ) {
		if ( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug )
			!= LBER_OPT_SUCCESS )
		{
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n",
				debug );
		}
		if ( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug )
			!= LDAP_OPT_SUCCESS )
		{
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n",
				debug );
		}
	}

	if( argc - optind > 1 ) {
		return usage();
	} else if ( argc - optind == 1 ) {
		if( ber ) {
			fprintf( stderr, "ftest: parameter %s unexpected\n",
				argv[optind] );
			return usage();
		}
		return filter2ber( argv[optind] );
	}

	return EXIT_FAILURE;
}

static int filter2ber( const char *filter )
{
	int rc;
	BerElement *ber = ber_alloc_t( LBER_USE_DER );
	struct berval *bv = NULL;

	if( ber == NULL ) {
		perror( "ber_alloc_t" );
		return EXIT_FAILURE;
	}

	rc = ldap_int_put_filter( ber, (char *) filter );

	ber_dump( ber, 0 );

	rc = ber_flatten( ber, &bv );

	if( rc < 0 ) {
		perror( "ber_flatten" );
		return EXIT_FAILURE;
	}

	ber_free( ber, 1 );
	ber_bvfree( bv );

	return EXIT_SUCCESS;
}