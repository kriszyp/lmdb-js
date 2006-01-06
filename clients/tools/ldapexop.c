/* ldapexop.c -- a tool for performing well-known extended operations */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005 The OpenLDAP Foundation.
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
 * This work was originally developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software based, in part, on other client tools.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include <ldap.h>
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

#include "common.h"


void
usage( void )
{
	fprintf( stderr, _("Issue LDAP extended operations\n\n"));
	fprintf( stderr, _("usage: %s [options]\n"), prog);
	tool_common_usage();
	exit( EXIT_FAILURE );
}


const char options[] = ""
	"d:D:e:h:H:InO:p:QR:U:vVw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	switch ( i ) {
	default:
		return 0;
	}
	return 1;
}


int
main( int argc, char *argv[] )
{
	int		rc;
	char		*user = NULL;

	LDAP		*ld = NULL;

	char		*matcheddn = NULL, *text = NULL, **refs = NULL;
	int		id, code;
	LDAPMessage	*res;

	tool_init();
	prog = lutil_progname( "ldapexop", argc, argv );

	/* LDAPv3 only */
	protocol = LDAP_VERSION3;

	tool_args( argc, argv );

	if ( argc - optind < 1 ) {
		usage();
	}

	if ( pw_file || want_bindpw ) {
		if ( pw_file ) {
			rc = lutil_get_filed_password( pw_file, &passwd );
			if( rc ) return EXIT_FAILURE;
		} else {
			passwd.bv_val = getpassphrase( _("Enter LDAP Password: ") );
			passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
		}
	}

	ld = tool_conn_setup( 0, 0 );

	tool_bind( ld );

	argv += optind;
	argc -= optind;

	if ( strcasecmp( argv[ 0 ], "whoami" ) == 0 ) {
		switch ( argc ) {
		case 2:
			user = argv[ 1 ];

		case 1:
			break;

		default:
			fprintf( stderr, "need [user]\n\n" );
			usage();
		}

		if ( assertion || manageDSAit || noop ) {
			fprintf( stderr, _("controls incompatible with WhoAmI exop\n\n") );
			usage();
		}

		if ( authzid ) {
			tool_server_controls( ld, NULL, 0 );
		}

		rc = ldap_whoami( ld, NULL, NULL, &id ); 
		if ( rc != LDAP_SUCCESS ) {
			tool_perror( "ldap_extended_operation", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

	} else if ( strcasecmp( argv[ 0 ], "cancel" ) == 0 ) {
		int		cancelid;

		switch ( argc ) {
		case 2:
			 if ( lutil_atoi( &cancelid, argv[ 1 ] ) != 0 || cancelid < 0 ) {
				fprintf( stderr, "invalid cancelid=%s\n\n", argv[ 1 ] );
				usage();
			}
			break;

		default:
			fprintf( stderr, "need cancelid\n\n" );
			usage();
		}

		rc = ldap_cancel( ld, cancelid, NULL, NULL, &id );
		if ( rc != LDAP_SUCCESS ) {
			tool_perror( "ldap_cancel", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

	} else if ( strcasecmp( argv[ 0 ], "passwd" ) == 0 ) {
		/* do we need this? */

	} else if ( strcasecmp( argv[ 0 ], "refresh" ) == 0 ) {
		int		ttl = 3600;
		struct berval	dn;

		switch ( argc ) {
		case 3:
			ttl = atoi( argv[ 2 ] );

		case 2:
			dn.bv_val = argv[ 1 ];
			dn.bv_len = strlen( dn.bv_val );

		case 1:
			break;

		default:
			fprintf( stderr, _("need DN [ttl]\n\n") );
			usage();
		}
		
		if ( assertion || manageDSAit || noop || authzid ) {
			tool_server_controls( ld, NULL, 0 );
		}

		rc = ldap_refresh( ld, &dn, ttl, NULL, NULL, &id ); 
		if ( rc != LDAP_SUCCESS ) {
			tool_perror( "ldap_extended_operation", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

	} else if ( tool_is_oid( argv[ 0 ] ) ) {
		
	} else {
		fprintf( stderr, "unknown exop \"%s\"\n\n", argv[ 0 ] );
		usage();
	}

	for ( ; ; ) {
		struct timeval	tv;

		if ( tool_check_abandon( ld, id ) ) {
			return LDAP_CANCELLED;
		}

		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ALL, &tv, &res );
		if ( rc < 0 ) {
			tool_perror( "ldap_result", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

		if ( rc != 0 ) {
			break;
		}
	}

	rc = ldap_parse_result( ld, res,
		&code, &matcheddn, &text, &refs, NULL, 0 );
	if ( rc == LDAP_SUCCESS ) {
		rc = code;
	}

	if ( rc != LDAP_SUCCESS ) {
		tool_perror( "ldap_parse_result", rc, NULL, matcheddn, text, refs );
		rc = EXIT_FAILURE;
		goto skip;
	}

	if ( strcasecmp( argv[ 0 ], "whoami" ) == 0 ) {
		char		*retoid = NULL;
		struct berval	*retdata = NULL;

		rc = ldap_parse_extended_result( ld, res, &retoid, &retdata, 1 );

		if ( rc != LDAP_SUCCESS ) {
			tool_perror( "ldap_parse_extended_result", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

		if ( retdata != NULL ) {
			if ( retdata->bv_len == 0 ) {
				printf(_("anonymous\n") );
			} else {
				printf("%s\n", retdata->bv_val );
			}
		}

		ber_memfree( retoid );
		ber_bvfree( retdata );

	} else if ( strcasecmp( argv[ 0 ], "cancel" ) == 0 ) {
		/* no extended response; returns specific errors */
		assert( 0 );

	} else if ( strcasecmp( argv[ 0 ], "passwd" ) == 0 ) {

	} else if ( strcasecmp( argv[ 0 ], "refresh" ) == 0 ) {
		int	newttl;

		rc = ldap_parse_refresh( ld, res, &newttl );

		if ( rc != LDAP_SUCCESS ) {
			tool_perror( "ldap_parse_refresh", rc, NULL, NULL, NULL, NULL );
			rc = EXIT_FAILURE;
			goto skip;
		}

		printf( "newttl=%d\n", newttl );

	} else if ( tool_is_oid( argv[ 0 ] ) ) {
		/* ... */
	}

	if( verbose || ( code != LDAP_SUCCESS ) || matcheddn || text || refs ) {
		printf( _("Result: %s (%d)\n"), ldap_err2string( code ), code );

		if( text && *text ) {
			printf( _("Additional info: %s\n"), text );
		}

		if( matcheddn && *matcheddn ) {
			printf( _("Matched DN: %s\n"), matcheddn );
		}

		if( refs ) {
			int i;
			for( i=0; refs[i]; i++ ) {
				printf(_("Referral: %s\n"), refs[i] );
			}
		}
	}

	ber_memfree( text );
	ber_memfree( matcheddn );
	ber_memvfree( (void **) refs );

skip:
	/* disconnect from server */
	tool_unbind( ld );
	tool_destroy();

	return code == LDAP_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
