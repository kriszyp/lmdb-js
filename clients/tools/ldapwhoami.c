/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
	fprintf( stderr, _("Issue LDAP Who am I? operation to request user's authzid\n\n"));
	fprintf( stderr, _("usage: %s [options]\n"), prog);
	tool_common_usage();
	exit( EXIT_FAILURE );
}


const char options[] = ""
	"Cd:D:e:h:H:InO:p:QR:U:vVw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	switch ( i ) {
#if 0
		char	*control, *cvalue;
		int		crit;
	case 'E': /* whoami controls */
		if( protocol == LDAP_VERSION2 ) {
			fprintf( stderr, _("%s: -E incompatible with LDAPv%d\n"),
				prog, protocol );
			exit( EXIT_FAILURE );
		}

		/* should be extended to support comma separated list of
		 *	[!]key[=value] parameters, e.g.  -E !foo,bar=567
		 */

		crit = 0;
		cvalue = NULL;
		if( optarg[0] == '!' ) {
			crit = 1;
			optarg++;
		}

		control = strdup( optarg );
		if ( (cvalue = strchr( control, '=' )) != NULL ) {
			*cvalue++ = '\0';
		}
		fprintf( stderr, _("Invalid whoami control name: %s\n"), control );
		usage();
#endif

	default:
		return 0;
	}
	return 1;
}


int
main( int argc, char *argv[] )
{
	int rc;
	char	*user = NULL;

	LDAP	       *ld = NULL;

	char *matcheddn = NULL, *text = NULL, **refs = NULL;
	char	*retoid = NULL;
	struct berval *retdata = NULL;

    tool_init();
	prog = lutil_progname( "ldapwhoami", argc, argv );

	/* LDAPv3 only */
	protocol = LDAP_VERSION3;

	tool_args( argc, argv );

	if( argc - optind > 1 ) {
		usage();
	} else if ( argc - optind == 1 ) {
		user = strdup( argv[optind] );
	} else {
		user = NULL;
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

	if ( not ) {
		rc = LDAP_SUCCESS;
		goto skip;
	}

	if ( authzid || manageDSAit || noop )
		tool_server_controls( ld, NULL, 0 );

	rc = ldap_whoami_s( ld, &retdata, NULL, NULL ); 

	if( retdata != NULL ) {
		if( retdata->bv_len == 0 ) {
			printf(_("anonymous\n") );
		} else {
			printf("%s\n", retdata->bv_val );
		}
	}

	if( verbose || ( rc != LDAP_SUCCESS ) || matcheddn || text || refs ) {
		printf( _("Result: %s (%d)\n"), ldap_err2string( rc ), rc );

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
	ber_memfree( retoid );
	ber_bvfree( retdata );

skip:
	/* disconnect from server */
	ldap_unbind (ld);

	return rc == LDAP_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
