/* ldapwhoami.c -- a tool for asking the directory "Who Am I?" */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
 * Portions Copyright 1998-2001 Net Boolean Incorporated.
 * Portions Copyright 2001-2003 IBM Corporation.
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
/* Portions Copyright (c) 1992-1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.  This
 * software is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by Kurt D. Zeilenga for inclusion
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
	fprintf( stderr, _("Issue LDAP Who am I? operation to request user's authzid\n\n"));
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
#if 0
		char	*control, *cvalue;
		int		crit;
	case 'E': /* whoami extension */
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

		fprintf( stderr, _("Invalid whoami extension name: %s\n"), control );
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

	if ( assertion || authzid || manageDSAit || noop ) {
		tool_server_controls( ld, NULL, 0 );
	}

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
