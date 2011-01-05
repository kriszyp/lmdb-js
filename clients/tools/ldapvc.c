/* ldapvc.c -- a tool for verifying credentials */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2011 The OpenLDAP Foundation.
 * Portions Copyright 2010 Kurt D. Zeilenga.
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

static int req_authzid = 0;
static int req_pp = 0;

static char * mech = NULL;
static char * dn = NULL;
static struct berval cred = {0, NULL};

void
usage( void )
{
	fprintf( stderr, _("Issue LDAP Verify Credentials operation to verify a user's credentials\n\n"));
	fprintf( stderr, _("usage: %s [options] (-S mech|[DN [cred]])\n"), prog);
	fprintf( stderr, _("where:\n"));
	fprintf( stderr, _("    DN\tDistinguished Name\n"));
	fprintf( stderr, _("    cred\tCredentials (prompt if not present)\n"));
	fprintf( stderr, _("options:\n"));
	fprintf( stderr, _("    -a\tRequest AuthzId\n"));
	fprintf( stderr, _("    -b\tRequest Password Policy Information\n"));
	fprintf( stderr, _("    -S mech\tSASL mechanism (default "" e.g. Simple)\n"));
	tool_common_usage();
	exit( EXIT_FAILURE );
}


const char options[] = "abS:"
	"d:D:e:h:H:InNO:o:p:QR:U:vVw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	switch ( i ) {
#if 0
		char	*control, *cvalue;
		int		crit;
	case 'E': /* vc extension */
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

		fprintf( stderr, _("Invalid Verify Credentials extension name: %s\n"), control );
		usage();
#endif

	case 'a':  /* request authzid */
		req_authzid++;
		break;

	case 'b':  /* request authzid */
		req_pp++;
		break;

	case 'S':  /* SASL mechanism */
		mech = optarg;
		break;

	default:
		return 0;
	}
	return 1;
}


int
main( int argc, char *argv[] )
{
	int		rc;
	LDAP		*ld = NULL;
	char		*matcheddn = NULL, *text = NULL, **refs = NULL;
	int rcode;
	char * diag = NULL;
	struct berval	*scookie = NULL;
	struct berval	*scred = NULL;
	int		id, code = 0;
	LDAPMessage	*res;
	LDAPControl	**ctrls = NULL;
	LDAPControl	**vcctrls = NULL;
	int nvcctrls = 0;

	tool_init( TOOL_VC );
	prog = lutil_progname( "ldapvc", argc, argv );

	/* LDAPv3 only */
	protocol = LDAP_VERSION3;

	tool_args( argc, argv );

	if (mech) {
		if (argc - optind > 0) {
			usage();
		}

		fprintf(stderr, "SASL credential verification not yet implemented!\n");
		rc = EXIT_FAILURE;
		goto skip;

	} else {
		if (argc - optind > 0) {
		 	dn = argv[optind++];
		}
		if (argc - optind > 0) {
		 	cred.bv_val = argv[optind++];
			cred.bv_len = strlen(cred.bv_val);
		}

		if (argc - optind > 0) {
		    usage();
	    }

	    if (!cred.bv_val) {
		    cred.bv_val = strdup(getpassphrase(_("User's password: ")));
	    }
		cred.bv_len = strlen(cred.bv_val);
	}

	ld = tool_conn_setup( 0, 0 );

	tool_bind( ld );

	if ( dont ) {
		rc = LDAP_SUCCESS;
		goto skip;
	}

	tool_server_controls( ld, NULL, 0 );

    if (req_authzid) {
		vcctrls = (LDAPControl **) malloc(3*sizeof(LDAPControl *));
		vcctrls[nvcctrls] = (LDAPControl *) malloc(sizeof(LDAPControl));
		vcctrls[nvcctrls]->ldctl_oid = ldap_strdup(LDAP_CONTROL_AUTHZID_REQUEST);
		vcctrls[nvcctrls]->ldctl_iscritical = 0;
		vcctrls[nvcctrls]->ldctl_value.bv_val = NULL;
		vcctrls[nvcctrls]->ldctl_value.bv_len = 0;
		vcctrls[++nvcctrls] = NULL;
    }

    if (req_pp) {
		if (!vcctrls) vcctrls = (LDAPControl **) malloc(3*sizeof(LDAPControl *));
		vcctrls[nvcctrls] = (LDAPControl *) malloc(sizeof(LDAPControl));
		vcctrls[nvcctrls]->ldctl_oid = ldap_strdup(LDAP_CONTROL_PASSWORDPOLICYREQUEST);
		vcctrls[nvcctrls]->ldctl_iscritical = 0;
		vcctrls[nvcctrls]->ldctl_value.bv_val = NULL;
		vcctrls[nvcctrls]->ldctl_value.bv_len = 0;
		vcctrls[++nvcctrls] = NULL;
    }

	rc = ldap_verify_credentials( ld,
		NULL,
		dn, mech, cred.bv_val ? &cred: NULL, vcctrls,
		NULL, NULL, &id ); 

	if( rc != LDAP_SUCCESS ) {
		tool_perror( "ldap_verify_credentials", rc, NULL, NULL, NULL, NULL );
		rc = EXIT_FAILURE;
		goto skip;
	}

	ldap_controls_free(vcctrls);
	vcctrls = NULL;

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
			return rc;
		}

		if ( rc != 0 ) {
			break;
		}
	}

	rc = ldap_parse_result( ld, res,
		&code, &matcheddn, &text, &refs, &ctrls, 0 );

	if ( rc == LDAP_SUCCESS ) {
		rc = code;
	}

	if ( rc != LDAP_SUCCESS ) {
		tool_perror( "ldap_parse_result", rc, NULL, matcheddn, text, refs );
		rc = EXIT_FAILURE;
		goto skip;
	}

	rc = ldap_parse_verify_credentials( ld, res, &rcode, &diag, &scookie, &scred, &vcctrls );
	ldap_msgfree(res);

	if( rc != LDAP_SUCCESS ) {
		tool_perror( "ldap_parse_verify_credentials", rc, NULL, NULL, NULL, NULL );
		rc = EXIT_FAILURE;
		goto skip;
	}

	if (rcode != LDAP_SUCCESS) {
		printf(_("Failed: %s (%d)\n"), ldap_err2string(rcode), rcode);
	}

	if (diag && *diag) {
	    printf(_("Diagnostic: %s\n"), diag);
	}

	if (vcctrls) {
		tool_print_ctrls( ld, vcctrls );
	}

skip:
	if ( verbose || ( code != LDAP_SUCCESS ) ||
		matcheddn || text || refs || ctrls )
	{
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

		if (ctrls) {
			tool_print_ctrls( ld, ctrls );
			ldap_controls_free( ctrls );
		}
	}

	ber_memfree( text );
	ber_memfree( matcheddn );
	ber_memvfree( (void **) refs );
	ber_bvfree( scookie );
	ber_bvfree( scred );
	ber_memfree( diag );

	/* disconnect from server */
	tool_unbind( ld );
	tool_destroy();

	return code == LDAP_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
