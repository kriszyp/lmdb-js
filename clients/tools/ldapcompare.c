/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/errno.h>
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

#include "common.h"


static int quiet = 0;


void
usage( void )
{
	fprintf( stderr,
"usage: %s [options] DN <attr:value|attr::b64value>\n"
"where:\n"
"  DN\tDistinguished Name\n"
"  attr\tassertion attribute\n"
"  value\tassertion value\n"
"  b64value\tbase64 encoding of assertion value\n"

"Compare options:\n"
"  -z         Quiet mode, don't print anything, use return values\n"
	         , prog );
	tool_common_usage();
	exit( EXIT_FAILURE );
}

static int docompare LDAP_P((
	LDAP *ld,
	char *dn,
	char *attr,
	struct berval *bvalue,
	int quiet,
	LDAPControl **sctrls,
	LDAPControl **cctrls));


const char options[] = "z" "Cd:D:e:h:H:IkKMnO:p:P:QR:U:vw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	switch ( i ) {
#if 0
		char	*control, *cvalue;
		int		crit;
	case 'E': /* compare controls */
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -E incompatible with LDAPv%d\n",
				prog, version );
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
		fprintf( stderr, "Invalid compare control name: %s\n", control );
		usage();
#endif

	case 'z':
		quiet = 1;
		break;

	default:
		return 0;
	}
	return 1;
}


int
main( int argc, char **argv )
{
	char	*compdn = NULL, *attrs = NULL;
	char	*sep;
	int		rc;
	LDAP	*ld = NULL;
	struct berval bvalue = { 0, NULL };

	prog = lutil_progname( "ldapcompare", argc, argv );

	tool_args( argc, argv );

	if ( argc - optind != 2 ) {
		usage();
	}

	compdn = argv[optind++];
	attrs = argv[optind++];

	/* user passed in only 2 args, the last one better be in
	 * the form attr:value or attr::b64value
	 */
	sep = strchr(attrs, ':');
	if (!sep) {
		usage();
	}

	*sep++='\0';
	if ( *sep != ':' ) {
		bvalue.bv_val = strdup( sep );
		bvalue.bv_len = strlen( bvalue.bv_val );

	} else {
		/* it's base64 encoded. */
		bvalue.bv_val = malloc( strlen( &sep[1] ));
		bvalue.bv_len = lutil_b64_pton( &sep[1],
			bvalue.bv_val, strlen( &sep[1] ));

		if (bvalue.bv_len == -1) {
			fprintf(stderr, "base64 decode error\n");
			exit(-1);
		}
	}

	if ( debug )
		ldif_debug = debug;

	ld = tool_conn_setup( 0, 0 );

	if ( pw_file || want_bindpw ) {
		if ( pw_file ) {
			rc = lutil_get_filed_password( pw_file, &passwd );
			if( rc ) return EXIT_FAILURE;
		} else {
			passwd.bv_val = getpassphrase( "Enter LDAP Password: " );
			passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
		}
	}

	tool_bind( ld );

	if ( authzid || manageDSAit || noop )
		tool_server_controls( ld, NULL, 0 );

	if ( verbose ) {
		fprintf( stderr, "DN:%s, attr:%s, value:%s\n",
			compdn, attrs, sep );
	}

	rc = docompare( ld, compdn, attrs, &bvalue, quiet, NULL, NULL );

	free( bvalue.bv_val );

	ldap_unbind( ld );

	return rc;
}


static int docompare(
	LDAP *ld,
	char *dn,
	char *attr,
	struct berval *bvalue,
	int quiet,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int			rc;

	if ( not ) {
		return LDAP_SUCCESS;
	}

	rc = ldap_compare_ext_s( ld, dn, attr, bvalue,
		sctrls, cctrls );

	if ( rc == -1 ) {
		ldap_perror( ld, "ldap_result" );
		return( rc );
	}

	/* if we were told to be quiet, use the return value. */
	if ( !quiet ) {
		if ( rc == LDAP_COMPARE_TRUE ) {
			rc = 0;
			printf("TRUE\n");
		} else if ( rc == LDAP_COMPARE_FALSE ) {
			rc = 0;
			printf("FALSE\n");
		} else {
			ldap_perror( ld, "ldap_compare" );
		}
	}

	return( rc );
}

