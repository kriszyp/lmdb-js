/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004 The OpenLDAP Foundation.
 * Portions Copyright 2004 Pierangelo Masarati.
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
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldif.h>
#include <lutil.h>

#include "slapcommon.h"

int
slapacl( int argc, char **argv )
{
	int			rc = EXIT_SUCCESS;
	const char		*progname = "slapacl";
	Connection		conn;
	Operation		op;
	Entry			e = { 0 };

	slap_tool_init( progname, SLAPACL, argc, argv );

	argv = &argv[ optind ];
	argc -= optind;

	memset( &conn, 0, sizeof( Connection ) );
	memset( &op, 0, sizeof( Operation ) );

	connection_fake_init( &conn, &op, &conn );

	if ( !BER_BVISNULL( &authcID ) ) {
		rc = slap_sasl_getdn( &conn, &op, &authcID, NULL, &authcDN, SLAP_GETDN_AUTHCID );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "ID: <%s> check failed %d (%s)\n",
					authcID.bv_val, rc,
					ldap_err2string( rc ) );
			rc = 1;
			goto destroy;
		}

	} else if ( !BER_BVISNULL( &authcDN ) ) {
		struct berval	ndn;

		rc = dnNormalize( 0, NULL, NULL, &authcDN, &ndn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "autchDN=\"%s\" normalization failed %d (%s)\n",
					authcDN.bv_val, rc,
					ldap_err2string( rc ) );
			rc = 1;
			goto destroy;
		}
		ch_free( authcDN.bv_val );
		authcDN = ndn;
	}


	if ( !BER_BVISNULL( &authcDN ) ) {
		fprintf( stderr, "DN: \"%s\"\n", authcDN.bv_val );
	}

	assert( !BER_BVISNULL( &baseDN ) );
	rc = dnPrettyNormal( NULL, &baseDN, &e.e_name, &e.e_nname, NULL );
	if ( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "base=\"%s\" normalization failed %d (%s)\n",
				baseDN.bv_val, rc,
				ldap_err2string( rc ) );
		rc = 1;
		goto destroy;
	}

	op.o_bd = be;
	if ( !BER_BVISNULL( &authcDN ) ) {
		op.o_dn = authcDN;
		op.o_ndn = authcDN;
	}

	for ( ; argc--; argv++ ) {
		slap_mask_t		mask;
		AttributeDescription	*desc = NULL;
		int			rc;
		struct berval		val;
		const char		*text;
		char			accessmaskbuf[ACCESSMASK_MAXLEN];
		char			*accessstr;
		slap_access_t		access = ACL_AUTH;

		val.bv_val = strchr( argv[0], ':' );
		if ( val.bv_val != NULL ) {
			val.bv_val[0] = '\0';
			val.bv_val++;
			val.bv_len = strlen( val.bv_val );
		}

		accessstr = strchr( argv[0], '/' );
		if ( accessstr != NULL ) {
			accessstr[0] = '\0';
			accessstr++;
			access = str2access( accessstr );
			if ( access == ACL_INVALID_ACCESS ) {
				fprintf( stderr, "unknown access \"%s\" for attribute \"%s\"\n",
						accessstr, argv[0] );
				if ( continuemode ) {
					continue;
				}
				break;
			}
		}

		rc = slap_str2ad( argv[0], &desc, &text );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "slap_str2ad(%s) failed %d (%s)\n",
					argv[0], rc, ldap_err2string( rc ) );
			if ( continuemode ) {
				continue;
			}
			break;
		}

		rc = access_allowed_mask( &op, &e, desc, &val, access,
				NULL, &mask );

		if ( accessstr ) {
			fprintf( stderr, "%s access to %s%s%s: %s\n",
					accessstr,
					desc->ad_cname.bv_val,
					val.bv_val ? "=" : "",
					val.bv_val ? val.bv_val : "",
					rc ? "ALLOWED" : "DENIED" );

		} else {
			fprintf( stderr, "%s%s%s: %s\n",
					desc->ad_cname.bv_val,
					val.bv_val ? "=" : "",
					val.bv_val ? val.bv_val : "",
					accessmask2str( mask, accessmaskbuf ) );
		}
		rc = 0;
	}

destroy:;
	slap_tool_destroy();

	return rc;
}

