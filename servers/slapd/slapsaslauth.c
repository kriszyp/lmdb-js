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

static int
do_check( Connection *c, Operation *op, struct berval *id )
{
	struct berval	authcDN;
	int		rc;

	rc = slap_sasl_getdn( c, op, id, NULL, &authcDN, SLAP_GETDN_AUTHCID );
	if ( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "ID: <%s> check failed %d (%s)\n",
				id->bv_val, rc,
				ldap_err2string( rc ) );
		rc = 1;
			
	} else {
		if ( !BER_BVISNULL( &authzID ) ) {
			rc = slap_sasl_authorized( op, &authcDN, &authzID );

			fprintf( stderr,
					"ID:      <%s>\n"
					"authcDN: <%s>\n"
					"authzDN: <%s>\n"
					"authorization %s\n",
					id->bv_val,
					authcDN.bv_val,
					authzID.bv_val,
					rc == LDAP_SUCCESS ? "OK" : "failed" );

		} else {
			fprintf( stderr, "ID: <%s> check succeeded\n"
					"authcID:     <%s>\n",
					id->bv_val,
					authcDN.bv_val );
			op->o_tmpfree( authcDN.bv_val, op->o_tmpmemctx );
		}
		rc = 0;
	}

	return rc;
}

int
slapsaslauth( int argc, char **argv )
{
	int			rc = EXIT_SUCCESS;
	const char		*progname = "slapsaslauth";
	Connection		conn;
	Operation		op;

#ifdef NEW_LOGGING
	lutil_log_initialize( argc, argv );
#endif
	slap_tool_init( progname, SLAPSASLAUTH, argc, argv );

	argv = &argv[ optind ];
	argc -= optind;

	memset( &conn, 0, sizeof( Connection ) );
	memset( &op, 0, sizeof( Operation ) );

	connection_fake_init( &conn, &op, &conn );

	if ( !BER_BVISNULL( &authzID ) ) {
		struct berval	authzDN;
		
		rc = slap_sasl_getdn( &conn, &op, &authzID, NULL, &authzDN,
				SLAP_GETDN_AUTHZID );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "authzID: <%s> check failed %d (%s)\n",
					authzID.bv_val, rc,
					ldap_err2string( rc ) );
			rc = 1;
			BER_BVZERO( &authzID );
			goto destroy;
		} 

		authzID = authzDN;
	}


	if ( !BER_BVISNULL( &authcID ) ) {
		if ( !BER_BVISNULL( &authzID ) || argc == 0 ) {
			rc = do_check( &conn, &op, &authcID );
			goto destroy;
		}

		for ( ; argc--; argv++ ) {
			struct berval	authzDN;
		
			ber_str2bv( argv[ 0 ], 0, 0, &authzID );

			rc = slap_sasl_getdn( &conn, &op, &authzID, NULL, &authzDN,
					SLAP_GETDN_AUTHZID );
			if ( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "authzID: <%s> check failed %d (%s)\n",
						authzID.bv_val, rc,
						ldap_err2string( rc ) );
				rc = 1;
				BER_BVZERO( &authzID );
				goto destroy;
			}

			authzID = authzDN;

			rc = do_check( &conn, &op, &authcID );

			op.o_tmpfree( authzID.bv_val, op.o_tmpmemctx );
			BER_BVZERO( &authzID );

			if ( rc ) {
				goto destroy;
			}
		}

		goto destroy;
	}

	for ( ; argc--; argv++ ) {
		struct berval	id;

		ber_str2bv( argv[ 0 ], 0, 0, &id );

		rc = do_check( &conn, &op, &id );

		if ( rc ) {
			goto destroy;
		}
	}

destroy:;
	if ( !BER_BVISNULL( &authzID ) ) {
		op.o_tmpfree( authzID.bv_val, op.o_tmpmemctx );
	}
	slap_tool_destroy();

	return rc;
}

