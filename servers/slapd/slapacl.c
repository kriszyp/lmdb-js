/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2005 The OpenLDAP Foundation.
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
	Connection		conn = { 0 };
	Listener		listener;
	char			opbuf[OPERATION_BUFFER_SIZE];
	Operation		*op;
	Entry			e = { 0 };
	char			*attr = NULL;

	slap_tool_init( progname, SLAPACL, argc, argv );

	argv = &argv[ optind ];
	argc -= optind;

	op = (Operation *)opbuf;
	connection_fake_init( &conn, op, &conn );

	conn.c_listener = &listener;
	conn.c_listener_url = listener_url;
	conn.c_peer_domain = peer_domain;
	conn.c_peer_name = peer_name;
	conn.c_sock_name = sock_name;
	op->o_ssf = ssf;
	op->o_transport_ssf = transport_ssf;
	op->o_tls_ssf = tls_ssf;
	op->o_sasl_ssf = sasl_ssf;

	if ( !BER_BVISNULL( &authcID ) ) {
		rc = slap_sasl_getdn( &conn, op, &authcID, NULL,
				&authcDN, SLAP_GETDN_AUTHCID );
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

	op->o_bd = be;
	if ( !BER_BVISNULL( &authcDN ) ) {
		op->o_dn = authcDN;
		op->o_ndn = authcDN;
	}

	if ( argc == 0 ) {
		argc = 1;
		attr = slap_schema.si_ad_entry->ad_cname.bv_val;
	}

	for ( ; argc--; argv++ ) {
		slap_mask_t		mask;
		AttributeDescription	*desc = NULL;
		int			rc;
		struct berval		val = BER_BVNULL,
					*valp = NULL;
		const char		*text;
		char			accessmaskbuf[ACCESSMASK_MAXLEN];
		char			*accessstr;
		slap_access_t		access = ACL_AUTH;

		if ( attr == NULL ) {
			attr = argv[ 0 ];
		}

		val.bv_val = strchr( attr, ':' );
		if ( val.bv_val != NULL ) {
			val.bv_val[0] = '\0';
			val.bv_val++;
			val.bv_len = strlen( val.bv_val );
			valp = &val;
		}

		accessstr = strchr( attr, '/' );
		if ( accessstr != NULL ) {
			accessstr[0] = '\0';
			accessstr++;
			access = str2access( accessstr );
			if ( access == ACL_INVALID_ACCESS ) {
				fprintf( stderr, "unknown access \"%s\" for attribute \"%s\"\n",
						accessstr, attr );
				if ( continuemode ) {
					continue;
				}
				break;
			}
		}

		rc = slap_str2ad( attr, &desc, &text );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "slap_str2ad(%s) failed %d (%s)\n",
					attr, rc, ldap_err2string( rc ) );
			if ( continuemode ) {
				continue;
			}
			break;
		}

		rc = access_allowed_mask( op, &e, desc, valp, access,
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
					accessmask2str( mask, accessmaskbuf, 1 ) );
		}
		rc = 0;
		attr = NULL;
	}

destroy:;
	slap_tool_destroy();

	return rc;
}

