/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
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
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */

#include "portable.h"

#ifdef SLAPD_SQL

#include <stdio.h>
#include <sys/types.h>
#include "ac/string.h"

#include "slap.h"
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "proto-sql.h"

static backsql_api *backsqlapi;

int
backsql_api_config( backsql_info *si, const char *name )
{
	backsql_api	*ba;

	assert( si );
	assert( name );

	for ( ba = backsqlapi; ba; ba = ba->ba_next ) {
		if ( strcasecmp( name, ba->ba_name ) == 0 ) {
			backsql_api	*ba2;

			ba2 = ch_malloc( sizeof( backsql_api ) );
			*ba2 = *ba;
			ba2->ba_next = si->si_api;
			si->si_api = ba2;
			return 0;
		}
	}

	return 1;
}

int
backsql_api_register( backsql_api *ba )
{
	backsql_api	*ba2;

	assert( ba );

	if ( ba->ba_name == NULL ) {
		fprintf( stderr, "API module has no name\n" );
		exit(EXIT_FAILURE);
	}

	for ( ba2 = backsqlapi; ba2; ba2 = ba2->ba_next ) {
		if ( strcasecmp( ba->ba_name, ba2->ba_name ) == 0 ) {
			fprintf( stderr, "API module \"%s\" already defined\n", ba->ba_name );
			exit(EXIT_FAILURE);
		}
	}

	ba->ba_next = backsqlapi;
	backsqlapi = ba;

	return 0;
}

int
backsql_api_dn2odbc( Operation *op, SlapReply *rs, struct berval *dn )
{
	backsql_info	*si = (backsql_info *)op->o_bd->be_private;
	backsql_api	*ba;
	int		rc;
	struct berval	bv;

	ba = si->si_api;

	if ( ba == NULL ) {
		return 0;
	}

	ber_dupbv( &bv, dn );

	for ( ; ba; ba = ba->ba_next ) {
		if ( ba->ba_dn2odbc ) {
			rc = ( *ba->ba_dn2odbc )( op, rs, &bv );

			if ( rc ) {
				return rc;
			}
		}
	}

	*dn = bv;

	return 0;
}

int
backsql_api_odbc2dn( Operation *op, SlapReply *rs, struct berval *dn )
{
	backsql_info	*si = (backsql_info *)op->o_bd->be_private;
	backsql_api	*ba;
	int		rc;
	struct berval	bv;

	ba = si->si_api;

	if ( ba == NULL ) {
		return 0;
	}

	ber_dupbv( &bv, dn );

	for ( ; ba; ba = ba->ba_next ) {
		if ( ba->ba_dn2odbc ) {
			rc = ( *ba->ba_odbc2dn )( op, rs, &bv );

			if ( rc ) {
				return rc;
			}
		}
	}

	*dn = bv;

	return 0;
}

#endif /* SLAPD_SQL */

