/* $OpenLDAP$ */
/*
 * Copyright 1998-2006 The OpenLDAP Foundation.
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

#include <stdio.h>

#include <lber.h>
#include <lber_pvt.h>	/* BER_BVC definition */
#include "lutil.h"
#include <ac/string.h>
#include <ac/unistd.h>

#include <radlib.h>

static LUTIL_PASSWD_CHK_FUNC chk_radius;
static const struct berval scheme = BER_BVC("{RADIUS}");
static char *config_filename;

static int
chk_radius(
	const struct berval	*sc,
	const struct berval	*passwd,
	const struct berval	*cred,
	const char		**text )
{
	unsigned int		i;
	int			rc = LUTIL_PASSWD_ERR;

	struct rad_handle	*h = NULL;

	for ( i = 0; i < cred->bv_len; i++ ) {
		if ( cred->bv_val[ i ] == '\0' ) {
			return LUTIL_PASSWD_ERR;	/* NUL character in cred */
		}
	}

	if ( cred->bv_val[ i ] != '\0' ) {
		return LUTIL_PASSWD_ERR;	/* cred must behave like a string */
	}

	for ( i = 0; i < passwd->bv_len; i++ ) {
		if ( passwd->bv_val[ i ] == '\0' ) {
			return LUTIL_PASSWD_ERR;	/* NUL character in password */
		}
	}

	if ( passwd->bv_val[ i ] != '\0' ) {
		return LUTIL_PASSWD_ERR;	/* passwd must behave like a string */
	}

	h = rad_auth_open();
	if ( h == NULL ) {
		return LUTIL_PASSWD_ERR;
	}

	if ( rad_config( h, config_filename ) != 0 ) {
		goto done;
	}

	if ( rad_create_request( h, RAD_ACCESS_REQUEST ) ) {
		goto done;
	}

	if ( rad_put_string( h, RAD_USER_NAME, passwd->bv_val ) != 0 ) {
		goto done;
	}

	if ( rad_put_string( h, RAD_USER_PASSWORD, cred->bv_val ) != 0 ) {
		goto done;
	}

	if ( rad_send_request( h ) == RAD_ACCESS_ACCEPT ) {
		rc = LUTIL_PASSWD_OK;
	}

done:;
	rad_close( h );

	return rc;
}

int
init_module( int argc, char *argv[] )
{
	int	i;

	for ( i = 0; i < argc; i++ ) {
		if ( strncasecmp( argv[ i ], "config=", STRLENOF( "config=" ) ) == 0 ) {
			/* FIXME: what if multiple loads of same module?
			 * does it make sense (e.g. override an existing one)? */
			if ( config_filename == NULL ) {
				config_filename = ber_strdup( &argv[ i ][ STRLENOF( "config=" ) ] );
			}

		} else {
			fprintf( stderr, "init_module(radius): unknown arg#%d=\"%s\".\n",
				i, argv[ i ] );
			return 1;
		}
	}

	return lutil_passwd_add( (struct berval *)&scheme, chk_radius, NULL );
}
