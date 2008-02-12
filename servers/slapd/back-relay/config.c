/* config.c - relay backend configuration file routine */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2008 The OpenLDAP Foundation.
 * Portions Copyright 2004 Pierangelo Masarati.
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
 * This work was initially developed by Pierangelo Masaratifor inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-relay.h"

int
relay_back_db_config(
	BackendDB	*be,
	const char	*fname,
	int		lineno,
	int		argc,
	char		**argv
)
{
	relay_back_info *ri = (struct relay_back_info *)be->be_private;

	if ( ri == NULL ) {
		fprintf( stderr, "%s: line %d: relay backend info is null!\n",
		    fname, lineno );
		return 1;
	}

	/* real naming context */
	if ( strcasecmp( argv[0], "relay" ) == 0 ) {
		struct berval	dn, ndn, pdn;
		int		rc;
		BackendDB	*bd;

		if ( !BER_BVISNULL( &ri->ri_realsuffix ) ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: "
				"relay dn already specified.\n",
				fname, lineno, 0 );
			return 1;
		}

		switch ( argc ) {
		case 3:
			if ( strcmp( argv[ 2 ], "massage" ) != 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: "
					"unknown arg[#2]=\"%s\" "
					"in \"relay <dn> [massage]\" line\n",
					fname, lineno, argv[ 2 ] );
				return 1;
			}

			if ( be->be_nsuffix == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: "
					"\"relay\" directive "
					"must appear after \"suffix\".\n",
					fname, lineno, 0 );
				return 1;
			}

			if ( !BER_BVISNULL( &be->be_nsuffix[ 1 ] ) ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: "
					"relaying of multiple suffix "
					"database not supported.\n",
					fname, lineno, 0 );
				return 1;
			}
			/* fallthru */

		case 2:
			break;

		case 1:
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: missing relay suffix "
				"in \"relay <dn> [massage]\" line.\n",
				fname, lineno, 0 );
			return 1;

		default:
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: extra cruft "
				"in \"relay <dn> [massage]\" line.\n",
				fname, lineno, 0 );
			return 1;
		}

		/* The man page says that the "relay" directive
		 * automatically instantiates slapo-rwm; I don't
		 * like this very much any more, I'd prefer to
		 * have automatic instantiation only when "massage"
		 * is specified, so one has better control on
		 * where the overlay gets instantiated, but this
		 * would break compatibility.  One can still control
		 * where the overlay is instantiated by moving
		 * around the "relay" directive, although this could
		 * make slapd.conf a bit confusing. */
		if ( overlay_config( be, "rwm" ) ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: unable to install "
				"rwm overlay "
				"in \"relay <dn> [massage]\" line\n",
				fname, lineno, 0 );
			return 1;
		}

		dn.bv_val = argv[ 1 ];
		dn.bv_len = strlen( argv[ 1 ] );
		rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn, NULL );
		if ( rc != LDAP_SUCCESS ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: "
				"relay dn \"%s\" is invalid "
				"in \"relay <dn> [massage]\" line\n",
				fname, lineno, argv[ 1 ] );
			return 1;
		}

		bd = select_backend( &ndn, 0, 1 );
		if ( bd == NULL ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: "
				"cannot find database "
				"of relay dn \"%s\" "
				"in \"relay <dn> [massage]\" line\n",
				fname, lineno, argv[ 1 ] );
			rc = 1;
			goto relay_done;

		} else if ( bd->be_private == be->be_private ) {
			Debug( LDAP_DEBUG_ANY,
				"%s: line %d: "
				"relay dn \"%s\" would call self "
				"in \"relay <dn> [massage]\" line\n",
				fname, lineno, pdn.bv_val );
			rc = 1;
			goto relay_done;
		}

		ri->ri_realsuffix = ndn;

		if ( argc == 3 ) {
			char	*cargv[ 4 ];

			cargv[ 0 ] = "rwm-suffixmassage";
			cargv[ 1 ] = be->be_suffix[0].bv_val;
			cargv[ 2 ] = pdn.bv_val;
			cargv[ 3 ] = NULL;

			rc = be->be_config( be, fname, lineno, 3, cargv );
		}

relay_done:;
		ch_free( pdn.bv_val );

		return rc;
	}

	/* anything else */
	return SLAP_CONF_UNKNOWN;
}

