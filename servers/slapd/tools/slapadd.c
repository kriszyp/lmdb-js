/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slapcommon.h"

int
main( int argc, char **argv )
{
	char		*buf;
	int         lineno;
	int         lmax;
	int			rc = EXIT_SUCCESS;

	slap_tool_init( "slapadd", SLAPADD, argc, argv );
	slap_startup( be );

	if( !be->be_entry_open &&
		!be->be_entry_close &&
		!be->be_entry_put )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	buf = NULL;
	lmax = 0;

	if( be->be_entry_open( be, 1 ) != 0 ) {
		fprintf( stderr, "%s: could not open database.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	while( ldif_read_record( ldiffp, &lineno, &buf, &lmax ) ) {
		ID id;
		Entry *e = str2entry( buf );

		if( e == NULL ) {
			fprintf( stderr, "%s: could not parse entry at line %d\n",
				progname, lineno );
			rc = EXIT_FAILURE;
			continue;
		}

		id = be->be_entry_put( be, e );

		if( id == NOID ) {
			fprintf( stderr, "%s: could not add entry (%s) at line %d\n",
				progname, e->e_dn, lineno );
			rc = EXIT_FAILURE;

		} else if ( verbose ) {
			fprintf( stderr, "added: \"%s\" (%08ld)\n",
				e->e_dn, (long) id );
		}

		entry_free( e );
	}

	be->be_entry_close( be );

	if( be->be_sync ) {
		be->be_sync( be );
	}

	slap_shutdown( be );
	slap_destroy();

	return rc;
}
