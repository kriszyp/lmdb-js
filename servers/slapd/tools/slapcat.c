/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slapcommon.h"

int
main( int argc, char **argv )
{
	ID id;
	int rc = EXIT_SUCCESS;

	slap_tool_init( "slapcat", SLAPCAT, argc, argv );

	if( !be->be_entry_open ||
		!be->be_entry_close ||
		!be->be_entry_first ||
		!be->be_entry_next ||
		!be->be_entry_get )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	if( be->be_entry_open( be, 0 ) != 0 ) {
		fprintf( stderr, "%s: could not open database.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	for ( id = be->be_entry_first( be );
		id != NOID;
		id = be->be_entry_next( be ) )
	{
		char *data;
		int len;
		Entry* e = be->be_entry_get( be, id );

		if( verbose ) {
			printf( "# id=%08lx\n", (long) id );
		}

		if ( e == NULL ) {
			printf("# no data for entry id=%08lx\n\n", (long) id );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		data = entry2str( e, &len );
		entry_free( e );

		if ( data == NULL ) {
			printf("# bad data for entry id=%08lx\n\n", (long) id );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		fputs( data, ldiffp );
		fputs( "\n", ldiffp );
	}

	be->be_entry_close( be );

	slap_tool_destroy();
	return rc;
}
