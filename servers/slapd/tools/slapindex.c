/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
	char		*type;
	AttributeDescription *desc;
	const char *text;
	ID id;
	int rc = EXIT_SUCCESS;

	slap_tool_init( "slapindex", SLAPINDEX, argc, argv );

	if( !be->be_entry_open &&
		!be->be_entry_close &&
		!be->be_entry_first &&
		!be->be_entry_next &&
		!be->be_entry_reindex )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	type = argv[argc - 1];

	rc = slap_str2ad( type, &desc, &text );

	if( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "%s: unrecognized attribute type: %s\n",
			progname, text );
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
		int rtn;

		if( verbose ) {
			printf("indexing id=%08lx\n", (long) id );
		}

		rtn =  be->be_entry_reindex( be, id );

		if( rtn != LDAP_SUCCESS ) {
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}
	}

	(void) be->be_entry_close( be );

	slap_tool_destroy();

	return( rc );
}
