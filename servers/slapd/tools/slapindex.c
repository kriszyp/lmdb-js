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
		!be->be_entry_get &&
		!be->be_index_attr &&
		!be->be_index_change )
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

	if ( !be->be_index_attr( be, desc ) ) {
		fprintf( stderr, "attribute type \"%s\": no indices to generate\n",
			type );
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
		Entry* e = be->be_entry_get( be, id );

		if ( e == NULL ) {
			fprintf( stderr,
				"entry id=%08lx: no data\n", (long) id );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		if( verbose ) {
			printf("indexing id=%08lx dn=\"%s\"\n",
				id, e->e_dn );
		}

		{
			Attribute *attr;
			
			for( attr = attrs_find( e->e_attrs, desc );
				attr != NULL;
				attr = attrs_find( attr->a_next, desc ) )
			{

				if ( be->be_index_change( be,
					desc, attr->a_vals, id, SLAP_INDEX_ADD_OP ) )
				{
					rc = EXIT_FAILURE;

					if( !continuemode ) {
						entry_free( e );
						goto done;
					}
				}
			}
		}

		entry_free( e );
	}

done:
	(void) be->be_entry_close( be );

	slap_tool_destroy();

	return( rc );
}
