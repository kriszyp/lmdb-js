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
	char		*type;
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

	type = attr_normalize( argv[argc - 1] );

	if ( !be->be_index_attr( be, type ) ) {
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
		struct berval **values;
		Entry* e = be->be_entry_get( be, id );
		struct berval bv;
		struct berval *bvals[2];

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

		if( strcasecmp( type, "dn" ) == 0 ) {
			bv.bv_val = e->e_ndn;
			bv.bv_len = strlen( bv.bv_val );
			bvals[0] = &bv;
			bvals[1] = NULL;

			values = bvals;

		} else {
			Attribute *attr = attr_find( e->e_attrs, type );

			if( attr == NULL ) {
				entry_free( e );
				continue;
			}

			values = attr->a_vals;
		}

		if ( be->be_index_change( be,
			type, values, id, SLAP_INDEX_ADD_OP ) )
		{
			rc = EXIT_FAILURE;

			if( !continuemode ) {
				entry_free( e );
				break;
			}
		}

		entry_free( e );
	}

	(void) be->be_entry_close( be );

	slap_tool_destroy();

	return( rc );
}
