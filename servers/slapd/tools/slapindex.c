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
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	AttributeDescription *desc;
	const char *text;
#else
	char *desc;
#endif
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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
	type = argv[argc - 1];

	if( strcasecmp( type, "dn" ) == 0 ) {
		desc = NULL;

	} else {
		rc = slap_str2ad( type, &desc, &text );

		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: unrecognized attribute type: %s\n",
				progname, text );
			exit( EXIT_FAILURE );
		}
	}
#else
	desc = type = attr_normalize( argv[argc - 1] );
#endif

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

#ifdef SLAPD_SCHEMA_NOT_COMPAT
		if( desc == NULL )
#else
		if( strcasecmp( type, "dn" ) == 0 )
#endif
		{
			bv.bv_val = e->e_ndn;
			bv.bv_len = strlen( bv.bv_val );
			bvals[0] = &bv;
			bvals[1] = NULL;

			values = bvals;

			if ( be->be_index_change( be,
				desc, values, id, SLAP_INDEX_ADD_OP ) )
			{
				rc = EXIT_FAILURE;

				if( !continuemode ) {
					entry_free( e );
					break;
				}
			}

		} else {
			Attribute *attr;
			
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			for( attr = attrs_find( e->e_attrs, desc );
				attr != NULL;
				attr = attrs_find( attr->a_next, desc ) )
#else
			if (( attr = attr_find( e->e_attrs, type )) != NULL )
#endif
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
