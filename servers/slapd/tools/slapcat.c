/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
 * Portions Copyright 2003 IBM Corporation.
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
 * This work was initially developed by Kurt Zeilenga for inclusion
 * in OpenLDAP Software.  Additional signficant contributors include
 *    Jong Hyuk Choi
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
	Operation op = {0};

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
		op.o_bd = be;

		if ( e == NULL ) {
			printf("# no data for entry id=%08lx\n\n", (long) id );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		if( sub_ndn.bv_len && !dnIsSuffix( &e->e_nname, &sub_ndn ) ) {
			be_entry_release_r( &op, e );
			continue;
		}

		if ( retrieve_ctxcsn == 0 ) {
			if ( is_entry_syncProviderSubentry( e ) ) {
				be_entry_release_r( &op, e );
				continue;
			}
		}

		if ( retrieve_synccookie == 0 ) {
			if ( is_entry_syncConsumerSubentry( e ) ) {
				be_entry_release_r( &op, e );
				continue;
			}
		}

		if( verbose ) {
			printf( "# id=%08lx\n", (long) id );
		}

		data = entry2str( e, &len );
		be_entry_release_r( &op, e );

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
