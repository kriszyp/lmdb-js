/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldif.h>

#include "slapcommon.h"

int
main( int argc, char **argv )
{
	char		*buf;
	int         lineno;
	int         lmax;
	int			rc = EXIT_SUCCESS;

	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN] = { '\0' };
	size_t textlen = sizeof textbuf;

	slap_tool_init( "slapadd", SLAPADD, argc, argv );

	if( !be->be_entry_open ||
		!be->be_entry_close ||
		!be->be_entry_put )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	buf = NULL;
	lmax = 0;
	lineno = 0;

	if( be->be_entry_open( be, 1 ) != 0 ) {
		fprintf( stderr, "%s: could not open database.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	while( ldif_read_record( ldiffp, &lineno, &buf, &lmax ) ) {
		ID id;
		Entry *e = str2entry( buf );
		char buf[1024];
		struct berval bvtext = { textlen, textbuf };

		if( e == NULL ) {
			fprintf( stderr, "%s: could not parse entry (line=%d)\n",
				progname, lineno );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		/* make sure the DN is not empty */
		if( !e->e_nname.bv_len ) {
			fprintf( stderr, "%s: empty dn=\"%s\" (line=%d)\n",
				progname, e->e_dn, lineno );
			rc = EXIT_FAILURE;
			entry_free( e );
			if( continuemode ) continue;
			break;
		}

		/* check backend */
		if( select_backend( &e->e_nname, is_entry_referral(e), nosubordinates )
			!= be )
		{
			fprintf( stderr, "%s: line %d: "
				"database (%s) not configured to hold \"%s\"\n",
				progname, lineno,
				be ? be->be_suffix[0]->bv_val : "<none>",
				e->e_dn );
			fprintf( stderr, "%s: line %d: "
				"database (%s) not configured to hold \"%s\"\n",
				progname, lineno,
				be ? be->be_nsuffix[0]->bv_val : "<none>",
				e->e_ndn );
			rc = EXIT_FAILURE;
			entry_free( e );
			if( continuemode ) continue;
			break;
		}

		{
			Attribute *sc = attr_find( e->e_attrs,
				slap_schema.si_ad_structuralObjectClass );
			Attribute *oc = attr_find( e->e_attrs,
				slap_schema.si_ad_objectClass );

			if( oc == NULL ) {
				fprintf( stderr, "%s: dn=\"%s\" (line=%d): %s\n",
					progname, e->e_dn, lineno,
					"no objectClass attribute");
				rc = EXIT_FAILURE;
				entry_free( e );
				if( continuemode ) continue;
				break;
			}

			if( sc == NULL ) {
				struct berval vals[2];

				int ret = structural_class( oc->a_vals, vals,
					NULL, &text, textbuf, textlen );

				if( vals[0].bv_len == 0 ) {
					fprintf( stderr, "%s: dn=\"%s\" (line=%d): %s\n",
					progname, e->e_dn, lineno, text );
					rc = EXIT_FAILURE;
					entry_free( e );
					if( continuemode ) continue;
					break;
				}

				vals[1].bv_val = NULL;
				attr_merge( e, slap_schema.si_ad_structuralObjectClass,
					vals );
			}
		}

		if( global_schemacheck ) {
			/* check schema */

			rc = entry_schema_check( be, e, NULL, &text, textbuf, textlen );

			if( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "%s: dn=\"%s\" (line=%d): %s\n",
					progname, e->e_dn, lineno, text );
				rc = EXIT_FAILURE;
				entry_free( e );
				if( continuemode ) continue;
				break;
			}
		}

		id = be->be_entry_put( be, e, &bvtext );
		if( id == NOID ) {
			fprintf( stderr, "%s: could not add entry dn=\"%s\" (line=%d): %s\n",
				progname, e->e_dn, lineno, bvtext.bv_val );
			rc = EXIT_FAILURE;
			entry_free( e );
			if( continuemode ) continue;
			break;

		}
		
		if ( verbose ) {
			fprintf( stderr, "added: \"%s\" (%08lx)\n",
				e->e_dn, (long) id );
		}

		entry_free( e );
	}

	ch_free( buf );

	be->be_entry_close( be );

	if( be->be_sync ) {
		be->be_sync( be );
	}

	slap_tool_destroy();
	return rc;
}
