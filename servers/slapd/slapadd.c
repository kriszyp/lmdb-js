/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
 *    Pierangelo Masarati
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
#include <lutil.h>

#include "slapcommon.h"

static char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
static char maxcsnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];

int
slapadd( int argc, char **argv )
{
	char *buf = NULL;
	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN] = { '\0' };
	size_t textlen = sizeof textbuf;
	const char *progname = "slapadd";

	struct berval csn;
	struct berval maxcsn;
	struct berval bvtext;
	Attribute *attr;
	Entry *ctxcsn_e;
	ID	ctxcsn_id, id;
	OperationBuffer opbuf;
	Operation *op;

	int match;
	int ret;
	int checkvals;
	int lineno;
	int lmax;
	int rc = EXIT_SUCCESS;
	int manage = 0;	

	slap_tool_init( progname, SLAPADD, argc, argv );

	memset( &opbuf, 0, sizeof(opbuf) );
	op = (Operation *) &opbuf;

	if( !be->be_entry_open ||
		!be->be_entry_close ||
		!be->be_entry_put ||
		(update_ctxcsn &&
		 (!be->be_dn2id_get ||
		  !be->be_id2entry_get ||
		  !be->be_entry_modify)) )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		if ( dryrun ) {
			fprintf( stderr, "\t(dry) continuing...\n" );

		} else {
			exit( EXIT_FAILURE );
		}
	}

	checkvals = (slapMode & SLAP_TOOL_QUICK) ? 0 : 1;

	lmax = 0;
	lineno = 0;

	if( !dryrun && be->be_entry_open( be, 1 ) != 0 ) {
		fprintf( stderr, "%s: could not open database.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	if ( update_ctxcsn ) {
		maxcsn.bv_val = maxcsnbuf;
		maxcsn.bv_len = 0;
	}

	while( ldif_read_record( ldiffp, &lineno, &buf, &lmax ) ) {
		Entry *e = str2entry2( buf, checkvals );

		/*
		 * Initialize text buffer
		 */
		bvtext.bv_len = textlen;
		bvtext.bv_val = textbuf;
		bvtext.bv_val[0] = '\0';

		if( e == NULL ) {
			fprintf( stderr, "%s: could not parse entry (line=%d)\n",
				progname, lineno );
			rc = EXIT_FAILURE;
			if( continuemode ) continue;
			break;
		}

		/* make sure the DN is not empty */
		if( BER_BVISEMPTY( &e->e_nname ) &&
			!BER_BVISEMPTY( be->be_nsuffix )) {
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
				be ? be->be_suffix[0].bv_val : "<none>",
				e->e_dn );
			fprintf( stderr, "%s: line %d: "
				"database (%s) not configured to hold \"%s\"\n",
				progname, lineno,
				be ? be->be_nsuffix[0].bv_val : "<none>",
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
				struct berval val;

				rc = structural_class( oc->a_vals, &val,
					NULL, &text, textbuf, textlen );

				if( rc != LDAP_SUCCESS ) {
					fprintf( stderr, "%s: dn=\"%s\" (line=%d): (%d) %s\n",
						progname, e->e_dn, lineno, rc, text );
					rc = EXIT_FAILURE;
					entry_free( e );
					if( continuemode ) continue;
					break;
				}

				attr_merge_one( e, slap_schema.si_ad_structuralObjectClass,
					&val, NULL );
			}

			/* check schema */
			op->o_bd = be;

			if ( (slapMode & SLAP_TOOL_NO_SCHEMA_CHECK) == 0) {
				rc = entry_schema_check( op, e, NULL, manage,
					&text, textbuf, textlen );

				if( rc != LDAP_SUCCESS ) {
					fprintf( stderr, "%s: dn=\"%s\" (line=%d): (%d) %s\n",
						progname, e->e_dn, lineno, rc, text );
					rc = EXIT_FAILURE;
					entry_free( e );
					if( continuemode ) continue;
					break;
				}
			}
		}

		if ( SLAP_LASTMOD(be) ) {
			time_t now = slap_get_time();
			char uuidbuf[ LDAP_LUTIL_UUIDSTR_BUFSIZE ];
			struct berval vals[ 2 ];

			struct berval name, timestamp;

			struct berval nvals[ 2 ];
			struct berval nname;
			char timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];

			vals[1].bv_len = 0;
			vals[1].bv_val = NULL;

			nvals[1].bv_len = 0;
			nvals[1].bv_val = NULL;

			csn.bv_len = lutil_csnstr( csnbuf, sizeof( csnbuf ), 0, 0 );
			csn.bv_val = csnbuf;

			timestamp.bv_val = timebuf;
			timestamp.bv_len = sizeof(timebuf);

			slap_timestamp( &now, &timestamp );

			if ( BER_BVISEMPTY( &be->be_rootndn ) ) {
				BER_BVSTR( &name, SLAPD_ANONYMOUS );
				nname = name;
			} else {
				name = be->be_rootdn;
				nname = be->be_rootndn;
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_entryUUID )
				== NULL )
			{
				vals[0].bv_len = lutil_uuidstr( uuidbuf, sizeof( uuidbuf ) );
				vals[0].bv_val = uuidbuf;
				attr_merge_normalize_one( e, slap_schema.si_ad_entryUUID, vals, NULL );
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_creatorsName )
				== NULL )
			{
				vals[0] = name;
				nvals[0] = nname;
				attr_merge( e, slap_schema.si_ad_creatorsName, vals, nvals );
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_modifiersName )
				== NULL )
			{
				vals[0] = name;
				nvals[0] = nname;
				attr_merge( e, slap_schema.si_ad_modifiersName, vals, nvals );
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_createTimestamp )
				== NULL )
			{
				vals[0] = timestamp;
				attr_merge( e, slap_schema.si_ad_createTimestamp, vals, NULL );
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_modifyTimestamp )
				== NULL )
			{
				vals[0] = timestamp;
				attr_merge( e, slap_schema.si_ad_modifyTimestamp, vals, NULL );
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_entryCSN )
				== NULL )
			{
				vals[0] = csn;
				attr_merge( e, slap_schema.si_ad_entryCSN, vals, NULL );
			}

			if ( update_ctxcsn ) {
				attr = attr_find( e->e_attrs, slap_schema.si_ad_entryCSN );
				if ( maxcsn.bv_len != 0 ) {
					match = 0;
					value_match( &match, slap_schema.si_ad_entryCSN,
						slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						&maxcsn, &attr->a_nvals[0], &text );
				} else {
					match = -1;
				}
				if ( match < 0 ) {
					strcpy( maxcsn.bv_val, attr->a_nvals[0].bv_val );
					maxcsn.bv_len = attr->a_nvals[0].bv_len;
				}
			}
		}

		if ( !dryrun ) {
			id = be->be_entry_put( be, e, &bvtext );
			if( id == NOID ) {
				fprintf( stderr, "%s: could not add entry dn=\"%s\" "
								 "(line=%d): %s\n", progname, e->e_dn,
								 lineno, bvtext.bv_val );
				rc = EXIT_FAILURE;
				entry_free( e );
				if( continuemode ) continue;
				break;
			}
			if ( verbose )
				fprintf( stderr, "added: \"%s\" (%08lx)\n",
					e->e_dn, (long) id );
		} else {
			if ( verbose )
				fprintf( stderr, "added: \"%s\"\n",
					e->e_dn );
		}

		entry_free( e );
	}

	bvtext.bv_len = textlen;
	bvtext.bv_val = textbuf;
	bvtext.bv_val[0] = '\0';

	if ( rc == EXIT_SUCCESS && update_ctxcsn && !dryrun && maxcsn.bv_len ) {
		ctxcsn_id = be->be_dn2id_get( be, be->be_nsuffix );
		if ( ctxcsn_id == NOID ) {
			fprintf( stderr, "%s: context entry is missing\n", progname );
			rc = EXIT_FAILURE;
		} else {
			ret = be->be_id2entry_get( be, ctxcsn_id, &ctxcsn_e );
			if ( ret == LDAP_SUCCESS ) {
				attr = attr_find( ctxcsn_e->e_attrs,
									slap_schema.si_ad_contextCSN );
				if ( attr ) {
					value_match( &match, slap_schema.si_ad_entryCSN,
						slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						&maxcsn, &attr->a_nvals[0], &text );
					if ( match > 0 ) {
						AC_MEMCPY( attr->a_vals[0].bv_val, maxcsn.bv_val, maxcsn.bv_len );
						attr->a_vals[0].bv_val[maxcsn.bv_len] = '\0';
						attr->a_vals[0].bv_len = maxcsn.bv_len;
					}
				} else {
					match = 1;
					attr_merge_one( ctxcsn_e, slap_schema.si_ad_contextCSN, &maxcsn, NULL );
				}
				if ( match > 0 ) {
					ctxcsn_id = be->be_entry_modify( be, ctxcsn_e, &bvtext );
					if( ctxcsn_id == NOID ) {
						fprintf( stderr, "%s: could not modify ctxcsn\n",
										progname);
						rc = EXIT_FAILURE;
					} else if ( verbose ) {
						fprintf( stderr, "modified: \"%s\" (%08lx)\n",
										 ctxcsn_e->e_dn, (long) ctxcsn_id );
					}
				}
			}
		} 
	}

	ch_free( buf );

	if ( !dryrun ) {
		if( be->be_entry_close( be ) ) {
			rc = EXIT_FAILURE;
		}

		if( be->be_sync ) {
			be->be_sync( be );
		}
	}

	slap_tool_destroy();

	return rc;
}

