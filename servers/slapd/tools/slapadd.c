/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Modified by Jong Hyuk Choi
 *
 * Modifications provided under the terms of the following condition:
 *
 * Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
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
static const struct berval slap_syncrepl_bvc = BER_BVC("syncreplxxx");
static const struct berval slap_syncrepl_cn_bvc = BER_BVC("cn=syncreplxxx");
static struct berval slap_syncrepl_bv = BER_BVNULL;
static struct berval slap_syncrepl_cn_bv = BER_BVNULL;

struct subentryinfo {
	struct berval cn;
	struct berval ndn;
	struct berval rdn;
	struct berval cookie;
	LDAP_SLIST_ENTRY( subentryinfo ) sei_next;
};

int
main( int argc, char **argv )
{
	char		*buf = NULL;
	int         lineno;
	int         lmax;
	int			rc = EXIT_SUCCESS;

	const char *text;
	char textbuf[SLAP_TEXT_BUFLEN] = { '\0' };
	size_t textlen = sizeof textbuf;

	struct berval csn;
	struct berval maxcsn = { 0, NULL };
	struct berval ldifcsn = { 0, NULL };
	int match;
	int	provider_subentry = 0;
	struct subentryinfo *sei;
	LDAP_SLIST_HEAD( consumer_subentry_slist, subentryinfo ) consumer_subentry;
	Attribute *attr;
	Entry *ctxcsn_e;
	ID	ctxcsn_id;
	struct berval	ctxcsn_ndn = { 0, NULL };
	int ret;
	struct berval bvtext;
	int i;
#ifdef NEW_LOGGING
	lutil_log_initialize(argc, argv );
#endif
	slap_tool_init( "slapadd", SLAPADD, argc, argv );

	LDAP_SLIST_INIT( &consumer_subentry );

	if( !be->be_entry_open ||
		!be->be_entry_close ||
		!be->be_entry_put )
	{
		fprintf( stderr, "%s: database doesn't support necessary operations.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	lmax = 0;
	lineno = 0;

	if( be->be_entry_open( be, 1 ) != 0 ) {
		fprintf( stderr, "%s: could not open database.\n",
			progname );
		exit( EXIT_FAILURE );
	}

	while( ldif_read_record( ldiffp, &lineno, &buf, &lmax ) ) {
		Entry *e = str2entry( buf );

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

		if( global_schemacheck ) {
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

				rc = structural_class( oc->a_vals, vals,
					NULL, &text, textbuf, textlen );

				if( rc != LDAP_SUCCESS ) {
					fprintf( stderr, "%s: dn=\"%s\" (line=%d): (%d) %s\n",
						progname, e->e_dn, lineno, rc, text );
					rc = EXIT_FAILURE;
					entry_free( e );
					if( continuemode ) continue;
					break;
				}

				vals[1].bv_len = 0;
				vals[1].bv_val = NULL;

				attr_merge( e, slap_schema.si_ad_structuralObjectClass,
					vals, NULL /* FIXME */ );
			}

			/* check schema */
			rc = entry_schema_check( be, e, NULL, &text, textbuf, textlen );

			if( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "%s: dn=\"%s\" (line=%d): (%d) %s\n",
					progname, e->e_dn, lineno, rc, text );
				rc = EXIT_FAILURE;
				entry_free( e );
				if( continuemode ) continue;
				break;
			}
		}

		if ( SLAP_LASTMOD(be) ) {
			struct tm *ltm;
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

			ltm = gmtime(&now);
			lutil_gentime( timebuf, sizeof(timebuf), ltm );

			csn.bv_len = lutil_csnstr( csnbuf, sizeof( csnbuf ), 0, 0 );
			csn.bv_val = csnbuf;

			timestamp.bv_val = timebuf;
			timestamp.bv_len = strlen(timebuf);

			if ( be->be_rootndn.bv_len == 0 ) {
				name.bv_val = SLAPD_ANONYMOUS;
				name.bv_len = sizeof(SLAPD_ANONYMOUS) - 1;
				nname.bv_val = SLAPD_ANONYMOUS;
				nname.bv_len = sizeof(SLAPD_ANONYMOUS) - 1;
			} else {
				name = be->be_rootdn;
				nname = be->be_rootndn;
			}

			if( attr_find( e->e_attrs, slap_schema.si_ad_entryUUID )
				== NULL )
			{
				vals[0].bv_len = lutil_uuidstr( uuidbuf, sizeof( uuidbuf ) );
				vals[0].bv_val = uuidbuf;
				attr_merge_normalize_one( e,
							slap_schema.si_ad_entryUUID, vals, NULL );
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

			if ( !is_entry_syncProviderSubentry( e ) &&
				 !is_entry_syncConsumerSubentry( e ) &&
				 update_ctxcsn != SLAP_TOOL_CTXCSN_KEEP ) {
				attr = attr_find( e->e_attrs, slap_schema.si_ad_entryCSN );
				if ( maxcsn.bv_len != 0 ) {
					value_match( &match, slap_schema.si_ad_entryCSN,
						slap_schema.si_ad_entryCSN->ad_type->sat_ordering,
						SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
						&maxcsn, &attr->a_nvals[0], &text );
				} else {
					match = -1;
				}
				if ( match < 0 ) {
					if ( maxcsn.bv_val )
						ch_free( maxcsn.bv_val );
					ber_dupbv( &maxcsn, &attr->a_nvals[0] );
				}
			}
		}

		if ( update_ctxcsn == SLAP_TOOL_CTXCSN_KEEP ) {
			if ( is_entry_syncProviderSubentry( e )) { 
				if ( !LDAP_SLIST_EMPTY( &consumer_subentry )) {
					fprintf( stderr, "%s: consumer and provider subentries "
									 "are both present\n", progname );
					rc = EXIT_FAILURE;
					entry_free( e );
					sei = LDAP_SLIST_FIRST( &consumer_subentry );
					while ( sei ) {
						ch_free( sei->cn.bv_val );
						ch_free( sei->ndn.bv_val );
						ch_free( sei->rdn.bv_val );
						ch_free( sei->cookie.bv_val );
						LDAP_SLIST_REMOVE_HEAD( &consumer_subentry, sei_next );
						ch_free( sei );
						sei = LDAP_SLIST_FIRST( &consumer_subentry );
					}
					break;
				}
				if ( provider_subentry ) {
					fprintf( stderr, "%s: multiple provider subentries are "
							"present : add -w flag to refresh\n", progname );
					rc = EXIT_FAILURE;
					entry_free( e );
					break;
				}
				attr = attr_find( e->e_attrs, slap_schema.si_ad_contextCSN );
				if ( attr == NULL ) {
					entry_free( e );
					continue;
				}
				provider_subentry = 1;
				ber_dupbv( &maxcsn, &attr->a_nvals[0] );
			} else if ( is_entry_syncConsumerSubentry( e )) {
				if ( provider_subentry ) {
					fprintf( stderr, "%s: consumer and provider subentries "
									 "are both present\n", progname );
					rc = EXIT_FAILURE;
					entry_free( e );
					break;
				}

				attr = attr_find( e->e_attrs, slap_schema.si_ad_cn );

				if ( attr == NULL ) {
					entry_free( e );
					continue;
				}

				if ( !LDAP_SLIST_EMPTY( &consumer_subentry )) {
					LDAP_SLIST_FOREACH( sei, &consumer_subentry, sei_next ) {
						value_match( &match, slap_schema.si_ad_cn,
							slap_schema.si_ad_cn->ad_type->sat_equality,
							SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
							&sei->cn, &attr->a_nvals[0], &text );
					}
					if ( !match ) {
						fprintf( stderr, "%s: multiple consumer subentries "
								"have the same id : add -w flag to refresh\n",
								progname );
						rc = EXIT_FAILURE;
						entry_free( e );
						sei = LDAP_SLIST_FIRST( &consumer_subentry );
						while ( sei ) {
							ch_free( sei->cn.bv_val );
							ch_free( sei->ndn.bv_val );
							ch_free( sei->rdn.bv_val );
							ch_free( sei->cookie.bv_val );
							LDAP_SLIST_REMOVE_HEAD( &consumer_subentry, sei_next );
							ch_free( sei );
							sei = LDAP_SLIST_FIRST( &consumer_subentry );
						}
						break;
					}
				}
				sei = ch_calloc( 1, sizeof( struct subentryinfo ));
				ber_dupbv( &sei->cn, &attr->a_nvals[0] );
				ber_dupbv( &sei->ndn, &e->e_nname );
				dnExtractRdn( &sei->ndn, &sei->rdn, NULL );
				attr = attr_find( e->e_attrs, slap_schema.si_ad_syncreplCookie );
				if ( attr == NULL ) {
					ch_free( sei->cn.bv_val );
					ch_free( sei->ndn.bv_val );
					ch_free( sei->rdn.bv_val );
					ch_free( sei->cookie.bv_val );
					ch_free( sei );
					entry_free( e );
					continue;
				}
				ber_dupbv( &sei->cookie, &attr->a_nvals[0] );
				LDAP_SLIST_INSERT_HEAD( &consumer_subentry, sei, sei_next );
			}
		}

		if ( !is_entry_syncProviderSubentry( e ) &&
			 !is_entry_syncConsumerSubentry( e )) {
			if (!dryrun) {
				ID id = be->be_entry_put( be, e, &bvtext );
				if( id == NOID ) {
					fprintf( stderr, "%s: could not add entry dn=\"%s\" "
									 "(line=%d): %s\n", progname, e->e_dn,
									 lineno, bvtext.bv_val );
					rc = EXIT_FAILURE;
					entry_free( e );
					if( continuemode ) continue;
					break;
				}
	
				if ( verbose ) {
					fprintf( stderr, "added: \"%s\" (%08lx)\n",
						e->e_dn, (long) id );
				}
			} else {
				if ( verbose ) {
					fprintf( stderr, "(dry) added: \"%s\"\n", e->e_dn );
				}
			}
		}

		entry_free( e );
	}

	bvtext.bv_len = textlen;
	bvtext.bv_val = textbuf;
	bvtext.bv_val[0] = '\0';

	if ( !LDAP_SLIST_EMPTY( &consumer_subentry )) {
		maxcsn.bv_len = 0;
		maxcsn.bv_val = NULL;
		LDAP_SLIST_FOREACH( sei, &consumer_subentry, sei_next ) {
			if ( maxcsn.bv_len != 0 ) {
				value_match( &match, slap_schema.si_ad_syncreplCookie,
					slap_schema.si_ad_syncreplCookie->ad_type->sat_ordering,
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					&maxcsn, &sei->cookie, &text );
			} else {
				match = -1;
			}
			if ( match < 0 ) {
				if ( maxcsn.bv_val )
					ch_free( maxcsn.bv_val );
				ber_dupbv( &maxcsn, &sei->cookie );
			}
		}
	}

	if ( SLAP_LASTMOD(be) && replica_promotion ) {
		if ( provider_subentry || update_ctxcsn == SLAP_TOOL_CTXCSN_BATCH ||
			 !LDAP_SLIST_EMPTY( &consumer_subentry )) {
			build_new_dn( &ctxcsn_ndn, &be->be_nsuffix[0],
						  (struct berval *)&slap_ldapsync_cn_bv, NULL );
			ctxcsn_id = be->be_dn2id_get( be, &ctxcsn_ndn );
		
			if ( ctxcsn_id == NOID ) {
				ctxcsn_e = slap_create_context_csn_entry( be, &maxcsn );
				if ( !dryrun ) {
					ctxcsn_id = be->be_entry_put( be, ctxcsn_e, &bvtext );
					if( ctxcsn_id == NOID ) {
						fprintf( stderr, "%s: could not add ctxcsn subentry\n",
										 progname);
						rc = EXIT_FAILURE;
					}
					if ( verbose ) {
						fprintf( stderr, "added: \"%s\" (%08lx)\n",
										 ctxcsn_e->e_dn, (long) ctxcsn_id );
					}
				} else {
					if ( verbose ) {
						fprintf( stderr, "(dry) added: \"%s\"\n", ctxcsn_e->e_dn );
					}
				}
				entry_free( ctxcsn_e );
			} else {
				ret = be->be_id2entry_get( be, ctxcsn_id, &ctxcsn_e );
				if ( ret == LDAP_SUCCESS ) {
					attr = attr_find( ctxcsn_e->e_attrs,
										slap_schema.si_ad_contextCSN );
					AC_MEMCPY( attr->a_vals[0].bv_val, maxcsn.bv_val, maxcsn.bv_len );
					attr->a_vals[0].bv_val[maxcsn.bv_len] = '\0';
					attr->a_vals[0].bv_len = maxcsn.bv_len;
					if ( !dryrun ) {
						ctxcsn_id = be->be_entry_modify( be, ctxcsn_e, &bvtext );
						if( ctxcsn_id == NOID ) {
							fprintf( stderr, "%s: could not modify ctxcsn "
											 "subentry\n", progname);
							rc = EXIT_FAILURE;
						}
						if ( verbose ) {
							fprintf( stderr, "modified: \"%s\" (%08lx)\n",
											 ctxcsn_e->e_dn, (long) ctxcsn_id );
						}
					} else {
						if ( verbose ) {
							fprintf( stderr, "(dry) modified: \"%s\"\n",
											 ctxcsn_e->e_dn );
						}
					}
				} else {
					fprintf( stderr, "%s: could not modify ctxcsn subentry\n",
									 progname);
					rc = EXIT_FAILURE;
				}
			}
		} 
	} else if ( SLAP_LASTMOD(be) && replica_demotion &&
				( update_ctxcsn == SLAP_TOOL_CTXCSN_BATCH ||
				provider_subentry )) {

		ber_dupbv( &slap_syncrepl_bv, (struct berval *) &slap_syncrepl_bvc );
		ber_dupbv( &slap_syncrepl_cn_bv,
					(struct berval *) &slap_syncrepl_cn_bvc );

		if ( replica_id_list == NULL ) {
			replica_id_list = ch_calloc( 2, sizeof( int ));
			replica_id_list[0] = 0;
			replica_id_list[1] = -1;
		}

		for ( i = 0; replica_id_list[i] > -1 ; i++ ) {
			slap_syncrepl_bv.bv_len = snprintf( slap_syncrepl_bv.bv_val,
									slap_syncrepl_bvc.bv_len,
									"syncrepl%d", replica_id_list[i] );
			slap_syncrepl_cn_bv.bv_len = snprintf( slap_syncrepl_cn_bv.bv_val,
										slap_syncrepl_cn_bvc.bv_len,
										"cn=syncrepl%d", replica_id_list[i] );
			build_new_dn( &ctxcsn_ndn, &be->be_nsuffix[0],
						  (struct berval *)&slap_syncrepl_cn_bv, NULL );
			ctxcsn_id = be->be_dn2id_get( be, &ctxcsn_ndn );

			if ( ctxcsn_id == NOID ) {
				ctxcsn_e = slap_create_syncrepl_entry( be, &maxcsn,
												&slap_syncrepl_cn_bv,
												&slap_syncrepl_bv );
				if ( !dryrun ) {
					ctxcsn_id = be->be_entry_put( be, ctxcsn_e, &bvtext );
					if( ctxcsn_id == NOID ) {
						fprintf( stderr, "%s: could not add ctxcsn subentry\n",
										 progname);
						rc = EXIT_FAILURE;
					}
					if ( verbose ) {
						fprintf( stderr, "added: \"%s\" (%08lx)\n",
										 ctxcsn_e->e_dn, (long) ctxcsn_id );
					}
				} else {
					if ( verbose ) {
						fprintf( stderr, "(dry) added: \"%s\"\n",
											ctxcsn_e->e_dn );
					}
				}
				entry_free( ctxcsn_e );
			} else {
				ret = be->be_id2entry_get( be, ctxcsn_id, &ctxcsn_e );
				if ( ret == LDAP_SUCCESS ) {
					attr = attr_find( ctxcsn_e->e_attrs,
									  slap_schema.si_ad_syncreplCookie );
					AC_MEMCPY( attr->a_vals[0].bv_val, maxcsn.bv_val, maxcsn.bv_len );
					attr->a_vals[0].bv_val[maxcsn.bv_len] = '\0';
					attr->a_vals[0].bv_len = maxcsn.bv_len;
					if ( !dryrun ) {
						ctxcsn_id = be->be_entry_modify( be,
											ctxcsn_e, &bvtext );
						if( ctxcsn_id == NOID ) {
							fprintf( stderr, "%s: could not modify ctxcsn "
											 "subentry\n", progname);
							rc = EXIT_FAILURE;
						}
						if ( verbose ) {
							fprintf( stderr, "modified: \"%s\" (%08lx)\n",
											 ctxcsn_e->e_dn, (long) ctxcsn_id );
						}
					} else {
						if ( verbose ) {
							fprintf( stderr, "(dry) modified: \"%s\"\n",
											 ctxcsn_e->e_dn );
						}
					}
				} else {
					fprintf( stderr, "%s: could not modify ctxcsn subentry\n",
									 progname);
					rc = EXIT_FAILURE;
				}
			}
		}
		
		if ( slap_syncrepl_bv.bv_val ) {
			ch_free( slap_syncrepl_bv.bv_val );
		}
		if ( slap_syncrepl_cn_bv.bv_val ) {
			ch_free( slap_syncrepl_cn_bv.bv_val );
		}
	} else if ( SLAP_LASTMOD(be) && replica_demotion &&
				!LDAP_SLIST_EMPTY( &consumer_subentry )) {

		LDAP_SLIST_FOREACH( sei, &consumer_subentry, sei_next ) {
			ctxcsn_id = be->be_dn2id_get( be, &sei->ndn );

			if ( ctxcsn_id == NOID ) {
				ctxcsn_e = slap_create_syncrepl_entry( be, &sei->cookie,
												&sei->rdn, &sei->cn );
				if ( !dryrun ) {
					ctxcsn_id = be->be_entry_put( be, ctxcsn_e, &bvtext );
					if( ctxcsn_id == NOID ) {
						fprintf( stderr, "%s: could not add ctxcsn subentry\n",
										 progname);
						rc = EXIT_FAILURE;
					}
					if ( verbose ) {
						fprintf( stderr, "added: \"%s\" (%08lx)\n",
										 ctxcsn_e->e_dn, (long) ctxcsn_id );
					}
				} else {
					if ( verbose ) {
						fprintf( stderr, "(dry) added: \"%s\"\n",
											ctxcsn_e->e_dn );
					}
				}
				entry_free( ctxcsn_e );
			} else {
				ret = be->be_id2entry_get( be, ctxcsn_id, &ctxcsn_e );
				if ( ret == LDAP_SUCCESS ) {
					attr = attr_find( ctxcsn_e->e_attrs,
									  slap_schema.si_ad_syncreplCookie );
					AC_MEMCPY( attr->a_vals[0].bv_val, maxcsn.bv_val, maxcsn.bv_len );
					attr->a_vals[0].bv_val[maxcsn.bv_len] = '\0';
					attr->a_vals[0].bv_len = maxcsn.bv_len;
					if ( !dryrun ) {
						ctxcsn_id = be->be_entry_modify( be,
											ctxcsn_e, &bvtext );
						if( ctxcsn_id == NOID ) {
							fprintf( stderr, "%s: could not modify ctxcsn "
											 "subentry\n", progname);
							rc = EXIT_FAILURE;
						}
						if ( verbose ) {
							fprintf( stderr, "modified: \"%s\" (%08lx)\n",
											 ctxcsn_e->e_dn, (long) ctxcsn_id );
						}
					} else {
						if ( verbose ) {
							fprintf( stderr, "(dry) modified: \"%s\"\n",
											 ctxcsn_e->e_dn );
						}
					}
				} else {
					fprintf( stderr, "%s: could not modify ctxcsn subentry\n",
									 progname);
					rc = EXIT_FAILURE;
				}
			}
		}
		
		if ( slap_syncrepl_bv.bv_val ) {
			ch_free( slap_syncrepl_bv.bv_val );
		}
		if ( slap_syncrepl_cn_bv.bv_val ) {
			ch_free( slap_syncrepl_cn_bv.bv_val );
		}
	}

	sei = LDAP_SLIST_FIRST( &consumer_subentry );
	while ( sei ) {
		ch_free( sei->cn.bv_val );
		ch_free( sei->ndn.bv_val );
		ch_free( sei->rdn.bv_val );
		ch_free( sei->cookie.bv_val );
		LDAP_SLIST_REMOVE_HEAD( &consumer_subentry, sei_next );
		ch_free( sei );
		sei = LDAP_SLIST_FIRST( &consumer_subentry );
	}

	ch_free( buf );

	if( be->be_entry_close( be )) rc = EXIT_FAILURE;

	if( be->be_sync ) {
		be->be_sync( be );
	}

	slap_tool_destroy();
	return rc;
}
