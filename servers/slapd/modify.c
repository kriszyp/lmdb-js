/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "lutil.h"

#include "ldap_pvt.h"
#include "slap.h"

int
do_modify(
    Connection	*conn,
    Operation	*op )
{
	struct berval dn = { 0, NULL };
	struct berval pdn = { 0, NULL };
	struct berval ndn = { 0, NULL };
	char		*last;
	ber_tag_t	tag;
	ber_len_t	len;
	Modifications	*modlist = NULL;
	Modifications	**modtail = &modlist;
#ifdef LDAP_DEBUG
	Modifications *tmp;
#endif
	Backend		*be;
	int rc;
	const char	*text;
	int manageDSAit;

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "do_modify: enter\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "do_modify\n", 0, 0, 0 );
#endif

	/*
	 * Parse the modify request.  It looks like this:
	 *
	 *	ModifyRequest := [APPLICATION 6] SEQUENCE {
	 *		name	DistinguishedName,
	 *		mods	SEQUENCE OF SEQUENCE {
	 *			operation	ENUMERATED {
	 *				add	(0),
	 *				delete	(1),
	 *				replace	(2)
	 *			},
	 *			modification	SEQUENCE {
	 *				type	AttributeType,
	 *				values	SET OF AttributeValue
	 *			}
	 *		}
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{m" /*}*/, &dn ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modify: ber_scanf failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modify: ber_scanf failed\n", 0, 0, 0 );
#endif

		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, "do_modify: dn (%s)\n", dn.bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn.bv_val, 0, 0 );
#endif


	/* collect modifications & save for later */

	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		ber_int_t mop;
		Modifications tmp, *mod;


		if ( ber_scanf( op->o_ber, "{i{m[W]}}", &mop,
		    &tmp.sml_type, &tmp.sml_bvalues )
		    == LBER_ERROR )
		{
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding modlist error" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		mod = (Modifications *) ch_malloc( sizeof(Modifications) );
		mod->sml_op = mop;
		mod->sml_type = tmp.sml_type;
		mod->sml_bvalues = tmp.sml_bvalues;
		mod->sml_desc = NULL;
		mod->sml_next =NULL;
		*modtail = mod;

		switch( mop ) {
		case LDAP_MOD_ADD:
			if ( mod->sml_bvalues == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"do_modify: modify/add operation (%ld) requires values\n",
					(long)mop, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"do_modify: modify/add operation (%ld) requires values\n",
					(long) mop, 0, 0 );
#endif

				send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
					NULL, "modify/add operation requires values",
					NULL, NULL );
				rc = LDAP_PROTOCOL_ERROR;
				goto cleanup;
			}

			/* fall through */

		case LDAP_MOD_DELETE:
		case LDAP_MOD_REPLACE:
			break;

		default: {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, ERR, 
					"do_modify: invalid modify operation (%ld)\n", (long)mop, 0, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"do_modify: invalid modify operation (%ld)\n",
					(long) mop, 0, 0 );
#endif

				send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
					NULL, "unrecognized modify operation", NULL, NULL );
				rc = LDAP_PROTOCOL_ERROR;
				goto cleanup;
			}
		}

		modtail = &mod->sml_next;
	}
	*modtail = NULL;

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "do_modify: get_ctrls failed\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modify: get_ctrls failed\n", 0, 0, 0 );
#endif

		goto cleanup;
	}

	rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn );
	if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, INFO, "do_modify: conn %d  invalid dn (%s)\n",
			conn->c_connid, dn.bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_modify: invalid dn (%s)\n", dn.bv_val, 0, 0 );
#endif
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( ndn.bv_len == 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_modify: attempt to modify root DSE.\n",0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_modify: root dse!\n", 0, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "modify upon the root DSE not supported", NULL, NULL );
		goto cleanup;

#if defined( SLAPD_SCHEMA_DN )
	} else if ( bvmatch( &ndn, &global_schemandn ) ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR,
			"do_modify: attempt to modify subschema subentry.\n" , 0, 0, 0  );
#else
		Debug( LDAP_DEBUG_ANY, "do_modify: subschema subentry!\n", 0, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "modification of subschema subentry not supported",
			NULL, NULL );
		goto cleanup;
#endif
	}

#ifdef LDAP_DEBUG
#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, DETAIL1, "do_modify: modifications:\n", 0, 0, 0  );
#else
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
#endif

	for ( tmp = modlist; tmp != NULL; tmp = tmp->sml_next ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, DETAIL1, "\t%s:  %s\n", 
			tmp->sml_op == LDAP_MOD_ADD ?
			"add" : (tmp->sml_op == LDAP_MOD_DELETE ?
			"delete" : "replace"), tmp->sml_type.bv_val, 0 );

		if ( tmp->sml_bvalues == NULL ) {
			LDAP_LOG( OPERATION, DETAIL1, "\t\tno values", 0, 0, 0 );
		} else if ( tmp->sml_bvalues[0].bv_val == NULL ) {
			LDAP_LOG( OPERATION, DETAIL1, "\t\tzero values", 0, 0, 0 );
		} else if ( tmp->sml_bvalues[1].bv_val == NULL ) {
			LDAP_LOG( OPERATION, DETAIL1, "\t\tone value", 0, 0, 0 );
		} else {
			LDAP_LOG( OPERATION, DETAIL1, "\t\tmultiple values", 0, 0, 0 );
		}

#else
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n",
			tmp->sml_op == LDAP_MOD_ADD
				? "add" : (tmp->sml_op == LDAP_MOD_DELETE
					? "delete" : "replace"), tmp->sml_type.bv_val, 0 );

		if ( tmp->sml_bvalues == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tno values", NULL, NULL );
		} else if ( tmp->sml_bvalues[0].bv_val == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tzero values", NULL, NULL );
		} else if ( tmp->sml_bvalues[1].bv_val == NULL ) {
			Debug( LDAP_DEBUG_ARGS, "%s, length %ld\n",
			   "\t\tone value", (long) tmp->sml_bvalues[0].bv_len, NULL );
		} else {
			Debug( LDAP_DEBUG_ARGS, "%s\n",
			   "\t\tmultiple values", NULL, NULL );
		}
#endif
	}
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%lu op=%lu MOD dn=\"%s\"\n",
	    op->o_connid, op->o_opid, dn.bv_val, 0, 0 );

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( &ndn, manageDSAit, 0 )) == NULL ) {
		BerVarray ref = referral_rewrite( default_referral,
			NULL, &pdn, LDAP_SCOPE_DEFAULT );

		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, ref ? ref : default_referral, NULL );

		ber_bvarray_free( ref );
		goto cleanup;
	}

	/* check restrictions */
	rc = backend_check_restrictions( be, conn, op, NULL, &text ) ;
	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, text, NULL, NULL );
		goto cleanup;
	}

	/* check for referrals */
	rc = backend_check_referrals( be, conn, op, &pdn, &ndn );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* deref suffix alias if appropriate */
	suffix_alias( be, &ndn );

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modify ) {
		/* do the update here */
		int repl_user = be_isupdate( be, &op->o_ndn );
#ifndef SLAPD_MULTIMASTER
		/* Multimaster slapd does not have to check for replicator dn
		 * because it accepts each modify request
		 */
		if ( !be->be_update_ndn.bv_len || repl_user )
#endif
		{
			int update = be->be_update_ndn.bv_len;
			const char *text;
			char textbuf[SLAP_TEXT_BUFLEN];
			size_t textlen = sizeof textbuf;

			rc = slap_mods_check( modlist, update, &text,
				textbuf, textlen );

			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto cleanup;
			}

			if ( !repl_user ) {
				for( modtail = &modlist;
					*modtail != NULL;
					modtail = &(*modtail)->sml_next )
				{
					/* empty */
				}

				rc = slap_mods_opattrs( be, op, modlist, modtail, &text,
					textbuf, textlen );
				if( rc != LDAP_SUCCESS ) {
					send_ldap_result( conn, op, rc,
						NULL, text,
						NULL, NULL );
					goto cleanup;
				}
			}

			if ( (*be->be_modify)( be, conn, op, &pdn, &ndn, modlist ) == 0
#ifdef SLAPD_MULTIMASTER
				&& !repl_user
#endif
			) {
				/* but we log only the ones not from a replicator user */
				replog( be, op, &pdn, &ndn, modlist );
			}

#ifndef SLAPD_MULTIMASTER
		/* send a referral */
		} else {
			BerVarray defref = be->be_update_refs
				? be->be_update_refs : default_referral;
			BerVarray ref = referral_rewrite( defref,
				NULL, &pdn, LDAP_SCOPE_DEFAULT );

			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				ref ? ref : defref, NULL );

			ber_bvarray_free( ref );
#endif
		}
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
		    NULL, "operation not supported within namingContext",
			NULL, NULL );
	}

cleanup:
	free( pdn.bv_val );
	free( ndn.bv_val );
	if ( modlist != NULL )
		slap_mods_free( modlist );
	return rc;
}

/*
 * Do basic attribute type checking and syntax validation.
 */
int slap_mods_check(
	Modifications *ml,
	int update,
	const char **text,
	char *textbuf,
	size_t textlen )
{
	int rc;

	for( ; ml != NULL; ml = ml->sml_next ) {
		AttributeDescription *ad = NULL;

		/* convert to attribute description */
		rc = slap_bv2ad( &ml->sml_type, &ml->sml_desc, text );

		if( rc != LDAP_SUCCESS ) {
			snprintf( textbuf, textlen, "%s: %s",
				ml->sml_type.bv_val, *text );
			*text = textbuf;
			return rc;
		}

		ad = ml->sml_desc;

		if( slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& !slap_ad_is_binary( ad ))
		{
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
				"%s: requires ;binary transfer",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( !slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& slap_ad_is_binary( ad ))
		{
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
				"%s: disallows ;binary transfer",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if( slap_ad_is_lang_range( ad )) {
			/* attribute requires binary transfer */
			snprintf( textbuf, textlen,
				"%s: inappropriate use of language range option",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_UNDEFINED_TYPE;
		}

		if (!update && is_at_no_user_mod( ad->ad_type )) {
			/* user modification disallowed */
			snprintf( textbuf, textlen,
				"%s: no user modification allowed",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		if ( is_at_obsolete( ad->ad_type ) &&
			( ml->sml_op == LDAP_MOD_ADD || ml->sml_bvalues != NULL ) )
		{
			/*
			 * attribute is obsolete,
			 * only allow replace/delete with no values
			 */
			snprintf( textbuf, textlen,
				"%s: attribute is obsolete",
				ml->sml_type.bv_val );
			*text = textbuf;
			return LDAP_CONSTRAINT_VIOLATION;
		}

		/*
		 * check values
		 */
		if( ml->sml_bvalues != NULL ) {
			ber_len_t nvals;
			slap_syntax_validate_func *validate =
				ad->ad_type->sat_syntax->ssyn_validate;
			slap_syntax_transform_func *pretty =
				ad->ad_type->sat_syntax->ssyn_pretty;
 
			if( !pretty && !validate ) {
				*text = "no validator for syntax";
				snprintf( textbuf, textlen,
					"%s: no validator for syntax %s",
					ml->sml_type.bv_val,
					ad->ad_type->sat_syntax->ssyn_oid );
				*text = textbuf;
				return LDAP_INVALID_SYNTAX;
			}

			/*
			 * check that each value is valid per syntax
			 *	and pretty if appropriate
			 */
			for( nvals = 0; ml->sml_bvalues[nvals].bv_val; nvals++ ) {
				struct berval pval;
				if( pretty ) {
					rc = pretty( ad->ad_type->sat_syntax,
						&ml->sml_bvalues[nvals], &pval );
				} else {
					rc = validate( ad->ad_type->sat_syntax,
						&ml->sml_bvalues[nvals] );
				}

				if( rc != 0 ) {
					snprintf( textbuf, textlen,
						"%s: value #%ld invalid per syntax",
						ml->sml_type.bv_val, (long) nvals );
					*text = textbuf;
					return LDAP_INVALID_SYNTAX;
				}

				if( pretty ) {
					ber_memfree( ml->sml_bvalues[nvals].bv_val );
					ml->sml_bvalues[nvals] = pval;
				}
			}

			/*
			 * a rough single value check... an additional check is needed
			 * to catch add of single value to existing single valued attribute
			 */
			if( ( ml->sml_op == LDAP_MOD_ADD || ml->sml_op == LDAP_MOD_REPLACE )
				&& nvals > 1 && is_at_single_value( ad->ad_type ))
			{
				snprintf( textbuf, textlen,
					"%s: multiple value provided",
					ml->sml_type.bv_val );
				*text = textbuf;
				return LDAP_CONSTRAINT_VIOLATION;
			}
		}
	}

	return LDAP_SUCCESS;
}

int slap_mods_opattrs(
	Backend *be,
	Operation *op,
	Modifications *mods,
	Modifications **modtail,
	const char **text,
	char *textbuf, size_t textlen )
{
	struct berval name, timestamp, csn;
	char timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
	char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
	Modifications *mod;

	int mop = op->o_tag == LDAP_REQ_ADD
		? LDAP_MOD_ADD : LDAP_MOD_REPLACE;

	assert( modtail != NULL );
	assert( *modtail == NULL );

	if( SLAP_LASTMOD(be) ) {
		struct tm *ltm;
		time_t now = slap_get_time();

		ldap_pvt_thread_mutex_lock( &gmtime_mutex );
		ltm = gmtime( &now );
		lutil_gentime( timebuf, sizeof(timebuf), ltm );

		csn.bv_len = lutil_csnstr( csnbuf, sizeof( csnbuf ), 0, 0 );
		ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
		csn.bv_val = csnbuf;

		timestamp.bv_val = timebuf;
		timestamp.bv_len = strlen(timebuf);

		if( op->o_dn.bv_len == 0 ) {
			name.bv_val = SLAPD_ANONYMOUS;
			name.bv_len = sizeof(SLAPD_ANONYMOUS)-1;
		} else {
			name = op->o_dn;
		}
	}

	if( op->o_tag == LDAP_REQ_ADD ) {
		struct berval tmpval;

		if( global_schemacheck ) {
			int rc = mods_structural_class( mods, &tmpval,
				text, textbuf, textlen );
			if( rc != LDAP_SUCCESS ) {
				return rc;
			}

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_structuralObjectClass;
			mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_bvalues[0], &tmpval );
			mod->sml_bvalues[1].bv_val = NULL;
			assert( mod->sml_bvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;
		}

		if( SLAP_LASTMOD(be) ) {
			char uuidbuf[ LDAP_LUTIL_UUIDSTR_BUFSIZE ];

			tmpval.bv_len = lutil_uuidstr( uuidbuf, sizeof( uuidbuf ) );
			tmpval.bv_val = uuidbuf;
		
			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_entryUUID;
			mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_bvalues[0], &tmpval );
			mod->sml_bvalues[1].bv_val = NULL;
			assert( mod->sml_bvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_creatorsName;
			mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_bvalues[0], &name );
			mod->sml_bvalues[1].bv_val = NULL;
			assert( mod->sml_bvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;

			mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
			mod->sml_op = mop;
			mod->sml_type.bv_val = NULL;
			mod->sml_desc = slap_schema.si_ad_createTimestamp;
			mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
			ber_dupbv( &mod->sml_bvalues[0], &timestamp );
			mod->sml_bvalues[1].bv_val = NULL;
			assert( mod->sml_bvalues[0].bv_val );
			*modtail = mod;
			modtail = &mod->sml_next;
		}
	}

	if( SLAP_LASTMOD(be) ) {
		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_entryCSN;
		mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_bvalues[0], &csn );
		mod->sml_bvalues[1].bv_val = NULL;
		assert( mod->sml_bvalues[0].bv_val );
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifiersName;
		mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_bvalues[0], &name );
		mod->sml_bvalues[1].bv_val = NULL;
		assert( mod->sml_bvalues[0].bv_val );
		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_malloc( sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_type.bv_val = NULL;
		mod->sml_desc = slap_schema.si_ad_modifyTimestamp;
		mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
		ber_dupbv( &mod->sml_bvalues[0], &timestamp );
		mod->sml_bvalues[1].bv_val = NULL;
		assert( mod->sml_bvalues[0].bv_val );
		*modtail = mod;
		modtail = &mod->sml_next;
	}

	*modtail = NULL;
	return LDAP_SUCCESS;
}
