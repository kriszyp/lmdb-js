/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

#include "ldap_pvt.h"
#include "slap.h"


int
do_modify(
    Connection	*conn,
    Operation	*op )
{
	char		*dn, *ndn = NULL;
	char		*last;
	ber_tag_t	tag;
	ber_len_t	len;
	LDAPModList	*modlist = NULL;
	LDAPModList	**modtail = &modlist;
#ifdef LDAP_DEBUG
	LDAPModList *tmp;
#endif
	Modifications *mods = NULL;
	Backend		*be;
	int rc;
	const char	*text;

	Debug( LDAP_DEBUG_TRACE, "do_modify\n", 0, 0, 0 );

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

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn, 0, 0 );

	/* collect modifications & save for later */

	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		ber_int_t mop;

		(*modtail) = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );

		if ( ber_scanf( op->o_ber, "{i{a[V]}}", &mop,
		    &(*modtail)->ml_type, &(*modtail)->ml_bvalues )
		    == LBER_ERROR )
		{
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding modlist error" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		switch( mop ) {
		case LDAP_MOD_ADD:
			if ( (*modtail)->ml_bvalues == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"do_modify: modify/add operation (%ld) requires values\n",
					(long) mop, 0, 0 );
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
				Debug( LDAP_DEBUG_ANY,
					"do_modify: invalid modify operation (%ld)\n",
					(long) mop, 0, 0 );
				send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
					NULL, "unrecognized modify operation", NULL, NULL );
				rc = LDAP_PROTOCOL_ERROR;
				goto cleanup;
			}
		}

		(*modtail)->ml_op = mop;
		modtail = &(*modtail)->ml_next;
	}
	*modtail = NULL;

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: get_ctrls failed\n", 0, 0, 0 );
		goto cleanup;
	}

	ndn = ch_strdup( dn );

	if(	dn_normalize( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: invalid dn (%s)\n", dn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( ndn == '\0' ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: root dse!\n", 0, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "modify upon the root DSE not supported", NULL, NULL );
		goto cleanup;
	}

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
	for ( tmp = modlist; tmp != NULL; tmp = tmp->ml_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n",
			tmp->ml_op == LDAP_MOD_ADD
				? "add" : (tmp->ml_op == LDAP_MOD_DELETE
					? "delete" : "replace"), tmp->ml_type, 0 );
	}
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d MOD dn=\"%s\"\n",
	    op->o_connid, op->o_opid, dn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
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
	rc = backend_check_referrals( be, conn, op, dn, ndn );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	/* deref suffix alias if appropriate */
	ndn = suffix_alias( be, ndn );

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modify ) {
		/* do the update here */
#ifndef SLAPD_MULTIMASTER
		/* we don't have to check for replicator dn
		 * because we accept each modify request
		 */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
#endif
		{
			int update = be->be_update_ndn != NULL;
			const char *text;
			rc = slap_modlist2mods( modlist, update, &mods, &text );

			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto cleanup;
			}

			if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
				global_lastmod == ON)) && !update )
			{
				Modifications **modstail;
				for( modstail = &mods;
					*modstail != NULL;
					modstail = &(*modstail)->sml_next )
				{
					/* empty */
				}
				rc = slap_mods_opattrs( op, modstail, &text );

				if( rc != LDAP_SUCCESS ) {
					send_ldap_result( conn, op, rc,
						NULL, text,
						NULL, NULL );
					goto cleanup;
				}
			}

			if ( (*be->be_modify)( be, conn, op, dn, ndn, mods ) == 0 
#ifdef SLAPD_MULTIMASTER
				&& ( be->be_update_ndn == NULL ||
					strcmp( be->be_update_ndn, op->o_ndn ) != 0 )
#endif
			) {
				/* but we log only the ones not from a replicator user */
				replog( be, op, dn, mods );
			}

#ifndef SLAPD_MULTIMASTER
		/* send a referral */
		} else {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				be->be_update_refs ? be->be_update_refs : default_referral,
				NULL );
#endif
		}
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
		    NULL, "operation not supported within namingContext", NULL, NULL );
	}

cleanup:
	free( dn );
	if( ndn != NULL ) free( ndn );
	if ( modlist != NULL )
		slap_modlist_free( modlist );
	if ( mods != NULL )
		slap_mods_free( mods );
	return rc;
}

/*
 * convert a raw list of modifications to internal format
 * Do basic attribute type checking and syntax validation.
 */
int slap_modlist2mods(
	LDAPModList *ml,
	int update,
	Modifications **mods,
	const char **text )
{
	int rc;
	Modifications **modtail = mods;

	for( ; ml != NULL; ml = ml->ml_next ) {
		Modifications *mod;
		AttributeDescription *ad = NULL;

		mod = (Modifications *)
			ch_calloc( 1, sizeof(Modifications) );

		/* copy the op */
		mod->sml_op = ml->ml_op;

		/* convert to attribute description */
		rc = slap_str2ad( ml->ml_type, &mod->sml_desc, text );

		if( rc != LDAP_SUCCESS ) {
			slap_mods_free( mod );
			return rc;
		}

		ad = mod->sml_desc;

		if( slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& !slap_ad_is_binary( ad ))
		{
			/* attribute requires binary transfer */
			slap_mods_free( mod );
			*text = "attribute requires ;binary transfer";
			return LDAP_UNDEFINED_TYPE;
		}

		if( !slap_syntax_is_binary( ad->ad_type->sat_syntax )
			&& slap_ad_is_binary( ad ))
		{
			/* attribute requires binary transfer */
			slap_mods_free( mod );
			*text = "attribute disallows ;binary transfer";
			return LDAP_UNDEFINED_TYPE;
		}

		if (!update && is_at_no_user_mod( ad->ad_type )) {
			/* user modification disallowed */
			slap_mods_free( mod );
			*text = "no user modification allowed";
			return LDAP_CONSTRAINT_VIOLATION;
		}

		/*
		 * check values
		 */
		if( ml->ml_bvalues != NULL ) {
			ber_len_t nvals;
			slap_syntax_validate_func *validate =
				ad->ad_type->sat_syntax->ssyn_validate;

			if( !validate ) {
				Debug( LDAP_DEBUG_TRACE,
					"modlist2mods: no validator for syntax %s\n",
					ad->ad_type->sat_syntax->ssyn_oid, 0, 0 );
				slap_mods_free( mod );
				*text = "no validator for syntax";
				return LDAP_INVALID_SYNTAX;
			}

			/*
			 * check that each value is valid per syntax
			 */
			for( nvals = 0; ml->ml_bvalues[nvals]; nvals++ ) {
				rc = validate( ad->ad_type->sat_syntax, ml->ml_bvalues[nvals] );

				if( rc != 0 ) {
					slap_mods_free( mod );
					*text = "value contains invalid data";
					return LDAP_INVALID_SYNTAX;
				}
			}

			/*
			 * a rough single value check... an additional check is needed
			 * to catch add of single value to existing single valued attribute
			 */
			if( ( mod->sml_op == LDAP_MOD_ADD || mod->sml_op == LDAP_MOD_REPLACE )
				&& nvals > 1 && is_at_single_value( ad->ad_type ))
			{
				slap_mods_free( mod );
				*text = "multiple values provided";
				return LDAP_INVALID_SYNTAX;
			}
		}

		mod->sml_bvalues = ml->ml_bvalues;
		ml->ml_values = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;
	}

	return LDAP_SUCCESS;
}

int slap_mods_opattrs(
	Operation *op,
	Modifications **modtail,
	const char **text )
{
	struct berval name, timestamp;
	time_t now = slap_get_time();
	char timebuf[22];
	struct tm *ltm;
	Modifications *mod;

	int mop = op->o_tag == LDAP_REQ_ADD
		? LDAP_MOD_ADD : LDAP_MOD_REPLACE;

	assert( modtail != NULL );
	assert( *modtail == NULL );

	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
	ltm = gmtime( &now );
	strftime( timebuf, sizeof(timebuf), "%Y%m%d%H%M%SZ", ltm );
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
	timestamp.bv_val = timebuf;
	timestamp.bv_len = strlen(timebuf);

	if( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		name.bv_val = SLAPD_ANONYMOUS;
		name.bv_len = sizeof(SLAPD_ANONYMOUS)-1;
	} else {
		name.bv_val = op->o_dn;
		name.bv_len = strlen( op->o_dn );
	}

	if( op->o_tag == LDAP_REQ_ADD ) {
		mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_desc = ad_dup( slap_schema.si_ad_creatorsName );
		mod->sml_bvalues = (struct berval **) malloc( 2 * sizeof( struct berval * ) );
		mod->sml_bvalues[0] = ber_bvdup( &name );
		mod->sml_bvalues[1] = NULL;

		*modtail = mod;
		modtail = &mod->sml_next;

		mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ) );
		mod->sml_op = mop;
		mod->sml_desc = ad_dup( slap_schema.si_ad_createTimestamp );
		mod->sml_bvalues = (struct berval **) malloc( 2 * sizeof( struct berval * ) );
		mod->sml_bvalues[0] = ber_bvdup( &timestamp );
		mod->sml_bvalues[1] = NULL;
		*modtail = mod;
		modtail = &mod->sml_next;
	}

	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ) );
	mod->sml_op = mop;
	mod->sml_desc = ad_dup( slap_schema.si_ad_modifiersName );
	mod->sml_bvalues = (struct berval **) malloc( 2 * sizeof( struct berval * ) );
	mod->sml_bvalues[0] = ber_bvdup( &name );
	mod->sml_bvalues[1] = NULL;
	*modtail = mod;
	modtail = &mod->sml_next;

	mod = (Modifications *) ch_calloc( 1, sizeof( Modifications ) );
	mod->sml_op = mop;
	mod->sml_desc = ad_dup( slap_schema.si_ad_modifyTimestamp );
	mod->sml_bvalues = (struct berval **) malloc( 2 * sizeof( struct berval * ) );
	mod->sml_bvalues[0] = ber_bvdup( &timestamp );
	mod->sml_bvalues[1] = NULL;
	*modtail = mod;
	modtail = &mod->sml_next;

	return LDAP_SUCCESS;
}


void
slap_mod_free(
	Modification	*mod,
	int				freeit
)
{
	ad_free( mod->sm_desc, 1 );

	if ( mod->sm_bvalues != NULL )
		ber_bvecfree( mod->sm_bvalues );

	if( freeit )
		free( mod );
}

void
slap_mods_free(
    Modifications	*ml
)
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		slap_mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}

void
slap_modlist_free(
    LDAPModList	*ml
)
{
	LDAPModList *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->ml_next;

		if (ml->ml_type)
			free( ml->ml_type );

		if ( ml->ml_bvalues != NULL )
			ber_bvecfree( ml->ml_bvalues );

		free( ml );
	}
}
