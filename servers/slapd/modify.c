/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

static void	modlist_free(LDAPModList *ml);
static void mods_free(Modifications *mods);

#ifdef SLAPD_SCHEMA_NOT_COMPAT
/* static */ int modlist2mods(
	LDAPModList *ml,
	Modifications **mods,
	char **text );
#endif

static int add_modified_attrs( Operation *op, Modifications **modlist );

int
do_modify(
    Connection	*conn,
    Operation	*op
)
{
	char		*dn, *ndn;
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

	Debug( LDAP_DEBUG_TRACE, "do_modify\n", 0, 0, 0 );

	if( op->o_bind_in_progress ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: SASL bind in progress.\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_SASL_BIND_IN_PROGRESS,
			NULL, "SASL bind in progress", NULL, NULL );
		return LDAP_SASL_BIND_IN_PROGRESS;
	}

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
		return -1;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", dn, 0, 0 );

	ndn = ch_strdup( dn );

	if(	dn_normalize( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: invalid dn (%s)\n", dn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

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
			rc = -1;
			goto cleanup;
		}

		(*modtail)->ml_op = mop;
		
		if ( (*modtail)->ml_op != LDAP_MOD_ADD &&
		    (*modtail)->ml_op != LDAP_MOD_DELETE &&
		    (*modtail)->ml_op != LDAP_MOD_REPLACE )
		{
			Debug( LDAP_DEBUG_ANY,
				"do_modify: invalid modify operation (%ld)\n",
				(long) (*modtail)->ml_op, 0, 0 );
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			    NULL, "unrecognized modify operation", NULL, NULL );
			rc = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}

		if ( (*modtail)->ml_bvalues == NULL && (
			(*modtail)->ml_op != LDAP_MOD_REPLACE &&
			(*modtail)->ml_op != LDAP_MOD_DELETE ) )
		{
			Debug( LDAP_DEBUG_ANY,
				"do_modify: invalid modify operation (%ld) without values\n",
				(long) (*modtail)->ml_op, 0, 0 );
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			    NULL, "unrecognized modify operation without values",
				NULL, NULL );
			rc = LDAP_PROTOCOL_ERROR;
			goto cleanup;
		}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
		attr_normalize( (*modtail)->ml_type );
#endif

		modtail = &(*modtail)->ml_next;
	}
	*modtail = NULL;

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: get_ctrls failed\n", 0, 0, 0 );
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

	/* make sure this backend recongizes critical controls */
	rc = backend_check_controls( be, conn, op ) ;

	if( rc != LDAP_SUCCESS ) {
		send_ldap_result( conn, op, rc,
			NULL, NULL, NULL, NULL );
		goto cleanup;
	}

	if ( global_readonly || be->be_readonly ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: database is read-only\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
		                  NULL, "database is read-only", NULL, NULL );
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
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			char *text;
			rc = modlist2mods( modlist, &mods, &text );

			if( rc != LDAP_SUCCESS ) {
				send_ldap_result( conn, op, rc,
					NULL, text, NULL, NULL );
				goto cleanup;
			}
#else
			mods = modlist;
			modlist = NULL;
#endif

			if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
				global_lastmod == ON)) && be->be_update_ndn == NULL )
			{
				rc = add_modified_attrs( op, &mods );

				if( rc != LDAP_SUCCESS ) {
					send_ldap_result( conn, op, rc,
						NULL, "no-user-modification attribute type",
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
		    NULL, "Function not implemented", NULL, NULL );
	}

cleanup:
	free( dn );
	free( ndn );
	if ( modlist != NULL )
		modlist_free( modlist );
	if ( mods != NULL )
		mods_free( mods );
	return rc;
}

static int
add_modified_attrs( Operation *op, Modifications **modlist )
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	/* not yet implemented */
#else
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	Modifications		*m;
	struct tm	*ltm;
	time_t		currenttime;

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to modify these attrs */
	for ( m = *modlist; m != NULL; m = m->ml_next ) {
		if ( oc_check_op_no_usermod_attr( m->ml_type ) ) {
			return LDAP_CONSTRAINT_VIOLATION;
		}
	}

	if ( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		bv.bv_val = "<anonymous>";
		bv.bv_len = sizeof("<anonymous>")-1;
	} else {
		bv.bv_val = op->o_dn;
		bv.bv_len = strlen( bv.bv_val );
	}
	m = (Modifications *) ch_calloc( 1, sizeof(Modifications) );
	m->ml_type = ch_strdup( "modifiersname" );
	m->ml_op = LDAP_MOD_REPLACE;
	m->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	m->ml_bvalues[0] = ber_bvdup( &bv );
	m->ml_next = *modlist;
	*modlist = m;

	currenttime = slap_get_time();
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );
	m = (Modifications *) ch_calloc( 1, sizeof(Modifications) );
	m->ml_type = ch_strdup( "modifytimestamp" );
	m->ml_op = LDAP_MOD_REPLACE;
	m->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	m->ml_bvalues[0] = ber_bvdup( &bv );
	m->ml_next = *modlist;
	*modlist = m;
#endif

	return LDAP_SUCCESS;
}

static void
mod_free(
	Modification	*mod,
	int				freeit
)
{
#ifdef SLAPD_SCHEMA_NOT_COMPAT
	ad_free( &mod->sm_desc, 0 );
#else
	if (mod->sm_desc) {
		free( mod->sm_desc );
	}
#endif

	if ( mod->sm_bvalues != NULL )
		ber_bvecfree( mod->sm_bvalues );

	if( freeit )
		free( mod );
}

static void
mods_free(
    Modifications	*ml
)
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}

static void
modlist_free(
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
