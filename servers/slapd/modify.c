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

#include "slap.h"

static void	modlist_free(LDAPModList *ml);

static int add_modified_attrs( Operation *op, LDAPModList **modlist );

int
do_modify(
    Connection	*conn,
    Operation	*op
)
{
	char		*ndn;
	char		*last;
	ber_tag_t	tag;
	ber_len_t	len;
	LDAPModList	*modlist;
	LDAPModList	**modtail;
#ifdef LDAP_DEBUG
	LDAPModList *tmp;
#endif
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

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &ndn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", ndn, 0, 0 );

	if(	dn_normalize_case( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: invalid dn (%s)\n", ndn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		free( ndn );
		return rc;
	}

	/* collect modifications & save for later */
	modlist = NULL;
	modtail = &modlist;

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
			free( ndn );
			free( *modtail );
			*modtail = NULL;
			modlist_free( modlist );
			return -1;
		}

		(*modtail)->ml_op = mop;
		
		if ( (*modtail)->ml_op != LDAP_MOD_ADD &&
		    (*modtail)->ml_op != LDAP_MOD_DELETE &&
		    (*modtail)->ml_op != LDAP_MOD_REPLACE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			    NULL, "unrecognized modify operation", NULL, NULL );
			free( ndn );
			modlist_free( modlist );
			return LDAP_PROTOCOL_ERROR;
		}

		if ( (*modtail)->ml_bvalues == NULL
			&& (*modtail)->ml_op != LDAP_MOD_DELETE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
			    NULL, "unrecognized modify operation", NULL, NULL );
			free( ndn );
			modlist_free( modlist );
			return LDAP_PROTOCOL_ERROR;
		}
		attr_normalize( (*modtail)->ml_type );

		modtail = &(*modtail)->ml_next;
	}
	*modtail = NULL;

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
	for ( tmp = modlist; tmp != NULL; tmp = tmp->ml_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n",
			tmp->ml_op == LDAP_MOD_ADD
				? "add" : (tmp->ml_op == LDAP_MOD_DELETE
					? "delete" : "replace"), tmp->ml_type, 0 );
	}
#endif

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		free( ndn );
		modlist_free( modlist );
		Debug( LDAP_DEBUG_ANY, "do_modify: get_ctrls failed\n", 0, 0, 0 );
		return rc;
	} 

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d MOD dn=\"%s\"\n",
	    op->o_connid, op->o_opid, ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		modlist_free( modlist );
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		return rc;
	}

	if ( global_readonly || be->be_readonly ) {
		Debug( LDAP_DEBUG_ANY, "do_modify: database is read-only\n",
		       0, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
		                  NULL, "database is read-only", NULL, NULL );
		goto done;
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
			if ( (be->be_lastmod == ON || (be->be_lastmod == UNDEFINED &&
				global_lastmod == ON)) && be->be_update_ndn == NULL )
			{
				rc = add_modified_attrs( op, &modlist );

				if( rc != LDAP_SUCCESS ) {
					free( ndn );
					modlist_free( modlist );
					send_ldap_result( conn, op, rc,
						NULL, "no-user-modification attribute type",
						NULL, NULL );
					return rc;
				}
			}

			if ( (*be->be_modify)( be, conn, op, ndn, modlist ) == 0 
#ifdef SLAPD_MULTIMASTER
				&& ( be->be_update_ndn == NULL ||
					strcmp( be->be_update_ndn, op->o_ndn ) != 0 )
#endif
			) {
				/* but we log only the ones not from a replicator user */
				replog( be, op, ndn, modlist );
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

done:
	free( ndn );
	modlist_free( modlist );
	return rc;
}

static int
add_modified_attrs( Operation *op, LDAPModList **modlist )
{
	char		buf[22];
	struct berval	bv;
	struct berval	*bvals[2];
	LDAPModList		*m;
	struct tm	*ltm;
	time_t		currenttime;

	bvals[0] = &bv;
	bvals[1] = NULL;

	/* remove any attempts by the user to modify these attrs */
	for ( m = *modlist; m != NULL; m = m->ml_next ) {
		if ( oc_check_no_usermod_attr( m->ml_type ) ) {
			return LDAP_CONSTRAINT_VIOLATION;
		}
	}

	if ( op->o_dn == NULL || op->o_dn[0] == '\0' ) {
		bv.bv_val = "NULLDN";
		bv.bv_len = strlen( bv.bv_val );
	} else {
		bv.bv_val = op->o_dn;
		bv.bv_len = strlen( bv.bv_val );
	}
	m = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );
	m->ml_type = ch_strdup( "modifiersname" );
	m->ml_op = LDAP_MOD_REPLACE;
	m->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	m->ml_bvalues[0] = ber_bvdup( &bv );
	m->ml_next = *modlist;
	*modlist = m;

	currenttime = slap_get_time();
	ldap_pvt_thread_mutex_lock( &gmtime_mutex );
#ifndef LDAP_LOCALTIME
	ltm = gmtime( &currenttime );
	strftime( buf, sizeof(buf), "%Y%m%d%H%M%SZ", ltm );
#else
	ltm = localtime( &currenttime );
	strftime( buf, sizeof(buf), "%y%m%d%H%M%SZ", ltm );
#endif
	ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

	bv.bv_val = buf;
	bv.bv_len = strlen( bv.bv_val );
	m = (LDAPModList *) ch_calloc( 1, sizeof(LDAPModList) );
	m->ml_type = ch_strdup( "modifytimestamp" );
	m->ml_op = LDAP_MOD_REPLACE;
	m->ml_bvalues = (struct berval **) ch_calloc(2, sizeof(struct berval *));
	m->ml_bvalues[0] = ber_bvdup( &bv );
	m->ml_next = *modlist;
	*modlist = m;

	return LDAP_SUCCESS;
}

static void
modlist_free(
    LDAPModList	*ml
)
{
	LDAPModList *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->ml_next;

		free( ml->ml_type );
		if ( ml->ml_bvalues != NULL )
			ber_bvecfree( ml->ml_bvalues );

		free( ml );
	}
}
