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

static void	modlist_free(LDAPMod *mods);


void
do_modify(
    Connection	*conn,
    Operation	*op
)
{
	char		*ndn;
	char		*last;
	unsigned long	tag, len;
	LDAPMod		*mods, *tmp;
	LDAPMod		**modtail;
	Backend		*be;

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

	if ( ber_scanf( op->o_ber, "{a" /*}*/, &ndn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}

	Debug( LDAP_DEBUG_ARGS, "do_modify: dn (%s)\n", ndn, 0, 0 );

	(void) dn_normalize_case( ndn );

	/* collect modifications & save for later */
	mods = NULL;
	modtail = &mods;
	for ( tag = ber_first_element( op->o_ber, &len, &last );
	    tag != LBER_DEFAULT;
	    tag = ber_next_element( op->o_ber, &len, last ) )
	{
		(*modtail) = (LDAPMod *) ch_calloc( 1, sizeof(LDAPMod) );

		if ( ber_scanf( op->o_ber, "{i{a[V]}}", &(*modtail)->mod_op,
		    &(*modtail)->mod_type, &(*modtail)->mod_bvalues )
		    == LBER_ERROR )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "decoding error" );
			free( ndn );
			free( *modtail );
			*modtail = NULL;
			modlist_free( mods );
			return;
		}

		if ( (*modtail)->mod_op != LDAP_MOD_ADD &&
		    (*modtail)->mod_op != LDAP_MOD_DELETE &&
		    (*modtail)->mod_op != LDAP_MOD_REPLACE )
		{
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "unrecognized modify operation" );
			free( ndn );
			modlist_free( mods );
			return;
		}

		if ( (*modtail)->mod_bvalues == NULL && (*modtail)->mod_op
		  != LDAP_MOD_DELETE ) {
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
			    "no values given" );
			free( ndn );
			modlist_free( mods );
			return;
		}
		attr_normalize( (*modtail)->mod_type );

		modtail = &(*modtail)->mod_next;
	}
	*modtail = NULL;

#ifdef LDAP_DEBUG
	Debug( LDAP_DEBUG_ARGS, "modifications:\n", 0, 0, 0 );
	for ( tmp = mods; tmp != NULL; tmp = tmp->mod_next ) {
		Debug( LDAP_DEBUG_ARGS, "\t%s: %s\n", tmp->mod_op
		    == LDAP_MOD_ADD ? "add" : (tmp->mod_op == LDAP_MOD_DELETE ?
		    "delete" : "replace"), tmp->mod_type, 0 );
	}
#endif

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d MOD dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		modlist_free( mods );
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
	}

	/* alias suffix if approp */
	ndn = suffixAlias ( ndn, op, be );

	/*
	 * do the modify if 1 && (2 || 3)
	 * 1) there is a modify function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modify != NULL ) {
		/* do the update here */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
		{

			if ( (*be->be_modify)( be, conn, op, ndn, mods ) == 0 ) {
				replog( be, LDAP_REQ_MODIFY, ndn, mods, 0 );
			}

		/* send a referral */
		} else {
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
			    default_referral );
		}
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( ndn );
	modlist_free( mods );
}

static void
modlist_free(
    LDAPMod	*mods
)
{
	LDAPMod	*next;

	for ( ; mods != NULL; mods = next ) {
		next = mods->mod_next;
		free( mods->mod_type );
		if ( mods->mod_bvalues != NULL )
			ber_bvecfree( mods->mod_bvalues );
		free( mods );
	}
}
