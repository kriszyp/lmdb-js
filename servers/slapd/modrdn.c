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

/*
 * LDAP v3 newSuperior support.
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "ldap_pvt.h"
#include "slap.h"

int
do_modrdn(
    Connection	*conn,
    Operation	*op
)
{
	char	*dn, *ndn = NULL, *newrdn;
	ber_int_t	deloldrdn;
	Backend	*be;
	/* Vars for LDAP v3 newSuperior support */
	char	*newSuperior = NULL;
	char    *nnewSuperior = NULL;
	Backend	*newSuperior_be = NULL;
	ber_len_t	length;
	int rc;
	const char *text;
	int manageDSAit;

#ifdef NEW_LOGGING
        LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY,
                   "do_modrdn: begin\n" ));
#else
	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );
#endif


	/*
	 * Parse the modrdn request.  It looks like this:
	 *
	 *	ModifyRDNRequest := SEQUENCE {
	 *		entry	DistinguishedName,
	 *		newrdn	RelativeDistinguishedName
	 *		deleteoldrdn	BOOLEAN,
	 *		newSuperior	[0] LDAPDN OPTIONAL (v3 Only!)
	 *	}
	 */

	if ( ber_scanf( op->o_ber, "{aab", &dn, &newrdn, &deloldrdn )
	    == LBER_ERROR ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn: ber_scanf failed\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
#endif

		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return SLAPD_DISCONNECT;
	}

	/* Check for newSuperior parameter, if present scan it */

	if ( ber_peek_tag( op->o_ber, &length ) == LDAP_TAG_NEWSUPERIOR ) {
		if ( op->o_protocol < LDAP_VERSION3 ) {
			/* Conection record indicates v2 but field 
			 * newSuperior is present: report error.
			 */
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "do_modrdn: (v2) invalid field newSuperior.\n" ));
#else
			Debug( LDAP_DEBUG_ANY,
			       "modrdn(v2): invalid field newSuperior!\n",
			       0, 0, 0 );
#endif

			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "newSuperior requires LDAPv3" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		if ( ber_scanf( op->o_ber, "a", &newSuperior ) 
		     == LBER_ERROR ) {

#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "do_modrdn: ber_scanf(\"a\") failed\n" ));
#else
			Debug( LDAP_DEBUG_ANY, "ber_scanf(\"a\") failed\n",
			   0, 0, 0 );
#endif

			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
			rc = SLAPD_DISCONNECT;
			goto cleanup;
		}

		nnewSuperior = ch_strdup( newSuperior );

		if( dn_normalize( nnewSuperior ) == NULL ) {
#ifdef NEW_LOGGING
                    LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                               "do_modrdn:  invalid new superior (%s)\n", newSuperior ));
#else
			Debug( LDAP_DEBUG_ANY, "do_modrdn: invalid new superior (%s)\n",
				newSuperior, 0, 0 );
#endif

			send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
				"invalid new superior DN", NULL, NULL );
			goto cleanup;
		}

	}

#ifdef NEW_LOGGING
        LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
                   "do_modrdn: dn (%s) newrdn (%s) newsuperior(%s)\n",
                   dn, newrdn, newSuperior != NULL ? newSuperior : "" ));
#else
	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) newsuperior (%s)\n",
		dn, newrdn,
		newSuperior != NULL ? newSuperior : "" );
#endif


	if ( ber_scanf( op->o_ber, /*{*/ "}") == LBER_ERROR ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn: ber_scanf failed\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: ber_scanf failed\n", 0, 0, 0 );
#endif

		send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
		rc = SLAPD_DISCONNECT;
		goto cleanup;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn: get_ctrls failed\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
#endif

		/* get_ctrls has sent results.  Now clean up. */
		goto cleanup;
	} 

	ndn = ch_strdup( dn );

	if( dn_normalize( ndn ) == NULL ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn: invalid dn (%s)\n", dn ));
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: invalid dn (%s)\n", dn, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		goto cleanup;
	}

	if( !rdn_validate( newrdn ) ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn: invalid rdn (%s).\n", newrdn ));
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: invalid rdn (%s)\n", newrdn, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid RDN", NULL, NULL );
		goto cleanup;
	}

	if( ndn == '\0' ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_modrdn:  attempt to modify root DSE.\n" ));
#else
		Debug( LDAP_DEBUG_ANY, "do_modrdn: root dse!\n", 0, 0, 0 );
#endif

		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "cannot rename the root DSE", NULL, NULL );
		goto cleanup;
	}

	Statslog( LDAP_DEBUG_STATS, "conn=%ld op=%d MODRDN dn=\"%s\"\n",
	    op->o_connid, op->o_opid, dn, 0, 0 );

	manageDSAit = get_manageDSAit( op );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn, manageDSAit )) == NULL ) {
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

	/* Make sure that the entry being changed and the newSuperior are in 
	 * the same backend, otherwise we return an error.
	 */
	if( newSuperior != NULL ) {
		newSuperior_be = select_backend( nnewSuperior, 0 );

		if ( newSuperior_be != be ) {
			/* newSuperior is in same backend */
			rc = LDAP_AFFECTS_MULTIPLE_DSAS;

			send_ldap_result( conn, op, rc,
				NULL, "cannot rename between DSAa", NULL, NULL );

			goto cleanup;
		}

		/* deref suffix alias if appropriate */
		nnewSuperior = suffix_alias( be, nnewSuperior );
	}

	/* deref suffix alias if appropriate */
	ndn = suffix_alias( be, ndn );

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modrdn ) {
		/* do the update here */
#ifndef SLAPD_MULTIMASTER
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
#endif
		{
			if ( (*be->be_modrdn)( be, conn, op, dn, ndn, newrdn,
			    deloldrdn, newSuperior ) == 0
#ifdef SLAPD_MULTIMASTER
				&& ( be->be_update_ndn == NULL ||
					strcmp( be->be_update_ndn, op->o_ndn ) )
#endif
			) {
				struct replog_moddn moddn;
			   	moddn.newrdn = newrdn;
				moddn.deloldrdn = deloldrdn;
				moddn.newsup = newSuperior;

				replog( be, op, dn, &moddn );
			}
#ifndef SLAPD_MULTIMASTER
		} else {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				be->be_update_refs ? be->be_update_refs : default_referral, NULL );
#endif
		}
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "operation not supported within namingContext", NULL, NULL );
	}

cleanup:
	free( dn );
	if( ndn != NULL ) free( ndn );
	free( newrdn );	
	if ( newSuperior != NULL )
		free( newSuperior );
	if ( nnewSuperior != NULL )
		free( nnewSuperior );
	return rc;
}
