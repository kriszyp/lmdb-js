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

#include "slap.h"

int
do_modrdn(
    Connection	*conn,
    Operation	*op
)
{
	char	*ndn, *newrdn;
	ber_int_t	deloldrdn;
	Backend	*be;
	/* Vars for LDAP v3 newSuperior support */
	char	*newSuperior = NULL;
	char    *nnewSuperior = NULL;
	Backend	*newSuperior_be = NULL;
	ber_len_t	length;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );

	if( op->o_bind_in_progress ) {
		Debug( LDAP_DEBUG_ANY, "do_modrdn: SASL bind in progress.\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_SASL_BIND_IN_PROGRESS,
			NULL, "SASL bind in progress", NULL, NULL );
		return LDAP_SASL_BIND_IN_PROGRESS;
	}

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

	if ( ber_scanf( op->o_ber, "{aab", &ndn, &newrdn, &deloldrdn )
	    == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	/* Check for newSuperior parameter, if present scan it */

	if ( ber_peek_tag( op->o_ber, &length ) == LDAP_TAG_NEWSUPERIOR ) {

		if ( op->o_protocol == 0 ) {
			/*
			 * Promote to LDAPv3
			 */
			ldap_pvt_thread_mutex_lock( &conn->c_mutex );
			conn->c_protocol = LDAP_VERSION3;
			ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
			op->o_protocol = LDAP_VERSION3;

		} else if ( op->o_protocol < LDAP_VERSION3 ) {
			/* Conection record indicates v2 but field 
			 * newSuperior is present: report error.
			 */
			Debug( LDAP_DEBUG_ANY,
			       "modrdn(v2): invalid field newSuperior!\n",
			       0, 0, 0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "newSuperior requires LDAPv3" );
			return -1;
		}

		if ( ber_scanf( op->o_ber, "a", &newSuperior ) 
		     == LBER_ERROR ) {

		    Debug( LDAP_DEBUG_ANY, "ber_scanf(\"a\"}) failed\n",
			   0, 0, 0 );
			send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
		    return -1;

		}

	}

	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) newsuperior (%s)\n",
		ndn, newrdn,
		newSuperior != NULL ? newSuperior : "" );

	if ( ber_scanf( op->o_ber, /*{*/ "}") == LBER_ERROR ) {
		free( ndn );
		free( newrdn );	
		free( newSuperior );
		Debug( LDAP_DEBUG_ANY, "do_modrdn: ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
				LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	if( (rc = get_ctrls( conn, op, 1 )) != LDAP_SUCCESS ) {
		free( ndn );
		free( newrdn );	
		free( newSuperior );
		Debug( LDAP_DEBUG_ANY, "do_modrdn: get_ctrls failed\n", 0, 0, 0 );
		return rc;
	} 

	if( newSuperior != NULL ) {
		/* GET BACKEND FOR NEW SUPERIOR */

		nnewSuperior = strdup( newSuperior );
		dn_normalize_case( nnewSuperior );

		if ( (newSuperior_be = select_backend( nnewSuperior )) 
		     == NULL ) {
		    
			/* We do not have a backend for newSuperior so we send
			 * a referral.
			 * XXX: We may need to do something else here, not sure
			 * what though.
			 */

			Debug( LDAP_DEBUG_ARGS,
			       "do_modrdn: cant find backend for=(%s)\n",
			       newSuperior, 0, 0 );
			
			free( ndn );
			free( newrdn );
			free( newSuperior );
			free( nnewSuperior );
			send_ldap_result( conn, op, LDAP_REFERRAL,
				NULL, NULL, default_referral, NULL );
			return 0;
		}
	}

	dn_normalize_case( ndn );

	Statslog( LDAP_DEBUG_STATS, "conn=%d op=%d MODRDN dn=\"%s\"\n",
	    conn->c_connid, op->o_opid, ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */

	if ( (be = select_backend( ndn )) == NULL ) {
		free( ndn );
		free( newrdn );	
		free( newSuperior );
		free( nnewSuperior );
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		return rc;
	}

	/* Make sure that the entry being changed and the newSuperior are in 
	 * the same backend, otherwise we return an error.
	 */

	if ( (newSuperior_be != NULL) && ( be != newSuperior_be) ) {

		Debug( LDAP_DEBUG_ANY, "dn=(%s), newSuperior=(%s)\n", ndn,
		       newSuperior, 0 );
		
		free( ndn );
		free( newrdn );
		free( newSuperior );
		free( nnewSuperior );
		
		send_ldap_result( conn, op, rc = LDAP_AFFECTS_MULTIPLE_DSAS,
			NULL, NULL, NULL, NULL );
	    
		return rc;

	}

	/*
	 * do the add if 1 && (2 || 3)
	 * 1) there is an add function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_modrdn ) {
		/* do the update here */
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
		{
			if ( (*be->be_modrdn)( be, conn, op, ndn, newrdn,
			    deloldrdn, newSuperior ) == 0 ) {
			        /* XXX: MAY NEED TO ADD newSuperior HERE */
				replog( be, LDAP_REQ_MODRDN, ndn, newrdn,
				    deloldrdn );
			}
		} else {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				be->be_update_refs ? be->be_update_refs : default_referral, NULL );
		}
	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "Function not implemented", NULL, NULL );
	}

	free( ndn );
	free( newrdn );	
	free( newSuperior );
	free( nnewSuperior );
	return rc;
}
