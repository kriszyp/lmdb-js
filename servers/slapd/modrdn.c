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

void
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

	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );

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
		send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL, "" );
		return;
	}

	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) deloldrdn (%d)\n", ndn, newrdn,
	    deloldrdn );


	/* Check for newSuperior parameter, if present scan it */

	if ( ber_peek_tag( op->o_ber, &length ) == LDAP_TAG_NEWSUPERIOR ) {

		if ( conn->c_protocol == LDAP_VERSION2 ) {

			/* Conection record indicates v2 but field 
			 * newSuperior is present: report error.
			 */
			Debug( LDAP_DEBUG_ANY,
			       "modrdn(v2) has field newSuperior!\n",
			       0, 0, 0 );
			send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR,
					  NULL, "" );
			return;

		} else if ( conn->c_protocol ==  0 ) {

			/* The other side is talking v3 but did not Bind as v3
			 * so we accept this and set the connection record
			 * accordingly.
			 */
		    
			conn->c_protocol = LDAP_VERSION3;

		}/* else if ( conn->c_protocol ==  0 ) */


		if ( ber_scanf( op->o_ber, /*{*/ "a}", &newSuperior ) 
		     == LBER_ERROR ) {

		    Debug( LDAP_DEBUG_ANY, "ber_scanf(\"a\"}) failed\n",
			   0, 0, 0 );
		    send_ldap_result( conn, op, LDAP_PROTOCOL_ERROR, NULL,
				      "" );
		    return;

		}/* if ( ber_scanf( ber, { "a}", &newSuperior ) == ... ) */


		Debug( LDAP_DEBUG_ARGS, "do_modrdn: newSuperior=(%s)\n",
		       newSuperior, 0, 0 );

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
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
					  default_referral );
			return;
			
		}

	}/* if ( ber_peek_tag( op->o_ber, &length ) == LDAP_TAG_NEWSUPERIOR )*/

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
		send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
		    default_referral );
		return;
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
		
		send_ldap_result( conn, op, LDAP_AFFECTS_MULTIPLE_DSAS,
				  NULL, "" );
	    
		return;

	}/* if ( (newSuperior_be != NULL) && ( be != newSuperior_be) ) */


	/* alias suffix if approp */
	ndn = suffixAlias( ndn, op, be );

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
			        /* XXX: MAY NEEED TO ADD newSuperior HERE */
				replog( be, LDAP_REQ_MODRDN, ndn, newrdn,
				    deloldrdn );
			}
		} else {
			send_ldap_result( conn, op, LDAP_PARTIAL_RESULTS, NULL,
			    default_referral );
		}
	} else {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "Function not implemented" );
	}

	free( ndn );
	free( newrdn );	
	free( newSuperior );
	free( nnewSuperior );
}
