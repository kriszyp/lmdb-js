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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

int
do_delete(
    Connection	*conn,
    Operation	*op
)
{
	char	*ndn;
	Backend	*be;
	int rc;

	Debug( LDAP_DEBUG_TRACE, "do_delete\n", 0, 0, 0 );

	if( op->o_bind_in_progress ) {
		Debug( LDAP_DEBUG_ANY, "do_delete: SASL bind in progress.\n",
			0, 0, 0 );
		send_ldap_result( conn, op, LDAP_SASL_BIND_IN_PROGRESS,
			NULL, "SASL bind in progress", NULL, NULL );
		return LDAP_SASL_BIND_IN_PROGRESS;
	}

	/*
	 * Parse the delete request.  It looks like this:
	 *
	 *	DelRequest := DistinguishedName
	 */

	if ( ber_scanf( op->o_ber, "a", &ndn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	if(	dn_normalize_case( ndn ) == NULL ) {
		Debug( LDAP_DEBUG_ANY, "do_delete: invalid dn (%s)\n", ndn, 0, 0 );
		send_ldap_result( conn, op, rc = LDAP_INVALID_DN_SYNTAX, NULL,
		    "invalid DN", NULL, NULL );
		free( ndn );
		return rc;
	}

	if( ( rc = get_ctrls( conn, op, 1 ) ) != LDAP_SUCCESS ) {
		free( ndn );
		Debug( LDAP_DEBUG_ANY, "do_add: get_ctrls failed\n", 0, 0, 0 );
		return rc;
	} 

	Debug( LDAP_DEBUG_ARGS, "do_delete: dn (%s)\n", ndn, 0, 0 );
	Debug( LDAP_DEBUG_STATS, "DEL dn=\"%s\"\n", ndn, 0, 0 );

	/*
	 * We could be serving multiple database backends.  Select the
	 * appropriate one, or send a referral to our "referral server"
	 * if we don't hold it.
	 */
	if ( (be = select_backend( ndn )) == NULL ) {
		send_ldap_result( conn, op, rc = LDAP_REFERRAL,
			NULL, NULL, default_referral, NULL );
		free( ndn );
		return rc;
	}

	if ( global_readonly || be->be_readonly ) {
		Debug( LDAP_DEBUG_ANY, "do_delete: database is read-only\n",
		       0, 0, 0 );
		free( ndn );
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
		                  NULL, "database is read-only", NULL, NULL );
		return LDAP_UNWILLING_TO_PERFORM;
	}

	/* deref suffix alias if appropriate */
	ndn = suffix_alias( be, ndn );

	/*
	 * do the delete if 1 && (2 || 3)
	 * 1) there is a delete function implemented in this backend;
	 * 2) this backend is master for what it holds;
	 * 3) it's a replica and the dn supplied is the update_ndn.
	 */
	if ( be->be_delete ) {
		/* do the update here */
#ifndef SLAPD_MULTIMASTER
		if ( be->be_update_ndn == NULL ||
			strcmp( be->be_update_ndn, op->o_ndn ) == 0 )
#endif
		{
			if ( (*be->be_delete)( be, conn, op, ndn ) == 0 ) {
#ifdef SLAPD_MULTIMASTER
				if (be->be_update_ndn == NULL ||
					strcmp( be->be_update_ndn, op->o_ndn ))
#endif
				{
					replog( be, op, ndn, NULL );
				}
			}
#ifndef SLAPD_MULTIMASTER
		} else {
			send_ldap_result( conn, op, rc = LDAP_REFERRAL, NULL, NULL,
				be->be_update_refs ? be->be_update_refs : default_referral, NULL );
#endif
		}

	} else {
		send_ldap_result( conn, op, rc = LDAP_UNWILLING_TO_PERFORM,
			NULL, "Function not implemented", NULL, NULL );
	}

	free( ndn );
	return rc;
}
