/*
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  modify.c
 */

#include "portable.h"

#ifndef lint 
static char copyright[] = "@(#) Copyright (c) 1990 Regents of the University of Michigan.\nAll rights reserved.\n";
#endif

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

/*
 * ldap_modify - initiate an ldap (and X.500) modify operation.  Parameters:
 *
 *	ld		LDAP descriptor
 *	dn		DN of the object to modify
 *	mods		List of modifications to make.  This is null-terminated
 *			array of struct ldapmod's, specifying the modifications
 *			to perform.
 *
 * Example:
 *	LDAPMod	*mods[] = { 
 *			{ LDAP_MOD_ADD, "cn", { "babs jensen", "babs", 0 } },
 *			{ LDAP_MOD_REPLACE, "sn", { "jensen", 0 } },
 *			0
 *		}
 *	msgid = ldap_modify( ld, dn, mods );
 */
int
ldap_modify( LDAP *ld, char *dn, LDAPMod **mods )
{
	BerElement	*ber;
	int		i, rc;

	/*
	 * A modify request looks like this:
	 *	ModifyRequet ::= SEQUENCE {
	 *		object		DistinguishedName,
	 *		modifications	SEQUENCE OF SEQUENCE {
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

	Debug( LDAP_DEBUG_TRACE, "ldap_modify\n", 0, 0, 0 );

	/* create a message to send */
	if ( (ber = ldap_alloc_ber_with_options( ld )) == NULLBER ) {
		return( -1 );
	}

	if ( ber_printf( ber, "{it{s{", ++ld->ld_msgid, LDAP_REQ_MODIFY, dn )
	    == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

	/* for each modification to be performed... */
	for ( i = 0; mods[i] != NULL; i++ ) {
		if (( mods[i]->mod_op & LDAP_MOD_BVALUES) != 0 ) {
			rc = ber_printf( ber, "{e{s[V]}}",
			    mods[i]->mod_op & ~LDAP_MOD_BVALUES,
			    mods[i]->mod_type, mods[i]->mod_bvalues );
		} else {
			rc = ber_printf( ber, "{e{s[v]}}", mods[i]->mod_op,
			    mods[i]->mod_type, mods[i]->mod_values );
		}

		if ( rc == -1 ) {
			ld->ld_errno = LDAP_ENCODING_ERROR;
			ber_free( ber, 1 );
			return( -1 );
		}
	}

	if ( ber_printf( ber, "}}}" ) == -1 ) {
		ld->ld_errno = LDAP_ENCODING_ERROR;
		ber_free( ber, 1 );
		return( -1 );
	}

	/* send the message */
	return( ldap_send_initial_request( ld, LDAP_REQ_MODIFY, dn, ber ));
}

int
ldap_modify_s( LDAP *ld, char *dn, LDAPMod **mods )
{
	int		msgid;
	LDAPMessage	*res;

	if ( (msgid = ldap_modify( ld, dn, mods )) == -1 )
		return( ld->ld_errno );

	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );

	return( ldap_result2error( ld, res, 1 ) );
}

