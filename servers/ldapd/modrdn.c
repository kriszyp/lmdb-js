/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
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

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/modifyrdn.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef LDAP_COMPAT20
#define MODRDNTAG	(ldap_compat == 20 ? OLD_LDAP_RES_MODRDN : LDAP_RES_MODRDN)
#else
#define MODRDNTAG	LDAP_RES_MODRDN
#endif

int
do_modrdn(
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	char			*dn, *newrdn;
	int			rc, deleteoldrdn;
	struct ds_modifyrdn_arg	ma;
	static CommonArgs	common = default_common_args;

	Debug( LDAP_DEBUG_TRACE, "do_modrdn\n", 0, 0, 0 );

	/*
	 * Parse the modrdn request.  It looks like this:
	 *	ModifyRDNRequest := SEQUENCE {
	 *		entry	DistinguishedName,
	 *		newrdn	RelativeDistinguishedName
	 *	}
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_ModifyDnArgument_INIT( &ma );
#endif
#endif

	if ( ber_scanf( ber, "{aa", &dn, &newrdn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, MODRDNTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	deleteoldrdn = 1;
	if ( ber_scanf( ber, "b", &deleteoldrdn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "found old modrdn\n", 0, 0, 0 );
	}

	Debug( LDAP_DEBUG_ARGS,
	    "do_modrdn: dn (%s) newrdn (%s) deleteoldrdn (%d)\n", dn, newrdn,
	    deleteoldrdn );

	ma.mra_object = ldap_str2dn( dn );
	free( dn );
	if ( ma.mra_object == NULLDN ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, MODRDNTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}

	ma.mra_newrdn = ldap_str2rdn( newrdn );
	free( newrdn );
	if ( ma.mra_newrdn == NULLRDN ) {
		Debug( LDAP_DEBUG_ANY, "str2rdn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, MODRDNTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "Bad RDN" );
		return( 0 );
	}
	ma.deleterdn = (deleteoldrdn ? 1 : 0);

	ma.mra_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_MODIFYRDN, m, &ma );

	dn_free( ma.mra_object );
	rdn_free( ma.mra_newrdn );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, MODRDNTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

void
modrdn_result( Sockbuf *sb, struct msg *m )
{
	send_ldap_msgresult( sb, MODRDNTAG, m, LDAP_SUCCESS, NULL, "" );

	return;
}
