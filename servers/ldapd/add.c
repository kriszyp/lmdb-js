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
#include <quipu/add.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>
#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef LDAP_COMPAT20
#define ADDTAG	(ldap_compat == 20 ? OLD_LDAP_RES_ADD : LDAP_RES_ADD)
#else
#define ADDTAG	LDAP_RES_ADD
#endif

int
do_add(
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	char				*dn;
	char				*type, *last;
	struct berval			**bvals;
	int				rc;
	unsigned long			tag, len;
	struct ds_addentry_arg		aa;
	static CommonArgs		common = default_common_args;

	Debug( LDAP_DEBUG_TRACE, "do_add\n", 0, 0, 0 );

	/*
	 * Parse the add request.  It looks like this:
	 *	AddRequest := [APPLICATION 14] SEQUENCE {
	 *		name	DistinguishedName,
	 *		attrs	SEQUENCE OF SEQUENCE {
	 *			type	AttributeType,
	 *			values	SET OF AttributeValue
	 *		}
	 *	}
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_AddEntryArgument_INIT ( &aa );
#endif
#endif

	if ( ber_scanf( ber, "{a", &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, ADDTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_add: dn (%s)\n", dn, 0, 0 );

	aa.ada_object = ldap_str2dn( dn );
	free( dn );
	if ( aa.ada_object == NULLDN ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, ADDTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}

	/* break out once we read them all, or return out on error */
	aa.ada_entry = NULLATTR;
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) ) {
		Attr_Sequence	as;

		if ( ber_scanf( ber, "{a{V}}", &type, &bvals ) == LBER_ERROR )
			break;

		if ( (as = get_as( clientsb, LDAP_RES_ADD, m, type,
		    bvals )) == NULLATTR )
			return( 0 );

		aa.ada_entry = as_merge( aa.ada_entry, as );
	}

	aa.ada_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_ADDENTRY, m, &aa );

	dn_free( aa.ada_object );
	as_free( aa.ada_entry );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, ADDTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

void
add_result(
    Sockbuf	*sb,
    struct msg	*m
)
{
	send_ldap_msgresult( sb, ADDTAG, m, LDAP_SUCCESS, NULL, "" );

	return;
}
