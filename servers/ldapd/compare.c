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
#include <quipu/compare.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef HAVE_COMPAT20
#define COMPTAG	(ldap_compat == 20 ? OLD_LDAP_RES_COMPARE : LDAP_RES_COMPARE)
#else
#define COMPTAG	LDAP_RES_COMPARE
#endif

int
do_compare( 
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	char			*dn, *attr, *value;
	int			rc;
	struct ds_compare_arg	ca;
	AttributeType		type;
	static CommonArgs	common = default_common_args;

	Debug( LDAP_DEBUG_TRACE, "do_compare\n", 0, 0, 0 );

	/*
	 * Parse the compare request.  It looks like this:
	 *	CompareRequest := [APPLICATION 14] SEQUENCE {
	 *		entry	DistinguishedName,
	 *		ava	SEQUENCE {
	 *			type	AttributeType,
	 *			value	AttributeValue
	 *		}
	 *	}
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_CompareArgument_INIT ( &ca );
#endif
#endif

	if ( ber_scanf( ber, "{a{aa}}", &dn, &attr, &value ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, COMPTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_compare: dn (%s) attr (%s) value (%s)\n",
	    dn, attr, value );

	ca.cma_object = ldap_str2dn( dn );
	free( dn );
	if ( ca.cma_object == NULLDN ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, COMPTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}

	type = str2AttrT( attr );
	if ( type == NULLAttrT ) {
		Debug( LDAP_DEBUG_ANY, "str2AttrT failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, COMPTAG, m,
		    LDAP_UNDEFINED_TYPE, NULL, attr );
		free( attr );
		return( 0 );
	}
	free( attr );
	ca.cma_purported.ava_type = type;

	ca.cma_purported.ava_value = ldap_str2AttrV( value, type->oa_syntax );
	free( value );
	if ( ca.cma_purported.ava_value == NULLAttrV ) {
		Debug( LDAP_DEBUG_ANY, "str2AttrV failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, COMPTAG, m,
		    LDAP_INVALID_SYNTAX, NULL, "" );
		return( 0 );
	}

	ca.cma_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_COMPARE, m, &ca );

	dn_free( ca.cma_object );
	AttrV_free( ca.cma_purported.ava_value );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, COMPTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

void
compare_result( 
    Sockbuf			*sb,
    struct msg			*m,
    struct ds_compare_result	*cr
)
{
	send_ldap_msgresult( sb, COMPTAG, m, cr->cmr_matched ?
	    LDAP_COMPARE_TRUE : LDAP_COMPARE_FALSE, NULL, "" );

	return;
}
