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
/* ac/socket.h must precede ISODE #includes or p_type must be #undeffed
 * after it is included.  (Because ISODE uses p_type as a field name, and
 * SunOS 5.5:sys/vtype.h defines it (and ac/socket.h indirectly includes it) */
#include <ac/socket.h>

#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>
#include <quipu/ds_error.h>
#include <quipu/remove.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

#ifdef HAVE_COMPAT20
#define DELTAG	(ldap_compat == 20 ? OLD_LDAP_RES_DELETE : LDAP_RES_DELETE)
#else
#define DELTAG	LDAP_RES_DELETE
#endif

/*
 * do_delete - Initiate an X.500 remove entry operation.  Returns 1 if
 * the operation was initiated successfully, and thus a response will be
 * coming back from the DSA.  Returns 0 if there was trouble and thus no
 * DSA response is expected.
 */

int
do_delete( 
    Sockbuf	*clientsb,
    struct msg	*m,
    BerElement	*ber
)
{
	char				*dn;
	int				rc;
	struct ds_removeentry_arg	ra;
	static CommonArgs		common = default_common_args;

	Debug( LDAP_DEBUG_TRACE, "do_delete\n", 0, 0, 0 );

	/*
	 * Parse the delete request.  It looks like this:
	 *	DelRequest := DistinguishedName
	 */

#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	DAS_RemoveEntryArgument_INIT( &ra );
#endif
#endif

	if ( ber_scanf( ber, "a", &dn ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, DELTAG, m,
		    LDAP_PROTOCOL_ERROR, NULL, "" );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_delete: dn (%s)\n", dn, 0, 0 );

	ra.rma_object = ldap_str2dn( dn );
	free( dn );
	if ( ra.rma_object == NULLDN ) {
		Debug( LDAP_DEBUG_ANY, "ldap_str2dn failed\n", 0, 0, 0 );
		send_ldap_msgresult( clientsb, DELTAG, m,
		    LDAP_INVALID_DN_SYNTAX, NULL, "" );
		return( 0 );
	}

	ra.rma_common = common;	/* struct copy */

	rc = initiate_dap_operation( OP_REMOVEENTRY, m, &ra );

	dn_free( ra.rma_object );

	if ( rc != 0 ) {
		send_ldap_msgresult( clientsb, DELTAG, m, rc, NULL, "" );
		return( 0 );
	}

	return( 1 );
}

void
delete_result(
    Sockbuf	*sb,
    struct msg	*m
)
{
	send_ldap_msgresult( sb, DELTAG, m, LDAP_SUCCESS, NULL, "" );

	return;
}
