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
#include <quipu/abandon.h>
#include <quipu/dap2.h>
#include <quipu/dua.h>

#include "lber.h"
#include "ldap.h"
#include "common.h"

int
do_abandon(
    struct conn	*dsaconn,
    BerElement	*ber,
    int		msgid
)
{
	int			id;
	struct ds_abandon_arg	aa;
	struct DAPindication	di;

	Debug( LDAP_DEBUG_TRACE, "do_abandon\n", 0, 0 ,0 );

	/*
	 * Parse the abandon request.  It looks like this:
	 *	AbandonRequest := MessageID
	 */

	if ( ber_scanf( ber, "i", &id ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0 ,0 );
		return( 0 );
	}

	Debug( LDAP_DEBUG_ARGS, "do_abandin: id %d\n", id, 0 ,0 );

	aa.aba_invokeid = id;

	Debug( LDAP_DEBUG_TRACE, "DapAbandon...\n", 0, 0 ,0 );
	if ( DapAbandon( dsaconn->c_ad, msgid, &aa, &di, ROS_ASYNC )
	    == NOTOK ) {
		Debug( LDAP_DEBUG_ANY, "DapAbandon failed\n", 0, 0 ,0 );
		return( 0 );
	}
	Debug( LDAP_DEBUG_TRACE, "DapAbandon completed\n", 0, 0 ,0 );

	return( 0 );
}
