/* abandon.c - decode and handle an ldap abandon operation */

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
#include <ac/socket.h>

#include "slap.h"

extern Backend	*select_backend();

extern char	*default_referral;

void
do_abandon(
    Connection	*conn,
    Operation	*op
)
{
	int		id;
	Backend		*be;
	Operation	*o;

	Debug( LDAP_DEBUG_TRACE, "do_abandon\n", 0, 0, 0 );

	/*
	 * Parse the abandon request.  It looks like this:
	 *
	 *	AbandonRequest := MessageID
	 */

	if ( ber_scanf( op->o_ber, "i", &id ) == LBER_ERROR ) {
		Debug( LDAP_DEBUG_ANY, "ber_scanf failed\n", 0, 0 ,0 );
		return;
	}

	Debug( LDAP_DEBUG_ARGS, "do_abandon: id %d\n", id, 0 ,0 );

	/*
	 * find the operation being abandoned and set the o_abandon
	 * flag.  It's up to the backend to periodically check this
	 * flag and abort the operation at a convenient time.
	 */

	pthread_mutex_lock( &conn->c_opsmutex );
	for ( o = conn->c_ops; o != NULL; o = o->o_next ) {
		if ( o->o_msgid == id )
			break;
	}

	if ( o != NULL ) {
		pthread_mutex_lock( &o->o_abandonmutex );
		o->o_abandon = 1;
		pthread_mutex_unlock( &o->o_abandonmutex );
	} else {
		Debug( LDAP_DEBUG_TRACE, "do_abandon: op not found\n", 0, 0,
		    0 );
	}
	pthread_mutex_unlock( &conn->c_opsmutex );
}
