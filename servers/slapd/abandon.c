/* abandon.c - decode and handle an ldap abandon operation */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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
#include <ac/socket.h>

#include "slap.h"

int
do_abandon(
    Connection	*conn,
    Operation	*op
)
{
	ber_int_t	id;
	Operation	*o;
	int		rc;
#ifdef LDAP_CLIENT_UPDATE
	int		i;
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, "conn: %d do_abandon\n", conn->c_connid, 0, 0);
#else
	Debug( LDAP_DEBUG_TRACE, "do_abandon\n", 0, 0, 0 );
#endif

	/*
	 * Parse the abandon request.  It looks like this:
	 *
	 *	AbandonRequest := MessageID
	 */

	if ( ber_scanf( op->o_ber, "i", &id ) == LBER_ERROR ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"conn: %d do_abandon: ber_scanf failed\n", conn->c_connid, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "do_abandon: ber_scanf failed\n", 0, 0 ,0 );
#endif
		send_ldap_disconnect( conn, op,
			LDAP_PROTOCOL_ERROR, "decoding error" );
		return -1;
	}

	if( (rc = get_ctrls( conn, op, 0 )) != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY, "do_abandon: get_ctrls failed\n", 0, 0 ,0 );
		return rc;
	} 

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ARGS, "do_abandon: conn: %d  id=%ld\n", 
		conn->c_connid, (long) id, 0 );
#else
	Debug( LDAP_DEBUG_ARGS, "do_abandon: id=%ld\n", (long) id, 0 ,0 );
#endif

	if( id <= 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, 
			"do_abandon: conn: %d bad msgid %ld\n", 
			conn->c_connid, (long) id, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			"do_abandon: bad msgid %ld\n", (long) id, 0, 0 );
#endif
		return LDAP_SUCCESS;
	}

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );
	/*
	 * find the operation being abandoned and set the o_abandon
	 * flag.  It's up to the backend to periodically check this
	 * flag and abort the operation at a convenient time.
	 */

	LDAP_STAILQ_FOREACH( o, &conn->c_ops, o_next ) {
		if ( o->o_msgid == id ) {
			o->o_abandon = 1;
			goto done;
		}
	}

	LDAP_STAILQ_FOREACH( o, &conn->c_pending_ops, o_next ) {
		if ( o->o_msgid == id ) {
			LDAP_STAILQ_REMOVE( &conn->c_pending_ops, o, slap_op, o_next );
			slap_op_free( o );
			goto done;
		}
	}

done:

	for ( i = 0; i < nbackends; i++ ) {
		Backend *be = &backends[i];

		if( be->be_abandon ) be->be_abandon( be, conn, op, id );
	}

	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

#ifdef NEW_LOGGING
	LDAP_LOG( OPERATION, ENTRY, 
		"do_abandon: conn: %d op=%ld %sfound\n",
		conn->c_connid, (long)id, o ? "" : "not " );
#else
	Debug( LDAP_DEBUG_TRACE, "do_abandon: op=%ld %sfound\n",
		(long) id, o ? "" : "not ", 0 );
#endif
	return LDAP_SUCCESS;
}
