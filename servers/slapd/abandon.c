/* abandon.c - decode and handle an ldap abandon operation */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
	ber_int_t		id;
	Operation	*o;
	Operation	**oo;
	int rc, notfound;

#ifdef NEW_LOGGING
        LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY, "conn: %d do_abandon\n", conn->c_connid));
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
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR, 
                       "conn: %d do_abandon: ber_scanf failed\n",
                       conn->c_connid ));
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
        LDAP_LOG(( "operation", LDAP_LEVEL_ARGS,
                   "do_abandon: conn: %d  id=%ld\n", conn->c_connid, (long) id ));
#else
	Debug( LDAP_DEBUG_ARGS, "do_abandon: id=%ld\n", (long) id, 0 ,0 );
#endif

	if( id <= 0 ) {
#ifdef NEW_LOGGING
            LDAP_LOG(( "operation", LDAP_LEVEL_ERR,
                       "do_abandon: conn: %d bad msgid %ld\n", conn->c_connid, (long) id ));
#else
		Debug( LDAP_DEBUG_ANY,
			"do_abandon: bad msgid %ld\n", (long) id, 0, 0 );
#endif
		return LDAP_SUCCESS;
	}

	notfound = 1; /* not found */
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );
	/*
	 * find the operation being abandoned and set the o_abandon
	 * flag.  It's up to the backend to periodically check this
	 * flag and abort the operation at a convenient time.
	 */

	for ( o = conn->c_ops; o != NULL; o = o->o_next ) {
		if ( o->o_msgid == id ) {
			ldap_pvt_thread_mutex_lock( &o->o_abandonmutex );
			o->o_abandon = 1;
			ldap_pvt_thread_mutex_unlock( &o->o_abandonmutex );

			notfound = 0;
			goto done;
		}
	}

	for ( oo = &conn->c_pending_ops;
		(*oo != NULL) && ((*oo)->o_msgid != id);
		oo = &(*oo)->o_next )
	{
		/* EMPTY */ ;
	}

	if( *oo != NULL ) {
		o = *oo;
		*oo = (*oo)->o_next;
		slap_op_free( o );
		notfound = 0;
	}

done:
	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

#ifdef NEW_LOGGING
        LDAP_LOG(( "operation", LDAP_LEVEL_ENTRY,
                   "do_abandon: conn: %d op=%ld %sfound\n",
                   conn->c_connid, (long)id, notfound ? "not " : "" ));
#else
	Debug( LDAP_DEBUG_TRACE, "do_abandon: op=%ld %sfound\n",
	       (long) id, notfound ? "not " : "", 0 );
#endif
	return LDAP_SUCCESS;
}
