/* $OpenLDAP$ */
/* cancel.c - LDAP cancel extended operation */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/krb.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

#include <lber_pvt.h>
#include <lutil.h>

int cancel_extop(
	Connection *conn,
	Operation *op,
	const char *reqoid,
	struct berval *reqdata,
	char **rspoid,
	struct berval **rspdata,
	LDAPControl ***rspctrls,
	const char **text,
	BerVarray *refs )
{
	Backend *be;
	int rc;
	int found = 0;
	int opid;
	BerElement *ber;

	assert( reqoid != NULL );
	assert( strcmp( LDAP_EXOP_X_CANCEL, reqoid ) == 0 );

	if ( reqdata == NULL ) {
		*text = "no message ID supplied";
		return LDAP_PROTOCOL_ERROR;
	}

	ber = ber_init( reqdata );
	if ( ber == NULL ) {
		*text = "internal error";
		return LDAP_OTHER;
	}

	if ( ber_scanf( ber, "{i}", &opid ) == LBER_ERROR ) {
		*text = "message ID parse failed";
		return LDAP_PROTOCOL_ERROR;
	}

	(void) ber_free( ber, 1 );

	if ( opid < 0 ) {
		*text = "message ID invalid";
		return LDAP_PROTOCOL_ERROR;
	}

	ldap_pvt_thread_mutex_lock( &conn->c_mutex );
	LDAP_STAILQ_FOREACH( op, &conn->c_pending_ops, o_next ) {
		if ( op->o_msgid == opid ) {
			LDAP_STAILQ_REMOVE( &conn->c_pending_ops, op, slap_op, o_next );
			slap_op_free( op );
			found = 1;
			break;
		}
	}
	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	if ( found )
		return LDAP_SUCCESS;

	found = 0;
	ldap_pvt_thread_mutex_lock( &conn->c_mutex );
	LDAP_STAILQ_FOREACH( op, &conn->c_ops, o_next ) {
		if ( op->o_msgid == opid ) {
			found = 1;
			break;
		}
	}

	if ( !found ) {
		*text = "message ID not found";
		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
		return LDAP_NO_SUCH_OPERATION;
	}

	if ( op->o_cancel != LDAP_CANCEL_NONE ) {
		*text = "message ID already being cancelled";
		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_cancel = LDAP_CANCEL_REQ;
	ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

	while ( op->o_cancel == LDAP_CANCEL_REQ ) {
		ldap_pvt_thread_yield();
	}

	if ( op->o_cancel == LDAP_CANCEL_ACK ) {
		rc = LDAP_SUCCESS;
	} else {
		rc = op->o_cancel;
	}

	op->o_cancel = LDAP_CANCEL_DONE;

	return rc;
}
