/* operation.c - routines to deal with pending ldap operations */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "slapi.h"


void
slap_op_free( Operation *op )
{
	assert( LDAP_STAILQ_NEXT(op, o_next) == NULL );

	if ( op->o_ber != NULL ) {
		ber_free( op->o_ber, 1 );
	}
	if ( op->o_dn.bv_val != NULL ) {
		free( op->o_dn.bv_val );
	}
	if ( op->o_ndn.bv_val != NULL ) {
		free( op->o_ndn.bv_val );
	}
	if ( op->o_authmech.bv_val != NULL ) {
		free( op->o_authmech.bv_val );
	}
	if ( op->o_ctrls != NULL ) {
		ldap_controls_free( op->o_ctrls );
	}

#ifdef LDAP_CONNECTIONLESS
	if ( op->o_res_ber != NULL ) {
		ber_free( op->o_res_ber, 1 );
	}
#endif
#ifdef LDAP_CLIENT_UPDATE
	if ( op->o_clientupdate_state.bv_val != NULL ) {
		free( op->o_clientupdate_state.bv_val );
	}
#endif
#ifdef LDAP_SYNC
	if ( op->o_sync_state.bv_val != NULL ) {
		free( op->o_sync_state.bv_val );
	}
#endif

#if defined( LDAP_SLAPI )
	if ( op->o_pb != NULL ) {
		slapi_pblock_destroy( (Slapi_PBlock *)op->o_pb );
	}
#endif /* defined( LDAP_SLAPI ) */

	free( (char *) op );
}

Operation *
slap_op_alloc(
    BerElement		*ber,
    ber_int_t	msgid,
    ber_tag_t	tag,
    ber_int_t	id
)
{
	Operation	*op;

	op = (Operation *) ch_calloc( 1, sizeof(Operation) );

	op->o_ber = ber;
	op->o_msgid = msgid;
	op->o_tag = tag;

	op->o_time = slap_get_time();
	op->o_opid = id;
#ifdef LDAP_CONNECTIONLESS
	op->o_res_ber = NULL;
#endif

#if defined( LDAP_SLAPI )
	op->o_pb = slapi_pblock_new();
#endif /* defined( LDAP_SLAPI ) */

	return( op );
}
