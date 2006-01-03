/* op.c - relay backend operations */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2004-2006 The OpenLDAP Foundation.
 * Portions Copyright 2004 Pierangelo Masarati.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Pierangelo Masarati for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "back-relay.h"

static int
relay_back_swap_bd( struct slap_op *op, struct slap_rep *rs )
{
	slap_callback	*cb = op->o_callback;
	BackendDB	*be = op->o_bd;

	op->o_bd = cb->sc_private;
	cb->sc_private = be;

	return SLAP_CB_CONTINUE;
}

static void
relay_back_add_cb( slap_callback *cb, struct slap_op *op )
{
	cb->sc_next = op->o_callback;
	cb->sc_response = relay_back_swap_bd;
	cb->sc_cleanup = relay_back_swap_bd;
	cb->sc_private = op->o_bd;
	op->o_callback = cb;
}

/*
 * selects the backend if not enforced at config;
 * in case of failure, behaves based on err:
 *	-1			don't send result
 *	LDAP_SUCCESS		don't send result; may send referral
 *	any valid error 	send as error result
 */
static BackendDB *
relay_back_select_backend( struct slap_op *op, struct slap_rep *rs, int err )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd = ri->ri_bd;

	if ( bd == NULL ) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
		if ( bd == op->o_bd ) {
			if ( err > LDAP_SUCCESS ) {
				send_ldap_error( op, rs,
						LDAP_UNWILLING_TO_PERFORM, 
						"back-relay would call self" );
			}
			return NULL;
		}
	}

	if ( bd == NULL && err > -1 ) {
		if ( default_referral ) {
			rs->sr_ref = referral_rewrite( default_referral,
				NULL, &op->o_req_dn, LDAP_SCOPE_DEFAULT );
			if ( !rs->sr_ref ) {
				rs->sr_ref = default_referral;
			}

			rs->sr_err = LDAP_REFERRAL;
			send_ldap_result( op, rs );

			if ( rs->sr_ref != default_referral ) {
				ber_bvarray_free( rs->sr_ref );
			}

		} else {
			/* NOTE: err is LDAP_INVALID_CREDENTIALS for bind,
			 * LDAP_NO_SUCH_OBJECT for other operations.
			 * noSuchObject cannot be returned by bind */
			rs->sr_err = err;
			send_ldap_result( op, rs );
		}
	}

	return bd;
}

int
relay_back_op_bind( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_INVALID_CREDENTIALS );
	if ( bd == NULL ) {
		return rc;
	}

	if ( bd->be_bind ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_bind )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;
}

int
relay_back_op_unbind( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd;
	int			rc = 1;

	bd = ri->ri_bd;
	if ( bd == NULL ) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
	}

	if ( bd && bd->be_unbind ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_unbind )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}
	}

	return 0;

}

int
relay_back_op_search( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_search ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_search )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_compare( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_compare ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_compare )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_modify( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_modify ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_modify )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_modrdn( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_modrdn ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_modrdn )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_add( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_add ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_add )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_delete( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_delete ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_delete )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}
	}

	return rc;

}

int
relay_back_op_abandon( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, -1 );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_abandon ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_abandon )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}
	}

	return rc;

}

int
relay_back_op_cancel( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_cancel ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_cancel )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_op_extended( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 1;

	bd = relay_back_select_backend( op, rs, LDAP_NO_SUCH_OBJECT );
	if ( bd == NULL ) {
		return 1;
	}

	if ( bd->be_extended ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_extended )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}

	} else {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
				"operation not supported "
				"within naming context" );
	}

	return rc;

}

int
relay_back_entry_release_rw( struct slap_op *op, Entry *e, int rw )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd;
	int			rc = 1;

	bd = ri->ri_bd;
	if ( bd == NULL) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
		if ( bd == NULL ) {
			return 1;
		}
	}

	if ( bd->be_release ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = bd;
		rc = ( bd->be_release )( op, e, rw );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_entry_get_rw( struct slap_op *op, struct berval *ndn,
	ObjectClass *oc, AttributeDescription *at, int rw, Entry **e )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd;
	int			rc = 1;

	bd = ri->ri_bd;
	if ( bd == NULL) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
		if ( bd == NULL ) {
			return 1;
		}
	}

	if ( bd->be_fetch ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = bd;
		rc = ( bd->be_fetch )( op, ndn, oc, at, rw, e );
		op->o_bd = be;
	}

	return rc;

}

/*
 * NOTE: even the existence of this function is questionable: we cannot
 * pass the bi_chk_referrals() call thru the rwm overlay because there
 * is no way to rewrite the req_dn back; but then relay_back_chk_referrals()
 * is passing the target database a DN that likely does not belong to its
 * naming context... mmmh.
 */
int
relay_back_chk_referrals( struct slap_op *op, struct slap_rep *rs )
{
	BackendDB		*bd;
	int			rc = 0;

	bd = relay_back_select_backend( op, rs, LDAP_SUCCESS );
	/* FIXME: this test only works if there are no overlays, so
	 * it is nearly useless; if made stricter, no nested back-relays
	 * can be instantiated... too bad. */
	if ( bd == NULL || bd == op->o_bd ) {
		return 0;
	}

	/* no nested back-relays... */
	if ( overlay_is_over( bd ) ) {
		slap_overinfo	*oi = (slap_overinfo *)bd->bd_info->bi_private;

		if ( oi->oi_orig == op->o_bd->bd_info ) {
			return 0;
		}
	}

	if ( bd->be_chk_referrals ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_chk_referrals )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}
	}

	return rc;

}

int
relay_back_operational( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd;
	int			rc = 1;

	bd = ri->ri_bd;
	if ( bd == NULL) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
		if ( bd == NULL ) {
			return 1;
		}
	}

	if ( bd->be_operational ) {
		BackendDB	*be = op->o_bd;
		slap_callback	cb;

		relay_back_add_cb( &cb, op );

		op->o_bd = bd;
		rc = ( bd->be_operational )( op, rs );
		op->o_bd = be;

		if ( op->o_callback == &cb ) {
			op->o_callback = op->o_callback->sc_next;
		}
	}

	return rc;

}

int
relay_back_has_subordinates( struct slap_op *op, Entry *e, int *hasSubs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	BackendDB		*bd;
	int			rc = 1;

	bd = ri->ri_bd;
	if ( bd == NULL) {
		bd = select_backend( &op->o_req_ndn, 0, 1 );
		if ( bd == NULL ) {
			return 1;
		}
	}

	if ( bd->be_has_subordinates ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = bd;
		rc = ( bd->be_has_subordinates )( op, e, hasSubs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_connection_init( BackendDB *bd, struct slap_conn *c )
{
	relay_back_info		*ri = (relay_back_info *)bd->be_private;

	bd = ri->ri_bd;
	if ( bd == NULL ) {
		return 0;
	}

	if ( bd->be_connection_init ) {
		return ( bd->be_connection_init )( bd, c );
	}

	return 0;
}

int
relay_back_connection_destroy( BackendDB *bd, struct slap_conn *c )
{
	relay_back_info		*ri = (relay_back_info *)bd->be_private;

	bd = ri->ri_bd;
	if ( bd == NULL) {
		return 0;
	}

	if ( bd->be_connection_destroy ) {
		return ( bd->be_connection_destroy )( bd, c );
	}

	return 0;

}

/*
 * FIXME: must implement tools as well
 */
