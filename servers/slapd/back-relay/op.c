/* op.c - relay backend operations */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003-2004 The OpenLDAP Foundation.
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-relay.h"

int
relay_back_op_bind( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_bind ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_bind )( op, rs );
		op->o_bd = be;
	}

	return rc;
}

int
relay_back_op_unbind( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_unbind ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_unbind )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_search( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_search ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_search )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_compare( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_compare ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_compare )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_modify( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_modify ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_modify )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_modrdn( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_modrdn ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_modrdn )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_add( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_add ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_add )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_delete( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_delete ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_delete )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_abandon( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_abandon ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_abandon )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_cancel( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_cancel ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_cancel )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_op_extended( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_extended ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_extended )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_entry_release_rw( struct slap_op *op, Entry *e, int rw )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_release ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_release )( op, e, rw );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_entry_get_rw( struct slap_op *op, struct berval *ndn,
	ObjectClass *oc, AttributeDescription *at, int rw, Entry **e )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_fetch ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_fetch )( op, ndn, oc, at, rw, e );
		op->o_bd = be;
	}

	return rc;

}

int relay_back_chk_referrals( struct slap_op *op, struct slap_rep *rs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_chk_referrals ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_chk_referrals )( op, rs );
		op->o_bd = be;
	}

	return rc;

}

int relay_back_operational( struct slap_op *op, struct slap_rep *rs, int opattrs, Attribute **ap )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_operational ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_operational )( op, rs, opattrs, ap );
		op->o_bd = be;
	}

	return rc;

}

int relay_back_has_subordinates( struct slap_op *op, Entry *e, int *hasSubs )
{
	relay_back_info		*ri = (relay_back_info *)op->o_bd->be_private;
	int			rc = 1;

	if ( ri->ri_bd->be_has_subordinates ) {
		BackendDB	*be = op->o_bd;

		op->o_bd = ri->ri_bd;
		rc = ( ri->ri_bd->be_has_subordinates )( op, e, hasSubs );
		op->o_bd = be;
	}

	return rc;

}

int
relay_back_connection_init( BackendDB *bd, struct slap_conn *c )
{
	relay_back_info		*ri = (relay_back_info *)bd->be_private;

	if ( ri->ri_bd->be_connection_init ) {
		return ( ri->ri_bd->be_connection_init )( ri->ri_bd, c );
	}

	return 1;

}

int
relay_back_connection_destroy( BackendDB *bd, struct slap_conn *c )
{
	relay_back_info		*ri = (relay_back_info *)bd->be_private;

	if ( ri->ri_bd->be_connection_destroy ) {
		return ( ri->ri_bd->be_connection_destroy )( ri->ri_bd, c );
	}

	return 1;

}

