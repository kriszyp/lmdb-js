/* backover.c - backend overlay routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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

/* Functions to overlay other modules over a backend. */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#define SLAPD_TOOLS
#include "slap.h"

static slap_overinst *overlays;

enum db_which { db_open = 0, db_close, db_destroy };

static int
over_db_func(
	BackendDB *be,
	enum db_which which
)
{
	slap_overinfo *oi = (slap_overinfo *) be->bd_info;
	slap_overinst *on = oi->oi_list;
	BackendDB bd;
	BI_db_open **func;
	int rc = 0;

	func = &oi->oi_bd.bd_info->bi_db_open;
	if ( func[which] ) {
		rc = func[which]( &oi->oi_bd );
		if ( rc ) return rc;
	}

	bd = *be;
	for (; on; on=on->on_next) {
		bd.bd_info = &on->on_bi;
		func = &on->on_bi.bi_db_open;
		if (func[which]) {
			rc = func[which]( &bd );
			if ( rc ) break;
		}
	}
	return rc;
}

static int
over_db_config(
	BackendDB *be,
	const char *fname,
	int lineno,
	int argc,
	char **argv
)
{
	slap_overinfo *oi = (slap_overinfo *) be->bd_info;
	slap_overinst *on = oi->oi_list;
	BackendDB bd;
	int rc = 0;

	if ( oi->oi_bd.bd_info->bi_db_config ) {
		rc = oi->oi_bd.bd_info->bi_db_config( &oi->oi_bd, fname, lineno,
			argc, argv );
		if ( rc ) return rc;
	}

	bd = *be;
	for (; on; on=on->on_next) {
		bd.bd_info = &on->on_bi;
		if (on->on_bi.bi_db_config) {
			rc = on->on_bi.bi_db_config( &bd, fname, lineno,
				argc, argv );
			if ( rc ) break;
		}
	}
	return rc;
}

static int
over_db_open(
	BackendDB *be
)
{
	return over_db_func( be, db_open );
}

static int
over_db_close(
	BackendDB *be
)
{
	return over_db_func( be, db_close );
}

static int
over_db_destroy(
	BackendDB *be
)
{
	slap_overinfo *oi = (slap_overinfo *) be->bd_info;
	slap_overinst *on = oi->oi_list, *next;
	int rc;

	rc = over_db_func( be, db_destroy );

	for (next = on->on_next; on; on=next) {
		next = on->on_next;
		free( on );
	}
	free( oi );
	return rc;
}

static int
over_back_response ( Operation *op, SlapReply *rs )
{
	slap_overinfo *oi = (slap_overinfo *) op->o_bd->bd_info;
	slap_overinst *on = oi->oi_list;
	int rc = SLAP_CB_CONTINUE;
	BackendDB *be = op->o_bd, db = *op->o_bd;
	slap_callback *sc = op->o_callback->sc_private;
	slap_callback *s0 = op->o_callback;

	op->o_bd = &db;
	op->o_callback = sc;
	for (; on; on=on->on_next ) {
		if ( on->on_response ) {
			db.bd_info = (BackendInfo *)on;
			rc = on->on_response( op, rs );
			if ( rc != SLAP_CB_CONTINUE ) break;
		}
	}
	if ( sc && (rc == SLAP_CB_CONTINUE) ) {
		rc = sc->sc_response( op, rs );
	}
	op->o_bd = be;
	op->o_callback = s0;
	return rc;
}

enum op_which { op_bind = 0, op_unbind, op_search, op_compare,
	op_modify, op_modrdn, op_add, op_delete, op_abandon,
	op_cancel, op_extended };

static int
over_op_func(
	Operation *op,
	SlapReply *rs,
	enum op_which which
)
{
	slap_overinfo *oi = (slap_overinfo *) op->o_bd->bd_info;
	slap_overinst *on = oi->oi_list;
	BI_op_bind **func;
	BackendDB *be = op->o_bd, db = *op->o_bd;
	slap_callback cb = {over_back_response, NULL};
	int rc = SLAP_CB_CONTINUE;

	op->o_bd = &db;
	cb.sc_private = op->o_callback;
	op->o_callback = &cb;

	for (; on; on=on->on_next ) {
		func = &on->on_bi.bi_op_bind;
		if ( func[which] ) {
			db.bd_info = (BackendInfo *)on;
			rc = func[which]( op, rs );
			if ( rc != SLAP_CB_CONTINUE ) break;
		}
	}

	op->o_bd = be;
	func = &oi->oi_bd.bd_info->bi_op_bind;
	if ( func[which] && rc == SLAP_CB_CONTINUE ) {
		rc = func[which]( op, rs );
	}
	/* should not fall thru this far without anything happening... */
	if ( rc == SLAP_CB_CONTINUE ) {
		rc = LDAP_UNWILLING_TO_PERFORM;
	}
	op->o_callback = cb.sc_private;
	return rc;
}

static int
over_op_bind( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_bind );
}

static int
over_op_unbind( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_unbind );
}

static int
over_op_search( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_search );
}

static int
over_op_compare( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_compare );
}

static int
over_op_modify( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_modify );
}

static int
over_op_modrdn( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_modrdn );
}

static int
over_op_add( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_add );
}

static int
over_op_delete( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_delete );
}

static int
over_op_abandon( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_abandon );
}

static int
over_op_cancel( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_cancel );
}

static int
over_op_extended( Operation *op, SlapReply *rs )
{
	return over_op_func( op, rs, op_extended );
}

int
overlay_register(
	slap_overinst *on
)
{
	on->on_next = overlays;
	overlays = on;
	return 0;
}

static const char overtype[] = "over";

/* add an overlay to a particular backend. */
int
overlay_config( BackendDB *be, const char *ov )
{
	slap_overinst *on, *on2, *prev;
	slap_overinfo *oi;
	BackendInfo *bi;

	for ( on = overlays; on; on=on->on_next ) {
		if (!strcmp( ov, on->on_bi.bi_type ) )
			break;
	}
	if (!on) {
		Debug( LDAP_DEBUG_ANY, "overlay %s not found\n", ov, 0, 0 );
		return 1;
	}

	/* If this is the first overlay on this backend, set up the
	 * overlay info structure
	 */
	if ( be->bd_info->bi_type != overtype ) {
		oi = ch_malloc( sizeof(slap_overinfo) );
		oi->oi_bd = *be;
		oi->oi_bi = *be->bd_info;
		oi->oi_list = NULL;
		bi = (BackendInfo *)oi;

		bi->bi_type = (char *)overtype;

		bi->bi_db_config = over_db_config;
		bi->bi_db_open = over_db_open;
		bi->bi_db_close = over_db_close;
		bi->bi_db_destroy = over_db_destroy;

		bi->bi_op_bind = over_op_bind;
		bi->bi_op_unbind = over_op_unbind;
		bi->bi_op_search = over_op_search;
		bi->bi_op_compare = over_op_compare;
		bi->bi_op_modify = over_op_modify;
		bi->bi_op_modrdn = over_op_modrdn;
		bi->bi_op_add = over_op_add;
		bi->bi_op_delete = over_op_delete;
		bi->bi_op_abandon = over_op_abandon;
		bi->bi_op_cancel = over_op_cancel;
		bi->bi_extended = over_op_extended;

		be->bd_info = bi;
	}

	/* Walk to the end of the list of overlays, add the new
	 * one onto the end
	 */
	oi = (slap_overinfo *) be->bd_info;
	for ( prev=NULL, on2 = oi->oi_list; on2; prev=on2, on2=on2->on_next );
	on2 = ch_calloc( 1, sizeof(slap_overinst) );
	if ( !prev ) {
		oi->oi_list = on2;
	} else {
		prev->on_next = on2;
	}
	*on2 = *on;
	on2->on_next = NULL;
	on2->on_info = oi;

	/* Any initialization needed? */
	if ( on->on_bi.bi_db_init ) {
		be->bd_info = (BackendInfo *)on2;
		on2->on_bi.bi_db_init( be );
		be->bd_info = (BackendInfo *)oi;
	}

	return 0;
}

