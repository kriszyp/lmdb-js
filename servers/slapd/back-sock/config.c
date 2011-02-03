/* config.c - sock backend configuration file routine */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2007-2011 The OpenLDAP Foundation.
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
 * This work was initially developed by Brian Candler for inclusion
 * in OpenLDAP Software. Dynamic config support by Howard Chu.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "config.h"
#include "back-sock.h"

static ConfigDriver bs_cf_gen;
static int sock_over_setup();
static slap_response sock_over_response;

enum {
	BS_EXT = 1
};

static ConfigTable bscfg[] = {
	{ "socketpath", "pathname", 2, 2, 0, ARG_STRING|ARG_OFFSET,
		(void *)offsetof(struct sockinfo, si_sockpath),
		"( OLcfgDbAt:7.1 NAME 'olcDbSocketPath' "
			"DESC 'Pathname for Unix domain socket' "
			"EQUALITY caseExactMatch "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ "extensions", "ext", 2, 0, 0, ARG_MAGIC|BS_EXT,
		bs_cf_gen, "( OLcfgDbAt:7.2 NAME 'olcDbSocketExtensions' "
			"DESC 'binddn, peername, or ssf' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ NULL, NULL }
};

static ConfigOCs bsocs[] = {
	{ "( OLcfgDbOc:7.1 "
		"NAME 'olcDbSocketConfig' "
		"DESC 'Socket backend configuration' "
		"SUP olcDatabaseConfig "
		"MUST olcDbSocketPath "
		"MAY olcDbSocketExtensions )",
			Cft_Database, bscfg },
	{ NULL, 0, NULL }
};

static ConfigOCs osocs[] = {
	{ "( OLcfgOvOc:22.1 "
		"NAME 'olcOvSocketConfig' "
		"DESC 'Socket overlay configuration' "
		"SUP olcOverlayConfig "
		"MUST olcDbSocketPath "
		"MAY olcDbSocketExtensions )",
			Cft_Overlay, bscfg },
	{ NULL, 0, NULL }
};

static slap_verbmasks bs_exts[] = {
	{ BER_BVC("binddn"), SOCK_EXT_BINDDN },
	{ BER_BVC("peername"), SOCK_EXT_PEERNAME },
	{ BER_BVC("ssf"), SOCK_EXT_SSF },
	{ BER_BVC("connid"), SOCK_EXT_CONNID },
	{ BER_BVNULL, 0 }
};

static int
bs_cf_gen( ConfigArgs *c )
{
	struct sockinfo	*si;
	int rc;

	if ( c->be && c->table == Cft_Database )
		si = c->be->be_private;
	else if ( c->bi )
		si = c->bi->bi_private;
	else
		return ARG_BAD_CONF;

	if ( c->op == SLAP_CONFIG_EMIT ) {
		switch( c->type ) {
		case BS_EXT:
			return mask_to_verbs( bs_exts, si->si_extensions, &c->rvalue_vals );
		}
	} else if ( c->op == LDAP_MOD_DELETE ) {
		switch( c->type ) {
		case BS_EXT:
			if ( c->valx < 0 ) {
				si->si_extensions = 0;
				rc = 0;
			} else {
				slap_mask_t dels = 0;
				rc = verbs_to_mask( c->argc, c->argv, bs_exts, &dels );
				if ( rc == 0 )
					si->si_extensions ^= dels;
			}
			return rc;
		}

	} else {
		switch( c->type ) {
		case BS_EXT:
			return verbs_to_mask( c->argc, c->argv, bs_exts, &si->si_extensions );
		}
	}
	return 1;
}

int
sock_back_init_cf( BackendInfo *bi )
{
	int rc;
	bi->bi_cf_ocs = bsocs;

	rc = config_register_schema( bscfg, bsocs );
	if ( !rc )
		rc = sock_over_setup();
	return rc;
}

/* sock overlay wrapper */
static slap_overinst sockover;

static int sock_over_db_init( Backend *be, struct config_reply_s *cr );
static int sock_over_db_destroy( Backend *be, struct config_reply_s *cr );

static BI_op_bind *sockfuncs[] = {
	sock_back_bind,
	sock_back_unbind,
	sock_back_search,
	sock_back_compare,
	sock_back_modify,
	sock_back_modrdn,
	sock_back_add,
	sock_back_delete
};

static int sock_over_op(
	Operation *op,
	SlapReply *rs
)
{
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	void *private = op->o_bd->be_private;
	slap_callback cb = { NULL, slap_null_cb, NULL, NULL };
	slap_operation_t which;
	int rc;

	switch (op->o_tag) {
	case LDAP_REQ_BIND:	which = op_bind; break;
	case LDAP_REQ_UNBIND:	which = op_unbind; break;
	case LDAP_REQ_SEARCH:	which = op_search; break;
	case LDAP_REQ_COMPARE:	which = op_compare; break;
	case LDAP_REQ_MODIFY:	which = op_modify; break;
	case LDAP_REQ_MODRDN:	which = op_modrdn; break;
	case LDAP_REQ_ADD:	which = op_add; break;
	case LDAP_REQ_DELETE:	which = op_delete; break;
	default:
		return SLAP_CB_CONTINUE;
	}
	op->o_bd->be_private = on->on_bi.bi_private;
	cb.sc_next = op->o_callback;
	op->o_callback = &cb;
	rc = sockfuncs[which]( op, rs );
	op->o_bd->be_private = private;
	op->o_callback = cb.sc_next;
	return rc;
}

static int
sock_over_response( Operation *op, SlapReply *rs )
{
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	struct sockinfo *si = (struct sockinfo *)on->on_bi.bi_private;
	FILE *fp;

	if ( rs->sr_type != REP_RESULT )
		return SLAP_CB_CONTINUE;

	if (( fp = opensock( si->si_sockpath )) == NULL )
		return SLAP_CB_CONTINUE;

	/* write out the result */
	fprintf( fp, "RESULT\n" );
	fprintf( fp, "msgid: %ld\n", (long) op->o_msgid );
	sock_print_conn( fp, op->o_conn, si );
	fprintf( fp, "code: %d\n", rs->sr_err );
	if ( rs->sr_matched )
		fprintf( fp, "matched: %s\n", rs->sr_matched );
	if (rs->sr_text )
		fprintf( fp, "info: %s\n", rs->sr_text );
	fprintf( fp, "\n" );
	fclose( fp );

	return SLAP_CB_CONTINUE;
}

static int
sock_over_setup()
{
	int rc;

	sockover.on_bi.bi_type = "sock";
	sockover.on_bi.bi_db_init = sock_over_db_init;
	sockover.on_bi.bi_db_destroy = sock_over_db_destroy;

	sockover.on_bi.bi_op_bind = sock_over_op;
	sockover.on_bi.bi_op_unbind = sock_over_op;
	sockover.on_bi.bi_op_search = sock_over_op;
	sockover.on_bi.bi_op_compare = sock_over_op;
	sockover.on_bi.bi_op_modify = sock_over_op;
	sockover.on_bi.bi_op_modrdn = sock_over_op;
	sockover.on_bi.bi_op_add = sock_over_op;
	sockover.on_bi.bi_op_delete = sock_over_op;
	sockover.on_response = sock_over_response;

	sockover.on_bi.bi_cf_ocs = osocs;

	rc = config_register_schema( bscfg, osocs );
	if ( rc ) return rc;

	return overlay_register( &sockover );
}

static int
sock_over_db_init(
    Backend	*be,
	struct config_reply_s *cr
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	void *private = be->be_private;
	int rc;

	be->be_private = NULL;
	rc = sock_back_db_init( be, cr );
	on->on_bi.bi_private = be->be_private;
	be->be_private = private;
	return rc;
}

static int
sock_over_db_destroy(
    Backend	*be,
	struct config_reply_s *cr
)
{
	slap_overinst	*on = (slap_overinst *)be->bd_info;
	void *private = be->be_private;
	int rc;

	be->be_private = on->on_bi.bi_private;
	rc = sock_back_db_destroy( be, cr );
	on->on_bi.bi_private = be->be_private;
	be->be_private = private;
	return rc;
}
