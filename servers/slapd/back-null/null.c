/* null.c - the null backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2004 The OpenLDAP Foundation.
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
 * This work was originally developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/string.h>

#include "slap.h"
#include "external.h"

/*
 * former external.h
 */

extern BI_db_init		null_back_db_init;
extern BI_db_destroy 		null_back_db_destroy;
extern BI_db_config		null_back_db_config;

extern BI_op_bind		null_back_bind;
extern BI_op_search		null_back_search;
extern BI_op_compare 		null_back_compare;
extern BI_op_modify		null_back_modify;
extern BI_op_modrdn		null_back_modrdn;
extern BI_op_add		null_back_add;
extern BI_op_delete		null_back_delete;

struct null_info {
	int bind_allowed;
};

int
null_back_bind( Operation *op, SlapReply *rs )
{
	struct null_info *ni = (struct null_info *) op->o_bd->be_private;

	if ( ni->bind_allowed ) {
		/* front end will send result on success (0) */
		return 0;
	}

	rs->sr_err = LDAP_INVALID_CREDENTIALS;
	send_ldap_result( op, rs );

	return 1;
}

/* add, delete, modify, modrdn, search */
int
null_back_success( Operation *op, SlapReply *rs )
{
	rs->sr_err = LDAP_SUCCESS;
	send_ldap_result( op, rs );
	return 0;
}

/* compare */
int
null_back_false( Operation *op, SlapReply *rs )
{
	rs->sr_err = LDAP_COMPARE_FALSE;
	send_ldap_result( op, rs );
	return 0;
}

int
null_back_db_config(
	BackendDB	*be,
	const char	*fname,
	int			lineno,
	int			argc,
	char		**argv )
{
	struct null_info *ni = (struct null_info *) be->be_private;

	if ( ni == NULL ) {
		fprintf( stderr, "%s: line %d: null database info is null!\n",
			fname, lineno );
		return 1;
	}

	/* bind requests allowed */
	if ( strcasecmp( argv[0], "bind" ) == 0 ) {
		if ( argc < 2 ) {
			fprintf( stderr,
	"%s: line %d: missing <on/off> in \"bind <on/off>\" line\n",
			         fname, lineno );
			return 1;
		}
		ni->bind_allowed = strcasecmp( argv[1], "off" );

	/* anything else */
	} else {
		return SLAP_CONF_UNKNOWN;
	}

	return 0;
}


int
null_back_db_init( BackendDB *be )
{
	struct null_info *ni;

	ni = ch_calloc( 1, sizeof(struct null_info) );
	ni->bind_allowed = 0;
	be->be_private = ni;
	return 0;
}

int
null_back_db_destroy(
    Backend	*be
)
{
	free( be->be_private );
	return 0;
}


int
null_back_initialize(
    BackendInfo	*bi
)
{
	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = null_back_db_init;
	bi->bi_db_config = null_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = null_back_db_destroy;

	bi->bi_op_bind = null_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = null_back_success;
	bi->bi_op_compare = null_back_false;
	bi->bi_op_modify = null_back_success;
	bi->bi_op_modrdn = null_back_success;
	bi->bi_op_add = null_back_success;
	bi->bi_op_delete = null_back_success;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

#if SLAPD_NULL == SLAPD_MOD_DYNAMIC

int
init_module( int argc, char *argv[] )
{
	BackendInfo bi;

	memset( &bi, '\0', sizeof( bi ) );
	bi.bi_type = "null";
	bi.bi_init = null_back_initialize;

	backend_add( &bi );

	return 0;
}

#endif /* SLAPD_NULL */
