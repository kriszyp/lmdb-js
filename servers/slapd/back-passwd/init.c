/* init.c - initialize passwd backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "back-passwd.h"
#include "external.h"

ldap_pvt_thread_mutex_t passwd_mutex;

int
passwd_back_initialize(
    BackendInfo	*bi
)
{
	ldap_pvt_thread_mutex_init( &passwd_mutex );

	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = passwd_back_destroy;

	bi->bi_db_init = 0;
	bi->bi_db_config = passwd_back_db_config;
	bi->bi_db_open = 0;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = 0;

	bi->bi_op_bind = 0;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = passwd_back_search;
	bi->bi_op_compare = 0;
	bi->bi_op_modify = 0;
	bi->bi_op_modrdn = 0;
	bi->bi_op_add = 0;
	bi->bi_op_delete = 0;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

int
passwd_back_destroy(
	BackendInfo *bi
)
{
	ldap_pvt_thread_mutex_destroy( &passwd_mutex );
	return 0;
}

#if SLAPD_PASSWD == SLAPD_MOD_DYNAMIC

int
init_module( int argc, char *argv[] )
{
	BackendInfo bi;

	memset( &bi, '\0', sizeof( bi ) );
	bi.bi_type = "passwd";
	bi.bi_init = passwd_back_initialize;

	backend_add( &bi );

	return 0;
}

#endif /* SLAPD_PASSWD */

