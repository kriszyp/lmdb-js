/* init.c - initialize relay backend */
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

#ifdef SLAPD_RELAY_DYNAMIC

int
init_module( int argc, char *argv[] ) {
	BackendInfo	bi;

	memset( &bi, '\0', sizeof( bi ) );
	bi.bi_type = "relay";
	bi.bi_init = relay_back_initialize;

	backend_add(&bi);
	return 0;
}

#endif /* SLAPD_RELAY_DYNAMIC */

int
relay_back_initialize( BackendInfo *bi )
{
	bi->bi_init = 0;
	bi->bi_open = 0;
	bi->bi_config = 0;
	bi->bi_close = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = relay_back_db_init;
	bi->bi_db_config = relay_back_db_config;
	bi->bi_db_open = relay_back_db_open;
	bi->bi_db_close = 0 /* relay_back_db_close */ ;
	bi->bi_db_destroy = relay_back_db_destroy;

	bi->bi_op_bind = relay_back_op_bind;
	bi->bi_op_unbind = relay_back_op_unbind;
	bi->bi_op_search = relay_back_op_search;
	bi->bi_op_compare = relay_back_op_compare;
	bi->bi_op_modify = relay_back_op_modify;
	bi->bi_op_modrdn = relay_back_op_modrdn;
	bi->bi_op_add = relay_back_op_add;
	bi->bi_op_delete = relay_back_op_delete;
	bi->bi_op_abandon = relay_back_op_abandon;
	bi->bi_op_cancel = relay_back_op_cancel;
	bi->bi_extended = relay_back_op_extended;
	bi->bi_entry_release_rw = relay_back_entry_release_rw;
	bi->bi_entry_get_rw = relay_back_entry_get_rw;
	bi->bi_chk_referrals = relay_back_chk_referrals;
	bi->bi_operational = relay_back_operational;
	bi->bi_has_subordinates = relay_back_has_subordinates;

	bi->bi_connection_init = relay_back_connection_init;
	bi->bi_connection_destroy = relay_back_connection_destroy;

	return 0;
}

int
relay_back_db_init( Backend *be )
{
	relay_back_info		*ri;

	be->be_private = NULL;

	ri = (relay_back_info *)ch_calloc( 1, sizeof( relay_back_info ) );
	if ( ri == NULL ) {
 		return -1;
 	}

	ri->ri_bd = NULL;

	be->be_private = (void *)ri;

	return 0;
}

int
relay_back_db_open( Backend *be )
{
	relay_back_info		*ri = (relay_back_info *)be->be_private;

	assert( ri != NULL );

#if 0
	if ( !ri->ri_do_not_massage ) {
		char	*argv[ 4 ];

		argv[ 0 ] = "suffixmassage";
		argv[ 1 ] = be->be_suffix[0].bv_val;
		argv[ 2 ] = ri->ri_bd->be_suffix[0].bv_val;
		argv[ 3 ] = NULL;

		if ( be->be_config( be, "back-relay", 1, 3, argv ) ) {
			return 1;
		}
	}
#endif

	return 0;
}

int
relay_back_db_close( Backend *be )
{
	return 0;
}

int
relay_back_db_destroy( Backend *be )
{
	relay_back_info		*ri = (relay_back_info *)be->be_private;

	if ( ri ) {
		ch_free( ri );
	}

	return 0;
}
