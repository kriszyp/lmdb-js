/* init.c - initialize relay backend */
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
#include <ac/string.h>

#include "slap.h"
#include "back-relay.h"

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
#if 0
	bi->bi_db_close =relay_back_db_close;
#endif
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
#if 0	/* see comment in op.c */
	bi->bi_chk_referrals = relay_back_chk_referrals;
#endif
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
	BER_BVZERO( &ri->ri_realsuffix );
	ri->ri_massage = 0;

	be->be_private = (void *)ri;

	return 0;
}

int
relay_back_db_open( Backend *be )
{
	relay_back_info		*ri = (relay_back_info *)be->be_private;

	assert( ri != NULL );

	if ( !BER_BVISNULL( &ri->ri_realsuffix ) ) {
		ri->ri_bd = select_backend( &ri->ri_realsuffix, 0, 1 );

		/* must be there: it was during config! */
		assert( ri->ri_bd != NULL );

		/* inherit controls */
		AC_MEMCPY( be->be_ctrls, ri->ri_bd->be_ctrls, sizeof( be->be_ctrls ) );

	} else {
		/* inherit all? */
		AC_MEMCPY( be->be_ctrls, frontendDB->be_ctrls, sizeof( be->be_ctrls ) );
	}

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
		if ( !BER_BVISNULL( &ri->ri_realsuffix ) ) {
			ch_free( ri->ri_realsuffix.bv_val );
		}
		ch_free( ri );
	}

	return 0;
}

#if SLAPD_RELAY == SLAPD_MOD_DYNAMIC

/* conditionally define the init_module() function */
SLAP_BACKEND_INIT_MODULE( relay )

#endif /* SLAPD_RELAY == SLAPD_MOD_DYNAMIC */

