/*
 * tcl_init.c - tcl backend initialization
 *
 * Copyright 1999, Ben Collins <bcollins@debian.org>, All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>

#include "slap.h"
#include "tcl_back.h"

ldap_pvt_thread_mutex_t tcl_interpreter_mutex;

int
tcl_back_initialize(
	BackendInfo	*bi
)
{
	/* Initialize the global interpreter array */
	global_i = (struct i_info *) ch_malloc (sizeof (struct i_info));
	global_i->count = 0;
	global_i->name = "default";
	global_i->next = NULL;
	global_i->interp = Tcl_CreateInterp ();
	Tcl_Init (global_i->interp);

	/* Initialize the global interpreter lock */
	ldap_pvt_thread_mutex_init( &tcl_interpreter_mutex );
	bi->bi_open = NULL;
	bi->bi_config = NULL;
	bi->bi_close = NULL;
	bi->bi_destroy = NULL;

	bi->bi_db_init = tcl_back_db_init;
	bi->bi_db_config = tcl_back_db_config;
	bi->bi_db_open = tcl_back_db_open;
	bi->bi_db_close = NULL;
	bi->bi_db_destroy = tcl_back_db_destroy;

	bi->bi_op_bind = tcl_back_bind;
	bi->bi_op_unbind = tcl_back_unbind;
	bi->bi_op_search = tcl_back_search;
	bi->bi_op_compare = tcl_back_compare;
	bi->bi_op_modify = tcl_back_modify;
	bi->bi_op_modrdn = tcl_back_modrdn;
	bi->bi_op_add = tcl_back_add;
	bi->bi_op_delete = tcl_back_delete;
	bi->bi_op_abandon = tcl_back_abandon;

	bi->bi_acl_group = NULL;

	return 0;
}

int
tcl_back_db_init(
	Backend	*be
)
{
	struct tclinfo	*ti;

	ti = (struct tclinfo *) ch_calloc( 1, sizeof(struct tclinfo) );

	/*
	 * For some reason this causes problems
	 * specifically set to NULL
	 */
	ti->ti_bind = NULL;
	ti->ti_unbind = NULL;
	ti->ti_search = NULL;
	ti->ti_compare = NULL;
	ti->ti_modify = NULL;
	ti->ti_modrdn = NULL;
	ti->ti_add = NULL;
	ti->ti_delete = NULL;
	ti->ti_abandon = NULL;

	be->be_private = ti;

	return ti == NULL;
}

int
tcl_back_db_destroy(
	Backend	*be
)
{
	free( be->be_private );
	return 0;
}
