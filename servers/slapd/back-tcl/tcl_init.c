/* $OpenLDAP$ */
/* tcl_init.c - tcl backend initialization
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

#ifdef SLAPD_TCL_DYNAMIC

void init_module(int argc, char *argv[]) {
   BackendInfo bi;

   memset( &bi, '\0', sizeof(bi) );
   bi.bi_type = "tcl";
   bi.bi_init = tcl_back_initialize;

   backend_add(&bi);
}

#endif /* SLAPD_TCL_DYNAMIC */

int
tcl_back_initialize (
	BackendInfo * bi
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
	ldap_pvt_thread_mutex_init (&tcl_interpreter_mutex);

	bi->bi_open = tcl_back_open;
	bi->bi_config = 0;
	bi->bi_close = tcl_back_close;
	bi->bi_destroy = tcl_back_destroy;

	bi->bi_db_init = tcl_back_db_init;
	bi->bi_db_config = tcl_back_db_config;
	bi->bi_db_open = tcl_back_db_open;
	bi->bi_db_close = tcl_back_db_close;
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

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	return 0;
}

int
tcl_back_open (
	BackendInfo * bi
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
	ldap_pvt_thread_mutex_init (&tcl_interpreter_mutex);

	return (0);
}

int
tcl_back_db_init (
	Backend * be
)
{
	struct tclinfo *ti;

	ti = (struct tclinfo *) ch_calloc (1, sizeof (struct tclinfo));

	ti->ti_script_path.bv_len = 0;
	ti->ti_script_path.bv_val = NULL;

	/*
	 * For some reason this causes problems
	 * specifically set to NULL
	 */
	ti->ti_bind.bv_len = 0;
	ti->ti_bind.bv_val = NULL;

	ti->ti_unbind.bv_len = 0;
	ti->ti_unbind.bv_val = NULL;

	ti->ti_search.bv_len = 0;
	ti->ti_search.bv_val = NULL;

	ti->ti_compare.bv_len = 0;
	ti->ti_compare.bv_val = NULL;

	ti->ti_modify.bv_len = 0;
	ti->ti_modify.bv_val = NULL;

	ti->ti_modrdn.bv_len = 0;
	ti->ti_modrdn.bv_val = NULL;

	ti->ti_add.bv_len = 0;
	ti->ti_add.bv_val = NULL;

	ti->ti_delete.bv_len = 0;
	ti->ti_delete.bv_val = NULL;

	ti->ti_abandon.bv_len = 0;
	ti->ti_abandon.bv_val = NULL;

	be->be_private = ti;

	return ti == NULL;
}

int
tcl_back_db_open (
	BackendDB * bd
)
{
	struct tclinfo *ti = (struct tclinfo *) bd->be_private;

	if (ti->ti_ii->interp == NULL) {	/* we need to make a new one */
		ti->ti_ii->interp = Tcl_CreateInterp ();
		Tcl_Init (ti->ti_ii->interp);
	}

	/* raise that count for the interpreter */
	ti->ti_ii->count++;

	/* now let's (try to) load the script */
	readtclscript (ti->ti_script_path.bv_val, ti->ti_ii->interp);

	/* install the debug command */
	Tcl_CreateCommand (ti->ti_ii->interp, "ldap:debug", &tcl_ldap_debug,
		NULL, NULL);

	return 0;
}
