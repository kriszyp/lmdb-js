/* $OpenLDAP$ */
/* close.c - tcl close routines
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

#include "slap.h"
#include "tcl_back.h"

int
tcl_back_close (
	BackendInfo * bi
)
{
	Tcl_DeleteInterp (global_i->interp);

	return (0);
}

int
tcl_back_destroy (
	BackendInfo * bi
)
{
	free (global_i->interp);
	free (global_i);
	ldap_pvt_thread_mutex_destroy (&tcl_interpreter_mutex);

	return (0);
}

int
tcl_back_db_close (
	BackendDB * bd
)
{
	struct tclinfo *ti = (struct tclinfo *) bd->be_private;
	struct i_info *ti_tmp;

	/* Disable the interp and associated struct */
	ti->ti_ii->count--;
	if (!ti->ti_ii->count && strcasecmp ("default", ti->ti_ii->name)) {
		/* no more db's using this and it's not the default */
		for (ti_tmp = global_i; ti_tmp->next != ti->ti_ii; ti_tmp
			= ti_tmp->next);
		/* This bypasses this interp struct in the global hash */
		ti_tmp->next = ti->ti_ii->next;
		Tcl_DeleteInterp (ti->ti_ii->interp);
	}
	return (0);
}

int
tcl_back_db_destroy (
	BackendDB * bd
)
{
	struct tclinfo *ti = (struct tclinfo *) bd->be_private;

	/*
	 * Now free up the allocated memory used
	 */
	ti->ti_ii->count--;
	if (!ti->ti_ii->count && strcasecmp ("default", ti->ti_ii->name)) {
		free (ti->ti_ii->interp);
		free (ti->ti_ii);
		free (ti);
	}
	free (bd->be_private);
	bd->be_private = NULL;

	return (0);
}
