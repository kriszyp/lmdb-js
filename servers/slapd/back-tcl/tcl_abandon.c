/* $OpenLDAP$ */
/* abandon.c - tcl abandon routine
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
tcl_back_abandon (
	Backend * be,
	Connection * conn,
	Operation * op,
	int msgid
)
{
	char *suf_tcl, *results, *command;
	int i, code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_abandon == NULL) {
		return (-1);
	}

	for (i = 0; be->be_suffix[i] != NULL; i++);
	suf_tcl = Tcl_Merge (i, be->be_suffix);

	command = (char *) ch_malloc (strlen (ti->ti_abandon) + strlen (suf_tcl)
		+ 20);
	sprintf (command, "%s ABANDON {%ld} {%s}",
		ti->ti_abandon, op->o_msgid, suf_tcl);
	Tcl_Free (suf_tcl);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OPERATIONS_ERROR;
		Debug (LDAP_DEBUG_SHELL, "tcl_abandon_error: %s\n", results,
			0, 0);
	}

	free (results);
	return (err);
}
