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
	char *results, *command;
	struct berval suf_tcl;
	int code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_abandon.bv_len == 0) {
		return (-1);
	}

	if (tcl_merge_bvlist(be->be_suffix, &suf_tcl) == NULL) {
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_abandon.bv_len + suf_tcl.bv_len
		+ 80);
	sprintf (command, "%s ABANDON {%ld/%ld} {%s} {%ld/%d}",
		ti->ti_abandon.bv_val, op->o_connid, (long) op->o_msgid,
		suf_tcl.bv_val, op->o_connid, msgid);
	Tcl_Free (suf_tcl.bv_val);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_abandon_error: %s\n", results,
			0, 0);
	}

	free (results);
	return (err);
}
