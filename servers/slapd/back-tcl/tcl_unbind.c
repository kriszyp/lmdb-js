/* $OpenLDAP$ */
/* unbind.c - tcl unbind routines
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
tcl_back_unbind (
	Operation * op,
	SlapReply * rs
)
{
	char *command, *results;
	struct berval suf_tcl;
	int code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) op->o_bd->be_private;

	if (ti->ti_unbind.bv_len == 0) {
		return (-1);
	}

	if (tcl_merge_bvlist (op->o_bd->be_suffix, &suf_tcl) == NULL) {
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_unbind.bv_len + suf_tcl.bv_len
		+ op->o_conn->c_dn.bv_len + 84);
	sprintf (command, "%s UNBIND {%ld/%ld} {%s} {%s}",
		ti->ti_unbind.bv_val, op->o_connid, (long) op->o_msgid,
		suf_tcl.bv_val, op->o_conn->c_dn.bv_val ?  op->o_conn->c_dn.bv_val : "");
	Tcl_Free (suf_tcl.bv_val);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		Debug (LDAP_DEBUG_SHELL, "tcl_unbind_error: %s\n", results,
			0, 0);
	}

	free (results);
	return (err);
}
