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
	Backend * be,
	Connection * conn,
	Operation * op
)
{
	char *command, *results;
	struct berval suf_tcl;
	int code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_unbind.bv_len == 0) {
		return (-1);
	}

	if (tcl_merge_bvlist (be->be_suffix, &suf_tcl) == NULL) {
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_unbind.bv_len + suf_tcl.bv_len
		+ conn->c_dn.bv_len + 64);
	sprintf (command, "%s UNBIND {%ld} {%s} {%s}",
		ti->ti_unbind.bv_val, (long) op->o_msgid, suf_tcl.bv_val, 
		conn->c_dn.bv_val ?  conn->c_dn.bv_val : "");
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
