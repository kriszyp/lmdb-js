/* $OpenLDAP$ */
/* add.c - tcl add routine
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
tcl_back_add (
	Operation * op,
	SlapReply * rs
)
{
	char *command, *entrystr, *results;
	struct berval suf_tcl;
	int code;
	struct tclinfo *ti = (struct tclinfo *) op->o_bd->be_private;

	if (ti->ti_add.bv_len == 0) {
		send_ldap_error (op, rs, LDAP_UNWILLING_TO_PERFORM,
			"add not implemented" );
		return (-1);
	}

	if (tcl_merge_bvlist (op->o_bd->be_suffix, &suf_tcl) == NULL) {
		send_ldap_error (op, rs, LDAP_OTHER, NULL);
		return (-1);
	}

	entrystr = tcl_clean_entry(op->oq_add.rs_e);

	command = (char *) ch_malloc (ti->ti_add.bv_len + suf_tcl.bv_len +
		strlen(entrystr) + 52);
	sprintf (command, "%s ADD {%ld/%ld} {%s} {%s}",
		ti->ti_add.bv_val, op->o_connid, (long) op->o_msgid, 
		suf_tcl.bv_val, entrystr);
	Tcl_Free (suf_tcl.bv_val);
	free (entrystr);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		rs->sr_err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_add_error: %s\n", results, 0, 0);
	} else {
		interp_send_results (op, rs, results);
	}

	if (rs->sr_err != LDAP_SUCCESS) {
		rs->sr_text = "internal backend error";
		send_ldap_result (op, rs);
	}

	free (results);
	return (rs->sr_err);
}
