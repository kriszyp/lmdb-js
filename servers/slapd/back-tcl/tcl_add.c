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
	Backend * be,
	Connection * conn,
	Operation * op,
	Entry * e
)
{
	char *command, *entrystr, *results;
	struct berval suf_tcl;
	int code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_add.bv_len == 0) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"add not implemented", NULL, NULL );
		return (-1);
	}

	if (tcl_merge_bvlist (be->be_suffix, &suf_tcl) == NULL) {
		send_ldap_result (conn, op, LDAP_OTHER, NULL,
			NULL, NULL, NULL );
		return (-1);
	}

	entrystr = tcl_clean_entry(e);

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
		err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_add_error: %s\n", results, 0, 0);
	} else {
		interp_send_results (be, conn, op, results, NULL, 0);
	}

	if (err != LDAP_SUCCESS)
		send_ldap_result (conn, op, err, NULL,
			"internal backend error", NULL, NULL );

	free (results);
	return (err);
}
