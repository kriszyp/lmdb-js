/* modrdn.c - tcl modify rdn routines
 *
 * $Id: tcl_modrdn.c,v 1.3 1999/02/18 01:18:39 bcollins Exp $
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
tcl_back_modrdn (
	Backend * be,
	Connection * conn,
	Operation * op,
	char *dn,
	char *newrdn,
	int deleteoldrdn
)
{
	char *command, *suf_tcl, *results;
	int i, code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_modrdn == NULL) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"modrdn not implemented");
		return (-1);
	}

	for (i = 0; be->be_suffix[i] != NULL; i++);
	suf_tcl = Tcl_Merge (i, be->be_suffix);

	command = (char *) ch_malloc (strlen (ti->ti_modrdn) + strlen (suf_tcl)
		+ strlen (dn) + strlen (newrdn) + 64);
	sprintf (command, "%s MODRDN {%ld} {%s} {%s} {%s} %d",
		ti->ti_add, op->o_msgid, suf_tcl, dn, newrdn, deleteoldrdn
		? 1 : 0);
	Tcl_Free (suf_tcl);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OPERATIONS_ERROR;
		Debug (LDAP_DEBUG_ANY, "tcl_modrdn_error: %s\n", results,
			0, 0);
	} else {
		interp_send_results (be, conn, op, results, NULL, 0);
	}

	if (err != LDAP_SUCCESS)
		send_ldap_result (conn, op, err, NULL,
			"internal backend error");

	free (results);
	return (err);
}
