/* $OpenLDAP$ */
/* bind.c - tcl bind routines
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
tcl_back_bind (
	Backend * be,
	Connection * conn,
	Operation * op,
	char *dn,
	char *ndn,
	int method,
	char		*mech,
	struct berval *cred,
	char **edn
)
{
	char *command, *suf_tcl, *results;
	int i, code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	*edn = NULL;

	if (ti->ti_bind == NULL) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"bind not implemented", NULL, NULL );
		return (-1);
	}

	for (i = 0; be->be_suffix[i] != NULL; i++);
	suf_tcl = Tcl_Merge (i, be->be_suffix);

	command = (char *) ch_malloc (strlen (ti->ti_bind) + strlen
		(suf_tcl) +
		strlen (dn) + strlen (cred->bv_val) + 64);
	sprintf (command, "%s BIND {%ld} {%s} {%s} {%d} {%lu} {%s}",
		ti->ti_bind, op->o_msgid, suf_tcl, dn, method, cred->bv_len,
		cred->bv_val);
	Tcl_Free (suf_tcl);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OPERATIONS_ERROR;
		Debug (LDAP_DEBUG_SHELL, "tcl_bind_error: %s\n", results, 0, 0);
	} else {
		err = interp_send_results (be, conn, op, results, NULL, 0);
	}

	if (err != LDAP_SUCCESS)
		send_ldap_result (conn, op, err, NULL,
			"internal backend error", NULL, NULL );

	free (results);
	return (err);
}
