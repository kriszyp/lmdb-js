/* $OpenLDAP$ */
/* search.c - tcl search routines
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
tcl_back_search (
	Backend * be,
	Connection * conn,
	Operation * op,
	char *base,
	char *nbase,
	int scope,
	int deref,
	int sizelimit,
	int timelimit,
	Filter * filter,
	char *filterstr,
	char **attrs,
	int attrsonly
)
{
	char *attrs_tcl = NULL, *suf_tcl, *results, *command;
	int i, err = 0, code;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;
	Entry *e;

	if (ti->ti_search == NULL) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"search not implemented", NULL, NULL );
		return (-1);
	}

	for (i = 0; attrs != NULL && attrs[i] != NULL; i++);
	if (i > 0)
		attrs_tcl = Tcl_Merge (i, attrs);

	for (i = 0; be->be_suffix[i] != NULL; i++);
	suf_tcl = Tcl_Merge (i, be->be_suffix);

	command = (char *) ch_malloc (strlen (ti->ti_search) + strlen (suf_tcl)
		+ strlen (base) + 40 + strlen (filterstr) + (attrs_tcl ==
			NULL ? 5
			: strlen (attrs_tcl)) + 72);
	sprintf (command,
		"%s SEARCH {%ld} {%s} {%s} {%d} {%d} {%d} {%d} {%s} {%d} {%s}",
		ti->ti_search, op->o_msgid, suf_tcl, base, scope, deref,
		sizelimit, timelimit, filterstr, attrsonly ? 1 : 0,
		attrs_tcl ==
		NULL ? "{all}" : attrs_tcl);
	Tcl_Free (attrs_tcl);
	Tcl_Free (suf_tcl);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OPERATIONS_ERROR;
		Debug (LDAP_DEBUG_SHELL, "tcl_search_error: %s\n", results,
			0, 0);
	} else {
		interp_send_results (be, conn, op, results, NULL, 0);
	}

	if (err != LDAP_SUCCESS)
		send_ldap_result (conn, op, err, NULL,
			"internal backend error", NULL, NULL );

	free (results);
	return (err);
}
