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
	struct berval *base,
	struct berval *nbase,
	int scope,
	int deref,
	int sizelimit,
	int timelimit,
	Filter * filter,
	struct berval *filterstr,
	AttributeName *attrs,
	int attrsonly
)
{
	char *attrs_tcl = NULL, *results, *command;
	struct berval suf_tcl;
	int i, err = 0, code;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;
	AttributeName *an;

	if (ti->ti_search.bv_len == 0) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"search not implemented", NULL, NULL );
		return (-1);
	}

	for (i = 0, an = attrs; an && an->an_name.bv_val; an++, i++);
	if (i > 0) {
		char **sattrs = ch_malloc( (i+1) * sizeof(char *));
		for (i = 0, an = attrs; an->an_name.bv_val; an++, i++)
			sattrs[i] = an->an_name.bv_val;
		sattrs[i] = NULL;
		attrs_tcl = Tcl_Merge (i, sattrs);
		ch_free(sattrs);
	}

	if (tcl_merge_bvlist (be->be_suffix, &suf_tcl) == NULL) {
		Tcl_Free (attrs_tcl);
		send_ldap_result (conn, op, LDAP_OTHER, NULL,
			NULL, NULL, NULL );
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_search.bv_len + suf_tcl.bv_len
		+ base->bv_len + 60 + filterstr->bv_len + 
		(attrs_tcl == NULL ? 5 : strlen (attrs_tcl)) + 72);
	sprintf (command,
		"%s SEARCH {%ld/%ld} {%s} {%s} {%d} {%d} {%d} {%d} {%s} {%d} {%s}",
		ti->ti_search.bv_val, op->o_connid, (long) op->o_msgid,
		suf_tcl.bv_val, base->bv_val, scope, deref,
		sizelimit, timelimit, filterstr->bv_val, attrsonly ? 1 : 0,
		attrs_tcl == NULL ? "{all}" : attrs_tcl);
	Tcl_Free (attrs_tcl);
	Tcl_Free (suf_tcl.bv_val);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_search_error: %s\n", results,
			0, 0);
	} else {
		interp_send_results (be, conn, op, results, attrs, 0);
	}

	if (err != LDAP_SUCCESS)
		send_ldap_result (conn, op, err, NULL,
			"internal backend error", NULL, NULL );

	free (results);
	return (err);
}
