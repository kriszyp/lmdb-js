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
	Operation * op,
	SlapReply * rs )
{
	char *attrs_tcl = NULL, *results, *command;
	struct berval suf_tcl;
	int i, code;
	struct tclinfo *ti = (struct tclinfo *) op->o_bd->be_private;
	AttributeName *an;

	if (ti->ti_search.bv_len == 0) {
		send_ldap_error (op, rs, LDAP_UNWILLING_TO_PERFORM,
			"search not implemented" );
		return (-1);
	}

	for (i = 0, an = op->oq_search.rs_attrs; an && an->an_name.bv_val; an++, i++);
	if (i > 0) {
		char **sattrs = ch_malloc( (i+1) * sizeof(char *));
		for (i = 0, an = op->oq_search.rs_attrs; an->an_name.bv_val; an++, i++)
			sattrs[i] = an->an_name.bv_val;
		sattrs[i] = NULL;
		attrs_tcl = Tcl_Merge (i, sattrs);
		ch_free(sattrs);
	}

	if (tcl_merge_bvlist (op->o_bd->be_suffix, &suf_tcl) == NULL) {
		Tcl_Free (attrs_tcl);
		send_ldap_error (op, rs, LDAP_OTHER, NULL);
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_search.bv_len + suf_tcl.bv_len
		+ op->o_req_dn.bv_len + 60 + op->oq_search.rs_filterstr.bv_len + 
		(attrs_tcl == NULL ? 5 : strlen (attrs_tcl)) + 72);
	sprintf (command,
		"%s SEARCH {%ld/%ld} {%s} {%s} {%d} {%d} {%d} {%d} {%s} {%d} {%s}",
		ti->ti_search.bv_val, op->o_connid, (long) op->o_msgid,
		suf_tcl.bv_val, op->o_req_dn.bv_val, op->oq_search.rs_scope, op->oq_search.rs_deref,
		op->oq_search.rs_slimit, op->oq_search.rs_tlimit, op->oq_search.rs_filterstr.bv_val,
		op->oq_search.rs_attrsonly ? 1 : 0, attrs_tcl == NULL ? "{all}" : attrs_tcl);
	Tcl_Free (attrs_tcl);
	Tcl_Free (suf_tcl.bv_val);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		rs->sr_err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_search_error: %s\n", results,
			0, 0);
	} else {
		interp_send_results (op, rs, results );
	}

	if (rs->sr_err != LDAP_SUCCESS) {
		rs->sr_text = "internal backend error";
		send_ldap_result (op, rs );
	}

	free (results);
	return (rs->sr_err);
}
