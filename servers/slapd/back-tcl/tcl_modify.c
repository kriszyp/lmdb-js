/* $OpenLDAP$ */
/* modify.c - tcl modify routines
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
tcl_back_modify (
	Operation * op,
	SlapReply * rs
)
{
	char *command, *bp, *tcl_mods, *results;
	struct berval suf_tcl;
	int i, code, len, bsize;
	struct tclinfo *ti = (struct tclinfo *) op->o_bd->be_private;
	Modifications *modlist = op->oq_modify.rs_modlist;

	if (ti->ti_modify.bv_len == 0) {
		send_ldap_error (op, rs, LDAP_UNWILLING_TO_PERFORM,
			"modify not implemented" );
		return (-1);
	}

	if (tcl_merge_bvlist (op->o_bd->be_suffix, &suf_tcl) == NULL) {
		send_ldap_error (op, rs, LDAP_OTHER, NULL);
		return (-1);
	}

	tcl_mods = (char *) ch_malloc (BUFSIZ);
	tcl_mods[0] = '\0';
	bsize = BUFSIZ;
	bp = tcl_mods;

	for (; modlist != NULL; modlist = modlist->sml_next) {
		Modification *mods = &modlist->sml_mod;
		const struct berval 
			op_add = { sizeof("add") - 1, "add" },
			op_delete = { sizeof("delete") - 1, "delete" },
			op_replace = { sizeof("replace") - 1, "replace" },
			*op = NULL;

		switch (mods->sm_op & ~LDAP_MOD_BVALUES) {
		case LDAP_MOD_ADD:
			op = &op_add;
			break;
		case LDAP_MOD_DELETE:
			op = &op_delete;
			break;
		case LDAP_MOD_REPLACE:
			op = &op_replace;
			break;
		default:
			assert(0);
		}

		len = mods->sm_type.bv_len + op->bv_len + 7;
		while (bp + len - tcl_mods > bsize) {
			bsize += BUFSIZ;
			tcl_mods = (char *) ch_realloc (tcl_mods, bsize);
		}
		sprintf (bp, "{ {%s: %s} ", op->bv_val, mods->sm_type.bv_val);
		bp += len;
		for (i = 0;
			mods->sm_bvalues != NULL && mods->sm_bvalues[i].bv_val
			!= NULL;
			i++) {
			len = mods->sm_type.bv_len +
				mods->sm_bvalues[i].bv_len + 5 +
				(mods->sm_bvalues[i + 1].bv_val == NULL ? 2 : 0);
			while (bp + len - tcl_mods > bsize) {
				bsize += BUFSIZ;
				tcl_mods = (char *) ch_realloc (tcl_mods, bsize);
			}
			sprintf (bp, "{%s: %s} %s", mods->sm_type.bv_val,
				mods->sm_bvalues[i].bv_val,
				mods->sm_bvalues[i + 1].bv_val ==
				NULL ? "} " : "");
			bp += len;
		}
	}

	command = (char *) ch_malloc (ti->ti_modify.bv_len + suf_tcl.bv_len
		+ op->o_req_dn.bv_len + strlen (tcl_mods) + 84);
	/* This space is simply for aesthetics--\  */
	sprintf (command, "%s MODIFY {%ld/%ld} {%s} {%s} { %s}",
		ti->ti_modify.bv_val, op->o_connid, (long) op->o_msgid,
		suf_tcl.bv_val, op->o_req_dn.bv_val, tcl_mods);
	Tcl_Free (suf_tcl.bv_val);
	free (tcl_mods);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		rs->sr_err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_modify_error: %s\n", results,
			0, 0);
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
