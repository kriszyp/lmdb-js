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
	Backend * be,
	Connection * conn,
	Operation * op,
	char *dn,
	char *ndn,
	LDAPModList * modlist
)
{
	char *command, *suf_tcl, *bp, *tcl_mods, *results;
	int i, code, err = 0, len, bsize;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_modify == NULL) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"modify not implemented", NULL, NULL );
		return (-1);
	}

	for (i = 0; be->be_suffix[i] != NULL; i++);
	suf_tcl = Tcl_Merge (i, be->be_suffix);

	tcl_mods = (char *) ch_malloc (BUFSIZ);
	tcl_mods[0] = '\0';
	bsize = BUFSIZ;
	bp = tcl_mods;

	for (; modlist != NULL; modlist = modlist->ml_next) {
		LDAPMod *mods = &modlist->ml_mod;
		char *op = NULL;

		switch (mods->mod_op & ~LDAP_MOD_BVALUES) {
		case LDAP_MOD_ADD:
			op = "add";
			break;
		case LDAP_MOD_DELETE:
			op = "delete";
			break;
		case LDAP_MOD_REPLACE:
			op = "replace";
			break;
		}

		len = strlen (mods->mod_type) + strlen (op) + 7;
		while (bp + len - tcl_mods > bsize) {
			bsize += BUFSIZ;
			tcl_mods = (char *) ch_realloc (tcl_mods, bsize);
		}
		sprintf (bp, "{ {%s: %s} ", op, mods->mod_type);
		bp += len;
		for (i = 0;
			mods->mod_bvalues != NULL && mods->mod_bvalues[i]
			!= NULL;
			i++) {
			len = strlen (mods->mod_type) + strlen (
				mods->mod_bvalues[i]->bv_val) + 5 +
				(mods->mod_bvalues[i + 1] == NULL ? 2 : 0);
			while (bp + len - tcl_mods > bsize) {
				bsize += BUFSIZ;
				tcl_mods = (char *) ch_realloc (tcl_mods, bsize);
			}
			sprintf (bp, "{%s: %s} %s", mods->mod_type,
				mods->mod_bvalues[i]->bv_val,
				mods->mod_bvalues[i + 1] ==
				NULL ? "} " : "");
			bp += len;
		}
	}

	command = (char *) ch_malloc (strlen (ti->ti_modify) + strlen (suf_tcl)
		+ strlen (dn) + strlen (tcl_mods) + 64);
	/* This space is simply for aesthetics--\  */
	sprintf (command, "%s MODIFY {%ld} {%s} {%s} { %s}",
		ti->ti_modify, op->o_msgid, suf_tcl, dn, tcl_mods);
	Tcl_Free (suf_tcl);
	free (tcl_mods);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OPERATIONS_ERROR;
		Debug (LDAP_DEBUG_SHELL, "tcl_modify_error: %s\n", results,
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
