/* $OpenLDAP$ */
/* modrdn.c - tcl modify rdn routines
 *
 * Copyright 1999, Ben Collins <bcollins@debian.org>, All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

/*
 * LDAP v3 newSuperior support.
 *
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
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
	struct berval *dn,
	struct berval *ndn,
	struct berval *newrdn,
	struct berval *nnewrdn,
	int deleteoldrdn,
	struct berval *newSuperior,
	struct berval *nnewSuperior
)
{
	char *command, *results;
	struct berval suf_tcl;
	int code, err = 0;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;

	if (ti->ti_modrdn.bv_len == 0) {
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"modrdn not implemented", NULL, NULL );
		return (-1);
	}

	if (tcl_merge_bvlist (be->be_suffix, &suf_tcl) == NULL) {
		send_ldap_result (conn, op, LDAP_OTHER, NULL,
			NULL, NULL, NULL );
		return (-1);
	}

	command = (char *) ch_malloc (ti->ti_modrdn.bv_len + suf_tcl.bv_len
		+ dn->bv_len + newrdn->bv_len
		+ (newSuperior ? newSuperior->bv_len : 0) + 84);
	if ( newSuperior ) {
		sprintf (command, "%s MODRDN {%ld/%ld} {%s} {%s} {%s} %d {%s}",
			 ti->ti_modrdn.bv_val,
			 op->o_connid, (long) op->o_msgid, 
			 suf_tcl.bv_val, dn->bv_val,
			 newrdn->bv_val, deleteoldrdn ? 1 : 0, 
			 newSuperior->bv_val );
	} else {
		sprintf (command, "%s MODRDN {%ld} {%s} {%s} {%s} %d",
			 ti->ti_modrdn.bv_val, (long) op->o_msgid, 
			 suf_tcl.bv_val, dn->bv_val,
			 newrdn->bv_val, deleteoldrdn ? 1 : 0 );
	}	
	Tcl_Free (suf_tcl.bv_val);

	ldap_pvt_thread_mutex_lock (&tcl_interpreter_mutex);
	code = Tcl_GlobalEval (ti->ti_ii->interp, command);
	results = (char *) ch_strdup (ti->ti_ii->interp->result);
	ldap_pvt_thread_mutex_unlock (&tcl_interpreter_mutex);
	free (command);

	if (code != TCL_OK) {
		err = LDAP_OTHER;
		Debug (LDAP_DEBUG_SHELL, "tcl_modrdn_error: %s\n", results,
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
