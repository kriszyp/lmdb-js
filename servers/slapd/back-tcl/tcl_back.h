/* $OpenLDAP$ */
/* tcl_back.h - tcl backend header (structs, functions)
 *
 * Copyright 1999, Ben Collins <bcollins@debian.org>, All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 */

#include <tcl.h>

#ifndef SLAPD_TCL_H
#define SLAPD_TCL_H

#include <ldap_cdefs.h>
#include "external.h"

extern ldap_pvt_thread_mutex_t tcl_interpreter_mutex;

struct i_info {
	Tcl_Interp *interp;
	char *name;
	struct i_info *next;
	int count;
};

extern struct i_info *global_i;

struct tclinfo {
	struct berval ti_script_path;
	struct i_info *ti_ii;
	struct berval ti_bind;
	struct berval ti_unbind;
	struct berval ti_search;
	struct berval ti_compare;
	struct berval ti_modify;
	struct berval ti_modrdn;
	struct berval ti_add;
	struct berval ti_delete;
	struct berval ti_abandon;
};

void readtclscript (char *script, Tcl_Interp * my_tcl);
char *tcl_clean_entry (Entry * e);
struct berval *tcl_merge_bvlist (BerVarray bvlist, struct berval *out);

int tcl_ldap_debug (
	ClientData clientData,
	Tcl_Interp * interp,
	int argc,
	char *argv[]
);

int interp_send_results (
	Operation * op,
	SlapReply * rs,
	char *result
);

#endif
