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
	char *script_path;
	struct i_info *ti_ii;
	char *ti_bind;
	char *ti_unbind;
	char *ti_search;
	char *ti_compare;
	char *ti_modify;
	char *ti_modrdn;
	char *ti_add;
	char *ti_delete;
	char *ti_abandon;
};

void readtclscript (char *script, Tcl_Interp * my_tcl);
char *tcl_clean_entry (Entry * e);

int tcl_ldap_debug (
	ClientData clientData,
	Tcl_Interp * interp,
	int argc,
	char *argv[]
);

int interp_send_results (
	Backend * be,
	Connection * conn,
	Operation * op,
	char *result,
	char **attrs,
	int attrsonly
);

#endif
