/* config.c - tcl backend configuration file routine
 *
 * $Id: tcl_config.c,v 1.6 1999/02/23 02:51:33 bcollins Exp $
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

struct i_info *global_i;

int
tcl_back_db_config (
	BackendDB * bd,
	const char *fname,
	int lineno,
	int argc,
	char **argv
)
{
	struct tclinfo *ti = (struct tclinfo *) bd->be_private;
	int script_loaded = 0;

	if (ti == NULL) {
		fprintf (stderr,
			"%s: line %d: tcl backend info is null!\n", fname,
			lineno);
		return (1);
	}
	if (ti->ti_ii == NULL) {
		ti->ti_ii = global_i;
	}

	/* Script to load */
	if (strcasecmp (argv[0], "scriptpath") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing script in \"scriptpath <script>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->script_path = (char *) ch_strdup (argv[1]);

		/* use local interpreter */
	} else if (strcasecmp (argv[0], "tclrealm") == 0) {
		struct i_info *ii;

		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing script in \"tclrealm <name>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_ii = NULL;

		ii = global_i;
		/* Try to see if it already exists */
		do {
			if (ii != NULL && !strcasecmp (ii->name, argv[1]))
				ti->ti_ii = ii;
			if (ii->next != NULL)
				ii = ii->next;
		} while (ii->next != NULL);

		if (ti->ti_ii == NULL) {	/* we need to make a new one */
			ii->next = (struct i_info *) ch_malloc
				(sizeof (struct i_info));

			ii->next->count = 0;
			ii->next->name = (char *) ch_strdup (argv[1]);
			ii->next->interp = NULL;
			ii->next->next = NULL;
			ti->ti_ii = ii->next;
		}

		/* proc for binds */
	} else if (strcasecmp (argv[0], "bind") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"bind <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_bind = (char *) ch_strdup (argv[1]);

		/* proc for unbinds */
	} else if (strcasecmp (argv[0], "unbind") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"unbind <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_unbind = (char *) ch_strdup (argv[1]);

		/* proc for search */
	} else if (strcasecmp (argv[0], "search") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"search <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_search = (char *) ch_strdup (argv[1]);

		/* proc for compares */
	} else if (strcasecmp (argv[0], "compare") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"compare <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_compare = (char *) ch_strdup (argv[1]);

		/* proc for modify */
	} else if (strcasecmp (argv[0], "modify") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"modify <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_modify = (char *) ch_strdup (argv[1]);

		/* proc for modrdn */
	} else if (strcasecmp (argv[0], "modrdn") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"modrdn <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_modrdn = (char *) ch_strdup (argv[1]);

		/* proc for add */
	} else if (strcasecmp (argv[0], "add") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"add <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_add = (char *) ch_strdup (argv[1]);

		/* proc for delete */
	} else if (strcasecmp (argv[0], "delete") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"delete <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_delete = (char *) ch_strdup (argv[1]);

		/* proc for abandon */
	} else if (strcasecmp (argv[0], "abandon") == 0) {
		if (argc < 2) {
			Debug (LDAP_DEBUG_CONFIG,
				"%s: line %d: missing proc in \"abandon <proc>\" line\n",
				fname, lineno, 0);
			return (1);
		}
		ti->ti_search = (char *) ch_strdup (argv[1]);

	} else {
		Debug (LDAP_DEBUG_CONFIG,
			"Unknown tcl backend config: %s\n", argv[0], 0, 0);
		return (1);
	}

	return 0;
}
