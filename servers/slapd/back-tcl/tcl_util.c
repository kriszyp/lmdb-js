/* $OpenLDAP$ */
/* result.c - tcl backend utility functions
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

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slap.h"
#include "tcl_back.h"

int
interp_send_results (
	Operation * op,
	SlapReply * rs,
	char *result
)
{
	int bsize, len, argcPtr, i, code;
	char *buf, *bp, **argvPtr, *line;
	struct tclinfo *ti = (struct tclinfo *) op->o_bd->be_private;

	/*
	 * read in the result and send it along 
	 */
	buf = (char *) ch_malloc (BUFSIZ);
	buf[0] = '\0';
	bsize = BUFSIZ;
	bp = buf;
	code = Tcl_SplitList (ti->ti_ii->interp, result, &argcPtr, &argvPtr);
	if (code != TCL_OK) {
		argcPtr = 0;
		send_ldap_error (op, rs, LDAP_UNWILLING_TO_PERFORM,
			"internal backend error" );
		return -1;
	}
	for (i = 0; i < argcPtr; i++) {
		line = argvPtr[i];

		/*
		 * ignore lines beginning with DEBUG: 
		 */
		if (strncasecmp (line, "DEBUG:", 6) == 0) {
			continue;
		}
		len = strlen (line) + 1;
		while (bp + len - buf > bsize) {
			bsize += BUFSIZ;
			buf = (char *) ch_realloc (buf, bsize);
		}
		sprintf (bp, "%s\n", line);
		bp += len;

		/*
		 * line marked the end of an entry or result 
		 */
		if (line[0] == '\0') {
			if (strncasecmp (buf, "RESULT", 6) == 0) {
				break;
			}
			if ((rs->sr_entry = str2entry (buf)) == NULL) {
				Debug (LDAP_DEBUG_SHELL,
					"str2entry(%s) failed\n",
					buf, 0, 0);
			} else {
				rs->sr_attrs = op->oq_search.rs_attrs;
				send_search_entry (op, rs);
				entry_free (rs->sr_entry);
			}

			bp = buf;
		}
	}

	(void) str2result (buf, &rs->sr_err, (char **)&rs->sr_matched, (char **)&rs->sr_text);

	/*
	 * otherwise, front end will send this result 
	 */
	if (rs->sr_err != 0 || op->o_tag != LDAP_REQ_BIND) {
		send_ldap_result (op, rs);
	}

	free (buf);
	Tcl_Free ((char *) argvPtr);
	return (rs->sr_err);
}

char *
tcl_clean_entry (
	Entry * e
)
{
	char *entrystr, *mark1, *mark2, *buf, *bp, *dup;
	int len, bsize;

	ldap_pvt_thread_mutex_lock(&entry2str_mutex);
	entrystr = entry2str (e, &len);

	buf = (char *) ch_malloc (BUFSIZ);
	buf[0] = '\0';
	bsize = BUFSIZ;
	bp = buf;
	bp++[0] = ' ';

	mark1 = entrystr;
	do {
		if (mark1[0] == '\n') {
			mark1++;
		}
		dup = (char *) ch_strdup (mark1);
		if (dup[0] != '\0') {
			if ((mark2 = (char *) strchr (dup, '\n')) != NULL) {
				mark2[0] = '\0';
			}
			len = strlen (dup) + 3;
			while (bp + len - buf > bsize) {
				bsize += BUFSIZ;
				buf = (char *) ch_realloc (buf, bsize);
			}
			if (mark1[0] == '\0') {
				sprintf (bp, "{} ");
			} else {
				sprintf (bp, "{%s} ", dup);
			}
			bp += len;
			if (mark2 != NULL) {
				mark2[0] = '\n';
			}
		}
		free (dup);
	} while ((mark1 = (char *) strchr (mark1, '\n')) != NULL);

	ldap_pvt_thread_mutex_unlock (&entry2str_mutex);
	return buf;
}

int
tcl_ldap_debug (
	ClientData clientData,
	Tcl_Interp * interp,
	int argc,
	char *argv[]
)
{
	if (argv[1] != NULL) {
		Debug (LDAP_DEBUG_SHELL, "tcl_debug: %s\n", argv[1], 0, 0);
	}
	return TCL_OK;
}

void
readtclscript (
	char *script,
	Tcl_Interp * my_tcl)
{
	int code;
	FILE *f;

	f = fopen (script, "r");
	if (f == NULL) {
		Debug (LDAP_DEBUG_SHELL, "Could not open scriptpath %s\n", script,
			0, 0);
		return;
	}
	fclose (f);
	code = Tcl_EvalFile (my_tcl, script);
	if (code != TCL_OK) {
		Debug (LDAP_DEBUG_SHELL, "%s: %s\n", script,
			Tcl_GetVar (my_tcl, "errorInfo", TCL_GLOBAL_ONLY), 0);
		Debug (LDAP_DEBUG_SHELL, "%s: error at line\n", script,
			my_tcl->errorLine, 0);
		return;
	}
}


struct berval *
tcl_merge_bvlist(
	BerVarray bvlist, struct berval *out)
{
	struct berval *ret = NULL;
	int i;

	if (bvlist == NULL)
		return NULL;

	if (out == NULL) {
		ret = (struct berval *)ch_malloc(sizeof(struct berval));
		if (ret == NULL) {
			return NULL;
		}
	} else {
		ret = out;
	}

	ret->bv_len = 0;
	ret->bv_val = NULL;

	for (i = 0; bvlist[i].bv_val != NULL; i++);

	if (i) {
		char **strlist = ch_malloc ((i + 1) * sizeof(char *));
		if (strlist == NULL) {
			if (out == NULL)
				ch_free (ret);
			return NULL;
		}
		for (i = 0; bvlist[i].bv_val != NULL; i++) {
			strlist[i] = bvlist[i].bv_val;
		}
		strlist[i] = NULL;
		ret->bv_val = Tcl_Merge(i, strlist);
		ret->bv_len = ret->bv_val ? strlen(ret->bv_val) : 0;
		ch_free (strlist);
	}

	return ret;
}

