/*
 * result.c - tcl backend utility functions
 *
 * Copyright 1999, Ben Collins <bcollins@debian.org>, All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted only
 * as authorized by the OpenLDAP Public License.  A copy of this
 * license is available at http://www.OpenLDAP.org/license.html or
 * in file LICENSE in the top-level directory of the distribution.
 *
 * $Id$
 *
 * $Log$
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/unistd.h>

#include "slap.h"
#include "tcl_back.h"

int
interp_send_results(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    char	*result,
    char	**attrs,
    int		attrsonly
)
{
	int	bsize, len, argcPtr, i, err, code;
	char	*buf, *bp, **argvPtr, *line, *matched, *info;
	Entry	*e;
	struct tclinfo *ti = (struct tclinfo *) be->be_private;
	/* read in the result and send it along */
	buf = (char *) ch_malloc( BUFSIZ );
	buf[0] = '\0';
	bsize = BUFSIZ;
	bp = buf;
	code = Tcl_SplitList(ti->ti_ii->interp, result, &argcPtr, &argvPtr);
	if (code != TCL_OK) {
		argcPtr = 0;
		send_ldap_result (conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
			"internal backend error");
		return -1;
	}
	for ( i = 0 ; i < argcPtr ; i++ ) {
		line = argvPtr[i];
		Debug( LDAP_DEBUG_ANY, "tcl search reading line (%s)\n",
		    line, 0, 0 );
		/* ignore lines beginning with DEBUG: */
		if ( strncasecmp( line, "DEBUG:", 6 ) == 0 ) {
			continue;
		}
		len = strlen( line ) + 1;
		while ( bp + len - buf > bsize ) {
			bsize += BUFSIZ;
			buf = (char *) ch_realloc( buf, bsize );
		}
		sprintf( bp, "%s\n", line );
		bp += len;

		/* line marked the end of an entry or result */
		if ( line[0] == '\0' ) {
			if ( strncasecmp( buf, "RESULT", 6 ) == 0 ) {
				break;
			}
			if ( (e = str2entry( buf )) == NULL ) {
				Debug( LDAP_DEBUG_ANY, "str2entry(%s) failed\n",
				    buf, 0, 0 );
			} else {
				send_search_entry( be, conn, op, e, attrs,
				    attrsonly );
				entry_free( e );
			}

			bp = buf;
		}
	}

	(void) str2result( buf, &err, &matched, &info );

	/* otherwise, front end will send this result */
	if ( err != 0 || op->o_tag != LDAP_REQ_BIND ) {
		send_ldap_result( conn, op, err, matched, info );
	}

	free( buf );
	Tcl_Free( result );
	Tcl_Free( (char *) argvPtr );
	return( err );
}

char *tcl_clean_entry (Entry *e)
{
	char *entrystr, *mark1, *mark2, *buf, *bp, *dup;
	int len, bsize;

	pthread_mutex_lock( &entry2str_mutex );
	entrystr = entry2str( e, &len, 0 );
	pthread_mutex_unlock( &entry2str_mutex );

	buf = (char *) ch_malloc( BUFSIZ );
	buf[0] = '\0';
	bsize = BUFSIZ;
	bp = buf;
	bp++[0] = ' ';

	mark1 = entrystr;
	do {
		if (mark1[0] == '\n') {
		    	mark1++;
		}
		dup = (char *) strdup(mark1);
			if (dup[0] != '\0') {
	    		if ((mark2 = (char *) strchr (dup, '\n')) != NULL) {
				mark2[0] = '\0';
	    		}
	    		len = strlen( dup ) + 3;
	    		while ( bp + len - buf > bsize ) {
				bsize += BUFSIZ;
				buf = (char *) ch_realloc( buf, bsize );
	    		}
	    		if (mark1[0] == '\0') {
				sprintf(bp, "{} ");
	    		} else {
				sprintf(bp, "{%s} ", dup);
	    		}
	    		bp += len;
	    		if (mark2 != NULL) {
				mark2[0] = '\n';
		    	}
		}
		free(dup);
	} while ((mark1 = (char *) strchr (mark1, '\n')) != NULL);
	return buf;
}

int tcl_ldap_debug (
    ClientData clientData,
    Tcl_Interp *interp,
    int argc,
    char *argv[]
)
{
	if (argv[1] != NULL) {
		Debug(LDAP_DEBUG_ANY, "tcl_debug: %s\n", argv[1], 0, 0);
	}
	return TCL_OK;
}
