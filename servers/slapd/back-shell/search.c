/* search.c - shell backend search function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "shell.h"

int
shell_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval *base,
    struct berval *nbase,
    int		scope,
    int		deref,
    int		size,
    int		time,
    Filter	*filter,
    struct berval	*filterstr,
    AttributeName	*attrs,
    int		attrsonly
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	AttributeName		*an;

	if ( si->si_search == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "search not implemented", NULL, NULL );
		return( -1 );
	}

	if ( (op->o_private = (void *) forkandexec( si->si_search, &rfp, &wfp ))
	    == (void *) -1 ) {
		send_ldap_result( conn, op, LDAP_OTHER, NULL,
		    "could not fork/exec", NULL, NULL );
		return( -1 );
	}

	/* write out the request to the search process */
	fprintf( wfp, "SEARCH\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, be );
	fprintf( wfp, "base: %s\n", base->bv_val );
	fprintf( wfp, "scope: %d\n", scope );
	fprintf( wfp, "deref: %d\n", deref );
	fprintf( wfp, "sizelimit: %d\n", size );
	fprintf( wfp, "timelimit: %d\n", time );
	fprintf( wfp, "filter: %s\n", filterstr->bv_val );
	fprintf( wfp, "attrsonly: %d\n", attrsonly ? 1 : 0 );
	fprintf( wfp, "attrs:%s", attrs == NULL ? " all" : "" );
	for ( an = attrs; an && an->an_name.bv_val; an++ ) {
		fprintf( wfp, " %s", an->an_name.bv_val );
	}
	fprintf( wfp, "\n" );
	fclose( wfp );

	/* read in the results and send them along */
	read_and_send_results( be, conn, op, rfp, attrs, attrsonly );

	fclose( rfp );
	return( 0 );
}
