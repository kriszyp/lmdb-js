/* abandon.c - shell backend abandon function */
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
shell_back_abandon(
    Operation	*op,
    SlapReply	*rs )
{
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	FILE			*rfp, *wfp;
	pid_t			pid;
	Operation		*o;

	if ( si->si_abandon == NULL ) {
		return 0;
	}

	pid = -1;
	LDAP_STAILQ_FOREACH( o, &op->o_conn->c_ops, o_next ) {
		if ( o->o_msgid == op->oq_abandon.rs_msgid ) {
			pid = (pid_t) o->o_private;
			break;
		}
	}

	if ( pid == -1 ) {
		Debug( LDAP_DEBUG_ARGS, "shell could not find op %ld\n",
		       (long) op->oq_abandon.rs_msgid, 0, 0 );
		return 0;
	}

	if ( forkandexec( si->si_abandon, &rfp, &wfp ) == -1 ) {
		return 0;
	}

	/* write out the request to the abandon process */
	fprintf( wfp, "ABANDON\n" );
	fprintf( wfp, "msgid: %d\n", op->oq_abandon.rs_msgid );
	print_suffixes( wfp, op->o_bd );
	fprintf( wfp, "pid: %ld\n", (long) pid );
	fclose( wfp );

	/* no result from abandon */
	fclose( rfp );

	return 0;
}
