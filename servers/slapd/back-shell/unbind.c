/* unbind.c - shell backend unbind function */
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
shell_back_unbind(
    Operation		*op,
    SlapReply		*rs
)
{
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	FILE			*rfp, *wfp;

	if ( si->si_unbind == NULL ) {
		return 0;
	}

	if ( forkandexec( si->si_unbind, &rfp, &wfp ) == (pid_t)-1 ) {
		return 0;
	}

	/* write out the request to the unbind process */
	fprintf( wfp, "UNBIND\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, op->o_bd );
	fprintf( wfp, "dn: %s\n", (op->o_conn->c_dn.bv_len ? op->o_conn->c_dn.bv_val : "") );
	fclose( wfp );

	/* no response to unbind */
	fclose( rfp );

	return 0;
}
