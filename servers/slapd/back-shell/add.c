/* add.c - shell backend add function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "shell.h"

int
shell_back_add(
    Operation	*op,
    SlapReply	*rs )
{
	struct shellinfo	*si = (struct shellinfo *) op->o_bd->be_private;
	AttributeDescription *entry = slap_schema.si_ad_entry;
	FILE			*rfp, *wfp;
	int			len;

	if ( si->si_add == NULL ) {
		send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
		    "add not implemented" );
		return( -1 );
	}

	if ( ! access_allowed( op, op->oq_add.rs_e,
		entry, NULL, ACL_WRITE, NULL ) )
	{
		send_ldap_error( op, rs, LDAP_INSUFFICIENT_ACCESS, NULL );
		return -1;
	}

	if ( (op->o_private = (void *) forkandexec( si->si_add, &rfp, &wfp )) == (void *) -1 ) {
		send_ldap_error( op, rs, LDAP_OTHER,
		    "could not fork/exec" );
		return( -1 );
	}

	/* write out the request to the add process */
	fprintf( wfp, "ADD\n" );
	fprintf( wfp, "msgid: %ld\n", (long) op->o_msgid );
	print_suffixes( wfp, op->o_bd );
	ldap_pvt_thread_mutex_lock( &entry2str_mutex );
	fprintf( wfp, "%s", entry2str( op->oq_add.rs_e, &len ) );
	ldap_pvt_thread_mutex_unlock( &entry2str_mutex );
	fclose( wfp );

	/* read in the result and send it along */
	read_and_send_results( op, rs, rfp );

	fclose( rfp );
	return( 0 );
}
