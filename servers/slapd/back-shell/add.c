/* add.c - shell backend add function */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "shell.h"

extern pthread_mutex_t	entry2str_mutex;
extern char		*entry2str();

void
shell_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	int			len;

	if ( si->si_add == NULL ) {
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM, NULL,
		    "add not implemented" );
		return;
	}

	if ( (op->o_private = forkandexec( si->si_add, &rfp, &wfp )) == -1 ) {
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR, NULL,
		    "could not fork/exec" );
		return;
	}

	/* write out the request to the add process */
	fprintf( wfp, "ADD\n" );
	fprintf( wfp, "msgid: %d\n", op->o_msgid );
	print_suffixes( wfp, be );
	pthread_mutex_lock( &entry2str_mutex );
	fprintf( wfp, "%s", entry2str( e, &len, 0 ) );
	pthread_mutex_unlock( &entry2str_mutex );
	fclose( wfp );

	/* read in the result and send it along */
	read_and_send_results( be, conn, op, rfp, NULL, 0 );

	fclose( rfp );
}
