/* abandon.c - shell backend abandon function */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>

#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "shell.h"

int
shell_back_abandon(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    int		msgid
)
{
	struct shellinfo	*si = (struct shellinfo *) be->be_private;
	FILE			*rfp, *wfp;
	pid_t			pid;
	Operation		*o;

	/* no abandon command defined - just kill the process handling it */
	if ( si->si_abandon == NULL ) {
		ldap_pvt_thread_mutex_lock( &conn->c_mutex );
		pid = -1;
		for ( o = conn->c_ops; o != NULL; o = o->o_next ) {
			if ( o->o_msgid == msgid ) {
				pid = (pid_t) o->o_private;
				break;
			}
		}
		if( pid == -1 ) {
			for ( o = conn->c_pending_ops; o != NULL; o = o->o_next ) {
				if ( o->o_msgid == msgid ) {
					pid = (pid_t) o->o_private;
					break;
				}
			}
		}
		ldap_pvt_thread_mutex_unlock( &conn->c_mutex );

		if ( pid != -1 ) {
			Debug( LDAP_DEBUG_ARGS, "shell killing pid %d\n",
			       (int) pid, 0, 0 );
			kill( pid, SIGTERM );
		} else {
			Debug( LDAP_DEBUG_ARGS, "shell could not find op %d\n",
			    msgid, 0, 0 );
		}
		return 0;
	}

	if ( forkandexec( si->si_abandon, &rfp, &wfp ) == -1 ) {
		return 0;
	}

	/* write out the request to the abandon process */
	fprintf( wfp, "ABANDON\n" );
	fprintf( wfp, "msgid: %d\n", msgid );
	print_suffixes( wfp, be );
	fclose( wfp );

	/* no result from abandon */
	fclose( rfp );

	return 0;
}
