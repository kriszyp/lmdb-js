/* init.c - initialize various things */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "portable.h"
#include "slap.h"

/*
 * read-only global variables or variables only written by the listener
 * thread (after they are initialized) - no need to protect them with a mutex.
 */
int		slap_debug = 0;

#ifdef LDAP_DEBUG
int		ldap_syslog = LDAP_DEBUG_STATS;
#else
int		ldap_syslog;
#endif

int		ldap_syslog_level = LOG_DEBUG;
char		*default_referral;
time_t		starttime;
ldap_pvt_thread_t	listener_tid;
int		g_argc;
char		**g_argv;

/*
 * global variables that need mutex protection
 */
int				active_threads;
ldap_pvt_thread_mutex_t	active_threads_mutex;
ldap_pvt_thread_cond_t	active_threads_cond;

time_t			currenttime;
ldap_pvt_thread_mutex_t	currenttime_mutex;

ldap_pvt_thread_mutex_t	new_conn_mutex;

#ifdef SLAPD_CRYPT
ldap_pvt_thread_mutex_t	crypt_mutex;
#endif

int				num_conns;
long			ops_initiated;
long			ops_completed;
ldap_pvt_thread_mutex_t	ops_mutex;

long			num_entries_sent;
long			num_bytes_sent;
ldap_pvt_thread_mutex_t	num_sent_mutex;
/*
 * these mutexes must be used when calling the entry2str()
 * routine since it returns a pointer to static data.
 */
ldap_pvt_thread_mutex_t	entry2str_mutex;
ldap_pvt_thread_mutex_t	replog_mutex;

void
init( void )
{
	(void) ldap_pvt_thread_initialize();

	ldap_pvt_thread_mutex_init( &active_threads_mutex );
	ldap_pvt_thread_cond_init( &active_threads_cond );

	ldap_pvt_thread_mutex_init( &new_conn_mutex );
	ldap_pvt_thread_mutex_init( &currenttime_mutex );
	ldap_pvt_thread_mutex_init( &entry2str_mutex );
	ldap_pvt_thread_mutex_init( &replog_mutex );
	ldap_pvt_thread_mutex_init( &ops_mutex );
	ldap_pvt_thread_mutex_init( &num_sent_mutex );
#ifdef SLAPD_CRYPT
	ldap_pvt_thread_mutex_init( &crypt_mutex );
#endif
}
