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
pthread_t	listener_tid;
int		g_argc;
char		**g_argv;

/*
 * global variables that need mutex protection
 */
int				active_threads;
pthread_mutex_t	active_threads_mutex;
pthread_cond_t	active_threads_cond;

time_t			currenttime;
pthread_mutex_t	currenttime_mutex;

pthread_mutex_t	new_conn_mutex;

#ifdef SLAPD_CRYPT
pthread_mutex_t	crypt_mutex;
#endif

int				num_conns;
long			ops_initiated;
long			ops_completed;
pthread_mutex_t	ops_mutex;

long			num_entries_sent;
long			num_bytes_sent;
pthread_mutex_t	num_sent_mutex;
/*
 * these mutexes must be used when calling the entry2str()
 * routine since it returns a pointer to static data.
 */
pthread_mutex_t	entry2str_mutex;
pthread_mutex_t	replog_mutex;

void
init( void )
{
	pthread_mutex_init( &active_threads_mutex, pthread_mutexattr_default );
	pthread_cond_init( &active_threads_cond, pthread_condattr_default );

	pthread_mutex_init( &new_conn_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &currenttime_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &entry2str_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &replog_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &ops_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &num_sent_mutex, pthread_mutexattr_default );
#ifdef SLAPD_CRYPT
	pthread_mutex_init( &crypt_mutex, pthread_mutexattr_default );
#endif
}
