/* init.c - initialize various things */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "portable.h"
#include "slap.h"

void
init( void )
{
	pthread_mutex_init( &active_threads_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &new_conn_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &currenttime_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &strtok_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &entry2str_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &replog_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &ops_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &num_sent_mutex, pthread_mutexattr_default );
#ifdef SLAPD_CRYPT
	pthread_mutex_init( &crypt_mutex, pthread_mutexattr_default );
#endif
}
