/* init.c - initialize various things */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "portable.h"
#include "slap.h"

extern pthread_mutex_t	active_threads_mutex;
extern pthread_mutex_t	new_conn_mutex;
extern pthread_mutex_t	currenttime_mutex;
extern pthread_mutex_t	entry2str_mutex;
extern pthread_mutex_t	replog_mutex;
extern pthread_mutex_t	ops_mutex;
extern pthread_mutex_t	num_sent_mutex;

init()
{
	pthread_mutex_init( &active_threads_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &new_conn_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &currenttime_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &entry2str_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &replog_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &ops_mutex, pthread_mutexattr_default );
	pthread_mutex_init( &num_sent_mutex, pthread_mutexattr_default );
}
