#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "portable.h"
#include "slap.h"
#include "ldapconfig.h"

extern void	slapd_daemon();
extern int	lber_debug;

extern char Versionstr[];


/*
 * read-only global variables or variables only written by the listener
 * thread (after they are initialized) - no need to protect them with a mutex.
 */
int		ldap_debug = 0;
#ifdef LDAP_DEBUG
int		ldap_syslog = LDAP_DEBUG_STATS;
#else
int		ldap_syslog;
#endif
int		ldap_syslog_level = LOG_DEBUG;
int		udp;
int		slapd_shutdown;
char		*default_referral;
char		*configfile;
time_t		starttime;
pthread_t	listener_tid;
int		g_argc;
char		**g_argv;
/*
 * global variables that need mutex protection
 */
time_t		currenttime;
pthread_mutex_t	currenttime_mutex;
int		active_threads;
pthread_mutex_t	active_threads_mutex;
pthread_mutex_t	new_conn_mutex;
long		ops_initiated;
long		ops_completed;
int		num_conns;
pthread_mutex_t	ops_mutex;
long		num_entries_sent;
long		num_bytes_sent;
pthread_mutex_t	num_sent_mutex;
/*
 * these mutexes must be used when calling the entry2str()
 * routine since it returns a pointer to static data.
 */
pthread_mutex_t	entry2str_mutex;
pthread_mutex_t	replog_mutex;

static
usage( name )
    char	*name;
{
	fprintf( stderr, "usage: %s [-d ?|debuglevel] [-f configfile] [-p portnumber] [-s sysloglevel]\n", name );
}

main( argc, argv )
    int		argc;
    char	**argv;
{
	int		i;
	int		inetd = 0;
	int		port;
	char		*myname;
	Backend		*be = NULL;
	FILE		*fp = NULL;
	extern char	*optarg;

	configfile = SLAPD_DEFAULT_CONFIGFILE;
	port = LDAP_PORT;
	g_argc = argc;
	g_argv = argv;

	while ( (i = getopt( argc, argv, "d:f:ip:s:u" )) != EOF ) {
		switch ( i ) {
#ifdef LDAP_DEBUG
		case 'd':	/* turn on debugging */
			if ( optarg[0] == '?' ) {
				printf( "Debug levels:\n" );
				printf( "\tLDAP_DEBUG_TRACE\t%d\n",
				    LDAP_DEBUG_TRACE );
				printf( "\tLDAP_DEBUG_PACKETS\t%d\n",
				    LDAP_DEBUG_PACKETS );
				printf( "\tLDAP_DEBUG_ARGS\t\t%d\n",
				    LDAP_DEBUG_ARGS );
				printf( "\tLDAP_DEBUG_CONNS\t%d\n",
				    LDAP_DEBUG_CONNS );
				printf( "\tLDAP_DEBUG_BER\t\t%d\n",
				    LDAP_DEBUG_BER );
				printf( "\tLDAP_DEBUG_FILTER\t%d\n",
				    LDAP_DEBUG_FILTER );
				printf( "\tLDAP_DEBUG_CONFIG\t%d\n",
				    LDAP_DEBUG_CONFIG );
				printf( "\tLDAP_DEBUG_ACL\t\t%d\n",
				    LDAP_DEBUG_ACL );
				printf( "\tLDAP_DEBUG_STATS\t%d\n",
				    LDAP_DEBUG_STATS );
				printf( "\tLDAP_DEBUG_STATS2\t%d\n",
				    LDAP_DEBUG_STATS2 );
				printf( "\tLDAP_DEBUG_SHELL\t%d\n",
				    LDAP_DEBUG_SHELL );
				printf( "\tLDAP_DEBUG_PARSE\t%d\n",
				    LDAP_DEBUG_PARSE );
				printf( "\tLDAP_DEBUG_ANY\t\t%d\n",
				    LDAP_DEBUG_ANY );
				exit( 0 );
			} else {
				ldap_debug |= atoi( optarg );
				lber_debug = (ldap_debug & LDAP_DEBUG_BER);
			}
			break;
#else
		case 'd':	/* turn on debugging */
			fprintf( stderr,
			    "must compile with LDAP_DEBUG for debugging\n" );
			break;
#endif

		case 'f':	/* read config file */
			configfile = strdup( optarg );
			break;

		case 'i':	/* run from inetd */
			inetd = 1;
			break;

		case 'p':	/* port on which to listen */
			port = atoi( optarg );
			break;

		case 's':	/* set syslog level */
			ldap_syslog = atoi( optarg );
			break;

		case 'u':	/* do udp */
			udp = 1;
			break;

		default:
			usage( argv[0] );
			exit( 1 );
		}
	}

	Debug( LDAP_DEBUG_TRACE, "%s", Versionstr, 0, 0 );

	if ( (myname = strrchr( argv[0], '/' )) == NULL ) {
		myname = strdup( argv[0] );
	} else {
		myname = strdup( myname + 1 );
	}

	if ( ! inetd ) {
		/* pre-open config file before detach in case it is a relative path */
		fp = fopen( configfile, "r" );
		detach();
	}
#ifdef LOG_LOCAL4
	openlog( myname, OPENLOG_OPTIONS, LOG_LOCAL4 );
#else
	openlog( myname, OPENLOG_OPTIONS );
#endif

	init();
	read_config( configfile, &be, fp );

	if ( ! inetd ) {
		pthread_attr_t	attr;
		int		status;

		time( &starttime );
		pthread_attr_init( &attr );
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED );

#ifndef THREAD_MIT_PTHREADS
		/* POSIX_THREADS or compatible
		 * This is a draft 10 or standard pthreads implementation
		 */
		if ( pthread_create( &listener_tid, &attr, (void *) slapd_daemon,
		    (void *) port ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "listener pthread_create failed\n", 0, 0, 0 );
			exit( 1 );
		}
#else	/* !THREAD_MIT_PTHREADS */
		/*
		 * This is a draft 4 or earlier pthreads implementation
		 */
		if ( pthread_create( &listener_tid, attr, (void *) slapd_daemon,
		    (void *) port ) != 0 ) {
			Debug( LDAP_DEBUG_ANY,
			    "listener pthread_create failed\n", 0, 0, 0 );
			exit( 1 );
		}
#endif	/* !THREAD_MIT_PTHREADS */
		pthread_attr_destroy( &attr );
		pthread_join( listener_tid, (void *) &status );
		pthread_exit( 0 );
	} else {
		Connection		c;
		Operation		*o;
		BerElement		ber;
		unsigned long		len, tag;
		long			msgid;
		int			flen;
		struct sockaddr_in	from;
		struct hostent		*hp;

		c.c_dn = NULL;
		c.c_ops = NULL;
		c.c_sb.sb_sd = 0;
		c.c_sb.sb_options = 0;
		c.c_sb.sb_naddr = udp ? 1 : 0;
		c.c_sb.sb_ber.ber_buf = NULL;
		c.c_sb.sb_ber.ber_ptr = NULL;
		c.c_sb.sb_ber.ber_end = NULL;
		pthread_mutex_init( &c.c_dnmutex, pthread_mutexattr_default );
		pthread_mutex_init( &c.c_opsmutex, pthread_mutexattr_default );
		pthread_mutex_init( &c.c_pdumutex, pthread_mutexattr_default );
#ifdef notdefcldap
		c.c_sb.sb_addrs = (void **) saddrlist;
		c.c_sb.sb_fromaddr = &faddr;
		c.c_sb.sb_useaddr = saddrlist[ 0 ] = &saddr;
#endif
		flen = sizeof(from);
		if ( getpeername( 0, (struct sockaddr *) &from, &flen ) == 0 ) {
#ifdef REVERSE_LOOKUP
			hp = gethostbyaddr( (char *) &(from.sin_addr.s_addr),
			    sizeof(from.sin_addr.s_addr), AF_INET );
#else
			hp = NULL;
#endif

			Debug( LDAP_DEBUG_ARGS, "connection from %s (%s)\n",
			    hp == NULL ? "unknown" : hp->h_name,
			    inet_ntoa( from.sin_addr ), 0 );

			c.c_addr = inet_ntoa( from.sin_addr );
			c.c_domain = strdup( hp == NULL ? "" : hp->h_name );
		} else {
			Debug( LDAP_DEBUG_ARGS, "connection from unknown\n",
			    0, 0, 0 );
		}

		ber_init( &ber, 0 );
		while ( (tag = ber_get_next( &c.c_sb, &len, &ber ))
		    == LDAP_TAG_MESSAGE ) {
			pthread_mutex_lock( &currenttime_mutex );
			time( &currenttime );
			pthread_mutex_unlock( &currenttime_mutex );

			if ( (tag = ber_get_int( &ber, &msgid ))
			    != LDAP_TAG_MSGID ) {
				/* log and send error */
				Debug( LDAP_DEBUG_ANY,
				    "ber_get_int returns 0x%x\n", tag, 0, 0 );
				return;
			}

			if ( (tag = ber_peek_tag( &ber, &len ))
			    == LBER_ERROR ) {
				/* log, close and send error */
				Debug( LDAP_DEBUG_ANY,
				    "ber_peek_tag returns 0x%x\n", tag, 0, 0 );
				ber_free( &ber, 1 );
				close( c.c_sb.sb_sd );
				c.c_sb.sb_sd = -1;
				return;
			}

			connection_activity( &c );

			ber_free( &ber, 1 );
		}
	}
}
