#include "portable.h"

#include <stdio.h>

#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>
#include <ac/signal.h>
#include <ac/errno.h>

#include "ldapconfig.h"
#include "slap.h"
#include "lutil.h"			/* Get lutil_detach() */

#ifdef LDAP_SIGCHLD
static RETSIGTYPE wait4child( int sig );
#endif

#ifdef WIN32
const char Versionstr[] = "OpenLDAP slapd 1.2 for Windows NT";
#endif

/*
 * when more than one slapd is running on one machine, each one might have
 * it's own LOCAL for syslogging and must have its own pid/args files
 */

#ifdef LOG_LOCAL4

#define DEFAULT_SYSLOG_USER  LOG_LOCAL4

typedef struct _str2intDispatch {
	char    *stringVal;
	int      abbr;
	int      intVal;
} STRDISP, *STRDISP_P;


/* table to compute syslog-options to integer */
static STRDISP  syslog_types[] = {
    { "LOCAL0",         6, LOG_LOCAL0 },
    { "LOCAL1",         6, LOG_LOCAL1 },
    { "LOCAL2",         6, LOG_LOCAL2 },
    { "LOCAL3",         6, LOG_LOCAL3 },
    { "LOCAL4",         6, LOG_LOCAL4 },
    { "LOCAL5",         6, LOG_LOCAL5 },
    { "LOCAL6",         6, LOG_LOCAL6 },
    { "LOCAL7",         6, LOG_LOCAL7 },
    { NULL }
};

static int   cnvt_str2int( char *, STRDISP_P, int );

#endif  /* LOG_LOCAL4 */


static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-d ?|debuglevel] [-f configfile] [-p portnumber] [-s sysloglevel]", name );
    fprintf( stderr, "\n        [-a bind-address] [-i]" );
#if LDAP_CONNECTIONLESS
	fprintf( stderr, " [-c]" );
#endif
#ifdef SLAPD_BDB2
    fprintf( stderr, " [-t]" );
#endif
#ifdef LOG_LOCAL4
    fprintf( stderr, " [-l sysloguser]" );
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
    fprintf( stderr, " [-u user] [-g group]" );
#endif
    fprintf( stderr, "\n" );
}

time_t starttime;
struct sockaddr_in	bind_addr;

int
main( int argc, char **argv )
{
	int		i;
	int		inetd = 0;
	int		rc;
	int		tcps;
	int		udp;
#ifdef LOG_LOCAL4
    int     syslogUser = DEFAULT_SYSLOG_USER;
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	char		*username = NULL, *groupname = NULL;
#endif
	char		*configfile;
	char        *serverName;
	int         serverMode = SLAP_SERVER_MODE;

	configfile = SLAPD_DEFAULT_CONFIGFILE;

	(void) memset( (void*) &bind_addr, '\0', sizeof(bind_addr));
	bind_addr.sin_family = AF_INET;
	bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind_addr.sin_port = htons(LDAP_PORT);

	g_argc = argc;
	g_argv = argv;

	while ( (i = getopt( argc, argv,
			     "d:f:ia:p:s:c"
#ifdef LOG_LOCAL4
			     "l:"
#endif
#ifdef SLAPD_BDB2
			     "t"
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
			     "u:g:"
#endif
			     )) != EOF ) {
		switch ( i ) {
		case 'a':	/* bind address */
#ifdef HAVE_WINSOCK
			if(!(bind_addr.sin_addr.S_un.S_addr = inet_addr(optarg)))
#else
			if(!inet_aton(optarg, &bind_addr.sin_addr))
#endif
			{
				fprintf(stderr, "invalid address (%s) for -a option", optarg);
			}
            break;

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
				slap_debug |= atoi( optarg );
			}
			break;
#else
		case 'd':	/* turn on debugging */
			fprintf( stderr,
			    "must compile with LDAP_DEBUG for debugging\n" );
			break;
#endif

		case 'f':	/* read config file */
			configfile = ch_strdup( optarg );
			break;

		case 'i':	/* run from inetd */
			inetd = 1;
			break;

		case 'p': {	/* port on which to listen */
				short port = (short)atoi( optarg );
				if(! port ) {
					fprintf(stderr, "-p %s must be numeric\n", optarg);
				} else {
					bind_addr.sin_port = htons(port);
				}
			} break;

		case 's':	/* set syslog level */
			ldap_syslog = atoi( optarg );
			break;

#ifdef LOG_LOCAL4
		case 'l':	/* set syslog local user */
			syslogUser = cnvt_str2int( optarg, syslog_types,
                                           DEFAULT_SYSLOG_USER );
			break;
#endif

#ifdef LDAP_CONNECTIONLESS
		case 'c':	/* do connectionless (udp) */
			udp = 1;
			break;
#endif

#ifdef SLAPD_BDB2
		case 't':  /* timed server */
			serverMode = SLAP_TIMEDSERVER_MODE;
			break;
#endif

#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		case 'u':	/* user name */
			if( username ) free(username);
			username = ch_strdup( optarg );
			break;

		case 'g':	/* group name */
			if( groupname ) free(groupname);
			groupname = ch_strdup( optarg );
			break;
#endif /* SETUID && GETUID */

		default:
			usage( argv[0] );
			exit( 1 );
		}
	}

	lber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &slap_debug);
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &slap_debug);
	ldif_debug = slap_debug;

	Debug( LDAP_DEBUG_TRACE, "%s", Versionstr, 0, 0 );

	if ( (serverName = strrchr( argv[0], '/' )) == NULL ) {
		serverName = ch_strdup( argv[0] );
	} else {
		serverName = ch_strdup( serverName + 1 );
	}

#ifdef LOG_LOCAL4
	openlog( serverName, OPENLOG_OPTIONS, syslogUser );
#else
	openlog( serverName, OPENLOG_OPTIONS );
#endif

	tcps = set_socket( inetd ? NULL : &bind_addr );

#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	if ( username != NULL || groupname != NULL )
		slap_init_user( username, groupname );
#endif

	if ( slap_init( serverMode, serverName ) != 0 ) {
		rc = 1;
		goto destroy;
	}

	if ( read_config( configfile ) != 0 ) {
		rc = 1;
		goto destroy;
	}

	(void) SIGNAL( LDAP_SIGUSR1, slap_do_nothing );
	(void) SIGNAL( LDAP_SIGUSR2, slap_set_shutdown );
#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif
#ifdef SIGHUP
	(void) SIGNAL( SIGHUP, slap_set_shutdown );
#endif
	(void) SIGNAL( SIGINT, slap_set_shutdown );
	(void) SIGNAL( SIGTERM, slap_set_shutdown );
#ifdef LDAP_SIGCHLD
	(void) SIGNAL( LDAP_SIGCHLD, wait4child );
#endif

#ifndef WIN32
	if(!inetd) {
#ifdef LDAP_DEBUG
		lutil_detach( ldap_debug, 0 );
#else
		lutil_detach( 0, 0 );
#endif
	}
#endif /* WIN32 */

	if ( slap_startup(-1)  != 0 ) {
		rc = 1;
		goto shutdown;
	}

	if(!inetd) {
		FILE *fp;

		Debug( LDAP_DEBUG_ANY, "slapd starting\n", 0, 0, 0 );

		if (( slapd_pid_file != NULL ) &&
			(( fp = fopen( slapd_pid_file, "w" )) != NULL ))
		{
			fprintf( fp, "%d\n", (int) getpid() );
			fclose( fp );
		}

		if (( slapd_args_file != NULL ) &&
			(( fp = fopen( slapd_args_file, "w" )) != NULL ))
		{
			for ( i = 0; i < g_argc; i++ ) {
				fprintf( fp, "%s ", g_argv[i] );
			}
			fprintf( fp, "\n" );
			fclose( fp );
		}
	}

	time( &starttime );

	rc = slapd_daemon( inetd, tcps );

shutdown:
	/* remember an error during shutdown */
	rc |= slap_shutdown(-1);
destroy:
	/* remember an error during destroy */
	rc |= slap_destroy();

	Debug( LDAP_DEBUG_ANY, "slapd stopped.\n", 0, 0, 0 );

	closelog();

	return rc;
}


#ifdef LDAP_SIGCHLD

/*
 *  Catch and discard terminated child processes, to avoid zombies.
 */

static RETSIGTYPE
wait4child( int sig )
{
    int save_errno = errno;

#ifdef WNOHANG
    errno = 0;
#ifdef HAVE_WAITPID
    while ( waitpid( (pid_t)-1, NULL, WNOHANG ) >= 0 || errno == EINTR )
	;	/* NULL */
#else
    while ( wait3( NULL, WNOHANG, NULL ) >= 0 || errno == EINTR )
	;	/* NULL */
#endif
#else
    (void) wait( NULL );
#endif
    (void) SIGNAL( sig, wait4child );
    errno = save_errno;
}

#endif /* SIGCHLD || SIGCLD */


#ifdef LOG_LOCAL4

/*
 *  Convert a string to an integer by means of a dispatcher table
 *  if the string is not in the table return the default
 */

static int
cnvt_str2int( char *stringVal, STRDISP_P dispatcher, int defaultVal )
{
    int        retVal = defaultVal;
    STRDISP_P  disp;

    for (disp = dispatcher; disp->stringVal; disp++) {

        if (!strncasecmp (stringVal, disp->stringVal, disp->abbr)) {

            retVal = disp->intVal;
            break;

        }
    }

    return (retVal);

} /* cnvt_str2int */

#endif  /* LOG_LOCAL4 */
