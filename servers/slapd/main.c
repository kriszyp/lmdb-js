/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
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

#include "ldap_defaults.h"
#include "slap.h"
#include "lutil.h"

#ifdef LDAP_SIGCHLD
static RETSIGTYPE wait4child( int sig );
#endif

#ifdef HAVE_WINSOCK
#define MAIN_RETURN(x) return
struct sockaddr_in	bind_addr;

/* in nt_main.c */
extern SERVICE_STATUS			SLAPDServiceStatus;
extern SERVICE_STATUS_HANDLE	hSLAPDServiceStatus;
extern ldap_pvt_thread_cond_t	started_event,		stopped_event;
extern int	  is_NT_Service;

void LogSlapdStartedEvent( char *svc, int slap_debug, char *configfile, char *urls );
void LogSlapdStoppedEvent( char *svc );

void CommenceStartupProcessing( LPCTSTR serviceName,
							   void(*stopper)(int));
void ReportSlapdShutdownComplete( void );
void *getRegParam( char *svc, char *value );

#define SERVICE_EXIT( e, n ) \
		if ( is_NT_Service ) \
{ \
			SLAPDServiceStatus.dwWin32ExitCode				= e; \
			SLAPDServiceStatus.dwServiceSpecificExitCode	= n; \
} 
#else
#define SERVICE_EXIT( e, n )
#define MAIN_RETURN(x) return(x)
#endif

/*
 * when more than one slapd is running on one machine, each one might have
 * it's own LOCAL for syslogging and must have its own pid/args files
 */

#ifndef HAVE_MKVERSION
const char Versionstr[] =
	OPENLDAP_PACKAGE " " OPENLDAP_VERSION " Standalone LDAP Server (slapd)";
#endif

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
	fprintf( stderr,
		"usage: %s options\n", name );
	fprintf( stderr,
#if LDAP_CONNECTIONLESS
		"\t-c\t\tEnable (experimental) Connectionless LDAP\n"
#endif
		"\t-d level\tDebug Level" "\n"
		"\t-f filename\tConfiguration File\n"
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		"\t-g group\tGroup (id or name) to ran as\n"
#endif
		"\t-h URLs\tList of URLs to serve\n"
#ifdef LOG_LOCAL4
		"\t-l sysloguser\tSyslog User (default: LOCAL4)\n"
#endif
#ifdef HAVE_WINSOCK
		"\t-n NTserviceName\tNT service name\n"
#endif

		"\t-p port\tLDAP Port\n"
#ifdef HAVE_TLS
		"\t-P port\tLDAP over TLS Port\n"
#endif
		"\t-s level\tSyslog Level\n"
#ifdef SLAPD_BDB2
		"\t-t\t\tEnable BDB2 timing\n"
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		"\t-u user\tUser (id or name) to ran as\n"
#endif
    );
}

#ifdef HAVE_WINSOCK
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv )
#else
int main( int argc, char **argv )
#endif
{
	int		i;
	int		rc;
	char *urls = NULL;
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	char *username = NULL;
	char *groupname = NULL;
#endif
#ifdef LOG_LOCAL4
    int     syslogUser = DEFAULT_SYSLOG_USER;
#endif
#ifdef HAVE_WINSOCK
	char        *NTservice  = SERVICE_NAME;
	char		*configfile = ".\\slapd.conf";
#else
	char		*configfile = SLAPD_DEFAULT_CONFIGFILE;
#endif
	char        *serverName;
	int         serverMode = SLAP_SERVER_MODE;

	int port = LDAP_PORT;
#ifdef HAVE_TLS
	int tls_port = LDAPS_PORT;
#else
	int tls_port = 0;
#endif

#ifdef CSRIMALLOC
	FILE *leakfile;
	if( ( leakfile = fopen( "slapd.leak", "w" )) == NULL ) {
		leakfile = stderr;
	}
#endif

	g_argc = argc;
	g_argv = argv;

#ifdef HAVE_WINSOCK
	{
		int *i;
		char *newConfigFile;
		if ( is_NT_Service ) CommenceStartupProcessing( NTservice, slap_set_shutdown );
		i = (int*)getRegParam( NULL, "Port" );
		if ( i != NULL )
		{
			port = *i;
			Debug ( LDAP_DEBUG_ANY, "new port from registry is: %d\n", port, 0, 0 );
		}
#ifdef HAVE_TLS
		i = (int*)getRegParam( NULL, "TLSPort" );
		if ( i != NULL )
		{
			tls_port = *i;
			Debug ( LDAP_DEBUG_ANY, "new TLS port from registry is: %d\n", tls_port, 0, 0 );
		}
#endif
		i = (int*)getRegParam( NULL, "DebugLevel" );
		if ( i != NULL ) 
		{
			slap_debug = *i;
			Debug( LDAP_DEBUG_ANY, "new debug level from registry is: %d\n", slap_debug, 0, 0 );
		}
		newConfigFile = (char*)getRegParam( NULL, "ConfigFile" );
		if ( newConfigFile != NULL ) 
		{
			configfile = newConfigFile;
			Debug ( LDAP_DEBUG_ANY, "new config file from registry is: %s\n", configfile, 0, 0 );
		}
	}
#endif

	while ( (i = getopt( argc, argv,
			     "d:f:h:p:s:"
#ifdef LOG_LOCAL4
			     "l:"
#endif
#ifdef SLAPD_BDB2
			     "t"
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
			     "u:g:"
#endif
#ifdef LDAP_CONNECTIONLESS
				 "c"
#endif
#ifdef HAVE_WINSOCK
				 "n:"
#endif
#ifdef HAVE_TLS
			     "P:"
#endif
			     )) != EOF ) {
		switch ( i ) {
		case 'h':	/* listen URLs */
			if ( urls != NULL ) free( urls );
			urls = ch_strdup( optarg );
            break;

#ifdef LDAP_DEBUG
		case 'd':	/* turn on debugging */
			slap_debug |= atoi( optarg );
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

		case 'p': {	/* port on which to listen */
				int p = atoi( optarg );
				if(! p ) {
					fprintf(stderr, "-p %s must be numeric\n", optarg);
				} else if( p < 0 || p >= 1<<16) {
					fprintf(stderr, "-p %s invalid\n", optarg);
				} else {
					port = p;
				}
			} break;

#ifdef HAVE_TLS
		case 'P': {	/* port on which to listen for TLS */
				int p = atoi( optarg );
				if(! p ) {
					fprintf(stderr, "-P %s must be numeric\n", optarg);
				} else if( p < 0 || p >= 1<<16) {
					fprintf(stderr, "-P %s invalid\n", optarg);
				} else {
					tls_port = p;
				}
			} break;
#endif

		case 's':	/* set syslog level */
			ldap_syslog = atoi( optarg );
			break;

#ifdef LOG_LOCAL4
		case 'l':	/* set syslog local user */
			syslogUser = cnvt_str2int( optarg,
				syslog_types, DEFAULT_SYSLOG_USER );
			break;
#endif

#ifdef LDAP_CONNECTIONLESS
		case 'c':	/* do connectionless (udp) */
			/* udp = 1; */
			fprintf( stderr, "connectionless support not supported");
			exit( EXIT_FAILURE );
			break;
#endif

#ifdef SLAPD_BDB2
		case 't':  /* timed server */
			serverMode |= SLAP_TIMED_MODE;
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

#ifdef HAVE_WINSOCK
		case 'n':  /* NT service name */
			NTservice = ch_strdup( optarg );
			break;
#endif
		default:
			usage( argv[0] );
			rc = 1;
			SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 15 );
			goto stop;
		}
	}

	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &slap_debug);
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &slap_debug);
	ldif_debug = slap_debug;

	Debug( LDAP_DEBUG_TRACE, "%s", Versionstr, 0, 0 );

	if ( (serverName = strrchr( argv[0], *LDAP_DIRSEP )) == NULL ) {
		serverName = ch_strdup( argv[0] );
	} else {
		serverName = ch_strdup( serverName + 1 );
	}

#ifdef LOG_LOCAL4
	openlog( serverName, OPENLOG_OPTIONS, syslogUser );
#else
	openlog( serverName, OPENLOG_OPTIONS );
#endif

	if( slapd_daemon_init( urls, port, tls_port ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 16 );
		goto stop;
	}

#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	if ( username != NULL || groupname != NULL ) {
		slap_init_user( username, groupname );
	}
#endif

	if ( slap_init( serverMode, serverName ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 18 );
		goto destroy;
	}

	if ( read_config( configfile ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 19 );
		goto destroy;
	}

#ifdef HAVE_TLS
	ldap_pvt_tls_init();
	ldap_pvt_tls_init_def_ctx();
#endif

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
#ifdef SIGBREAK
	/* SIGBREAK is generated when Ctrl-Break is pressed. */
	(void) SIGNAL( SIGBREAK, slap_set_shutdown );
#endif

#ifndef HAVE_WINSOCK
#ifdef LDAP_DEBUG
		lutil_detach( ldap_debug, 0 );
#else
		lutil_detach( 0, 0 );
#endif
#endif /* HAVE_WINSOCK */

#ifdef CSRIMALLOC
	mal_leaktrace(1);
#endif

	if ( slap_startup( NULL )  != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 20 );
		goto shutdown;
	}

	{
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

#ifdef HAVE_WINSOCK
	LogSlapdStartedEvent( NTservice, slap_debug, configfile, urls );
#endif

	rc = slapd_daemon();

#ifdef HAVE_WINSOCK
	/* Throw away the event that we used during the startup process. */
	if ( is_NT_Service )
		ldap_pvt_thread_cond_destroy( &started_event );
#endif

shutdown:
	/* remember an error during shutdown */
	rc |= slap_shutdown( NULL );

destroy:
	/* remember an error during destroy */
	rc |= slap_destroy();

stop:
#ifdef HAVE_WINSOCK
	LogSlapdStoppedEvent( NTservice );
#endif

	Debug( LDAP_DEBUG_ANY, "slapd stopped.\n", 0, 0, 0 );

#ifdef HAVE_WINSOCK
	ReportSlapdShutdownComplete();
#endif

    closelog();
	slapd_daemon_destroy();

#ifdef CSRIMALLOC
	mal_dumpleaktrace( leakfile );
#endif

	MAIN_RETURN(rc);
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
}

#endif  /* LOG_LOCAL4 */
