/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>
#include <ac/errno.h>

#include "ldap_pvt.h"

#include "slap.h"
#include "lutil.h"
#include "ldif.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif

#ifdef LDAP_SIGCHLD
static RETSIGTYPE wait4child( int sig );
#endif

#ifdef HAVE_NT_SERVICE_MANAGER
#define MAIN_RETURN(x) return
static struct sockaddr_in	bind_addr;

#define SERVICE_EXIT( e, n )	do { \
	if ( is_NT_Service ) { \
		lutil_ServiceStatus.dwWin32ExitCode				= (e); \
		lutil_ServiceStatus.dwServiceSpecificExitCode	= (n); \
	} \
} while ( 0 )

#else
#define SERVICE_EXIT( e, n )
#define MAIN_RETURN(x) return(x)
#endif

typedef int (MainFunc) LDAP_P(( int argc, char *argv[] ));
extern MainFunc slapadd, slapcat, slapdn, slapindex, slappasswd,
	slaptest, slapauth, slapacl;

static struct {
	char *name;
	MainFunc *func;
} tools[] = {
	{"slapadd", slapadd},
	{"slapcat", slapcat},
	{"slapdn", slapdn},
	{"slapindex", slapindex},
	{"slappasswd", slappasswd},
	{"slaptest", slaptest},
	{"slapauth", slapauth},
	{"slapacl", slapacl},
	/* NOTE: new tools must be added in chronological order,
	 * not in alphabetical order, because for backwards
	 * compatibility name[4] is used to identify the
	 * tools; so name[4]=='a' must refer to "slapadd" and
	 * not to "slapauth".  Alphabetical order can be used
	 * for tools whose name[4] is not used yet */
	{NULL, NULL}
};

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
	char	*stringVal;
	int	 abbr;
	int	 intVal;
} STRDISP, *STRDISP_P;


/* table to compute syslog-options to integer */
static STRDISP	syslog_types[] = {
	{ "LOCAL0", sizeof("LOCAL0"), LOG_LOCAL0 },
	{ "LOCAL1", sizeof("LOCAL1"), LOG_LOCAL1 },
	{ "LOCAL2", sizeof("LOCAL2"), LOG_LOCAL2 },
	{ "LOCAL3", sizeof("LOCAL3"), LOG_LOCAL3 },
	{ "LOCAL4", sizeof("LOCAL4"), LOG_LOCAL4 },
	{ "LOCAL5", sizeof("LOCAL5"), LOG_LOCAL5 },
	{ "LOCAL6", sizeof("LOCAL6"), LOG_LOCAL6 },
	{ "LOCAL7", sizeof("LOCAL7"), LOG_LOCAL7 },
	{ NULL, 0, 0 }
};

static int   cnvt_str2int( char *, STRDISP_P, int );

#endif	/* LOG_LOCAL4 */

#define CHECK_NONE	0x00
#define CHECK_CONFIG	0x01
static int check = CHECK_NONE;
static int version = 0;

void *slap_tls_ctx;

static int
slapd_opt_slp( const char *val, void *arg )
{
#ifdef HAVE_SLP
	/* NULL is default */
	if ( val == NULL || strcasecmp( val, "on" ) == 0 ) {
		slapd_register_slp = 1;

	} else if ( strcasecmp( val, "off" ) == 0 ) {
		slapd_register_slp = 0;

	/* NOTE: add support for URL specification? */

	} else {
		fprintf(stderr, "unrecognized value \"%s\" for SLP option\n", val );
		return -1;
	}

	return 0;
		
#else
	fputs( "slapd: SLP support is not available\n", stderr );
	return 0;
#endif
}

struct option_helper {
	struct berval	oh_name;
	int		(*oh_fnc)(const char *val, void *arg);
	void		*oh_arg;
} option_helpers[] = {
	{ BER_BVC("slp"),	slapd_opt_slp,	NULL },
	{ BER_BVNULL }
};

static void
usage( char *name )
{
	fprintf( stderr,
		"usage: %s options\n", name );
	fprintf( stderr,
		"\t-4\t\tIPv4 only\n"
		"\t-6\t\tIPv6 only\n"
		"\t-T {add|auth|cat|dn|index|passwd|test}\n"
		"\t\t\tRun in Tool mode\n"
		"\t-c cookie\tSync cookie of consumer\n"
		"\t-d level\tDebug level" "\n"
		"\t-f filename\tConfiguration file\n"
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		"\t-g group\tGroup (id or name) to run as\n"
#endif
		"\t-h URLs\t\tList of URLs to serve\n"
#ifdef LOG_LOCAL4
		"\t-l facility\tSyslog facility (default: LOCAL4)\n"
#endif
		"\t-n serverName\tService name\n"
		"\t-o <opt>[=val]\tGeneric means to specify options; supported options:\n"
#ifdef HAVE_SLP
		"\t\t\t\tslp[={on|off}]\n"
#endif
#ifdef HAVE_CHROOT
		"\t-r directory\tSandbox directory to chroot to\n"
#endif
		"\t-s level\tSyslog level\n"
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		"\t-u user\t\tUser (id or name) to run as\n"
#endif
		"\t-V\t\tprint version info (-VV only)\n"
    );
}

#ifdef HAVE_NT_SERVICE_MANAGER
void WINAPI ServiceMain( DWORD argc, LPTSTR *argv )
#else
int main( int argc, char **argv )
#endif
{
	int		i, no_detach = 0;
	int		rc = 1;
	char *urls = NULL;
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	char *username = NULL;
	char *groupname = NULL;
#endif
#if defined(HAVE_CHROOT)
	char *sandbox = NULL;
#endif
#ifdef LOG_LOCAL4
    int	    syslogUser = DEFAULT_SYSLOG_USER;
#endif
	
	int g_argc = argc;
	char **g_argv = argv;

#ifdef HAVE_NT_SERVICE_MANAGER
	char		*configfile = ".\\slapd.conf";
#else
	char		*configfile = SLAPD_DEFAULT_CONFIGFILE;
#endif
	char	    *serverName;
	int	    serverMode = SLAP_SERVER_MODE;

	struct berval cookie = BER_BVNULL;
	struct sync_cookie *scp = NULL;
	struct sync_cookie *scp_entry = NULL;

#ifdef CSRIMALLOC
	FILE *leakfile;
	if( ( leakfile = fopen( "slapd.leak", "w" )) == NULL ) {
		leakfile = stderr;
	}
#endif
	char	*serverNamePrefix = "";
	size_t	l;

	slap_sl_mem_init();

	serverName = lutil_progname( "slapd", argc, argv );

	if ( strcmp( serverName, "slapd" ) ) {
		for (i=0; tools[i].name; i++) {
			if ( !strcmp( serverName, tools[i].name ) ) {
				rc = tools[i].func(argc, argv);
				MAIN_RETURN(rc);
			}
		}
	}

#ifdef HAVE_NT_SERVICE_MANAGER
	{
		int *i;
		char *newConfigFile;
		char *newUrls;
		char *regService = NULL;

		if ( is_NT_Service ) {
			lutil_CommenceStartupProcessing( serverName, slap_sig_shutdown );
			if ( strcmp(serverName, SERVICE_NAME) )
			    regService = serverName;
		}

		i = (int*)lutil_getRegParam( regService, "DebugLevel" );
		if ( i != NULL ) {
			slap_debug = *i;
#ifdef NEW_LOGGING
			lutil_log_initialize( argc, argv );
			LDAP_LOG( SLAPD, INFO, 
				"main: new debug level from registry is: %d\n", 
				slap_debug, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"new debug level from registry is: %d\n", slap_debug, 0, 0 );
#endif
		}

		newUrls = (char *) lutil_getRegParam(regService, "Urls");
		if (newUrls) {
		    if (urls)
			ch_free(urls);

		    urls = ch_strdup(newUrls);
#ifdef NEW_LOGGING
		    LDAP_LOG( SLAPD, INFO, 
				"main: new urls from registry: %s\n", urls, 0, 0 );
#else
		    Debug(LDAP_DEBUG_ANY, "new urls from registry: %s\n",
				urls, 0, 0);
#endif
		}

		newConfigFile = (char*)lutil_getRegParam( regService, "ConfigFile" );
		if ( newConfigFile != NULL ) {
			configfile = newConfigFile;
#ifdef NEW_LOGGING
			LDAP_LOG( SLAPD, INFO, 
				"main: new config file from registry is: %s\n", configfile, 0, 0 );
#else
			Debug ( LDAP_DEBUG_ANY, "new config file from registry is: %s\n", configfile, 0, 0 );
#endif
		}
	}
#endif

	while ( (i = getopt( argc, argv,
			     "c:d:f:h:n:o:s:StT:V"
#if LDAP_PF_INET6
				"46"
#endif
#ifdef HAVE_CHROOT
				"r:"
#endif
#ifdef LOG_LOCAL4
			     "l:"
#endif
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
			     "u:g:"
#endif
			     )) != EOF ) {
		switch ( i ) {
#ifdef LDAP_PF_INET6
		case '4':
			slap_inet4or6 = AF_INET;
			break;
		case '6':
			slap_inet4or6 = AF_INET6;
			break;
#endif

		case 'h':	/* listen URLs */
			if ( urls != NULL ) free( urls );
			urls = ch_strdup( optarg );
			break;

		case 'c':	/* provide sync cookie, override if exist in replica */
			scp = (struct sync_cookie *) ch_calloc( 1,
										sizeof( struct sync_cookie ));
			ber_str2bv( optarg, strlen( optarg ), 1, &cookie );
			ber_bvarray_add( &scp->octet_str, &cookie );
			slap_parse_sync_cookie( scp );

			LDAP_STAILQ_FOREACH( scp_entry, &slap_sync_cookie, sc_next ) {
				if ( scp->rid == scp_entry->rid ) {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, CRIT,
							"main: duplicated replica id in cookies\n",
							0, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						    "main: duplicated replica id in cookies\n",
							0, 0, 0 );
#endif
					slap_sync_cookie_free( scp, 1 );
					goto destroy;
				}
			}
			LDAP_STAILQ_INSERT_TAIL( &slap_sync_cookie, scp, sc_next );
			break;

		case 'd':	/* set debug level and 'do not detach' flag */
			no_detach = 1;
#ifdef LDAP_DEBUG
			slap_debug |= atoi( optarg );
#else
			if ( atoi( optarg ) != 0 )
				fputs( "must compile with LDAP_DEBUG for debugging\n",
				       stderr );
#endif
			break;

		case 'f':	/* read config file */
			configfile = ch_strdup( optarg );
			break;

		case 'o': {
			char		*val = strchr( optarg, '=' );
			struct berval	opt;
			int		i;

			opt.bv_val = optarg;
			
			if ( val ) {
				opt.bv_len = ( val - optarg );
				val++;
			
			} else {
				opt.bv_len = strlen( optarg );
			}

			for ( i = 0; !BER_BVISNULL( &option_helpers[i].oh_name ); i++ ) {
				if ( ber_bvstrcasecmp( &option_helpers[i].oh_name, &opt ) == 0 ) {
					assert( option_helpers[i].oh_fnc != NULL );
					if ( (*option_helpers[i].oh_fnc)( val, option_helpers[i].oh_arg ) == -1 ) {
						/* we assume the option parsing helper
						 * issues appropriate and self-explanatory
						 * error messages... */
						goto stop;
					}
					break;
				}
			}

			if ( BER_BVISNULL( &option_helpers[i].oh_name ) ) {
				goto unhandled_option;
			}
			break;
		}

		case 's':	/* set syslog level */
			ldap_syslog = atoi( optarg );
			break;

#ifdef LOG_LOCAL4
		case 'l':	/* set syslog local user */
			syslogUser = cnvt_str2int( optarg,
			syslog_types, DEFAULT_SYSLOG_USER );
			break;
#endif

#ifdef HAVE_CHROOT
		case 'r':
			if( sandbox ) free(sandbox);
			sandbox = ch_strdup( optarg );
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

		case 'n':  /* NT service name */
			serverName = ch_strdup( optarg );
			break;

		case 't':
			/* deprecated; use slaptest instead */
			fprintf( stderr, "option -t deprecated; "
				"use slaptest command instead\n" );
			check |= CHECK_CONFIG;
			break;

		case 'V':
			version++;
			break;

		case 'T':
			/* try full option string first */
			for ( i = 0; tools[i].name; i++ ) {
				if ( strcmp( optarg, &tools[i].name[4] ) == 0 ) {
					rc = tools[i].func( argc, argv );
					MAIN_RETURN( rc );
				}
			}

			/* try bits of option string (backward compatibility for single char) */
			l = strlen( optarg );
			for ( i = 0; tools[i].name; i++ ) {
				if ( strncmp( optarg, &tools[i].name[4], l ) == 0 ) {
					rc = tools[i].func( argc, argv );
					MAIN_RETURN( rc );
				}
			}
			
			/* issue error */
			serverName = optarg;
			serverNamePrefix = "slap";
			fprintf( stderr, "program name \"%s%s\" unrecognized; "
					"aborting...\n", serverNamePrefix, serverName );
			/* FALLTHRU */
		default:
unhandled_option:;
			usage( argv[0] );
			rc = 1;
			SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 15 );
			goto stop;
		}
	}

#ifdef NEW_LOGGING
	lutil_log_initialize( argc, argv );
#else
	lutil_set_debug_level( "slapd", slap_debug );
	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &slap_debug);
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &slap_debug);
	ldif_debug = slap_debug;
#endif

	if ( version ) {
		fprintf( stderr, "%s\n", Versionstr );
		if ( version > 1 ) goto stop;
	}

	{
		char *logName;
#ifdef HAVE_EBCDIC
		logName = ch_strdup( serverName );
		__atoe( logName );
#else
		logName = serverName;
#endif

#ifdef LOG_LOCAL4
		openlog( logName, OPENLOG_OPTIONS, syslogUser );
#elif LOG_DEBUG
		openlog( logName, OPENLOG_OPTIONS );
#endif
#ifdef HAVE_EBCDIC
		free( logName );
#endif
	}

#ifdef NEW_LOGGING
	LDAP_LOG( SLAPD, INFO, "%s", Versionstr, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "%s", Versionstr, 0, 0 );
#endif

	if( check == CHECK_NONE && slapd_daemon_init( urls ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 16 );
		goto stop;
	}

#if defined(HAVE_CHROOT)
	if ( sandbox ) {
		if ( chdir( sandbox ) ) {
			perror("chdir");
			rc = 1;
			goto stop;
		}
		if ( chroot( sandbox ) ) {
			perror("chroot");
			rc = 1;
			goto stop;
		}
	}
#endif

#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
	if ( username != NULL || groupname != NULL ) {
		slap_init_user( username, groupname );
	}
#endif

	extops_init();
	lutil_passwd_init();
	slap_op_init();

#ifdef SLAPD_MODULES
	if ( module_init() != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 17 );
		goto destroy;
	}
#endif

	if ( slap_schema_init( ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT, "main: schema initialization error\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "schema initialization error\n",
		    0, 0, 0 );
#endif

		goto destroy;
	}

	if ( slap_init( serverMode, serverName ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 18 );
		goto destroy;
	}

	if ( slap_controls_init( ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT, "main: controls initialization error\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "controls initialization error\n",
		    0, 0, 0 );
#endif

		goto destroy;
	}

#ifdef HAVE_TLS
	/* Library defaults to full certificate checking. This is correct when
	 * a client is verifying a server because all servers should have a
	 * valid cert. But few clients have valid certs, so we want our default
	 * to be no checking. The config file can override this as usual.
	 */
	rc = 0;
	(void) ldap_pvt_tls_set_option( NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &rc );
#endif

#ifdef LDAP_SLAPI
	if ( slapi_int_initialize() != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, CRIT, "main: slapi initialization error\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "slapi initialization error\n",
		    0, 0, 0 );
#endif

		goto destroy;
	}
#endif /* LDAP_SLAPI */

	if ( overlay_init() ) {
		goto destroy;
	}

	if ( read_config( configfile, 0 ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 19 );

		if ( check & CHECK_CONFIG ) {
			fprintf( stderr, "config check failed\n" );
		}

		goto destroy;
	}

	if ( check & CHECK_CONFIG ) {
		fprintf( stderr, "config check succeeded\n" );

		check &= ~CHECK_CONFIG;
		if ( check == CHECK_NONE ) {
			rc = 0;
			goto destroy;
		}
	}

	if ( glue_sub_init( ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( SLAPD, CRIT, "main: subordinate config error\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "subordinate config error\n",
		    0, 0, 0 );
#endif
		goto destroy;
	}

	if ( slap_schema_check( ) != 0 ) {
#ifdef NEW_LOGGING
		LDAP_LOG( SLAPD, CRIT, "main: schema prep error\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "schema prep error\n",
		    0, 0, 0 );
#endif

		goto destroy;
	}

#ifdef HAVE_TLS
	rc = ldap_pvt_tls_init();
	if( rc != 0) {
#ifdef NEW_LOGGING
		LDAP_LOG( SLAPD, CRIT, "main: tls init failed: %d\n", rc, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		    "main: TLS init failed: %d\n",
		    0, 0, 0 );
#endif
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 20 );
		goto destroy;
	}

	{
		void *def_ctx = NULL;

		/* Save existing default ctx, if any */
		ldap_pvt_tls_get_option( NULL, LDAP_OPT_X_TLS_CTX, &def_ctx );

		/* Force new ctx to be created */
		ldap_pvt_tls_set_option( NULL, LDAP_OPT_X_TLS_CTX, NULL );

		rc = ldap_pvt_tls_init_def_ctx();
		if( rc != 0) {
#ifdef NEW_LOGGING
			LDAP_LOG( SLAPD, CRIT, "main: tls init def ctx failed: %d\n", rc, 0, 0 );
#else
			Debug( LDAP_DEBUG_ANY,
			    "main: TLS init def ctx failed: %d\n",
			    rc, 0, 0 );
#endif
			rc = 1;
			SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 20 );
			goto destroy;
		}
		/* Retrieve slapd's own ctx */
		ldap_pvt_tls_get_option( NULL, LDAP_OPT_X_TLS_CTX, &slap_tls_ctx );
		/* Restore previous ctx */
		ldap_pvt_tls_set_option( NULL, LDAP_OPT_X_TLS_CTX, def_ctx );
	}
#endif

	(void) SIGNAL( LDAP_SIGUSR1, slap_sig_wake );
	(void) SIGNAL( LDAP_SIGUSR2, slap_sig_shutdown );

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif
#ifdef SIGHUP
	(void) SIGNAL( SIGHUP, slap_sig_shutdown );
#endif
	(void) SIGNAL( SIGINT, slap_sig_shutdown );
	(void) SIGNAL( SIGTERM, slap_sig_shutdown );
#ifdef LDAP_SIGCHLD
	(void) SIGNAL( LDAP_SIGCHLD, wait4child );
#endif
#ifdef SIGBREAK
	/* SIGBREAK is generated when Ctrl-Break is pressed. */
	(void) SIGNAL( SIGBREAK, slap_sig_shutdown );
#endif

#ifndef HAVE_WINSOCK
	lutil_detach( no_detach, 0 );
#endif /* HAVE_WINSOCK */

#ifdef CSRIMALLOC
	mal_leaktrace(1);
#endif

	/*
	 * FIXME: moved here from slapd_daemon_task()
	 * because back-monitor db_open() needs it
	 */
	time( &starttime );

	if ( slap_startup( NULL )  != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 21 );
		goto shutdown;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( SLAPD, INFO, "main: slapd starting.\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "slapd starting\n", 0, 0, 0 );
#endif


	if ( slapd_pid_file != NULL ) {
		FILE *fp = fopen( slapd_pid_file, "w" );

		if( fp != NULL ) {
			fprintf( fp, "%d\n", (int) getpid() );
			fclose( fp );

		} else {
			free(slapd_pid_file);
			slapd_pid_file = NULL;
		}
	}

	if ( slapd_args_file != NULL ) {
		FILE *fp = fopen( slapd_args_file, "w" );

		if( fp != NULL ) {
			for ( i = 0; i < g_argc; i++ ) {
				fprintf( fp, "%s ", g_argv[i] );
			}
			fprintf( fp, "\n" );
			fclose( fp );
		} else {
			free(slapd_args_file);
			slapd_args_file = NULL;
		}
	}

#ifdef HAVE_NT_EVENT_LOG
	if (is_NT_Service)
	lutil_LogStartedEvent( serverName, slap_debug, configfile, urls );
#endif

	rc = slapd_daemon();

#ifdef HAVE_NT_SERVICE_MANAGER
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

	while ( !LDAP_STAILQ_EMPTY( &slap_sync_cookie )) {
		scp = LDAP_STAILQ_FIRST( &slap_sync_cookie );
		LDAP_STAILQ_REMOVE_HEAD( &slap_sync_cookie, sc_next );
		ch_free( scp );
	}

#ifdef SLAPD_MODULES
	module_kill();
#endif

	slap_op_destroy();

	extops_kill();

stop:
#ifdef HAVE_NT_EVENT_LOG
	if (is_NT_Service)
	lutil_LogStoppedEvent( serverName );
#endif

#ifdef NEW_LOGGING
	LDAP_LOG( SLAPD, CRIT, "main: slapd stopped.\n", 0, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "slapd stopped.\n", 0, 0, 0 );
#endif


#ifdef HAVE_NT_SERVICE_MANAGER
	lutil_ReportShutdownComplete();
#endif

#ifdef LOG_DEBUG
    closelog();
#endif
	slapd_daemon_destroy();

	controls_destroy();

	schema_destroy();

	lutil_passwd_destroy();

#ifdef HAVE_TLS
	ldap_pvt_tls_destroy();
#endif

	if ( slapd_pid_file != NULL ) {
		unlink( slapd_pid_file );
	}
	if ( slapd_args_file != NULL ) {
		unlink( slapd_args_file );
	}

	config_destroy();

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
    while ( waitpid( (pid_t)-1, NULL, WNOHANG ) > 0 || errno == EINTR )
	;	/* NULL */
#else
    while ( wait3( NULL, WNOHANG, NULL ) > 0 || errno == EINTR )
	;	/* NULL */
#endif
#else
    (void) wait( NULL );
#endif
    (void) SIGNAL_REINSTALL( sig, wait4child );
    errno = save_errno;
}

#endif /* LDAP_SIGCHLD */


#ifdef LOG_LOCAL4

/*
 *  Convert a string to an integer by means of a dispatcher table
 *  if the string is not in the table return the default
 */

static int
cnvt_str2int( char *stringVal, STRDISP_P dispatcher, int defaultVal )
{
    int	       retVal = defaultVal;
    STRDISP_P  disp;

    for (disp = dispatcher; disp->stringVal; disp++) {

	if (!strncasecmp (stringVal, disp->stringVal, disp->abbr)) {

	    retVal = disp->intVal;
	    break;

	}
    }

    return (retVal);
}

#endif	/* LOG_LOCAL4 */
