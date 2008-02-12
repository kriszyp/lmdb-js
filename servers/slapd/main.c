/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>
#include <ac/errno.h>

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
#ifdef LOG_USER
	{ "USER", sizeof("USER"), LOG_USER },
#endif
#ifdef LOG_DAEMON
	{ "DAEMON", sizeof("DAEMON"), LOG_DAEMON },
#endif
	{ NULL, 0, 0 }
};

static int cnvt_str2int( char *, STRDISP_P, int );
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

/*
 * Option helper structure:
 * 
 * oh_nam	is left-hand part of <option>[=<value>]
 * oh_fnc	is handler function
 * oh_arg	is an optional arg to oh_fnc
 * oh_usage	is the one-line usage string related to the option,
 *		which is assumed to start with <option>[=<value>]
 *
 * please leave valid options in the structure, and optionally #ifdef
 * their processing inside the helper, so that reasonable and helpful
 * error messages can be generated if a disabled option is requested.
 */
struct option_helper {
	struct berval	oh_name;
	int		(*oh_fnc)(const char *val, void *arg);
	void		*oh_arg;
	const char	*oh_usage;
} option_helpers[] = {
	{ BER_BVC("slp"),	slapd_opt_slp,	NULL, "slp[={on|off}] enable/disable SLP" },
	{ BER_BVNULL, 0, NULL, NULL }
};

int
parse_debug_unknowns( char **unknowns, int *levelp )
{
	int i, level, rc = 0;

	for ( i = 0; unknowns[ i ] != NULL; i++ ) {
		level = 0;
		if ( str2loglevel( unknowns[ i ], &level )) {
			fprintf( stderr,
				"unrecognized log level \"%s\"\n", unknowns[ i ] );
			rc = 1;
		} else {
			*levelp |= level;
		}
	}
	return rc;
}

int
parse_debug_level( const char *arg, int *levelp, char ***unknowns )
{
	int	level;

	if ( arg != NULL && arg[ 0 ] != '-' && !isdigit( arg[ 0 ] ) )
	{
		int	i;
		char	**levels;

		levels = ldap_str2charray( arg, "," );

		for ( i = 0; levels[ i ] != NULL; i++ ) {
			level = 0;

			if ( str2loglevel( levels[ i ], &level ) ) {
				/* remember this for later */
				ldap_charray_add( unknowns, levels[ i ] );
				fprintf( stderr,
					"unrecognized log level \"%s\" (deferred)\n",
					levels[ i ] );
			} else {
				*levelp |= level;
			}
		}

		ldap_charray_free( levels );

	} else {
		if ( lutil_atoix( &level, arg, 0 ) != 0 ) {
			fprintf( stderr,
				"unrecognized log level "
				"\"%s\"\n", arg );
			return 1;
		}

		if ( level == 0 ) {
			*levelp = 0;

		} else {
			*levelp |= level;
		}
	}

	return 0;
}

static void
usage( char *name )
{
	fprintf( stderr,
		"usage: %s options\n", name );
	fprintf( stderr,
		"\t-4\t\tIPv4 only\n"
		"\t-6\t\tIPv6 only\n"
		"\t-T {acl|add|auth|cat|dn|index|passwd|test}\n"
		"\t\t\tRun in Tool mode\n"
		"\t-c cookie\tSync cookie of consumer\n"
		"\t-d level\tDebug level" "\n"
		"\t-f filename\tConfiguration file\n"
		"\t-F dir\tConfiguration directory\n"
#if defined(HAVE_SETUID) && defined(HAVE_SETGID)
		"\t-g group\tGroup (id or name) to run as\n"
#endif
		"\t-h URLs\t\tList of URLs to serve\n"
#ifdef LOG_LOCAL4
		"\t-l facility\tSyslog facility (default: LOCAL4)\n"
#endif
		"\t-n serverName\tService name\n"
		"\t-o <opt>[=val] generic means to specify options" );
	if ( !BER_BVISNULL( &option_helpers[0].oh_name ) ) {
		int	i;

		fprintf( stderr, "; supported options:\n" );
		for ( i = 0; !BER_BVISNULL( &option_helpers[i].oh_name ); i++) {
			fprintf( stderr, "\t\t%s\n", option_helpers[i].oh_usage );
		}
	} else {
		fprintf( stderr, "\n" );
	}
	fprintf( stderr,	
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
	int syslogUser = DEFAULT_SYSLOG_USER;
#endif
	
	int g_argc = argc;
	char **g_argv = argv;

	char *configfile = NULL;
	char *configdir = NULL;
	char *serverName;
	int serverMode = SLAP_SERVER_MODE;

	struct sync_cookie *scp = NULL;
	struct sync_cookie *scp_entry = NULL;

	char **debug_unknowns = NULL;
	char **syslog_unknowns = NULL;

	char *serverNamePrefix = "";
	size_t	l;

	int slapd_pid_file_unlink = 0, slapd_args_file_unlink = 0;

#ifdef CSRIMALLOC
	FILE *leakfile;
	if( ( leakfile = fopen( "slapd.leak", "w" )) == NULL ) {
		leakfile = stderr;
	}
#endif

	slap_sl_mem_init();

	(void) ldap_pvt_thread_initialize();

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
		char *newConfigDir;
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
			Debug( LDAP_DEBUG_ANY,
				"new debug level from registry is: %d\n", slap_debug, 0, 0 );
		}

		newUrls = (char *) lutil_getRegParam(regService, "Urls");
		if (newUrls) {
		    if (urls)
			ch_free(urls);

		    urls = ch_strdup(newUrls);
		    Debug(LDAP_DEBUG_ANY, "new urls from registry: %s\n",
				urls, 0, 0);
		}

		newConfigFile = (char*)lutil_getRegParam( regService, "ConfigFile" );
		if ( newConfigFile != NULL ) {
			configfile = newConfigFile;
			Debug ( LDAP_DEBUG_ANY, "new config file from registry is: %s\n", configfile, 0, 0 );
		}

		newConfigDir = (char*)lutil_getRegParam( regService, "ConfigDir" );
		if ( newConfigDir != NULL ) {
			configdir = newConfigDir;
			Debug ( LDAP_DEBUG_ANY, "new config dir from registry is: %s\n", configdir, 0, 0 );
		}
	}
#endif

	while ( (i = getopt( argc, argv,
			     "c:d:f:F:h:n:o:s:tT:V"
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
			ber_str2bv( optarg, 0, 1, &scp->octet_str );
			
			/* This only parses out the rid at this point */
			slap_parse_sync_cookie( scp, NULL );

			if ( scp->rid == -1 ) {
				Debug( LDAP_DEBUG_ANY,
						"main: invalid cookie \"%s\"\n",
						optarg, 0, 0 );
				slap_sync_cookie_free( scp, 1 );
				goto destroy;
			}

			LDAP_STAILQ_FOREACH( scp_entry, &slap_sync_cookie, sc_next ) {
				if ( scp->rid == scp_entry->rid ) {
					Debug( LDAP_DEBUG_ANY,
						    "main: duplicated replica id in cookies\n",
							0, 0, 0 );
					slap_sync_cookie_free( scp, 1 );
					goto destroy;
				}
			}
			LDAP_STAILQ_INSERT_TAIL( &slap_sync_cookie, scp, sc_next );
			break;

		case 'd': {	/* set debug level and 'do not detach' flag */
			int	level = 0;

			no_detach = 1;
			if ( parse_debug_level( optarg, &level, &debug_unknowns ) ) {
				goto destroy;
			}
#ifdef LDAP_DEBUG
			slap_debug |= level;
#else
			if ( level != 0 )
				fputs( "must compile with LDAP_DEBUG for debugging\n",
				       stderr );
#endif
			} break;

		case 'f':	/* read config file */
			configfile = ch_strdup( optarg );
			break;

		case 'F':	/* use config dir */
			configdir = ch_strdup( optarg );
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
			if ( parse_debug_level( optarg, &ldap_syslog, &syslog_unknowns ) ) {
				goto destroy;
			}
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

	ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &slap_debug);
	ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &slap_debug);
	ldif_debug = slap_debug;

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

	Debug( LDAP_DEBUG_ANY, "%s", Versionstr, 0, 0 );

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

	rc = slap_init( serverMode, serverName );
	if ( rc ) {
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 18 );
		goto destroy;
	}

	if ( read_config( configfile, configdir ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 19 );

		if ( check & CHECK_CONFIG ) {
			fprintf( stderr, "config check failed\n" );
		}

		goto destroy;
	}

	if ( debug_unknowns ) {
		rc = parse_debug_unknowns( debug_unknowns, &slap_debug );
		ldap_charray_free( debug_unknowns );
		debug_unknowns = NULL;
		if ( rc )
			goto destroy;
	}
	if ( syslog_unknowns ) {
		rc = parse_debug_unknowns( syslog_unknowns, &ldap_syslog );
		ldap_charray_free( syslog_unknowns );
		syslog_unknowns = NULL;
		if ( rc )
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

	if ( glue_sub_attach( ) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "subordinate config error\n",
		    0, 0, 0 );

		goto destroy;
	}

	if ( slap_schema_check( ) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "schema prep error\n",
		    0, 0, 0 );

		goto destroy;
	}

#ifdef HAVE_TLS
	rc = ldap_pvt_tls_init();
	if( rc != 0) {
		Debug( LDAP_DEBUG_ANY,
		    "main: TLS init failed: %d\n",
		    0, 0, 0 );
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

		rc = ldap_pvt_tls_init_def_ctx( 1 );
		if( rc == 0 ) {
			ldap_pvt_tls_get_option( NULL, LDAP_OPT_X_TLS_CTX, &slap_tls_ctx );
			/* Restore previous ctx */
			ldap_pvt_tls_set_option( NULL, LDAP_OPT_X_TLS_CTX, def_ctx );
			load_extop( &slap_EXOP_START_TLS, 0, starttls_extop );
		} else if ( rc != LDAP_NOT_SUPPORTED ) {
			Debug( LDAP_DEBUG_ANY,
			    "main: TLS init def ctx failed: %d\n",
			    rc, 0, 0 );
			rc = 1;
			SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 20 );
			goto destroy;
		}
	}
#endif

#ifdef HAVE_CYRUS_SASL
	if( global_host == NULL ) {
		global_host = ldap_pvt_get_fqdn( NULL );
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
#ifdef SIGTRAP
	(void) SIGNAL( SIGTRAP, slap_sig_shutdown );
#endif
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

	if ( slapd_pid_file != NULL ) {
		FILE *fp = fopen( slapd_pid_file, "w" );

		if ( fp == NULL ) {
			int save_errno = errno;

			Debug( LDAP_DEBUG_ANY, "unable to open pid file "
				"\"%s\": %d (%s)\n",
				slapd_pid_file,
				save_errno, strerror( save_errno ) );

			free( slapd_pid_file );
			slapd_pid_file = NULL;

			rc = 1;
			goto destroy;
		}
		fprintf( fp, "%d\n", (int) getpid() );
		fclose( fp );
		slapd_pid_file_unlink = 1;
	}

	if ( slapd_args_file != NULL ) {
		FILE *fp = fopen( slapd_args_file, "w" );

		if ( fp == NULL ) {
			int save_errno = errno;

			Debug( LDAP_DEBUG_ANY, "unable to open args file "
				"\"%s\": %d (%s)\n",
				slapd_args_file,
				save_errno, strerror( save_errno ) );

			free( slapd_args_file );
			slapd_args_file = NULL;

			rc = 1;
			goto destroy;
		}

		for ( i = 0; i < g_argc; i++ ) {
			fprintf( fp, "%s ", g_argv[i] );
		}
		fprintf( fp, "\n" );
		fclose( fp );
		slapd_args_file_unlink = 1;
	}

	/*
	 * FIXME: moved here from slapd_daemon_task()
	 * because back-monitor db_open() needs it
	 */
	time( &starttime );

	if ( slap_startup( NULL ) != 0 ) {
		rc = 1;
		SERVICE_EXIT( ERROR_SERVICE_SPECIFIC_ERROR, 21 );
		goto shutdown;
	}

	Debug( LDAP_DEBUG_ANY, "slapd starting\n", 0, 0, 0 );

#ifdef HAVE_NT_EVENT_LOG
	if (is_NT_Service)
	lutil_LogStartedEvent( serverName, slap_debug, configfile ?
		configfile : SLAPD_DEFAULT_CONFIGFILE , urls );
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

	extops_kill();

stop:
#ifdef HAVE_NT_EVENT_LOG
	if (is_NT_Service)
	lutil_LogStoppedEvent( serverName );
#endif

	Debug( LDAP_DEBUG_ANY, "slapd stopped.\n", 0, 0, 0 );


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

	if ( slapd_pid_file_unlink ) {
		unlink( slapd_pid_file );
	}
	if ( slapd_args_file_unlink ) {
		unlink( slapd_args_file );
	}

	config_destroy();

	if ( configfile )
		ch_free( configfile );
	if ( configdir )
		ch_free( configdir );
	if ( urls )
		ch_free( urls );

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
