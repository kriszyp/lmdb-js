/*
 * Copyright (c) 1990-1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */
/*
 * Some code fragments to run from inetd stolen from the University
 * of Minnesota gopher distribution, which had this copyright on it:
 *
 * Part of the Internet Gopher program, copyright (C) 1991
 * University of Minnesota Microcomputer Workstation and Networks Center
 */

#include "portable.h"

#include <stdio.h>

#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#ifdef LDAP_PROCTITLE
#include <ac/setproctitle.h>
#endif

#include <quipu/commonarg.h>
#include <quipu/ds_error.h>

#include "lber.h"
#include "../../libraries/liblber/lber-int.h"	/* get struct sockbuf */
#include "ldap.h"
#include "common.h"
#include "lutil.h"		/* Get lutil_detach() */

#ifdef HAVE_TCPD
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* TCP_WRAPPERS */

static int	set_socket( int port, int udp );
static void	do_queries( int clientsock, int udp );
static RETSIGTYPE wait4child( int sig );
#ifdef LDAP_CONNECTIONLESS
static int	udp_init( int port, int createsocket );
#endif

#ifdef LDAP_DEBUG
int	ldap_debug;
#endif
int	version;
#ifdef LDAP_COMPAT
int	ldap_compat;
#endif
int	dosyslog;
int	do_tcp = 1;
#ifdef LDAP_CONNECTIONLESS
int	do_udp = 0;
#endif
int	idletime = DEFAULT_TIMEOUT;
int	referral_connection_timeout = DEFAULT_REFERRAL_TIMEOUT;
struct timeval	conn_start_tv;
#ifdef HAVE_KERBEROS
char	*krb_ldap_service = "ldapserver";
char	*krb_x500_service = "x500dsa";
char	*krb_x500_instance;
char	*krb_x500_nonce;
char	*kerberos_keyfile;
#endif

int	dtblsize;
int	RunFromInetd = 0;

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-d debuglvl] [-p port] [-l] [-c dsa] [-r referraltimeout]", name );
#ifdef LDAP_CONNECTIONLESS
	fprintf( stderr, " [ -U | -t timeout ]" );
#else
	fprintf( stderr, " [ -t timeout ]" );
#endif
	fprintf( stderr, " [-I]" );
#ifdef HAVE_KERBEROS
	fprintf( stderr, " [-i dsainstance]" );
#endif
	fprintf( stderr, "\n" );
}

int
main( int argc, char **argv )
{
	int			tcps, ns;
#ifdef LDAP_CONNECTIONLESS
	int			udps;
#endif
	int			myport = LDAP_PORT;
	int			no_detach = 0;
	int			i, pid, socktype;
	char			*myname;
	fd_set			readfds;
	struct hostent		*hp;
	struct sockaddr_in	from;
	socklen_t         	len;
	int			dsapargc;
	char			**dsapargv;
#ifdef LDAP_PROCTITLE
	char			title[80];
#endif

#ifdef VMS
	/* Pick up socket from inetd-type server on VMS */
	if ( (ns = socket_from_server( NULL )) > 0 )
		RunFromInetd = 1;
#else
        /* Socket from inetd is usually 0 */
        ns = 0;
#endif

	/* for dsap_init */
        if ( (dsapargv = (char **) malloc( 4 * sizeof(char *) )) == NULL ) {
                perror( "malloc" );
                exit( 1 );
        }
        dsapargv[0] = argv[0];
        dsapargv[1] = 0;
        dsapargv[2] = 0;
        dsapargv[3] = 0;
        dsapargc = 1;
#ifdef HAVE_KERBEROS
	kerberos_keyfile = "";
#endif

	/* process command line arguments */
	while ( (i = getopt( argc, argv, "d:lp:f:i:c:r:t:IuU" )) != EOF ) {
		switch ( i ) {
		case 'c':	/* specify dsa to contact */
			dsapargv[1] = "-call";
			dsapargv[2] = strdup( optarg );
			dsapargc = 3;
			break;

		case 'd':	/* set debug level and 'do not detach' flag */
			no_detach = 1;
#ifdef LDAP_DEBUG
			ldap_debug = atoi( optarg );
			if ( ldap_debug & LDAP_DEBUG_PACKETS )
				ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ldap_debug );
#else
			if ( atoi( optarg ) != 0 )
				fputs( "Not compiled with -DLDAP_DEBUG!\n", stderr );
#endif
			break;

		case 'l':	/* do syslogging */
			dosyslog = 1;
			break;

		case 'p':	/* specify port number */
			myport = atoi( optarg );
			break;

		case 'r':	/* timeout for referral connections */
			referral_connection_timeout = atoi( optarg );
			break;

		case 't':	/* timeout for idle connections */
			idletime = atoi( optarg );
			break;

#ifdef HAVE_KERBEROS
		case 'f':	/* kerberos key file */
			kerberos_keyfile = strdup( optarg );
			break;

		case 'i':	/* x500 dsa kerberos instance */
			if ( krb_x500_instance != NULL )
				free( krb_x500_instance );
			krb_x500_instance = strdup( optarg );
			break;
#endif

		case 'I':	/* Run from inetd */
			RunFromInetd = 1;
			break;

#ifdef LDAP_CONNECTIONLESS
		case 'U':	/* UDP only (no TCP) */
			do_tcp = 0;
			do_udp = 1;
			break;

#ifdef NOTYET
		case 'u':	/* allow UDP requests (CLDAP) */
			do_udp = 1;
			break;
#endif /* NOTYET */

#endif /* LDAP_CONNECTIONLESS */

		default:
			usage( argv[0] );
			exit( 1 );
		}
	}

	if ( optind < argc ) {
		usage( argv[ 0 ] );
		exit( 1 );
	}

#ifdef LDAP_CONNECTIONLESS
	if ( do_udp && !do_tcp && idletime != DEFAULT_TIMEOUT ) {
		usage( argv[ 0 ] );
		exit( 1 );
	}
#endif

	Debug( LDAP_DEBUG_TRACE, "%s", Versionstr, 0, 0 );

#ifdef HAVE_SYSCONF
	dtblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	dtblsize = getdtablesize();
#else
	dtblsize = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if( dtblsize > FD_SETSIZE ) {
		dtblsize = FD_SETSIZE;
	}
#endif /* FD_SETSIZE */

#if defined(LDAP_PROCTITLE) && !defined( HAVE_SETPROCTITLE )
	/* for setproctitle */
	Argv = argv;
	Argc = argc;
#endif

	if ( (myname = strrchr( argv[0], '/' )) == NULL )
		myname = strdup( argv[0] );
	else
		myname = strdup( myname + 1 );

	/* 
	 * detach from the terminal if stderr is redirected or no
	 * debugging is wanted, and then arrange to reap children
	 * that have exited
	 */
	if (!RunFromInetd) {
#ifdef LDAP_PROCTITLE
		setproctitle( "initializing" );
#endif
#ifndef VMS
		lutil_detach( no_detach, 1 );
#endif
		(void) SIGNAL( SIGCHLD, wait4child );
		(void) SIGNAL( SIGINT, log_and_exit );
	}

	/* 
	 * set up syslogging (if desired)
	 */
	if ( dosyslog ) {
#ifdef LOG_LOCAL4
		openlog( myname, OPENLOG_OPTIONS, LOG_LOCAL4 );
#else
		openlog( myname, OPENLOG_OPTIONS );
#endif
	}

	/* 
	 * load the syntax handlers, oidtables, and initialize some stuff,
	 * then start listening
	 */

	(void) quipu_syntaxes();
#ifdef LDAP_USE_PP
	(void) pp_quipu_init( argv[0] );
#endif
#if ISODEPACKAGE == IC
#if ICRELEASE > 2
	dsa_operation_syntaxes();
#endif
#endif
	(void) dsap_init( &dsapargc, &dsapargv );
	(void) get_syntaxes();
	if (RunFromInetd) {
		len = sizeof( socktype );
		getsockopt( ns, SOL_SOCKET, SO_TYPE, (char *)&socktype, &len );
		if ( socktype == SOCK_DGRAM ) {
#ifdef LDAP_CONNECTIONLESS
			Debug( LDAP_DEBUG_ARGS,
			    "CLDAP request from unknown (%s)\n",
			    inet_ntoa( from.sin_addr ), 0, 0 );
			conn_start_tv.tv_sec = 0;
			udp_init( 0, 0 );
			do_queries( ns, 1 );
#else /* LDAP_CONNECTIONLESS */
			Debug( LDAP_DEBUG_ARGS,
			    "Compile with -DLDAP_CONNECTIONLESS for UDP support\n",0,0,0 );
#endif /* LDAP_CONNECTIONLESS */
			exit( 0 );
		}

		len = sizeof(from);
		if ( getpeername( ns, (struct sockaddr *) &from, &len )
		    == 0 ) {
			hp = gethostbyaddr( (char *) &(from.sin_addr.s_addr),
			sizeof(from.sin_addr.s_addr), AF_INET );
			Debug( LDAP_DEBUG_ARGS, "connection from %s (%s)\n",
			    (hp == NULL) ? "unknown" : hp->h_name,
			    inet_ntoa( from.sin_addr ), 0 );

			if ( dosyslog ) {
				syslog( LOG_INFO, "connection from %s (%s)",
				    (hp == NULL) ? "unknown" : hp->h_name,
				    inet_ntoa( from.sin_addr ) );
			}

#ifdef LDAP_PROCTITLE
			sprintf( title, "%s %d\n", hp == NULL ?
			    inet_ntoa( from.sin_addr ) : hp->h_name, myport );
			setproctitle( title );
#endif
		}
		gettimeofday( &conn_start_tv, (struct timezone *) NULL );
		do_queries( ns, 0 );

		exit( 0 );
	}

	if ( do_tcp )
	    tcps = set_socket( myport, 0 );

#ifdef LDAP_CONNECTIONLESS
	if ( do_udp )
		udps = udp_init( myport, 1 );
#endif

	/*
	 * loop, wait for a connection, then fork off a child to handle it
	 * if we are doing CLDAP as well, handle those requests on the fly
	 */

#ifdef LDAP_PROCTITLE
#ifdef LDAP_CONNECTIONLESS
        sprintf( title, "listening %s/%s %d", do_tcp ? "tcp" : "",
            do_udp ? "udp" : "", myport );
#else
        sprintf( title, "listening %s %d", do_tcp ? "tcp" : "", myport );
#endif
	setproctitle( title );
#endif

	for ( ;; ) {
		FD_ZERO( &readfds );
		if ( do_tcp )
			FD_SET( tcps, &readfds );
#ifdef LDAP_CONNECTIONLESS
		if ( do_udp )
			FD_SET( udps, &readfds );
#endif

		if ( select( dtblsize, &readfds, 0, 0, 0 ) < 1 ) {
#ifdef LDAP_DEBUG
			if ( ldap_debug ) perror( "main select" );
#endif
			continue;
		}

#ifdef LDAP_CONNECTIONLESS
		if ( do_udp && FD_ISSET( udps, &readfds ) ) {
			do_queries( udps, 1 );
		}
#endif

		if ( !do_tcp || ! FD_ISSET( tcps, &readfds ) ) {
			continue;
		}

		len = sizeof(from);
		if ( (ns = accept( tcps, (struct sockaddr *) &from, &len ))
		    == -1 ) {
#ifdef LDAP_DEBUG
			if ( ldap_debug ) perror( "accept" );
#endif
			continue;
		}

		hp = gethostbyaddr( (char *) &(from.sin_addr.s_addr),
		    sizeof(from.sin_addr.s_addr), AF_INET );

#ifdef HAVE_TCPD
		if ( !hosts_ctl("ldapd", (hp == NULL) ? "unknown" : hp->h_name,
			inet_ntoa( from.sin_addr ), STRING_UNKNOWN ) {

			Debug( LDAP_DEBUG_ARGS, "connection from %s (%s) denied.\n",
		   		(hp == NULL) ? "unknown" : hp->h_name,
		   		inet_ntoa( from.sin_addr ), 0 );

			if ( dosyslog ) {
				syslog( LOG_NOTICE, "connection from %s (%s) denied.",
				    (hp == NULL) ? "unknown" : hp->h_name,
				    inet_ntoa( from.sin_addr ) );
			}

			tcp_close(ns);
			continue;
		}
#endif /* TCP_WRAPPERS */

		Debug( LDAP_DEBUG_ARGS, "connection from %s (%s)\n",
		    (hp == NULL) ? "unknown" : hp->h_name,
		    inet_ntoa( from.sin_addr ), 0 );


		if ( dosyslog ) {
			syslog( LOG_INFO, "connection from %s (%s)",
			    (hp == NULL) ? "unknown" : hp->h_name,
			    inet_ntoa( from.sin_addr ) );
		}

#ifdef VMS
		/* This is for debug on terminal on VMS */
		tcp_close( tcps );
#ifdef LDAP_PROCTITLE
		setproctitle( hp == NULL ? inet_ntoa( from.sin_addr ) :
		    hp->h_name );
#endif
		gettimeofday( &conn_start_tv, (struct timezone *) NULL );
		(void) SIGNAL( SIGPIPE, log_and_exit );

		do_queries( ns, 0 );
		/* NOT REACHED */
#endif

		switch( pid = fork() ) {
		case 0:         /* child */
			tcp_close( tcps );
#ifdef LDAP_PROCTITLE
                        sprintf( title, "%s (%d)\n", hp == NULL ?
				inet_ntoa( from.sin_addr ) : hp->h_name,
				myport );
			setproctitle( title );
#endif
			gettimeofday( &conn_start_tv, (struct timezone *) NULL );
			(void) SIGNAL( SIGPIPE, log_and_exit );

			do_queries( ns, 0 );
			break;

		case -1:        /* failed */
#ifdef LDAP_DEBUG
			if ( ldap_debug ) perror( "fork" );
#endif
			tcp_close( ns );
			syslog( LOG_ERR, "fork failed %m" );
			/* let things cool off */
			sleep( 15 );
			break;

		default:        /* parent */
			tcp_close( ns );
			Debug( LDAP_DEBUG_TRACE, "forked child %d\n", pid, 0,
			    0 );
			break;
		}
	}
	/* NOT REACHED */
}

static void
do_queries(
    int	clientsock,
    int	udp		/* is this a UDP (CLDAP) request? */
)
{
	fd_set		readfds;
	int		rc;
	struct timeval	timeout;
	Sockbuf		sb;
#ifdef LDAP_CONNECTIONLESS
	struct sockaddr	saddr, faddr;
	struct sockaddr *saddrlist[ 1 ];
#endif /* LDAP_CONNECTIONLESS */

	Debug( LDAP_DEBUG_TRACE, "do_queries%s\n",
	    udp ? " udp" : "", 0, 0 );

	/*
	 * Loop, wait for a request from the client or a response from
	 * a dsa, then handle it.  Dsap_ad is always a connection to the
	 * "default" dsa.  Other connections can be made as a result of
	 * a referral being chased down.  These association descriptors
	 * are kept track of with the message that caused the referral.
	 * The set_dsa_fds() routine traverses the list of outstanding
	 * messages, setting the appropriate bits in readfds.
	 */

	if ( !udp ) {
		conn_init();
	}

   	ber_pvt_sb_init( &sb );
   	ber_pvt_sb_set_desc( &sb, clientsock );
	ber_pvt_sb_set_io( &sb, (udp) ? &ber_pvt_sb_io_udp :
					&ber_pvt_sb_io_tcp, NULL );
	timeout.tv_sec = idletime;
	timeout.tv_usec = 0;
	for ( ;; ) {
		struct conn		*dsaconn;

		FD_ZERO( &readfds );
		FD_SET( clientsock, &readfds );
		conn_setfds( &readfds );

#ifdef LDAP_DEBUG
		if ( ldap_debug & LDAP_DEBUG_CONNS ) {
			int i;
			Debug( LDAP_DEBUG_CONNS, "FDLIST:", 0, 0, 0 );
			for ( i = 0; i < dtblsize; i++ ) {
				if ( FD_ISSET( i, &readfds ) ) {
					Debug( LDAP_DEBUG_CONNS, " %d", i, 0,
					    0);
				}
			}
			Debug( LDAP_DEBUG_CONNS, "\n", 0, 0, 0 );
		}
#endif

		/* 
		 * hack - because of lber buffering, there might be stuff
		 * already waiting for us on the client sock.
		 */

		if ( ! ber_pvt_sb_data_ready( &sb ) ) {
			if ( (rc = select( dtblsize, &readfds, 0, 0,
			    udp ? 0 : &timeout )) < 1 ) {
#ifdef LDAP_DEBUG
				if ( ldap_debug ) perror( "do_queries select" );
#endif
				if ( rc == 0 )
					log_and_exit( 0 ); /* idle timeout */

				Debug( LDAP_DEBUG_ANY, "select returns %d!\n",
				    rc, 0, 0 );

				/* client gone away - we can too */
				if ( isclosed( clientsock ) )
					log_and_exit( 0 );

				/*
				 * check if a dsa conn has gone away -
				 * mark it bad if so
				 */
				conn_badfds();

				continue;
			}
		}

		if ( ber_pvt_sb_data_ready( &sb ) ||
		    FD_ISSET( clientsock, &readfds ) ) {
			client_request( &sb, conns, udp );
		} else {
			if ( (dsaconn = conn_getfd( &readfds )) == NULL ) {
				Debug( LDAP_DEBUG_ANY, "No DSA activity!\n",
				    0, 0, 0 );
				continue;
			}

			dsa_response( dsaconn, &sb );
		}
	}
	/* NOT REACHED */
}

static int
set_socket(
    int	port,
    int	udp	/* UDP port? */
)
{
	int			s, i;
	struct sockaddr_in	addr;

	if ( (s = socket( AF_INET, udp ? SOCK_DGRAM:SOCK_STREAM, 0 )) == -1 ) {
                perror( "socket" );
                exit( 1 );
        }

#ifdef SO_REUSEADDR
        /* set option so clients can't keep us from coming back up */
		i = 1;
        if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (void *) &i, sizeof(i) )
		    < 0 )
		{
                perror( "setsockopt" );
                exit( 1 );
        }
#endif
#ifdef SO_KEEPALIVE
        /* enable keep alives */
		i = 1;
        if ( setsockopt( s, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i) )
		    < 0 )
		{
                perror( "setsockopt" );
                exit( 1 );
        }
#endif

        /* bind to a name */
	(void)memset( (void *)&addr, '\0', sizeof( addr ));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons( port );
        if ( bind( s, (struct sockaddr *) &addr, sizeof(addr) ) ) {
                perror( "bind" );
                exit( 1 );
        }

	if ( !udp ) {
		/* listen for connections */
		if ( listen( s, 5 ) == -1 ) {
			perror( "listen" );
			exit( 1 );
		}
	}
 
	Debug( LDAP_DEBUG_TRACE, "listening on %s port %d\n",
		udp ? "udp" : "tcp", port, 0 );

	return( s );
}

static RETSIGTYPE
wait4child( int sig )
{
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE     status;
#endif

	Debug( LDAP_DEBUG_TRACE, "parent: catching child status\n", 0, 0, 0 );

#ifdef HAVE_WAITPID
	while( waitpid( (pid_t) -1, (int *) NULL, WAIT_FLAGS ) > 0 )
		;       /* NULL */
#else
	while ( wait4( (pid_t) -1, &status, WAIT_FLAGS, 0 ) > 0 )
		;       /* NULL */
#endif

	(void) SIGNAL( SIGCHLD, wait4child );
}


RETSIGTYPE
log_and_exit( int exitcode )
{
	struct timeval	tv;

	if ( dosyslog ) {
		if ( conn_start_tv.tv_sec == 0 ) {
			syslog( LOG_INFO, "UDP exit(%d)", exitcode );
		} else {
			gettimeofday( &tv, (struct timezone *)NULL );
			syslog( LOG_INFO, "TCP closed %d seconds,  exit(%d)",
			    tv.tv_sec - conn_start_tv.tv_sec, exitcode );
		}
	}

	exit( exitcode );
}


#ifdef LDAP_CONNECTIONLESS
static int
udp_init(
    int	port,
    int	createsocket
)
{
	int	s, bound;
	char	*matched;

	if ( createsocket )
		s = set_socket( port, 1 );

	conn_init();
	conns->c_dn = strdup("");
	conns->c_cred = strdup("");
	conns->c_credlen = 0;
	conns->c_method = LDAP_AUTH_SIMPLE;

       if ( dsa_address == NULL || (conns->c_paddr = str2paddr( dsa_address ))
            == NULLPA ) {
                fprintf(stderr, "Bad DSA address (%s)\n", dsa_address ?
                    dsa_address : "NULL" );
                exit( 1 );
        } else {
                conns->c_paddr = psap_cpy(conns->c_paddr);
	}

        if ( do_bind_real(conns, &bound, &matched) != LDAP_SUCCESS) {
                fprintf(stderr, "Cannot bind to directory\n");
                exit( 1 );
        }
        if ( matched != NULL )
                free( matched );

	return( createsocket ? s : 0 );
}
#endif
