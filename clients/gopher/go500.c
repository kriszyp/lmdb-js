/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
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

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/syslog.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#include <ac/param.h>
#include <ac/setproctitle.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <ldap.h>
#include <disptmpl.h>

#include "ldap_defaults.h"

#define ldap_debug debug
#include "ldap_log.h"

#include "lutil.h"


int	debug;
int	dosyslog;
int ldap_syslog;
int ldap_syslog_level;
int	inetd;
int	dtblsize;

char	*ldaphost = NULL;
char	*base = NULL;
int	rdncount = GO500_RDNCOUNT;
char	*filterfile = FILTERFILE;
char	*templatefile = TEMPLATEFILE;

char	myhost[MAXHOSTNAMELEN];
int	myport;

static void usage	( char *name ) LDAP_GCCATTR((noreturn));
static int  set_socket	(int port);
static RETSIGTYPE wait4child(int sig);
static void do_queries	(int s)    LDAP_GCCATTR((noreturn));
static void do_error	(FILE *fp, char *s);
static void do_search	(LDAP *ld, FILE *fp, char *buf);
static void do_read	(LDAP *ld, FILE *fp, char *dn);

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-d debuglevel] [-f filterfile] [-t templatefile]\r\n\t[-a] [-l] [-p port] [-x ldaphost] [-b searchbase] [-c rdncount]\r\n", name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int			s, ns, rc;
	int			port = -1;
	int			i, pid;
	char			*myname;
	fd_set			readfds;
	struct hostent		*hp;
	struct sockaddr_in	from;
	socklen_t         	fromlen;

#if defined( LDAP_PROCTITLE ) && !defined( HAVE_SETPROCTITLE )
	/* for setproctitle */
	Argv = argv;
 	Argc = argc;
#endif

	while ( (i = getopt( argc, argv, "b:d:f:lp:c:t:x:I" )) != EOF ) {
		switch( i ) {
		case 'b':	/* searchbase */
			base = strdup( optarg );
			break;

		case 'd':	/* debug level */
			debug |= atoi( optarg );
			break;

		case 'f':	/* ldap filter file */
			filterfile = strdup( optarg );
			break;

		case 'l':	/* log via LOG_LOCAL3 */
			dosyslog = 1;
			break;

		case 'p':	/* port to listen to */
			port = atoi( optarg );
			break;

		case 'c':	/* number of DN components to show */
			rdncount = atoi( optarg );
			break;

		case 't':	/* ldap template file */
			templatefile = strdup( optarg );
			break;

		case 'x':	/* ldap server hostname */
			ldaphost = strdup( optarg );
			break;

		case 'I':	/* run from inetd */
			inetd = 1;
			break;

		default:
			usage( argv[0] );
		}
	}

#ifdef GO500_HOSTNAME
	strcpy( myhost, GO500_HOSTNAME );
#else
	if ( myhost[0] == '\0' && gethostname( myhost, sizeof(myhost) )
	    == -1 ) {
		perror( "gethostname" );
		exit( EXIT_FAILURE );
	}
#endif

#ifdef HAVE_SYSCONF
	dtblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	dtblsize = getdtablesize();
#else
	dtblsize = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if (dtblsize > FD_SETSIZE) {
		dtblsize = FD_SETSIZE;
	}
#endif	/* FD_SETSIZE*/

	/* detach if stderr is redirected or no debugging */
	if ( inetd == 0 )
		lutil_detach( debug && !isatty( 1 ), 1 );

	if ( (myname = strrchr( argv[0], '/' )) == NULL )
		myname = strdup( argv[0] );
	else
		myname = strdup( myname + 1 );

	if ( debug ) {
		ber_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
		ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

	if ( dosyslog ) {
#ifdef LOG_LOCAL3
		openlog( myname, OPENLOG_OPTIONS, LOG_LOCAL3 );
#elif LOG_DEBUG
		openlog( myname, OPENLOG_OPTIONS );
#endif
	}
	if ( dosyslog )
		syslog( LOG_INFO, "initializing" );

	/* set up the socket to listen on */
	if ( inetd == 0 ) {
		s = set_socket( port );

		/* arrange to reap children */
		(void) SIGNAL( SIGCHLD, wait4child );
	} else {
		myport = GO500_PORT;

		fromlen = sizeof(from);
		if ( getpeername( 0, (struct sockaddr *) &from, &fromlen )
		    == 0 ) {
			hp = gethostbyaddr( (char *) &(from.sin_addr),
			    sizeof(from.sin_addr), AF_INET );
			Debug( LDAP_DEBUG_ARGS, "connection from %s (%s)\n",
			    (hp == NULL) ? "unknown" : hp->h_name,
			    inet_ntoa( from.sin_addr ), 0 );

			if ( dosyslog ) {
				syslog( LOG_INFO, "connection from %s (%s)",
				    (hp == NULL) ? "unknown" : hp->h_name,
				    inet_ntoa( from.sin_addr ) );
			}

#ifdef LDAP_PROCTITLE
			setproctitle( "%s", hp == NULL ? inet_ntoa( from.sin_addr ) :
			    hp->h_name );
#endif
		}

		do_queries( 0 );

		exit( EXIT_SUCCESS );
	}

	for ( ;; ) {
		FD_ZERO( &readfds );
		FD_SET( s, &readfds );

		if ( (rc = select( dtblsize, &readfds, 0, 0 ,0 )) == -1 ) {
			if ( debug ) perror( "select" );
			continue;
		} else if ( rc == 0 ) {
			continue;
		}

		if ( ! FD_ISSET( s, &readfds ) )
			continue;

		fromlen = sizeof(from);
		if ( (ns = accept( s, (struct sockaddr *) &from, &fromlen ))
		    == -1 ) {
			if ( debug ) perror( "accept" );
			exit( EXIT_FAILURE );
		}

		hp = gethostbyaddr( (char *) &(from.sin_addr),
		    sizeof(from.sin_addr), AF_INET );

		if ( dosyslog ) {
			syslog( LOG_INFO, "TCP connection from %s (%s)",
			    (hp == NULL) ? "unknown" : hp->h_name,
			    inet_ntoa( from.sin_addr ) );
		}

		switch( pid = fork() ) {
		case 0:		/* child */
			tcp_close( s );
			do_queries( ns );
			break;

		case -1:	/* failed */
			perror( "fork" );
			break;

		default:	/* parent */
			tcp_close( ns );
			if ( debug )
				fprintf( stderr, "forked child %d\n", pid );
			break;
		}
	}
	/* NOT REACHED */
}

static int
set_socket( int port )
{
	int			s, one;
	struct sockaddr_in	addr;

	if ( port == -1 )
		port = GO500_PORT;
	myport = port;

	if ( (s = socket( AF_INET, SOCK_STREAM, 0 )) == -1 ) {
                perror( "socket" );
                exit( EXIT_FAILURE );
        }

#ifdef SO_REUSEADDR
        /* set option so clients can't keep us from coming back up */
		one = 1;
        if ( setsockopt( s, SOL_SOCKET, SO_REUSEADDR, (char *) &one,
	    sizeof(one) ) < 0 ) {
                perror( "setsockopt" );
                exit( EXIT_FAILURE );
        }
#endif
#ifdef SO_KEEPALIVE
		/* enable keep alives */
		one = 1;
        if ( setsockopt( s, SOL_SOCKET, SO_KEEPALIVE, (char *) &one,
	    sizeof(one) ) < 0 ) {
                perror( "setsockopt" );
                exit( EXIT_FAILURE );
        }
#endif

        /* bind to a name */
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons( port );
        if ( bind( s, (struct sockaddr *) &addr, sizeof(addr) ) ) {
                perror( "bind" );
                exit( EXIT_FAILURE );
        }

	/* listen for connections */
        if ( listen( s, 5 ) == -1 ) {
                perror( "listen" );
                exit( EXIT_FAILURE );
        }

        if ( debug ) printf("tcp socket allocated, bound, and listening\n");

	return( s );
}

static RETSIGTYPE
wait4child( int sig )
{
#ifndef HAVE_WAITPID
        WAITSTATUSTYPE     status;
#endif

        if ( debug ) printf( "parent: catching child status\n" );

#ifdef HAVE_WAITPID
	while (waitpid ((pid_t) -1, (int *) NULL, WAIT_FLAGS) > 0)
		;	/* NULL */
#else
	while ( wait4((pid_t) -1, &status, WAIT_FLAGS, 0 ) > 0 )
		;	/* NULL */
#endif

	(void) SIGNAL( SIGCHLD, wait4child );
}

static void
do_queries( int s )
{
	char		buf[1024], *query;
	int		len;
	FILE		*fp;
	int		rc;
	struct timeval	timeout;
	fd_set		readfds;
	LDAP		*ld;

	if ( (fp = fdopen( s, "a+")) == NULL ) {
		exit( EXIT_FAILURE );
	}

	timeout.tv_sec = GO500_TIMEOUT;
	timeout.tv_usec = 0;
	FD_ZERO( &readfds );
	FD_SET( fileno( fp ), &readfds );

	if ( (rc = select( dtblsize, &readfds, 0, 0, &timeout )) <= 0 )
		exit( EXIT_FAILURE );

	if ( fgets( buf, sizeof(buf), fp ) == NULL )
		exit( EXIT_FAILURE );

	len = strlen( buf );
	if ( debug ) {
		fprintf( stderr, "got %d bytes\n", len );
#ifdef LDAP_DEBUG
		ber_bprint( buf, len );
#endif
	}

	/* strip of \r \n */
	if ( buf[len - 1] == '\n' )
		buf[len - 1] = '\0';
	len--;
	if ( buf[len - 1] == '\r' )
		buf[len - 1] = '\0';
	len--;

	query = buf;

	/* strip off leading white space */
	while ( isspace( (unsigned char) *query )) {
		++query;
		--len;
	}

	rewind(fp);

	if ( *query == '~' || *query == '@' ) {
		ld = NULL;
	} else if ( (ld = ldap_init( ldaphost, 0 )) == NULL ) {
		fprintf(fp,
			"0An error occurred (explanation)\t@%d\t%s\t%d\r\n",
			LDAP_SERVER_DOWN, myhost, myport );
		fprintf( fp, ".\r\n" );
		rewind(fp);
		exit( EXIT_FAILURE );
	} else {
		int deref = GO500_DEREF;
		ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

		rc = ldap_simple_bind_s( ld, NULL, NULL );
		if ( rc != LDAP_SUCCESS ) {
			fprintf(fp,
			    "0An error occurred (explanation)\t@%d\t%s\t%d\r\n",
			    rc, myhost, myport );
			fprintf( fp, ".\r\n" );
			rewind(fp);
			exit( EXIT_FAILURE );
		}
	}

	switch ( *query ) {
	case '~':
		fprintf( fp, "The query you specified was not specific enough, causing a size limit\r\n" );
		fprintf( fp, "to be exceeded and the first several matches found to be returned.\r\n" );
		fprintf( fp, "If you did not find the match you were looking for, try issuing a more\r\n" );
		fprintf( fp, "specific query, for example one that contains both first and last name.\r\n" );
		fprintf( fp, ".\r\n" );
		break;

	case '=':
		do_read( ld, fp, ++query );
		break;

	case '@':
		do_error( fp, ++query );
		break;

	default:
		do_search( ld, fp, query );
		break;
	}

	fprintf( fp, ".\r\n" );
	rewind(fp);

	if ( ld != NULL) {
		ldap_unbind( ld );
	}

	exit( EXIT_FAILURE );
	/* NOT REACHED */
}

static void
do_error( FILE *fp, char *s )
{
	int	code;

	code = atoi( s );

	fprintf( fp, "An error occurred searching X.500.  The error code was %d\r\n", code );
	fprintf( fp, "The corresponding error is: %s\r\n", ldap_err2string( code ) );
	fprintf( fp, "No additional information is available\r\n" );
	fprintf( fp, ".\r\n" );
}

static void
do_search( LDAP *ld, FILE *fp, char *buf )
{
	char		*dn, *rdn;
	char		**title;
	int		rc, matches = 0;
	struct timeval	tv;
	LDAPFiltInfo	*fi;
	LDAPFiltDesc	*filtd;
	LDAPMessage	*e, *res;
	static char	*attrs[] = { "title", 0 };

#ifdef GO500_UFN
	if ( strchr( buf, ',' ) != NULL ) {
		ldap_ufn_setprefix( ld, base );
		tv.tv_sec = GO500_TIMEOUT;
		tv.tv_usec = 0;
		ldap_ufn_timeout( (void *) &tv );

		if ( (rc = ldap_ufn_search_s( ld, buf, attrs, 0, &res ))
		    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
			fprintf(fp,
			    "0An error occurred (explanation)\t@%d\t%s\t%d\r\n",
			    rc, myhost, myport );
			return;
		}

		matches = ldap_count_entries( ld, res );
	} else {
#endif
		if ( (filtd = ldap_init_getfilter( filterfile )) == NULL ) {
			fprintf( stderr, "Cannot open filter file (%s)\n",
			    filterfile );
			exit( EXIT_FAILURE );
		}

		tv.tv_sec = GO500_TIMEOUT;
		tv.tv_usec = 0;
		for ( fi = ldap_getfirstfilter( filtd, "go500", buf );
		    fi != NULL;
		    fi = ldap_getnextfilter( filtd ) )
		{
			if ( (rc = ldap_search_st( ld, base, LDAP_SCOPE_SUBTREE,
			    fi->lfi_filter, attrs, 0, &tv, &res ))
			    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
				fprintf(fp, "0An error occurred (explanation)\t@%d\t%s\t%d\r\n",
				    rc, myhost, myport );
				ldap_getfilter_free( filtd );
				return;
			}

			if ( (matches = ldap_count_entries( ld, res )) != 0 )
				break;
		}
		ldap_getfilter_free( filtd );
#ifdef GO500_UFN
	}
#endif

	if ( matches <= 0 ) {
		return;
	}

#ifdef GO500_SORT_ATTR
	ldap_sort_entries( ld, &res, GO500_SORT_ATTR, strcasecmp );
#endif

	for ( e = ldap_first_entry( ld, res ); e != NULL;
	    e = ldap_next_entry( ld, e ) ) {
		char	*s;

		dn = ldap_get_dn( ld, e );
		rdn = strdup( dn );
		if ( (s = strchr( rdn, ',' )) != NULL )
			*s = '\0';

		if ( (s = strchr( rdn, '=' )) == NULL )
			s = rdn;
		else
			++s;

		title = ldap_get_values( ld, e, "title" );

		if ( title != NULL ) {
			char	*p;

			for ( p = title[0]; *p; p++ ) {
				if ( *p == '/' )
					*p = '\\';
			}
		}

		fprintf( fp, "0%-20s    %s\t=%s\t%s\t%d\r\n", s,
		    title ? title[0] : "", dn, myhost, myport );

		if ( title != NULL )
			ldap_value_free( title );

		free( rdn );
		free( dn );
	}

	if ( ldap_result2error( ld, res, 1 ) == LDAP_SIZELIMIT_EXCEEDED ) {
		fprintf( fp, "0A size limit was exceeded (explanation)\t~\t%s\t%d\r\n",
		    myhost, myport );
	}
}

static int
entry2textwrite( void *fp, char *buf, ber_len_t len )
{
	return( fwrite( buf, len, 1, (FILE *)fp ) == 0 ? -1 : len );
}

static void
do_read( LDAP *ld, FILE *fp, char *dn )
{
	static struct ldap_disptmpl *tmpllist;

	ldap_init_templates( templatefile, &tmpllist );

	if ( ldap_entry2text_search( ld, dn, base, NULL, tmpllist, NULL, NULL,
	    entry2textwrite, (void *) fp, "\r\n", rdncount,
	    LDAP_DISP_OPT_DOSEARCHACTIONS ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_entry2text_search" );
		exit( EXIT_FAILURE );
	}

	if ( tmpllist != NULL ) {
		ldap_free_templates( tmpllist );
	}
}
