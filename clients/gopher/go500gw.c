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

#define ldap_debug debug
#include "ldap_log.h"

#include "lutil.h"


#include "ldap_defaults.h"

int	debug;
int ldap_syslog;
int ldap_syslog_level;
int	dosyslog;
int	inetd;
int	dtblsize;

char		*ldaphost = NULL;
int		ldapport = 0;
int		searchaliases = 1;
char		*helpfile = GO500GW_HELPFILE;
char		*filterfile = FILTERFILE;
char		*templatefile = TEMPLATEFILE;
char		*friendlyfile = FRIENDLYFILE;
int		rdncount = GO500GW_RDNCOUNT;

static void usage	( char *name ) LDAP_GCCATTR((noreturn));
static int  set_socket	(int port);
static RETSIGTYPE wait4child(int sig);
static void do_queries	(int s)    LDAP_GCCATTR((noreturn));
static char *pick_oc	( char **oclist );
static int  isnonleaf	( LDAP *ld, char **oclist, char *dn );
static void do_menu	(LDAP *ld, FILE *fp, char *dn);
static void do_list	(LDAP *ld, FILE *fp, char *dn);
static int  isoc	( char **ocl, char *oc );
static int  make_scope	( LDAP *ld, char *dn );
static void do_search	(LDAP *ld, FILE *fp, char *query);
static int  entry2textwrite( void *fp, char *buf, ber_len_t len );
static void do_read	(LDAP *ld, FILE *fp, char *dn);
static void do_help	(FILE *op);
static void do_sizelimit(FILE *fp, char type);
static void do_error	(FILE *fp, char *s);

char	myhost[MAXHOSTNAMELEN];
int	myport = GO500GW_PORT;

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-d debuglevel] [-I] [-p port] [-P ldapport] [-l]\r\n\t[-x ldaphost] [-a] [-h helpfile] [-f filterfile] [-t templatefile] [-c rdncount]\r\n", name );
	exit( EXIT_FAILURE );
}

int
main (int  argc, char **argv )
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

	while ( (i = getopt( argc, argv, "P:ad:f:h:lp:t:x:Ic:" )) != EOF ) {
		switch( i ) {
		case 'a':	/* search aliases */
			searchaliases = 0;
			break;

		case 'd':	/* debugging level */
			debug |= atoi( optarg );
			break;

		case 'f':	/* ldap filter file */
			filterfile = strdup( optarg );
			break;

		case 'h':	/* gopher help file */
			helpfile = strdup( optarg );
			break;

		case 'l':	/* log to LOG_LOCAL3 */
			dosyslog = 1;
			break;

		case 'p':	/* port to listen on */
			port = atoi( optarg );
			break;

		case 'P':	/* port to connect to ldap server */
			ldapport = atoi( optarg );
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

		case 'c':	/* count of DN components to show */
			rdncount = atoi( optarg );
			break;

		default:
			usage( argv[0] );
		}
	}

#ifdef HAVE_SYSCONF
	dtblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	dtblsize = getdtablesize();
#else
	dtblsize = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if ( dtblsize > FD_SETSIZE ) {
		dtblsize = FD_SETSIZE;
	}
#endif	/* FD_SETSIZE*/



#ifdef GO500GW_HOSTNAME
	strcpy( myhost, GO500GW_HOSTNAME );
#else
	if ( myhost[0] == '\0' && gethostname( myhost, sizeof(myhost) )
	    == -1 ) {
		perror( "gethostname" );
		exit( EXIT_FAILURE );
	}
#endif

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
	}

	if ( inetd ) {
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

		tcp_close( 0 );

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
		port = GO500GW_PORT;
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

        if ( debug )
		printf( "go500gw listening on port %d\n", port );

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
	while (wait4( (pid_t) -1, &status, WAIT_FLAGS, 0 ) > 0 )
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
	int		deref;
	struct timeval	timeout;
	fd_set		readfds;
	LDAP		*ld;

	if ( (fp = fdopen( s, "a+")) == NULL ) {
		perror( "fdopen" );
		exit( EXIT_FAILURE );
	}

	timeout.tv_sec = GO500GW_TIMEOUT;
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

	if ( *query == 'H' || *query == 'L' || *query == 'E' ) {
		switch ( *query++ ) {
		case 'H':	/* help file */
			do_help( fp );
			break;

		case 'L':	/* size limit explanation */
			do_sizelimit( fp, *query );
			break;

		case 'E':	/* error explanation */
			do_error( fp, query );
			break;
		}

		fprintf( fp, ".\r\n" );
		rewind(fp);

		exit( EXIT_SUCCESS );
		/* NOT REACHED */
	}

	if ( (ld = ldap_init( ldaphost, ldapport )) == NULL ) {
		if ( debug ) perror( "ldap_init" );
		fprintf(fp, "0An error occurred (explanation)\tE%d\t%s\t%d\r\n",
		    LDAP_SERVER_DOWN, myhost, myport );
		fprintf( fp, ".\r\n" );
		rewind(fp);
		exit( EXIT_FAILURE );
	}

	deref = LDAP_DEREF_ALWAYS;
	if ( !searchaliases )
		deref = LDAP_DEREF_FINDING;

	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( (rc = ldap_simple_bind_s( ld, NULL, NULL ))
	    != LDAP_SUCCESS ) {
		if ( debug ) ldap_perror( ld, "ldap_simple_bind_s" );
		fprintf(fp, "0An error occurred (explanation)\tE%d\t%s\t%d\r\n",
		    rc, myhost, myport );
		fprintf( fp, ".\r\n" );
		rewind(fp);
		exit( EXIT_FAILURE );
	}

	switch ( *query++ ) {
	case 'R':	/* read an entry */
		do_read( ld, fp, query );
		break;

	case 'S':	/* search */
		do_search( ld, fp, query );
		break;

	case 'M':	/* X.500 menu */
		do_menu( ld, fp, query );
		break;

	default:
		do_menu( ld, fp, "" );
		break;
	}

	fprintf( fp, ".\r\n" );
	rewind(fp);

	exit( EXIT_SUCCESS );
	/* NOT REACHED */
}

static char *
pick_oc( char **oclist )
{
	int	i;

	if ( oclist == NULL )
		return( "unknown" );

	for ( i = 0; oclist[i] != NULL; i++ ) {
		if ( strcasecmp( oclist[i], "top" ) != 0 &&
		    strcasecmp( oclist[i], "quipuObject" ) != 0 &&
		    strcasecmp( oclist[i], "quipuNonLeafObject" ) != 0 )
			return( oclist[i] );
	}

	return( "unknown" );
}

static int
isnonleaf( LDAP *ld, char **oclist, char *dn )
{
	int	i, quipuobject = 0;

	if ( oclist == NULL )
		return( 0 );

	for ( i = 0; oclist[i] != NULL; i++ ) {
		if ( strcasecmp( oclist[i], "quipuObject" ) == 0 )
			quipuobject = 1;
		if ( strcasecmp( oclist[i], "quipuNonLeafObject" ) == 0 ||
		    strcasecmp( oclist[i], "externalNonLeafObject" ) == 0 )
			return( 1 );
	}

	/*
	 * not a quipu thang - no easy way to tell leaves from nonleaves
	 * except by trying to search or list.  ldap only lets us search.
	 */

	/* expensive - just guess for now */
	return( quipuobject ? 0 : 1 );

#ifdef notdef
	if ( !quipuobject ) {
		int		rc, numentries;
		struct timeval	timeout;
		LDAPMessage	*res = NULL;
		static char	*attrs[] = { "objectClass", 0 };
		int sizelimit = 1;

		timeout.tv_sec = GO500GW_TIMEOUT;
		timeout.tv_usec = 0;
		ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
		if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_ONELEVEL,
		    NULL, attrs, 0, &timeout, &res ))
		    == LDAP_SUCCESS || rc == LDAP_SIZELIMIT_EXCEEDED ) {
			sizelimit = LDAP_NO_LIMIT;
			ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);

			numentries = ldap_count_entries( ld, res );
			if ( res != NULL )
				ldap_msgfree( res );
			return( numentries == 1 ? 1 : 0 );
		}
	}

	return( 0 );
#endif
}

static void
do_menu( LDAP *ld, FILE *fp, char *dn )
{
	char		**s;
	char		*rdn = NULL;
	LDAPFriendlyMap	*fm = NULL;

	if ( strcmp( dn, "" ) != 0 ) {
		s = ldap_explode_dn( dn, 1 );

		if ( s[1] == NULL )
			rdn = ldap_friendly_name( friendlyfile, s[0], &fm );
		else
			rdn = s[0];
		fprintf( fp, "0Read %s entry\tR%s\t%s\t%d\r\n", rdn ? rdn: s[0],
		    dn, myhost, myport );

		ldap_value_free( s );
	} else {
		fprintf( fp, "0About the Gopher to X.500 Gateway\tH\t%s\t%d\r\n",
		    myhost, myport );
	}

	fprintf( fp, "7Search %s\tS%s\t%s\t%d\r\n", rdn ? rdn : "root", dn,
	    myhost, myport );

	do_list( ld, fp, dn );

	ldap_free_friendlymap( &fm );
}

static void
do_list( LDAP *ld, FILE *fp, char *dn )
{
	int		rc;
	LDAPMessage	*e, *res;
	struct timeval	timeout;
	LDAPFriendlyMap	*fm = NULL;
	static char	*attrs[] = { "objectClass", 0 };
	int deref = LDAP_DEREF_FINDING;

	timeout.tv_sec = GO500GW_TIMEOUT;
	timeout.tv_usec = 0;

	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( (rc = ldap_search_st( ld, dn, LDAP_SCOPE_ONELEVEL,
	    "(!(objectClass=dSA))", attrs, 0, &timeout, &res )) != LDAP_SUCCESS
	    && rc != LDAP_SIZELIMIT_EXCEEDED ) {
		fprintf(fp, "0An error occurred (explanation)\tE%d\t%s\t%d\r\n",
		    rc, myhost, myport );
		return;
	}

	deref = LDAP_DEREF_ALWAYS;
	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( ldap_count_entries( ld, res ) < 1 ) {
		return;
	}

#ifdef GO500GW_SORT_ATTR
	ldap_sort_entries( ld, &res, GO500GW_SORT_ATTR, strcasecmp );
#endif

	fm = NULL;
	for ( e = ldap_first_entry( ld, res ); e != NULL;
	    e = ldap_next_entry( ld, e ) ) {
		char	**s, **oc;
		char	*rdn, *doc;

		dn = ldap_get_dn( ld, e );
		s = ldap_explode_dn( dn, 1 );
		oc = ldap_get_values( ld, e, "objectClass" );

		doc = pick_oc( oc );
		if ( strcasecmp( doc, "country" ) == 0 ) {
			rdn = ldap_friendly_name( friendlyfile, s[0], &fm );
		} else {
			rdn = s[0];
		}
		if ( rdn == NULL ) {
			rdn = s[0];
		}

		if ( strncasecmp( rdn, "{ASN}", 5 ) != 0 ) {
			if ( isnonleaf( ld, oc, dn ) ) {
				fprintf( fp, "1%s (%s)\tM%s\t%s\t%d\r\n", rdn,
				    doc, dn, myhost, myport );
			} else {
				fprintf( fp, "0%s (%s)\tR%s\t%s\t%d\r\n", rdn,
				    doc, dn, myhost, myport );
			}
		}

		free( dn );
		ldap_value_free( s );
		ldap_value_free( oc );
	}
	ldap_free_friendlymap( &fm );

	if ( ldap_result2error( ld, res, 1 ) == LDAP_SIZELIMIT_EXCEEDED ) {
		fprintf( fp, "0A size limit was exceeded (explanation)\tLL\t%s\t%d\r\n",
		    myhost, myport );
	}
}

static int
isoc( char **ocl, char *oc )
{
	int	i;

	for ( i = 0; ocl[i] != NULL; i++ ) {
		if ( strcasecmp( ocl[i], oc ) == 0 )
			return( 1 );
	}

	return( 0 );
}

static int
make_scope( LDAP *ld, char *dn )
{
	int		scope;
	char		**oc;
	LDAPMessage	*res;
	struct timeval	timeout;
	static char	*attrs[] = { "objectClass", 0 };

	if ( strcmp( dn, "" ) == 0 )
		return( LDAP_SCOPE_ONELEVEL );

	timeout.tv_sec = GO500GW_TIMEOUT;
	timeout.tv_usec = 0;
	if ( ldap_search_st( ld, dn, LDAP_SCOPE_BASE, NULL,
	    attrs, 0, &timeout, &res ) != LDAP_SUCCESS ) {
		return( -1 );
	}

	oc = ldap_get_values( ld, ldap_first_entry( ld, res ), "objectClass" );

	if ( isoc( oc, "organization" ) || isoc( oc, "organizationalUnit" ) )
		scope = LDAP_SCOPE_SUBTREE;
	else
		scope = LDAP_SCOPE_ONELEVEL;

	ldap_value_free( oc );
	ldap_msgfree( res );

	return( scope );
}

static void
do_search( LDAP *ld, FILE *fp, char *query )
{
	int deref;
	int		scope;
	char		*base, *filter;
	char		*filtertype;
	int		count, rc;
	struct timeval	timeout;
	LDAPFiltInfo	*fi;
	LDAPMessage	*e, *res;
	LDAPFiltDesc	*filtd;
	static char	*attrs[] = { "objectClass", 0 };

	if ( (filter = strchr( query, '\t' )) == NULL ) {
		fprintf( fp, "3Missing filter!\r\n" );
		exit( EXIT_FAILURE );
	}
	*filter++ = '\0';
	base = query;

#ifdef GO500GW_UFN
	if ( strchr( filter, ',' ) != NULL ) {
		ldap_ufn_setprefix( ld, base );
		timeout.tv_sec = GO500GW_TIMEOUT;
		timeout.tv_usec = 0;
		ldap_ufn_timeout( (void *) &timeout );

		deref = LDAP_DEREF_FINDING;
		ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

		if ( (rc = ldap_ufn_search_s( ld, filter, attrs, 0, &res ))
		    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
			fprintf(fp,
			    "0An error occurred (explanation)\t@%d\t%s\t%d\r\n",
			    rc, myhost, myport );
			return;
		}

		count = ldap_count_entries( ld, res );
	} else {
#endif
		if ( (scope = make_scope( ld, base )) == -1 ) {
			fprintf( fp, "3Bad scope\r\n" );
			exit( EXIT_FAILURE );
		}

		filtertype = (scope == LDAP_SCOPE_ONELEVEL ?
		    "go500gw onelevel" : "go500gw subtree");
		deref = (scope == LDAP_SCOPE_ONELEVEL ?
		    LDAP_DEREF_FINDING : LDAP_DEREF_ALWAYS);
		ldap_set_option(ld, LDAP_OPT_DEREF, &deref);
		timeout.tv_sec = GO500GW_TIMEOUT;
		timeout.tv_usec = 0;

		if ( (filtd = ldap_init_getfilter( filterfile )) == NULL ) {
			fprintf( stderr, "Cannot open filter file (%s)\n",
			    filterfile );
			exit( EXIT_FAILURE );
		}

		count = 0;
		res = NULL;
		for ( fi = ldap_getfirstfilter( filtd, filtertype, filter );
		    fi != NULL; fi = ldap_getnextfilter( filtd ) )
		{
			if ( (rc = ldap_search_st( ld, base, scope,
			    fi->lfi_filter, attrs, 0, &timeout, &res ))
			    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
				fprintf(fp, "0An error occurred (explanation)\tE%d\t%s\t%d\r\n",
				    rc, myhost, myport );
				return;
			}
			if ( (count = ldap_count_entries( ld, res )) != 0 )
				break;
		}
		deref = LDAP_DEREF_ALWAYS;
		ldap_set_option(ld, LDAP_OPT_DEREF, &deref);
		ldap_getfilter_free( filtd );
#ifdef GO500GW_UFN
	}
#endif

	if ( count == 0 ) {
		return;
	}

	if ( count == 1 ) {
		char	*dn, **oc;

		e = ldap_first_entry( ld, res );
		oc = ldap_get_values( ld, e, "objectClass" );
		dn = ldap_get_dn( ld, e );

		if ( isnonleaf( ld, oc, dn ) ) {
			do_menu( ld, fp, dn );

			free( dn );
			return;
		}

		free( dn );
		ldap_value_free( oc );
	}

#ifdef GO500GW_SORT_ATTR
	ldap_sort_entries( ld, &res, GO500GW_SORT_ATTR, strcasecmp );
#endif

	for ( e = ldap_first_entry( ld, res ); e != NULL;
	    e = ldap_next_entry( ld, e ) ) {
		char	**s, **oc;
		char	*dn;

		dn = ldap_get_dn( ld, e );
		s = ldap_explode_dn( dn, 1 );
		oc = ldap_get_values( ld, e, "objectClass" );

		if ( isnonleaf( ld, oc, dn ) )
			fprintf( fp, "1%s (%s)\tM%s\t%s\t%d\r\n", s[0],
			    pick_oc( oc ), dn, myhost, myport );
		else
			fprintf( fp, "0%s (%s)\tR%s\t%s\t%d\r\n", s[0],
			    pick_oc( oc ), dn, myhost, myport );

		free( dn );
		ldap_value_free( s );
		ldap_value_free( oc );
	}

	if ( ldap_result2error( ld, res, 1 ) == LDAP_SIZELIMIT_EXCEEDED ) {
		fprintf( fp, "0A size limit was exceeded (explanation)\tLS\t%s\t%d\r\n",
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

	if ( ldap_entry2text_search( ld, dn, NULL, NULL, tmpllist, NULL, NULL,
	    entry2textwrite,(void *) fp, "\r\n", rdncount, 0 )
	    != LDAP_SUCCESS ) {
		int ld_errno = 0;
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &ld_errno);

		fprintf(fp,
		    "0An error occurred (explanation)\t@%s\t%s\t%d\r\n",
		    ldap_err2string( ld_errno ), myhost, myport );
	}

	if ( tmpllist != NULL ) {
		ldap_free_templates( tmpllist );
	}
}

static void
do_help( FILE *op )
{
	FILE	*fp;
	char	line[BUFSIZ];

	if ( (fp = fopen( helpfile, "r" )) == NULL ) {
		fprintf( op, "Cannot access helpfile (%s)\r\n", helpfile );
		return;
	}

	while ( fgets( line, sizeof(line), fp ) != NULL ) {
		line[ strlen( line ) - 1 ] = '\0';

		fprintf( op, "%s\r\n", line );
	}

	fclose( fp );
}

static void
do_sizelimit( FILE *fp, char type )
{
	if ( type == 'S' ) {
		fprintf( fp, "The query you specified was not specific enough, causing a size limit\r\n" );
		fprintf( fp, "to be exceeded and the first several matches found to be returned.\r\n" );
		fprintf( fp, "If you did not find the match you were looking for, try issuing a more\r\n" );
		fprintf( fp, "specific query, for example one that contains both first and last name.\r\n" );
	} else {
		fprintf( fp, "Not all entries could be returned because a size limit was exceeded.\r\n" );
		fprintf( fp, "There is no way to defeat this feature, but if you know who you are\r\n" );
		fprintf( fp, "looking for, try choosing the \"Search\" option listed above and\r\n" );
		fprintf( fp, "specifying the name of the person you want.\r\n" );
	}
	fprintf( fp, ".\r\n" );
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
