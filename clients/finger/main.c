/* $OpenLDAP$ */
/*
 * Copyright (c) 1990,1994 Regents of the University of Michigan.
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

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <ldap.h>
#include <disptmpl.h>

#include "ldap_defaults.h"


int	dosyslog = 1;
char	*ldaphost = NULL;
int	ldapport = 0;
char	*base = NULL;
int	deref;
char	*filterfile = FILTERFILE;
char	*templatefile = TEMPLATEFILE;
int	rdncount = FINGER_RDNCOUNT;

static void do_query(void);
static void do_search(LDAP *ld, char *buf);
static void do_read(LDAP *ld, LDAPMessage *e);

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-l] [-x ldaphost] [-p ldapport] [-f filterfile] [-t templatefile] [-c rdncount]\r\n", name );
	exit( EXIT_FAILURE );
}

int
main( int argc, char **argv )
{
	int			i;
	char			*myname;
	struct hostent		*hp;
	struct sockaddr_in	peername;
	socklen_t         	peernamelen;
	int			interactive = 0;

	deref = FINGER_DEREF;
	while ( (i = getopt( argc, argv, "f:ilp:t:x:p:c:" )) != EOF ) {
		switch( i ) {
		case 'f':	/* ldap filter file */
			filterfile = strdup( optarg );
			break;

		case 'i':	/* interactive */
			interactive = 1;
			break;

		case 'l':	/* don't do syslogging */
			dosyslog = 0;
			break;

		case 't':	/* ldap template file */
			templatefile = strdup( optarg );
			break;

		case 'x':	/* specify ldap host */
			ldaphost = strdup( optarg );
			break;

		case 'p':	/* specify ldap port */
			ldapport = atoi( optarg );
			break;

		case 'c':	/* specify number of DN components to show */
			rdncount = atoi( optarg );
			break;

		default:
			usage( argv[0] );
		}
	}

	if ( !interactive ) {
		peernamelen = sizeof(peername);
		if ( getpeername( 0, (struct sockaddr *)&peername,
		    &peernamelen ) != 0 ) {
			perror( "getpeername" );
			exit( EXIT_FAILURE );
		}
	}

#ifdef FINGER_BANNER
	if ( FINGER_BANNER != NULL && strcmp( FINGER_BANNER, "" ) != 0 ) {
		printf( FINGER_BANNER );
		fflush( stdout );
	}
#endif

	if ( (myname = strrchr( argv[0], '/' )) == NULL )
		myname = strdup( argv[0] );
	else
		myname = strdup( myname + 1 );

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

	if ( dosyslog ) {
#ifdef LOG_LOCAL4
		openlog( myname, OPENLOG_OPTIONS, LOG_LOCAL4 );
#elif LOG_DEBUG
		openlog( myname, OPENLOG_OPTIONS );
#endif
	}

	if ( dosyslog && !interactive ) {
		hp = gethostbyaddr( (char *) &peername.sin_addr,
				    sizeof(peername.sin_addr), AF_INET );
		syslog( LOG_INFO, "connection from %s (%s)",
			(hp == NULL) ? "unknown" : hp->h_name,
			inet_ntoa( peername.sin_addr ) );
	}

	do_query();

	return( 0 );
}

static void
do_query( void )
{
	char		buf[256];
	int		len, rc, tblsize;
	struct timeval	timeout;
	fd_set		readfds;
	LDAP		*ld;

	if ( (ld = ldap_init( ldaphost, ldapport )) == NULL ) {
		fprintf( stderr, FINGER_UNAVAILABLE );
		perror( "ldap_init" );
		exit( EXIT_FAILURE );
	}

	{
		int limit = FINGER_SIZELIMIT;
		ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &limit);
	}
	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( ldap_simple_bind_s( ld, NULL, NULL )
		!= LDAP_SUCCESS )
	{
		fprintf( stderr, FINGER_UNAVAILABLE );
		ldap_perror( ld, "ldap_simple_bind_s" );
		exit( EXIT_FAILURE );
	}

#ifdef HAVE_SYSCONF
	tblsize = sysconf( _SC_OPEN_MAX );
#elif HAVE_GETDTABLESIZE
	tblsize = getdtablesize();
#else
	tblsize = FD_SETSIZE;
#endif

#ifdef FD_SETSIZE
	if (tblsize > FD_SETSIZE) {
		tblsize = FD_SETSIZE;
	}
#endif	/* FD_SETSIZE*/

	timeout.tv_sec = FINGER_TIMEOUT;
	timeout.tv_usec = 0;
	FD_ZERO( &readfds );
	FD_SET( fileno( stdin ), &readfds );

	if ( (rc = select( tblsize, &readfds, 0, 0, &timeout )) <= 0 ) {
		if ( rc < 0 )
			perror( "select" );
		else
			fprintf( stderr, "connection timed out on input\r\n" );
		exit( EXIT_FAILURE );
	}

	if ( fgets( buf, sizeof(buf), stdin ) == NULL )
		exit( EXIT_FAILURE );

	len = strlen( buf );

	/* strip off \r \n */
	if ( buf[len - 1] == '\n' ) {
		buf[len - 1] = '\0';
		len--;
	}
	if ( buf[len - 1] == '\r' ) {
		buf[len - 1] = '\0';
		len--;
	}

	if ( len == 0 ) {
		printf( "No campus-wide login information available.  Info for this machine only:\r\n" );
		fflush( stdout );
		execl( FINGER_CMD, FINGER_CMD, NULL );
	} else {
		char	*p;

		/* skip and ignore stinking /w */
		if ( strncmp( buf, "/W ", 2 ) == 0 ) {
			p = buf + 2;
		} else {
			p = buf;
		}

		for ( ; *p && isspace( (unsigned char) *p ); p++ )
			;	/* NULL */

		do_search( ld, p );
	}
}

static void
spaces2dots( char *s )
{
	for ( ; *s; s++ ) {
		if ( *s == ' ' ) {
			*s = '.';
		}
	}
}

static void
do_search( LDAP *ld, char *buf )
{
	char		*dn, *rdn;
	char		**title;
	int		rc, matches, i, ufn;
	struct timeval	tv;
	LDAPFiltDesc	*fd;
	LDAPFiltInfo	*fi;
	LDAPMessage	*result, *e;
	static char	*attrs[] = { "cn", "title", "objectClass", "joinable",
#ifdef FINGER_SORT_ATTR
					FINGER_SORT_ATTR,
#endif
					0 };

	ufn = 0;
#ifdef FINGER_UFN
	if ( strchr( buf, ',' ) != NULL ) {
		ldap_ufn_setprefix( ld, base );
		tv.tv_sec = FINGER_TIMEOUT;
		tv.tv_usec = 0;
		ldap_ufn_timeout( (void *) &tv );

		if ( (rc = ldap_ufn_search_s( ld, buf, attrs, 0, &result ))
		    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED ) {
			fprintf( stderr, FINGER_UNAVAILABLE );
			ldap_perror( ld, "ldap_search_st" );
			exit( EXIT_FAILURE );
		}

		matches = ldap_count_entries( ld, result );
		ufn = 1;
	} else {
#endif
		if ( (fd = ldap_init_getfilter( filterfile ))
		    == NULL ) {
			fprintf( stderr, "Cannot open filter file (%s)\n",
			    filterfile );
			exit( EXIT_FAILURE );
		}

		for ( fi = ldap_getfirstfilter( fd, "finger", buf );
		    fi != NULL;
		    fi = ldap_getnextfilter( fd ) )
		{
			tv.tv_sec = FINGER_TIMEOUT;
			tv.tv_usec = 0;
			if ( (rc = ldap_search_st( ld, base, LDAP_SCOPE_SUBTREE,
			    fi->lfi_filter, attrs, 0, &tv, &result ))
			    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED
			    && rc != LDAP_TIMELIMIT_EXCEEDED )
			{
				fprintf( stderr, FINGER_UNAVAILABLE );
				ldap_perror( ld, "ldap_search_st" );
				exit( EXIT_FAILURE );
			}

			if ( (matches = ldap_count_entries( ld, result )) != 0 )
				break;

			ldap_msgfree( result );
			result = NULL;
		}
#ifdef FINGER_UFN
	}
#endif

	if ( rc == LDAP_SIZELIMIT_EXCEEDED ) {
		printf( "(Partial results - a size limit was exceeded)\r\n" );
	} else if ( rc == LDAP_TIMELIMIT_EXCEEDED ) {
		printf( "(Partial results - a time limit was exceeded)\r\n" );
	}

	if ( matches == 0 ) {
		printf( FINGER_NOMATCH );
		fflush( stdout );
	} else if ( matches < 0 ) {
		fprintf( stderr, "error return from ldap_count_entries\r\n" );
		exit( EXIT_FAILURE );
	} else if ( matches <= FINGER_LISTLIMIT ) {
		printf( "%d %s match%s found for \"%s\":\r\n", matches,
		    ufn ? "UFN" : fi->lfi_desc, matches > 1 ? "es" : "", buf );
		fflush( stdout );

		for ( e = ldap_first_entry( ld, result ); e != NULL; ) {
			do_read( ld, e );
			e = ldap_next_entry( ld, e );
			if ( e != NULL ) {
				printf( "--------------------\r\n" );
			}
		}
	} else {
		printf( "%d %s matches for \"%s\":\r\n", matches,
		    ufn ? "UFN" : fi->lfi_desc, buf );
		fflush( stdout );

#ifdef FINGER_SORT_ATTR
		ldap_sort_entries( ld, &result, FINGER_SORT_ATTR, strcasecmp );
#endif

		for ( e = ldap_first_entry( ld, result ); e != NULL;
		    e = ldap_next_entry( ld, e ) ) {
			char	*p;

			dn = ldap_get_dn( ld, e );
			rdn = dn;
			if ( (p = strchr( dn, ',' )) != NULL )
				*p = '\0';
			while ( *rdn && *rdn != '=' )
				rdn++;
			if ( *rdn )
				rdn++;

			/* hack attack */
			for ( i = 0; buf[i] != '\0'; i++ ) {
				if ( buf[i] == '.' || buf[i] == '_' )
					buf[i] = ' ';
			}
			if ( strcasecmp( rdn, buf ) == 0 ) {
				char	**cn;
				int	i, last;

				cn = ldap_get_values( ld, e, "cn" );
				for ( i = 0; cn[i] != NULL; i++ ) {
					last = strlen( cn[i] ) - 1;
					if (isdigit((unsigned char) cn[i][last])) {
						rdn = strdup( cn[i] );
						break;
					}
				}
			}
					
			title = ldap_get_values( ld, e, "title" );

			spaces2dots( rdn );
			printf( "  %-20s    %s\r\n", rdn,
			    title ? title[0] : "" );
			if ( title != NULL ) {
				for ( i = 1; title[i] != NULL; i++ )
					printf( "  %-20s    %s\r\n", "",
					    title[i] );
			}
			fflush( stdout );

			if ( title != NULL )
				ldap_value_free( title );

			free( dn );
		}
	}

	if ( result != NULL ) {
		ldap_msgfree( result );
	}
	ldap_unbind( ld );
}


static int
entry2textwrite( void *fp, char *buf, ber_len_t len )
{
	return( fwrite( buf, len, 1, (FILE *)fp ) == 0 ? -1 : len );
}


static void
do_read( LDAP *ld, LDAPMessage *e )
{
	static struct ldap_disptmpl *tmpllist;
	static char	*defattrs[] = { "mail", NULL };
	static char	*mailvals[] = FINGER_NOEMAIL;
	static char	**defvals[] = { mailvals, NULL };

	ldap_init_templates( templatefile, &tmpllist );

	if ( ldap_entry2text_search( ld, NULL, base, e, tmpllist, defattrs,
	    defvals, entry2textwrite, (void *)stdout, "\r\n", rdncount,
	    LDAP_DISP_OPT_DOSEARCHACTIONS ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_entry2text_search" );
		exit( EXIT_FAILURE );
	}

	if ( tmpllist != NULL ) {
	    ldap_free_templates( tmpllist );
	}
}
