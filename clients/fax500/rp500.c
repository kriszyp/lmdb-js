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

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <ldap.h>

#include "fax500.h"
#include "ldap_defaults.h"

#define DEFAULT_PORT		79
#define DEFAULT_SIZELIMIT	50

int		debug;
char	*ldaphost = NULL;
char	*base = NULL;
int		deref = LDAP_DEREF_ALWAYS;
int		sizelimit = DEFAULT_SIZELIMIT;
LDAPFiltDesc	*filtd;

static void	print_entry(LDAP *ld, LDAPMessage *e);

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-d debuglevel] [-x ldaphost] [-b searchbase] [-a] [-z sizelimit] [-f filterfile] searchstring\r\n", name );
	exit( -1 );
}

int
main( int argc, char **argv )
{
	int		i, rc, matches;
	char		*filterfile = FILTERFILE;
	char		buf[10];
	char		*key;
	LDAP		*ld;
	LDAPMessage	*result, *e;
	LDAPFiltDesc	*filtd;
	LDAPFiltInfo	*fi;
	static char	*attrs[] = { "title", "o", "ou", "postalAddress",
					"telephoneNumber", "mail",
					"facsimileTelephoneNumber", NULL };

	while ( (i = getopt( argc, argv, "ab:d:f:x:z:" )) != EOF ) {
		switch( i ) {
		case 'a':	/* do not deref aliases when searching */
			deref = LDAP_DEREF_FINDING;
			break;

		case 'b':	/* search base */
			base = strdup( optarg );
			break;

		case 'd':	/* turn on debugging */
			debug = atoi( optarg );
			break;

		case 'f':	/* ldap filter file */
			filterfile = strdup( optarg );
			break;

		case 'x':	/* specify ldap host */
			ldaphost = strdup( optarg );
			break;

		case 'z':	/* size limit */
			sizelimit = atoi( optarg );
			break;

		default:
			usage( argv[0] );
		}
	}

	if ( optind == argc ) {
		usage( argv[0] );
	}
	key = argv[optind];

	if ( (filtd = ldap_init_getfilter( filterfile )) == NULL ) {
		fprintf( stderr, "Cannot open filter file (%s)\n", filterfile );
		exit( -1 );
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

	if ( (ld = ldap_init( ldaphost, 0 )) == NULL ) {
		perror( "ldap_init" );
		exit( -1 );
	}

	ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
	ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

	if ( ldap_simple_bind_s( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		fprintf( stderr, "X.500 is temporarily unavailable.\n" );
		ldap_perror( ld, "ldap_simple_bind_s" );
		exit( -1 );
	}

	result = NULL;
#ifdef LDAP_UFN
	if ( strchr( key, ',' ) != NULL ) {
		int ld_deref = LDAP_DEREF_FINDING;
		ldap_set_option(ld, LDAP_OPT_DEREF, &ld_deref);
		if ( (rc = ldap_ufn_search_s( ld, key, attrs, 0, &result ))
		    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED &&
		    rc != LDAP_TIMELIMIT_EXCEEDED )
		{
			ldap_perror( ld, "ldap_ufn_search_s" );
			exit( -1 );
		}
		matches = ldap_count_entries( ld, result );
	} else
#endif
	{
		for ( fi = ldap_getfirstfilter( filtd, "rp500", key );
		    fi != NULL; fi = ldap_getnextfilter( filtd ) ) {
			if ( (rc = ldap_search_s( ld, base, LDAP_SCOPE_SUBTREE,
			    fi->lfi_filter, attrs, 0, &result ))
			    != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED
			    && rc != LDAP_TIMELIMIT_EXCEEDED )
			{
				ldap_perror( ld, "ldap_search" );
				exit( -1 );
			}

			if ( (matches = ldap_count_entries( ld, result )) != 0
			    || rc != LDAP_SUCCESS ) {
				break;
			}
		}
	}

	if ( matches == 1 ) {
		e = ldap_first_entry( ld, result );

		print_entry( ld, e );
	} else if ( matches > 1 ) {
		fprintf( stderr, "%d %s matches for \"%s\":\r\n", matches,
		    fi->lfi_desc, key );

		for ( i = 1, e = ldap_first_entry( ld, result ); e != NULL;
		    i++, e = ldap_next_entry( ld, e ) ) {
			int	j;
			char	*p, *dn, *rdn;
			char	**title;

			dn = ldap_get_dn( ld, e );
			rdn = dn;
			if ( (p = strchr( dn, ',' )) != NULL )
				*p = '\0';
			while ( *rdn && *rdn != '=' )
				rdn++;
			if ( *rdn )
				rdn++;
			if ( strcasecmp( rdn, buf ) == 0 ) {
				char	**cn;
				int	i, last;

				cn = ldap_get_values( ld, e, "cn" );
				for ( i = 0; cn[i] != NULL; i++ ) {
					last = strlen( cn[i] ) - 1;
					if ( isdigit((unsigned char) cn[i][last]) ) {
						rdn = strdup( cn[i] );
						break;
					}
				}
			}
					
			title = ldap_get_values( ld, e, "title" );

			fprintf( stderr, "  %d: %-20s    %s\r\n", i, rdn,
			    title ? title[0] : "" );
			if ( title != NULL ) {
				for ( j = 1; title[j] != NULL; j++ )
					fprintf( stderr, "  %-20s    %s\r\n",
					    "", title[j] );
			}
			if ( title != NULL )
				ldap_value_free( title );

			free( dn );
		}
		if ( rc == LDAP_SIZELIMIT_EXCEEDED
		    || rc == LDAP_TIMELIMIT_EXCEEDED ) {
			fprintf( stderr, "(Size or time limit exceeded)\n" );
		}

		fprintf( stderr, "Enter the number of the person you want: ");

		if ( fgets( buf, sizeof(buf), stdin ) == NULL
		    || buf[0] == '\n' ) {
			exit( EXIT_FAILURE );
		}
		i = atoi( buf ) - 1;
		e = ldap_first_entry( ld, result );
		for ( ; i > 0 && e != NULL; i-- ) {
			e = ldap_next_entry( ld, e );
		}
		if ( e == NULL ) {
			fprintf( stderr, "Invalid choice!\n" );
			exit( EXIT_FAILURE );
		}

		print_entry( ld, e );
	} else if ( matches == 0 ) {
		fprintf( stderr, "No matches found for \"%s\"\n", key );
		exit( EXIT_FAILURE );
	} else {
		fprintf( stderr, "Error return from ldap_count_entries\n" );
		exit( -1 );
	}

	ldap_unbind( ld );
	return( 0 );
}

static void
print_entry( LDAP *ld, LDAPMessage *e )
{
	int	i;
	char	*dn, *rdn;
	char	**ufn;
	char	**title, **dept, **addr, **phone, **fax, **mail;
	char	*faxmail, *org;

	dn = ldap_get_dn( ld, e );
	ufn = ldap_explode_dn( dn, 0 );
	rdn = strchr( ufn[0], '=' ) + 1;

	if ( (fax = ldap_get_values( ld, e, "facsimileTelephoneNumber" ))
	    == NULL ) {
		fprintf( stderr, "Entry \"%s\" has no fax number.\n", dn );
		exit( EXIT_FAILURE );
	}
	faxmail = faxtotpc( fax[0], NULL );
	title = ldap_get_values( ld, e, "title" );
	phone = ldap_get_values( ld, e, "telephoneNumber" );
	mail = ldap_get_values( ld, e, "mail" );
	dept = ldap_get_values( ld, e, "ou" );
	addr = ldap_get_values( ld, e, "postalAddress" );
	org = "";
	for ( i = 0; ufn[i] != NULL; i++ ) {
		if ( strncmp( "o=", ufn[i], 2 ) == 0 ) {
			org = strdup( strchr( ufn[i], '=' ) + 1 );
			break;
		}
	}

	printf( "To: %s\n", faxmail );
	printf( "Subject:\n" );
	printf( "--------\n" );
	printf( "#<application/remote-printing\n" );
	printf( "Recipient:      %s\r\n", rdn );
	printf( "Title:          %s\r\n", title ? title[0] : "" );
	printf( "Organization:   %s\r\n", org );
	printf( "Department:     %s\r\n", dept ? dept[0] : "" );
	printf( "Telephone:      %s\r\n", phone ? phone[0] : "" );
	printf( "Facsimile:      %s\r\n", fax ? fax[0] : "" );
	printf( "Email:          %s\r\n", mail ? mail[0] : "" );
}
