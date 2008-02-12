/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/time.h>

#include <ac/ctype.h>
#include <ac/param.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/wait.h>
#include <ac/time.h>

#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <lutil.h>

#define LOOPS	100

static int
do_bind( char *uri, char *host, int port, char *dn, char *pass, int maxloop,
	int force );

static int
do_base( char *uri, char *host, int port, char *base, char *pass, int maxloop,
	int force );

/* This program can be invoked two ways: if -D is used to specify a Bind DN,
 * that DN will be used repeatedly for all of the Binds. If instead -b is used
 * to specify a base DN, a search will be done for all "person" objects under
 * that base DN. Then DNs from this list will be randomly selected for each
 * Bind request. All of the users must have identical passwords. Also it is
 * assumed that the users are all onelevel children of the base.
 */
static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-h <host>] -p port (-D <dn>|-b <baseDN> [-f <searchfilter>]) -w <passwd> [-l <loops>] [-F]\n",
			name );
	exit( EXIT_FAILURE );
}

static char *filter = "(objectClass=person)";

int
main( int argc, char **argv )
{
	int		i;
	char		*uri = NULL;
	char		*host = "localhost";
	char		*dn = NULL;
	char		*base = NULL;
	char		*pass = NULL;
	int		port = -1;
	int		loops = LOOPS;
	int		force = 0;

	while ( (i = getopt( argc, argv, "b:H:h:p:D:w:l:f:F" )) != EOF ) {
		switch( i ) {
			case 'b':		/* base DN of a tree of user DNs */
				base = strdup( optarg );
				break;

			case 'H':		/* the server uri */
				uri = strdup( optarg );
			break;
			case 'h':		/* the servers host */
				host = strdup( optarg );
			break;

			case 'p':		/* the servers port */
				if ( lutil_atoi( &port, optarg ) != 0 ) {
					usage( argv[0] );
				}
				break;

			case 'D':
				dn = strdup( optarg );
				break;

			case 'w':
				pass = strdup( optarg );
				break;

			case 'l':		/* the number of loops */
				if ( lutil_atoi( &loops, optarg ) != 0 ) {
					usage( argv[0] );
				}
				break;

			case 'f':
				filter = optarg;
				break;

			case 'F':
				force = 1;
				break;

			default:
				usage( argv[0] );
				break;
		}
	}

	if ( port == -1 && uri == NULL )
		usage( argv[0] );

	if ( base )
		do_base( uri, host, port, base, pass, ( 20 * loops ), force );
	else
		do_bind( uri, host, port, dn, pass, ( 20 * loops ), force );
	exit( EXIT_SUCCESS );
}


static int
do_bind( char *uri, char *host, int port, char *dn, char *pass, int maxloop,
	int force )
{
	LDAP	*ld = NULL;
	int  	i, rc = -1;
	pid_t	pid = getpid();

	if ( maxloop > 1 )
		fprintf( stderr, "PID=%ld - Bind(%d): dn=\"%s\".\n",
			 (long) pid, maxloop, dn );

	for ( i = 0; i < maxloop; i++ ) {
		if ( uri ) {
			ldap_initialize( &ld, uri );
		} else {
			ld = ldap_init( host, port );
		}
		if ( ld == NULL ) {
			perror( "ldap_init" );
			rc = -1;
			break;
		}

		{
			int version = LDAP_VERSION3;
			(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
				&version ); 
		}

		rc = ldap_bind_s( ld, dn, pass, LDAP_AUTH_SIMPLE );
		if ( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
		}
		ldap_unbind( ld );
		if ( rc != LDAP_SUCCESS && !force ) {
			break;
		}
	}

	if ( maxloop > 1 )
		fprintf( stderr, " PID=%ld - Bind done.\n", (long) pid );

	return rc;
}


static int
do_base( char *uri, char *host, int port, char *base, char *pass, int maxloop,
	int force )
{
	LDAP	*ld = NULL;
	int  	i = 0;
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;
	ber_int_t msgid;
	LDAPMessage *res, *msg;
	char **rdns = NULL;
	char *attrs[] = { "dn", NULL };
	int nrdns = 0;
#ifdef _WIN32
	DWORD beg, end;
#else
	struct timeval beg, end;
#endif

	srand(pid);

	if ( uri ) {
		ldap_initialize( &ld, uri );
	} else {
		ld = ldap_init( host, port );
	}
	if ( ld == NULL ) {
		perror( "ldap_init" );
		exit( EXIT_FAILURE );
	}

	{
		int version = LDAP_VERSION3;
		(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
			&version ); 
	}
	(void) ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );

	rc = ldap_bind_s( ld, NULL, NULL, LDAP_AUTH_SIMPLE );
	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		exit( EXIT_FAILURE );
	}

	rc = ldap_search_ext( ld, base, LDAP_SCOPE_ONE,
			filter, attrs, 0, NULL, NULL, 0, 0, &msgid );
	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_search_ex" );
		exit( EXIT_FAILURE );
	}

	while (( rc=ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ONE, NULL, &res )) >0){
		BerElement *ber;
		struct berval bv;
		char *ptr;
		int done = 0;

		for (msg = ldap_first_message( ld, res ); msg;
			msg = ldap_next_message( ld, msg )) {
			switch ( ldap_msgtype( msg )) {
			case LDAP_RES_SEARCH_ENTRY:
				rc = ldap_get_dn_ber( ld, msg, &ber, &bv );
				ptr = strchr( bv.bv_val, ',');
				i = ptr-bv.bv_val;
				rdns = realloc( rdns, (nrdns+1)*sizeof(char *));
				rdns[nrdns] = malloc( i+1 );
				strncpy(rdns[nrdns], bv.bv_val, i );
				rdns[nrdns][i] = '\0';
				nrdns++;
				ber_free( ber, 0 );
				break;
			case LDAP_RES_SEARCH_RESULT:
				done = 1;
				break;
			}
			if ( done )
				break;
		}
		ldap_msgfree( res );
		if ( done ) break;
	}
	ldap_unbind( ld );

#ifdef _WIN32
	beg = GetTickCount();
#else
	gettimeofday( &beg, NULL );
#endif

	if ( nrdns == 0 ) {
		fprintf( stderr, "No RDNs.\n" );
		return 1;
	}

	/* Ok, got list of RDNs, now start binding to each */
	for (i=0; i<maxloop; i++) {
		char dn[BUFSIZ], *ptr;
		int j = rand() % nrdns;
		ptr = lutil_strcopy(dn, rdns[j]);
		*ptr++ = ',';
		strcpy(ptr, base);
		if ( do_bind( uri, host, port, dn, pass, 1, force ) && !force )
			break;
	}
#ifdef _WIN32
	end = GetTickCount();
	end -= beg;

	fprintf( stderr, "Done %d Binds in %d.%03d seconds.\n", i,
		end / 1000, end % 1000 );
#else
	gettimeofday( &end, NULL );
	end.tv_usec -= beg.tv_usec;
	if (end.tv_usec < 0 ) {
		end.tv_usec += 1000000;
		end.tv_sec -= 1;
	}
	end.tv_sec -= beg.tv_sec;

	fprintf( stderr, "Done %d Binds in %ld.%06ld seconds.\n", i,
		(long) end.tv_sec, (long) end.tv_usec );
#endif
	return 0;
}
