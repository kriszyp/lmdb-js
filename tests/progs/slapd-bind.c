/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2006 The OpenLDAP Foundation.
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

#include <ldap.h>
#include <lutil.h>

#include "slapd-common.h"

#define LOOPS	100

static int
do_bind( char *uri, char *dn, struct berval *pass, int maxloop, int force, int noinit, LDAP **ldp );

static int
do_base( char *uri, struct berval *base, struct berval *pass, int maxloop, int force, int noinit, int delay );

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
	fprintf( stderr, "usage: %s [-h <host>] -p port (-D <dn>|-b <baseDN> [-f <searchfilter>]) -w <passwd> [-l <loops>] [-F] [-I] [-t delay]\n",
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
	struct berval	base = { 0, NULL };
	struct berval	pass = { 0, NULL };
	int		port = -1;
	int		loops = LOOPS;
	int		force = 0;
	int		noinit = 0;
	int		delay = 0;

	tester_init( "slapd-bind" );

	while ( (i = getopt( argc, argv, "b:H:h:p:D:w:l:f:FIt:" )) != EOF ) {
		switch( i ) {
			case 'b':		/* base DN of a tree of user DNs */
				ber_str2bv( optarg, 0, 0, &base );
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
				pass.bv_val = strdup( optarg );
				pass.bv_len = strlen( optarg );
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
				force++;
				break;

			case 'I':
				/* reuse connection */
				noinit++;
				break;

			case 't':
				/* sleep between binds */
				if ( lutil_atoi( &delay, optarg ) != 0 ) {
					usage( argv[0] );
				}
				break;

			default:
				usage( argv[0] );
				break;
		}
	}

	if ( port == -1 && uri == NULL ) {
		usage( argv[0] );
	}

	uri = tester_uri( uri, host, port );

	if ( base.bv_val != NULL ) {
		do_base( uri, &base, &pass, ( 20 * loops ), force, noinit, delay );
	} else {
		do_bind( uri, dn, &pass, ( 20 * loops ), force, noinit, NULL );
	}
	exit( EXIT_SUCCESS );
}


static int
do_bind( char *uri, char *dn, struct berval *pass, int maxloop, int force, int noinit, LDAP **ldp )
{
	LDAP	*ld = ldp ? *ldp : NULL;
	int  	i, first = 1, rc = -1;
	pid_t	pid = getpid();

	if ( maxloop > 1 )
		fprintf( stderr, "PID=%ld - Bind(%d): dn=\"%s\".\n",
			 (long) pid, maxloop, dn );

	for ( i = 0; i < maxloop; i++ ) {
		if ( !noinit || ld == NULL ) {
			int version = LDAP_VERSION3;
			ldap_initialize( &ld, uri );
			if ( ld == NULL ) {
				tester_perror( "ldap_initialize" );
				rc = -1;
				break;
			}

			(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
				&version ); 
		}

		rc = ldap_sasl_bind_s( ld, dn, LDAP_SASL_SIMPLE, pass, NULL, NULL, NULL );
		switch ( rc ) {
		case LDAP_SUCCESS:
			break;

		case LDAP_INVALID_CREDENTIALS:
			/* don't log: it's intended */
			if ( force >= 2 ) {
				if ( !first ) {
					break;
				}
				first = 0;
			}
			/* fallthru */

		default:
			tester_ldap_error( ld, "ldap_sasl_bind_s" );
		}

		if ( !noinit ) {
			ldap_unbind_ext( ld, NULL, NULL );
			ld = NULL;
		}
		if ( rc != LDAP_SUCCESS && !force ) {
			break;
		}
	}

	if ( maxloop > 1 ) {
		fprintf( stderr, " PID=%ld - Bind done (%d).\n", (long) pid, rc );
	}

	if ( ldp ) {
		*ldp = ld;

	} else if ( ld != NULL ) {
		ldap_unbind_ext( ld, NULL, NULL );
	}

	return rc;
}


static int
do_base( char *uri, struct berval *base, struct berval *pass, int maxloop, int force, int noinit, int delay )
{
	LDAP	*ld = NULL;
	int  	i = 0;
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;
	ber_int_t msgid;
	LDAPMessage *res, *msg;
	struct berval *rdns = NULL;
	char *attrs[] = { LDAP_NO_ATTRS, NULL };
	int nrdns = 0;
#ifdef _WIN32
	DWORD beg, end;
#else
	struct timeval beg, end;
#endif
	int version = LDAP_VERSION3;
	struct berval pw = { 0, NULL };

	srand(pid);

	ldap_initialize( &ld, uri );
	if ( ld == NULL ) {
		tester_perror( "ldap_initialize" );
		exit( EXIT_FAILURE );
	}

	(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	(void) ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );

	rc = ldap_sasl_bind_s( ld, NULL, LDAP_SASL_SIMPLE, &pw, NULL, NULL, NULL );
	if ( rc != LDAP_SUCCESS ) {
		tester_ldap_error( ld, "ldap_sasl_bind_s" );
		exit( EXIT_FAILURE );
	}

	rc = ldap_search_ext( ld, base->bv_val, LDAP_SCOPE_ONE,
			filter, attrs, 0, NULL, NULL, 0, 0, &msgid );
	if ( rc != LDAP_SUCCESS ) {
		tester_ldap_error( ld, "ldap_search_ext" );
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
				assert( ptr != NULL );
				bv.bv_len = ptr - bv.bv_val + 1;
				rdns = realloc( rdns, (nrdns+1)*sizeof(struct berval));
				ber_dupbv( &rdns[nrdns], &bv );
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

#ifdef _WIN32
	beg = GetTickCount();
#else
	gettimeofday( &beg, NULL );
#endif

	if ( nrdns == 0 ) {
		tester_error( "No RDNs" );
		return 1;
	}

	/* Ok, got list of RDNs, now start binding to each */
	for ( i = 0; i < maxloop; i++ ) {
		char dn[BUFSIZ], *ptr;
		int j, k;

		for ( k = 0; k < nrdns; k++) {
			j = rand() % nrdns;
			if ( base->bv_len + rdns[j].bv_len < sizeof( dn ) ) {
				break;
			}
		}

		if ( k == nrdns ) {
			
		}
		
		ptr = lutil_strcopy(dn, rdns[j].bv_val);
		strcpy(ptr, base->bv_val);
		if ( do_bind( uri, dn, pass, 1, force, noinit, &ld ) && !force ) {
			break;
		}

		if ( delay ) {
			sleep( delay );
		}
	}

	if ( ld != NULL ) {
		ldap_unbind_ext( ld, NULL, NULL );
		ld = NULL;
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

	if ( rdns ) {
		for ( i = 0; i < nrdns; i++ ) {
			free( rdns[i].bv_val );
		}
		free( rdns );
	}

	return 0;
}
