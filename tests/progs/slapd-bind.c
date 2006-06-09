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
#include <lber_pvt.h>

#include "slapd-common.h"

#define LOOPS	100

static int
do_bind( char *uri, char *dn, struct berval *pass, int maxloop,
	int force, int chaserefs, int noinit, LDAP **ldp );

static int
do_base( char *uri, struct berval *base, struct berval *pass, char *pwattr,
	int maxloop, int force, int chaserefs, int noinit, int delay );

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
	fprintf( stderr, "usage: %s "
		"[-H uri | -h <host> [-p port]] "
		"[-D <dn> [-w <passwd>]] "
		"[-b <baseDN> [-f <searchfilter>] [-a pwattr]] "
		"[-l <loops>] "
		"[-L <outerloops>] "
		"[-F] "
		"[-C] "
		"[-I] "
		"[-t delay]\n",
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
	char		*pwattr = NULL;
	int		port = -1;
	int		loops = LOOPS;
	int		outerloops = 1;
	int		force = 0;
	int		chaserefs = 0;
	int		noinit = 0;
	int		delay = 0;

	tester_init( "slapd-bind" );

	while ( (i = getopt( argc, argv, "a:b:H:h:p:D:w:l:L:f:FIt:" )) != EOF ) {
		switch( i ) {
		case 'a':
			pwattr = optarg;
			break;

		case 'b':		/* base DN of a tree of user DNs */
			ber_str2bv( optarg, 0, 0, &base );
			break;

		case 'C':
			chaserefs++;
			break;

		case 'H':		/* the server uri */
			uri = optarg;
			break;

		case 'h':		/* the servers host */
			host = optarg;
			break;

		case 'p':		/* the servers port */
			if ( lutil_atoi( &port, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'D':
			dn = optarg;
			break;

		case 'w':
			ber_str2bv( optarg, 0, 0, &pass );
			break;

		case 'l':		/* the number of loops */
			if ( lutil_atoi( &loops, optarg ) != 0 ) {
				usage( argv[0] );
			}
			break;

		case 'L':		/* the number of outerloops */
			if ( lutil_atoi( &outerloops, optarg ) != 0 ) {
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

	for ( i = 0; i < outerloops; i++ ) {
		if ( base.bv_val != NULL ) {
			do_base( uri, &base, &pass, pwattr, loops,
				force, chaserefs, noinit, delay );
		} else {
			do_bind( uri, dn, &pass, loops,
				force, chaserefs, noinit, NULL );
		}
	}

	exit( EXIT_SUCCESS );
}


static int
do_bind( char *uri, char *dn, struct berval *pass, int maxloop,
	int force, int chaserefs, int noinit, LDAP **ldp )
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
				tester_perror( "ldap_initialize", NULL );
				rc = -1;
				break;
			}

			(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION,
				&version ); 
			(void) ldap_set_option( ld, LDAP_OPT_REFERRALS,
				chaserefs ? LDAP_OPT_ON: LDAP_OPT_OFF );
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
			tester_ldap_error( ld, "ldap_sasl_bind_s", NULL );
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

	if ( ldp && noinit ) {
		*ldp = ld;

	} else if ( ld != NULL ) {
		ldap_unbind_ext( ld, NULL, NULL );
	}

	return rc;
}


static int
do_base( char *uri, struct berval *base, struct berval *pass, char *pwattr,
	int maxloop, int force, int chaserefs, int noinit, int delay )
{
	LDAP	*ld = NULL;
	int  	i = 0;
	pid_t	pid = getpid();
	int     rc = LDAP_SUCCESS;
	ber_int_t msgid;
	LDAPMessage *res, *msg;
	char **dns = NULL;
	struct berval *creds = NULL;
	char *attrs[] = { LDAP_NO_ATTRS, NULL };
	int ndns = 0;
#ifdef _WIN32
	DWORD beg, end;
#else
	struct timeval beg, end;
#endif
	int version = LDAP_VERSION3;
	struct berval pw = { 0, NULL };
	char *nullstr = "";

	srand(pid);

	ldap_initialize( &ld, uri );
	if ( ld == NULL ) {
		tester_perror( "ldap_initialize", NULL );
		exit( EXIT_FAILURE );
	}

	(void) ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	(void) ldap_set_option( ld, LDAP_OPT_REFERRALS,
		chaserefs ? LDAP_OPT_ON: LDAP_OPT_OFF );

	rc = ldap_sasl_bind_s( ld, NULL, LDAP_SASL_SIMPLE, &pw, NULL, NULL, NULL );
	if ( rc != LDAP_SUCCESS ) {
		tester_ldap_error( ld, "ldap_sasl_bind_s", NULL );
		exit( EXIT_FAILURE );
	}

	fprintf( stderr, "PID=%ld - Bind(%d): base=\"%s\", filter=\"%s\" attr=\"%s\".\n",
			(long) pid, maxloop, base->bv_val, filter, pwattr );

	if ( pwattr != NULL ) {
		attrs[ 0 ] = pwattr;
	}
	rc = ldap_search_ext( ld, base->bv_val, LDAP_SCOPE_SUBTREE,
			filter, attrs, 0, NULL, NULL, 0, 0, &msgid );
	if ( rc != LDAP_SUCCESS ) {
		tester_ldap_error( ld, "ldap_search_ext", NULL );
		exit( EXIT_FAILURE );
	}

	while ( ( rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ONE, NULL, &res ) ) > 0 )
	{
		BerElement *ber;
		struct berval bv;
		int done = 0;

		for ( msg = ldap_first_message( ld, res ); msg;
			msg = ldap_next_message( ld, msg ) )
		{
			switch ( ldap_msgtype( msg ) ) {
			case LDAP_RES_SEARCH_ENTRY:
				rc = ldap_get_dn_ber( ld, msg, &ber, &bv );
				dns = realloc( dns, (ndns + 1)*sizeof(char *) );
				dns[ndns] = ber_strdup( bv.bv_val );
				if ( pwattr != NULL ) {
					struct berval	**values = ldap_get_values_len( ld, msg, pwattr );

					creds = realloc( creds, (ndns + 1)*sizeof(struct berval) );
					if ( values == NULL ) {
novals:;
						if ( pass != NULL ) {
							ber_dupbv( &creds[ndns], pass );

						} else {
							creds[ndns].bv_len = 0;
							creds[ndns].bv_val = nullstr;
						}

					} else {
						static struct berval	cleartext = BER_BVC( "{CLEARTEXT} " );
						struct berval		value = *values[ 0 ];

						if ( value.bv_val[ 0 ] == '{' ) {
							char *end = ber_bvchr( &value, '}' );

							if ( end ) {
								if ( ber_bvcmp( &value, &cleartext ) == 0 ) {
									value.bv_val += cleartext.bv_len;
									value.bv_len -= cleartext.bv_len;

								} else {
									ldap_value_free_len( values );
									goto novals;
								}
							}

						}

						ber_dupbv( &creds[ndns], &value );
						ldap_value_free_len( values );
					}
				}
				ndns++;
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

	if ( ndns == 0 ) {
		tester_error( "No RDNs" );
		return 1;
	}

	fprintf( stderr, "  PID=%ld - got %d values.\n", (long) pid, ndns );

	/* Ok, got list of RDNs, now start binding to each */
	for ( i = 0; i < maxloop; i++ ) {
		int j, k;
		struct berval *cred = pass;

		for ( j = 0, k = 0; k < ndns; k++) {
			j = rand() % ndns;
		}

		if ( creds && !BER_BVISEMPTY( &creds[j] ) ) {
			cred = &creds[j];
		}
		if ( do_bind( uri, dns[j], cred, 1, force, chaserefs, noinit, &ld )
			&& !force )
		{
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

	fprintf( stderr, " PID=%ld - Bind done %d in %d.%03d seconds.\n",
		(long) pid, i, end / 1000, end % 1000 );
#else
	gettimeofday( &end, NULL );
	end.tv_usec -= beg.tv_usec;
	if (end.tv_usec < 0 ) {
		end.tv_usec += 1000000;
		end.tv_sec -= 1;
	}
	end.tv_sec -= beg.tv_sec;

	fprintf( stderr, " PID=%ld - Bind done %d in %ld.%06ld seconds.\n",
		(long) pid, i, (long) end.tv_sec, (long) end.tv_usec );
#endif

	if ( dns ) {
		for ( i = 0; i < ndns; i++ ) {
			free( dns[i] );
		}
		free( dns );
	}

	if ( creds ) {
		for ( i = 0; i < ndns; i++ ) {
			if ( creds[i].bv_val != nullstr ) {
				free( creds[i].bv_val );
			}
		}
		free( creds );
	}

	return 0;
}
