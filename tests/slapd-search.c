#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#include <sys/param.h>

#include "lber.h"
#include "ldap.h"

#define LOOPS	100

static void
do_search( char *host, int port, char *sbase, char *filter, int maxloop );

static void
usage( char *name )
{
	fprintf( stderr, "usage: %s [-h <host>] -p port -b <searchbase> -f <searchfiter> [-l <loops>]\n",
			name );
	exit( 1 );
}

int
main( int argc, char **argv )
{
	int		i, j;
	char        *host = "localhost";
	int			port = -1;
	char        *sbase = NULL;
	char		*filter  = NULL;
	int			loops = LOOPS;

	while ( (i = getopt( argc, argv, "h:p:b:f:l:" )) != EOF ) {
		switch( i ) {
			case 'h':		/* the servers host */
				host = strdup( optarg );
			break;

			case 'p':		/* the servers port */
				port = atoi( optarg );
				break;

			case 'b':		/* file with search base */
				sbase = strdup( optarg );
			break;

			case 'f':		/* the search request */
				filter = strdup( optarg );
				break;

			case 'l':		/* number of loops */
				loops = atoi( optarg );
				break;

			default:
				usage( argv[0] );
				break;
		}
	}

	if (( sbase == NULL ) || ( filter == NULL ) || ( port == -1 ))
		usage( argv[0] );

	if ( *filter == '\0' ) {

		fprintf( stderr, "%s: invalid EMPTY search filter.\n",
				argv[0] );
		exit( 1 );

	}

	do_search( host, port, sbase, filter, loops );

	exit( 0 );
}


static void
do_search( char *host, int port, char *sbase, char *filter, int maxloop )
{
	LDAP	*ld;
	int  	i;
	char	*attrs[] = { "cn", "sn", NULL };

	if (( ld = ldap_init( host, port )) == NULL ) {
		perror( "ldap_init" );
		exit( 1 );
	}

	if ( ldap_bind_s( ld, NULL, NULL, LDAP_AUTH_SIMPLE ) != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_bind" );
		 exit( 1 );
	}


	fprintf( stderr, "Search(%d): base=\"%s\", filter=\"%s\".\n",
		maxloop, sbase, filter );

	for ( i = 0; i < maxloop; i++ ) {
		 LDAPMessage *res;

		if ( ldap_search_s( ld, sbase, LDAP_SCOPE_SUBTREE,
				filter, attrs, 0, &res ) != LDAP_SUCCESS ) {

			ldap_perror( ld, "ldap_search" );
			break;

		}

		ldap_msgfree( res );
	}

	ldap_unbind( ld );
}


