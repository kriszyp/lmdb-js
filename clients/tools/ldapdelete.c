/* ldapdelete.c - simple program to delete an entry using LDAP */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <ac/string.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>

static char	*binddn = NULL;
static char	*passwd = NULL;
static char	*base = NULL;
static char	*ldaphost = NULL;
static int	ldapport = 0;
static int	not, verbose, contoper;
static LDAP	*ld;

#define safe_realloc( ptr, size )	( ptr == NULL ? malloc( size ) : \
					 realloc( ptr, size ))

static int dodelete LDAP_P((
    LDAP	*ld,
    char	*dn));

int
main( int argc, char **argv )
{
	char		*usage = "usage: %s [-n] [-v] [-k] [-W] [-d debug-level] [-f file] [-h ldaphost] [-P version] [-p ldapport] [-D binddn] [-w passwd] [dn]...\n";
    char		buf[ 4096 ];
    FILE		*fp;
	int		i, rc, authmethod, want_bindpw, version, debug;

    not = verbose = contoper = want_bindpw = debug = 0;
    fp = NULL;
    authmethod = LDAP_AUTH_SIMPLE;
	version = LDAP_VERSION2;

    while (( i = getopt( argc, argv, "WnvkKch:P:p:D:w:d:f:" )) != EOF ) {
	switch( i ) {
	case 'k':	/* kerberos bind */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
	    break;
	case 'K':	/* kerberos bind, part one only */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
	    break;
	case 'c':	/* continuous operation mode */
	    ++contoper;
	    break;
	case 'h':	/* ldap host */
	    ldaphost = strdup( optarg );
	    break;
	case 'D':	/* bind DN */
	    binddn = strdup( optarg );
	    break;
	case 'w':	/* password */
	    passwd = strdup( optarg );
	    break;
	case 'f':	/* read DNs from a file */
	    if (( fp = fopen( optarg, "r" )) == NULL ) {
		perror( optarg );
		exit( 1 );
	    }
	    break;
	case 'd':
	    debug |= atoi( optarg );
	    break;
	case 'p':
	    ldapport = atoi( optarg );
	    break;
	case 'n':	/* print deletes, don't actually do them */
	    ++not;
	    break;
	case 'v':	/* verbose mode */
	    verbose++;
	    break;
	case 'W':
		want_bindpw++;
		break;
	case 'P':
		switch(optarg[0])
		{
		case '2':
			version = LDAP_VERSION2;
			break;
		case '3':
			version = LDAP_VERSION3;
			break;
		}
		break;
	default:
	    fprintf( stderr, usage, argv[0] );
	    exit( 1 );
	}
    }

    if ( fp == NULL ) {
	if ( optind >= argc ) {
	    fp = stdin;
	}
    }

	if ( debug ) {
		lber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug );
		ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug );
	}

    if (( ld = ldap_open( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_open" );
	exit( 1 );
    }

	{
		/* this seems prudent */
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref );
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

	ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );

    if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_bind" );
	exit( 1 );
    }

    if ( fp == NULL ) {
	for ( ; optind < argc; ++optind ) {
	    rc = dodelete( ld, argv[ optind ] );
	}
    } else {
	rc = 0;
	while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove trailing newline */
	    if ( *buf != '\0' ) {
		rc = dodelete( ld, buf );
	    }
	}
    }

    ldap_unbind( ld );

    exit( rc );

	/* UNREACHABLE */
	return(0);
}


static int dodelete(
    LDAP	*ld,
    char	*dn)
{
    int	rc;

    if ( verbose ) {
	printf( "%sdeleting entry %s\n", not ? "!" : "", dn );
    }
    if ( not ) {
	rc = LDAP_SUCCESS;
    } else {
	if (( rc = ldap_delete_s( ld, dn )) != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_delete" );
	} else if ( verbose ) {
	    printf( "entry removed\n" );
	}
    }

    return( rc );
}
