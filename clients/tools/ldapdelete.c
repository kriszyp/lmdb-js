/* ldapdelete.c - simple program to delete an entry using LDAP */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <lber.h>
#include <ldap.h>

#include "ldapconfig.h"

static char	*binddn = LDAPDELETE_BINDDN;
static char	*base = LDAPDELETE_BASE;
static char	*passwd = NULL;
static char	*ldaphost = LDAPHOST;
static int	ldapport = LDAP_PORT;
static int	not, verbose, contoper;
static LDAP	*ld;

#ifdef LDAP_DEBUG
extern int ldap_debug, lber_debug;
#endif /* LDAP_DEBUG */

#define safe_realloc( ptr, size )	( ptr == NULL ? malloc( size ) : \
					 realloc( ptr, size ))


main( argc, argv )
    int		argc;
    char	**argv;
{
    char		*usage = "usage: %s [-n] [-v] [-k] [-d debug-level] [-f file] [-h ldaphost] [-p ldapport] [-D binddn] [-w passwd] [dn]...\n";
    char		*p, buf[ 4096 ];
    FILE		*fp;
    int			i, rc, kerberos, linenum, authmethod;

    extern char	*optarg;
    extern int	optind;

    kerberos = not = verbose = contoper = 0;
    fp = NULL;

    while (( i = getopt( argc, argv, "nvkKch:p:D:w:d:f:" )) != EOF ) {
	switch( i ) {
	case 'k':	/* kerberos bind */
	    kerberos = 2;
	    break;
	case 'K':	/* kerberos bind, part one only */
	    kerberos = 1;
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
#ifdef LDAP_DEBUG
	    ldap_debug = lber_debug = atoi( optarg );	/* */
#else /* LDAP_DEBUG */
	    fprintf( stderr, "compile with -DLDAP_DEBUG for debugging\n" );
#endif /* LDAP_DEBUG */
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

    if (( ld = ldap_open( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_open" );
	exit( 1 );
    }

    ld->ld_deref = LDAP_DEREF_NEVER;	/* prudent, but probably unnecessary */

    if ( !kerberos ) {
	authmethod = LDAP_AUTH_SIMPLE;
    } else if ( kerberos == 1 ) {
	authmethod = LDAP_AUTH_KRBV41;
    } else {
	authmethod = LDAP_AUTH_KRBV4;
    }
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
}


dodelete( ld, dn )
    LDAP	*ld;
    char	*dn;
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
