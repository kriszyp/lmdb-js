/* ldapmodrdn.c - generic program to modify an entry's RDN using LDAP */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
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

static int domodrdn LDAP_P((
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    int		remove));	/* flag: remove old RDN */

int
main(int argc, char **argv)
{
    char		*usage = "usage: %s [-nvkc] [-d debug-level] [-h ldaphost] [-p ldapport] [-D binddn] [-w passwd] [ -f file | < entryfile | dn newrdn ]\n";
    char		*myname,*infile, *entrydn, *rdn, buf[ 4096 ];
    FILE		*fp;
    int			rc, i, kerberos, remove, havedn, authmethod;

    infile = NULL;
    kerberos = not = contoper = verbose = remove = 0;

    myname = (myname = strrchr(argv[0], '/')) == NULL ? argv[0] : ++myname;

    while (( i = getopt( argc, argv, "kKcnvrh:p:D:w:d:f:" )) != EOF ) {
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
	case 'd':
#ifdef LDAP_DEBUG
	    ldap_debug = lber_debug = atoi( optarg );	/* */
#else /* LDAP_DEBUG */
	    fprintf( stderr, "compile with -DLDAP_DEBUG for debugging\n" );
#endif /* LDAP_DEBUG */
	    break;
	case 'f':	/* read from file */
	    infile = strdup( optarg );
	    break;
	case 'p':
	    ldapport = atoi( optarg );
	    break;
	case 'n':	/* print adds, don't actually do them */
	    ++not;
	    break;
	case 'v':	/* verbose mode */
	    verbose++;
	    break;
	case 'r':	/* remove old RDN */
	    remove++;
	    break;
	default:
	    fprintf( stderr, usage, argv[0] );
	    exit( 1 );
	}
    }

    havedn = 0;
    if (argc - optind == 2) {
	if (( rdn = strdup( argv[argc - 1] )) == NULL ) {
	    perror( "strdup" );
	    exit( 1 );
	}
        if (( entrydn = strdup( argv[argc - 2] )) == NULL ) {
	    perror( "strdup" );
	    exit( 1 );
        }
	++havedn;
    } else if ( argc - optind != 0 ) {
	fprintf( stderr, "%s: invalid number of arguments, only two allowed\n", myname);
	fprintf( stderr, usage, argv[0] );
	exit( 1 );
    }

    if ( infile != NULL ) {
	if (( fp = fopen( infile, "r" )) == NULL ) {
	    perror( infile );
	    exit( 1 );
	}
    } else {
	fp = stdin;
    }

    if (( ld = ldap_open( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_open" );
	exit( 1 );
    }

	/* this seems prudent */
	ldap_set_option( ld, LDAP_OPT_DEREF, LDAP_DEREF_NEVER);

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

    rc = 0;
    if (havedn)
	rc = domodrdn(ld, entrydn, rdn, remove);
    else while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	if ( *buf != '\0' ) {	/* blank lines optional, skip */
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove nl */

	    if ( havedn ) {	/* have DN, get RDN */
		if (( rdn = strdup( buf )) == NULL ) {
                    perror( "strdup" );
                    exit( 1 );
		}
		rc = domodrdn(ld, entrydn, rdn, remove);
		havedn = 0;
	    } else if ( !havedn ) {	/* don't have DN yet */
	        if (( entrydn = strdup( buf )) == NULL ) {
		    perror( "strdup" );
		    exit( 1 );
	        }
		++havedn;
	    }
	}
    }

    ldap_unbind( ld );

    exit( rc );

	/* UNREACHABLE */
	return(0);
}

static int domodrdn(
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    int		remove)	/* flag: remove old RDN */
{
    int	i;

    if ( verbose ) {
	printf( "modrdn %s:\n\t%s\n", dn, rdn );
	if (remove)
	    printf("removing old RDN\n");
	else
	    printf("keeping old RDN\n");
    }

    if ( !not ) {
	i = ldap_modrdn2_s( ld, dn, rdn, remove );
	if ( i != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_modrdn2_s" );
	} else if ( verbose ) {
	    printf( "modrdn complete\n" );
	}
    } else {
	i = LDAP_SUCCESS;
    }

    return( i );
}
