/* ldapmodrdn.c - generic program to modify an entry's RDN using LDAP.
 *
 * Support for MODIFYDN REQUEST V3 (newSuperior) by:
 * 
 * Copyright 1999, Juan C. Gomez, All rights reserved.
 * This software is not subject to any license of Silicon Graphics 
 * Inc. or Purdue University.
 *
 * Redistribution and use in source and binary forms are permitted
 * without restriction or fee of any kind as long as this notice
 * is preserved.
 *
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
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

#define safe_realloc( ptr, size )	( (ptr) == NULL ? malloc( size ) : \
					 realloc( ptr, size ))

static int domodrdn LDAP_P((
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    int		remove,		/* flag: remove old RDN */
    char	*newSuperior));

int
main(int argc, char **argv)
{
	char		*usage = "usage: %s [-nvkWc] [-d debug-level] [-h ldaphost] [-P version] [-p ldapport] [-D binddn] [-w passwd] [ -f file | < entryfile | dn newrdn ] [-s newSuperior]\n";
    char		*myname,*infile, *entrydn, *rdn, buf[ 4096 ];
    FILE		*fp;
	int		rc, i, remove, havedn, authmethod, version, want_bindpw, debug;
    char	*newSuperior=NULL;

    infile = NULL;
    not = contoper = verbose = remove = want_bindpw = debug = 0;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    myname = (myname = strrchr(argv[0], '/')) == NULL ? argv[0] : ++myname;

    while (( i = getopt( argc, argv, "WkKcnvrh:P:p:D:w:d:f:s:" )) != EOF ) {
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
	case 's':	/* newSuperior */
	    newSuperior = strdup( optarg );
	    version = LDAP_VERSION3;	/* This option => force V3 */
	    break;
	case 'w':	/* password */
	    passwd = strdup( optarg );
	    break;
	case 'd':
	    debug |= atoi( optarg );
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

    if ((newSuperior != NULL) && (version != LDAP_VERSION3))
    {
	fprintf( stderr,
		 "%s: version conflict!, -s newSuperior requires LDAP v3\n",
		 myname);
	fprintf( stderr, usage, argv[0] );
	exit( 1 );
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

	if ( debug ) {
		ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug );
		ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug );
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

    if (( ld = ldap_init( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_init" );
	exit( 1 );
    }

	/* this seems prudent */
	{
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref);
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

	if( version != -1) {
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version );
	}

    if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_bind" );
	exit( 1 );
    }

    rc = 0;
    if (havedn)
	rc = domodrdn(ld, entrydn, rdn, remove, newSuperior);
    else while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	if ( *buf != '\0' ) {	/* blank lines optional, skip */
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove nl */

	    if ( havedn ) {	/* have DN, get RDN */
		if (( rdn = strdup( buf )) == NULL ) {
                    perror( "strdup" );
                    exit( 1 );
		}
		rc = domodrdn(ld, entrydn, rdn, remove, newSuperior);
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
    int		remove,		/* flag: remove old RDN */
    char	*newSuperior)
{
    int	i;

    if ( verbose ) {
	printf( "modrdn %s:\n\t%s\n", dn, rdn );
	if (remove)
	    printf("removing old RDN\n");
	else
	    printf("keeping old RDN\n");
	if(newSuperior!=NULL)
	    printf("placing node under a new parent = %s\n", newSuperior);
    }

    if ( !not ) {
	i = ldap_rename2_s( ld, dn, rdn, remove, newSuperior );
	if ( i != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_rename2_s" );
	} else if ( verbose ) {
	    printf( "modrdn complete\n" );
	}
    } else {
	i = LDAP_SUCCESS;
    }

    return( i );
}
