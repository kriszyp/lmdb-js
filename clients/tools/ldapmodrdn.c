/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
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

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>

static char	*binddn = NULL;
static char	*passwd = NULL;
static char	*ldaphost = NULL;
static int	ldapport = 0;
static int	not, verbose, contoper;
static LDAP	*ld;

static int domodrdn(
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    char	*newSuperior,
    int		remove );	/* flag: remove old RDN */

int
main(int argc, char **argv)
{
	char		*usage = "usage: %s [-nvkWc] [-M[M]] [-d debug-level] [-h ldaphost] [-P version] [-p ldapport] [-D binddn] [-w passwd] [ -f file | < entryfile | dn newrdn ] [-s newSuperior]\n";
    char		*myname,*infile, *entrydn, *rdn, buf[ 4096 ];
    FILE		*fp;
	int		rc, i, remove, havedn, authmethod, version, want_bindpw, debug, manageDSAit;
    char	*newSuperior=NULL;

    infile = NULL;
    not = contoper = verbose = remove = want_bindpw = debug = manageDSAit = 0;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    myname = (myname = strrchr(argv[0], '/')) == NULL ? argv[0] : ++myname;

    while (( i = getopt( argc, argv, "WkKMcnvrh:P:p:D:w:d:f:s:" )) != EOF ) {
	switch( i ) {
	case 'k':	/* kerberos bind */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
		return( EXIT_FAILURE );
#endif
	    break;
	case 'K':	/* kerberos bind, part one only */
#ifdef HAVE_KERBEROS
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
		return( EXIT_FAILURE );
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
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
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
	case 'M':
		/* enable Manage DSA IT */
		manageDSAit++;
		break;
	case 'W':
		want_bindpw++;
		break;
	case 'P':
		switch( atoi(optarg) )
		{
		case 2:
			version = LDAP_VERSION2;
			break;
		case 3:
			version = LDAP_VERSION3;
			break;
		default:
			fprintf( stderr, "protocol version should be 2 or 3\n" );
		    fprintf( stderr, usage, argv[0] );
		    return( EXIT_FAILURE );
		}
		break;
	default:
	    fprintf( stderr, usage, argv[0] );
	    return( EXIT_FAILURE );
	}
    }

	if( authmethod != LDAP_AUTH_SIMPLE ) {
		if( version == LDAP_VERSION3 ) {
			fprintf(stderr, "Kerberos requires LDAPv2\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION2;
	}

	if( manageDSAit ) {
		if( version == LDAP_VERSION2 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

    if (newSuperior != NULL) {
		if (version == LDAP_VERSION2) {
			fprintf( stderr,
				"%s: version conflict!, -s newSuperior requires LDAPv3\n",
				myname);
			fprintf( stderr, usage, argv[0] );
			return( EXIT_FAILURE );
		}

		/* promote to LDAPv3 */
		version = LDAP_VERSION3;
    }
    
    havedn = 0;
    if (argc - optind == 2) {
	if (( rdn = strdup( argv[argc - 1] )) == NULL ) {
	    perror( "strdup" );
	    return( EXIT_FAILURE );
	}
        if (( entrydn = strdup( argv[argc - 2] )) == NULL ) {
	    perror( "strdup" );
	    return( EXIT_FAILURE );
        }
	++havedn;
    } else if ( argc - optind != 0 ) {
	fprintf( stderr, "%s: invalid number of arguments, only two allowed\n", myname);
	fprintf( stderr, usage, argv[0] );
	return( EXIT_FAILURE );
    }

    if ( infile != NULL ) {
	if (( fp = fopen( infile, "r" )) == NULL ) {
	    perror( infile );
	    return( EXIT_FAILURE );
	}
    } else {
	fp = stdin;
    }

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug ) != LBER_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

    if (( ld = ldap_init( ldaphost, ldapport )) == NULL ) {
	perror( "ldap_init" );
	return( EXIT_FAILURE );
    }

	/* this seems prudent */
	{
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref);
	}
	/* don't chase referrals */
	ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );


	if (version != -1 &&
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS)
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

    if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	ldap_perror( ld, "ldap_bind" );
	return( EXIT_FAILURE );
    }

	if ( manageDSAit ) {
		int err;
		LDAPControl c;
		LDAPControl *ctrls[2];
		ctrls[0] = &c;
		ctrls[1] = NULL;

		c.ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		c.ldctl_value.bv_val = NULL;
		c.ldctl_value.bv_len = 0;
		c.ldctl_iscritical = manageDSAit > 1;

		err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, &ctrls );

		if( err != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set Manage DSA IT Control\n" );
			if( c.ldctl_iscritical ) {
				exit( EXIT_FAILURE );
			}
		}
	}

    rc = 0;
    if (havedn)
	rc = domodrdn( ld, entrydn, rdn, newSuperior, remove );
    else while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	if ( *buf != '\0' ) {	/* blank lines optional, skip */
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove nl */

	    if ( havedn ) {	/* have DN, get RDN */
		if (( rdn = strdup( buf )) == NULL ) {
                    perror( "strdup" );
                    return( EXIT_FAILURE );
		}
		rc = domodrdn(ld, entrydn, rdn, newSuperior, remove );
		havedn = 0;
	    } else if ( !havedn ) {	/* don't have DN yet */
	        if (( entrydn = strdup( buf )) == NULL ) {
		    perror( "strdup" );
		    return( EXIT_FAILURE );
	        }
		++havedn;
	    }
	}
    }

    ldap_unbind( ld );

	/* UNREACHABLE */
	return( rc );
}

static int domodrdn(
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    char	*newSuperior,
    int		remove ) /* flag: remove old RDN */
{
    int	i;

    if ( verbose ) {
		printf( "Renaming \"%s\"\n", dn );
		printf( "\tnew rdn=\"%s\" (%s old rdn)\n",
			rdn, remove ? "delete" : "keep" );
		if( newSuperior != NULL ) {
			printf("\tnew parent=\"%s\"\n", newSuperior);
		}
	}

    if ( !not ) {
	i = ldap_rename2_s( ld, dn, rdn, newSuperior, remove );
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
