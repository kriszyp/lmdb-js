/* ldapdelete.c - simple program to delete an entry using LDAP */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
static int	prune = 0;
#ifdef HAVE_CYRUS_SASL
static char	*sasl_authc_id = NULL;
static char	*sasl_authz_id = NULL;
static char	*sasl_mech = NULL;
static int	sasl_integrity = 0;
static int	sasl_privacy = 0;
#endif
static int	use_tls = 0;
static int	not, verbose, contoper;
static LDAP	*ld;

static int dodelete LDAP_P((
    LDAP	*ld,
    char	*dn));

static int deletechildren LDAP_P(( LDAP *ld,
                                   char *dn ));

static void
usage( const char *s )
{
	fprintf( stderr,
"Delete entries from an LDAP server\n\n"
"usage: %s [options] [dn]...\n"
"	dn: list of DNs to delete. If not given, it will be readed from stdin\n"
"	    or from the file specified with \"-f file\".\n"
"options:\n"
"	-c\t\tcontinuous operation mode (do not stop on errors)\n"
"	-d level\tset LDAP debugging level to `level'\n"
"	-D binddn\tbind DN\n"
"	-E\t\trequest SASL privacy (-EE to make it critical)\n"
"	-f file\t\tdelete DNs listed in `file'\n"
"	-h host\t\tLDAP server\n"
"	-I\t\trequest SASL integrity checking (-II to make it\n"
"		\tcritical)\n"
"	-k\t\tuse Kerberos authentication\n"
"	-K\t\tlike -k, but do only step 1 of the Kerberos bind\n"
"	-M\t\tenable Manage DSA IT control (-MM to make it critical)\n"
"	-n\t\tshow what would be done but don't actually delete\n"
"	-p port\t\tport on LDAP server\n"
"	-P version\tprocotol version (2 or 3)\n"
"	-r\t\tdelete recursively\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\trun in verbose mode (diagnostics to standard output)\n"
"	-w passwd\tbind passwd (for simple authentication)\n"
"	-W\t\tprompt for bind passwd\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-Z\t\trequest the use of TLS (-ZZ to make it critical)\n"
,		s );

	exit( EXIT_FAILURE );
}


int
main( int argc, char **argv )
{
	char		buf[ 4096 ];
	FILE		*fp;
	int		i, rc, authmethod, want_bindpw, version, debug, manageDSAit;

    not = verbose = contoper = want_bindpw = debug = manageDSAit = 0;
    fp = NULL;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    while (( i = getopt( argc, argv, "cD:d:Ef:h:IKkMnP:p:rU:vWw:X:Y:Z" )) != EOF ) {
	switch( i ) {
	case 'k':	/* kerberos bind */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'K':	/* kerberos bind, part one only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
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
	case 'w':	/* password */
	    passwd = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
	    break;
	case 'f':	/* read DNs from a file */
	    if (( fp = fopen( optarg, "r" )) == NULL ) {
		perror( optarg );
		exit( EXIT_FAILURE );
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
	case 'r':
		prune = 1;
		break;
	case 'v':	/* verbose mode */
	    verbose++;
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
			usage( argv[0] );
			return( EXIT_FAILURE );
		}
		break;
	case 'I':
#ifdef HAVE_CYRUS_SASL
		sasl_integrity++;
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'E':
#ifdef HAVE_CYRUS_SASL
		sasl_privacy++;
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Y':
#ifdef HAVE_CYRUS_SASL
		if ( strcasecmp( optarg, "any" ) && strcmp( optarg, "*" ) ) {
			sasl_mech = strdup( optarg );
		}
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
		sasl_authc_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'X':
#ifdef HAVE_CYRUS_SASL
		sasl_authz_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Z':
#ifdef HAVE_TLS
		use_tls++;
#else
		fprintf( stderr, "%s was not compiled with TLS support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	default:
		usage( argv[0] );
		return( EXIT_FAILURE );
	}
    }

	if ( ( authmethod == LDAP_AUTH_KRBV4 ) || ( authmethod ==
			LDAP_AUTH_KRBV41 ) ) {
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "Kerberos requires LDAPv2\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION2;
	}
	else if ( authmethod == LDAP_AUTH_SASL ) {
		if( version != -1 || version != LDAP_VERSION3 ) {
			fprintf( stderr, "SASL requires LDAPv3\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION3;
	}

	if( manageDSAit ) {
		if( version != -1 || version != LDAP_VERSION3 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

	if( use_tls ) {
		if( version != -1 || version != LDAP_VERSION3 ) {
			fprintf(stderr, "Start TLS requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

    if ( fp == NULL ) {
	if ( optind >= argc ) {
	    fp = stdin;
	}
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

	{
		/* this seems prudent */
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref );
	}

	/* don't chase referrals */
	ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );

	if (version != -1 &&
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS)
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n", version );
	}

	if ( use_tls && ldap_start_tls( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		if ( use_tls > 1 ) {
			ldap_perror( ld, "ldap_start_tls" );
			return( EXIT_FAILURE );
		}
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		int	minssf = 0, maxssf = 0;

		if ( sasl_integrity > 0 )
			maxssf = 1;
		if ( sasl_integrity > 1 )
			minssf = 1;
		if ( sasl_privacy > 0 )
			maxssf = 100000; /* Something big value */
		if ( sasl_privacy > 1 )
			minssf = 56;
		
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MINSSF,
				(void *)&minssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MINSSF"
				"%d\n", minssf);
			return( EXIT_FAILURE );
		}
		if ( ldap_set_option( ld, LDAP_OPT_X_SASL_MAXSSF,
				(void *)&maxssf ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_X_SASL_MAXSSF"
				"%d\n", maxssf);
			return( EXIT_FAILURE );
		}
		
		if ( ldap_negotiated_sasl_bind_s( ld, binddn, sasl_authc_id,
				sasl_authz_id, sasl_mech, NULL, NULL, NULL )
					!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_bind" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
	}
	else {
		if ( ldap_bind_s( ld, binddn, passwd, authmethod )
				!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
			return( EXIT_FAILURE );
		}
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
    if ( fp == NULL ) {
	for ( ; optind < argc; ++optind ) {
	    rc = dodelete( ld, argv[ optind ] );
	}
    } else {
	while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	    buf[ strlen( buf ) - 1 ] = '\0';	/* remove trailing newline */
	    if ( *buf != '\0' ) {
		rc = dodelete( ld, buf );
	    }
	}
    }

    ldap_unbind( ld );

	return( rc );
}


static int dodelete(
    LDAP	*ld,
    char	*dn)
{
    int	rc;

    if ( verbose ) {
	printf( "%sdeleting entry \"%s\"\n",
		(not ? "!" : ""), dn );
    }
    if ( not ) {
	rc = LDAP_SUCCESS;
    } else {
		/* If prune is on, remove a whole subtree.  Delete the children of the
		 * DN recursively, then the DN requested.
		 */
		if ( prune ) deletechildren( ld, dn );
		if (( rc = ldap_delete_s( ld, dn )) != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_delete" );
	} else if ( verbose ) {
	    printf( "\tremoved\n" );
	}
    }

    return( rc );
}

/*
 * Delete all the children of an entry recursively until leaf nodes are reached.
 *
 */
static int deletechildren( LDAP *ld,
                           char *dn )
{
    LDAPMessage *res, *e;
    int entries;
    int rc;
	int timeout = 30 * 10000;

    ldap_set_option( ld, LDAP_OPT_TIMEOUT, &timeout );
    if ( verbose ) printf ( "deleting children of: %s\n", dn );
    /*
     * Do a one level search at dn for children.  For each, delete its children.
     */
    if ( ldap_search_s( ld, dn, LDAP_SCOPE_ONELEVEL, NULL, NULL, 0, &res ) == -1 )
    {
        ldap_perror( ld, "ldap_search" );
		ldap_get_option( ld, LDAP_OPT_ERROR_NUMBER, &rc );
        return( rc );
    }

    entries = ldap_count_entries( ld, res );
    if ( entries > 0 )
    {
        int i;

        for (e = ldap_first_entry( ld, res ), i = 0; e != NULL;
             e = ldap_next_entry( ld, e ), i++ )
        {
            if ( (rc = deletechildren( ld, ldap_get_dn( ld, e) )) == -1 )
            {
                ldap_perror( ld, "ldap_prune" );
                return rc;
            }
            if ( verbose )
            {
                printf( "\tremoving %s\n", ldap_get_dn( ld, e ) );
            }
            if ( ( rc = ldap_delete_s( ld, ldap_get_dn( ld, e ) ) ) == -1 )
            {
                ldap_perror( ld, "ldap_delete" );
                return rc;
            }
            else if ( verbose )
            {
                printf( "\t%s removed\n", ldap_get_dn( ld, e ) );
            }
        }
    }
    ldap_msgfree( res );
    return rc;
}
