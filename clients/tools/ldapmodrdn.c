/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ldap.h>

static char	*binddn = NULL;
static struct berval passwd = { 0, NULL};
static char	*ldaphost = NULL;
static int	ldapport = 0;
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

static int domodrdn(
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    char	*newSuperior,
    int		remove );	/* flag: remove old RDN */

static void
usage( const char *s )
{
	fprintf( stderr,
"Rename LDAP entries\n\n"
"usage: %s [options] [dn rdn]\n"
"	dn rdn: If given, rdn will replace the RDN of the entry specified by DN\n"
"		If not given, the list of modifications is read from stdin or\n"
"		from the file specified by \"-f file\" (see man page).\n"
"options:\n"
"	-c\t\tcontinuous operation mode (do not stop on errors)\n"
"	-C\t\tchase referrals\n"
"	-d level\tset LDAP debugging level to `level'\n"
"	-D binddn\tbind DN\n"
"	-E\t\trequest SASL privacy (-EE to make it critical)\n"
"	-f file\t\tdo renames listed in `file'\n"
"	-h host\t\tLDAP server\n"
"	-I\t\trequest SASL integrity checking (-II to make it\n"
"		\tcritical)\n"
"	-k\t\tuse Kerberos authentication\n"
"	-K\t\tlike -k, but do only step 1 of the Kerberos bind\n"
"	-M\t\tenable Manage DSA IT control (-MM to make it critical)\n"
"	-n\t\tshow what would be done but don't actually do it\n"
"	-p port\t\tport on LDAP server\n"
"	-P version\tprocotol version (default: 3)\n"
"	-r\t\tremove old RDN\n"
"	-s newsuperior\tnew superior entry\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\trun in verbose mode (diagnostics to standard output)\n"
"	-w passwd\tbind passwd (for simple authentication)\n"
"	-W\t\tprompt for bind passwd\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-Z\t\tissue Start TLS request (-ZZ to require successful response)\n"
,		s );

	exit( EXIT_FAILURE );
}

int
main(int argc, char **argv)
{
    char		*myname,*infile, *entrydn = NULL, *rdn = NULL, buf[ 4096 ];
    FILE		*fp;
	int		rc, i, remove, havedn, authmethod, version, want_bindpw, debug, manageDSAit;
	int		referrals;
    char	*newSuperior=NULL;

    infile = NULL;
    not = contoper = verbose = remove = want_bindpw =
		debug = manageDSAit = referrals = 0;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    myname = (myname = strrchr(argv[0], '/')) == NULL ? argv[0] : ++myname;

    while (( i = getopt( argc, argv, "cCD:d:Ef:h:IKkMnP:p:rs:U:vWw:X:Y:Z" )) != EOF ) {
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
	case 'C':
		referrals++;
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
	    passwd.bv_val = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
		passwd.bv_len = strlen( passwd.bv_val );
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
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf( stderr, "SASL requires LDAPv3\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION3;
	}

	if( manageDSAit ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

	if( use_tls ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "Start TLS requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

    if (newSuperior != NULL) {
		if (version == LDAP_VERSION2) {
			fprintf( stderr,
				"%s: version conflict!, -s newSuperior requires LDAPv3\n",
				myname);
			usage( argv[0] );
			return( EXIT_FAILURE );
		}
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
	usage( argv[0] );
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

	/* referrals */
	if( ldap_set_option( ld, LDAP_OPT_REFERRALS,
		referrals ? LDAP_OPT_ON : LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
		return EXIT_FAILURE;
	}

	if (version == -1 ) {
		version = 3;
	}

	if( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version )
		!= LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
			version );
		return EXIT_FAILURE;
	}

	if ( use_tls && ldap_start_tls_s( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		if ( use_tls > 1 ) {
			ldap_perror( ld, "ldap_start_tls" );
			return( EXIT_FAILURE );
		}
		fprintf( stderr, "WARNING: could not start TLS\n" );
	}

	if (want_bindpw) {
		passwd.bv_val = getpassphrase("Enter LDAP Password: ");
		passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
	}

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
		
		rc = ldap_negotiated_sasl_bind_s( ld, binddn, sasl_authc_id,
				sasl_authz_id, sasl_mech,
				passwd.bv_len ? &passwd : NULL,
				NULL, NULL );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_negotiated_sasl_bind_s" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
	}
	else {
		if ( ldap_bind_s( ld, binddn, passwd.bv_val, authmethod )
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
			fprintf( stderr, "Could not set ManageDSAit %scontrol\n",
				c.ldctl_iscritical ? "critical " : "" );
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
	int rc, code, id;
	char *matcheddn=NULL, *text=NULL, **refs=NULL;
	LDAPMessage *res;

    if ( verbose ) {
		printf( "Renaming \"%s\"\n", dn );
		printf( "\tnew rdn=\"%s\" (%s old rdn)\n",
			rdn, remove ? "delete" : "keep" );
		if( newSuperior != NULL ) {
			printf("\tnew parent=\"%s\"\n", newSuperior);
		}
	}

	if( not ) return LDAP_SUCCESS;

	rc = ldap_rename( ld, dn, rdn, newSuperior, remove,
		NULL, NULL, &id );

	if ( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "ldapmodrdn: ldap_rename: %s (%d)\n",
			ldap_err2string( rc ), rc );
		return rc;
	}

	rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res );
	if ( rc < 0 ) {
		ldap_perror( ld, "ldapmodrdn: ldap_result" );
		return rc;
	}

	rc = ldap_parse_result( ld, res, &code, &matcheddn, &text, &refs, NULL, 1 );

	if( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "ldapmodrdn: ldap_parse_result: %s (%d)\n",
			ldap_err2string( rc ), rc );
		return rc;
	}

	if( verbose || code != LDAP_SUCCESS ||
		(matcheddn && *matcheddn) || (text && *text) || (refs && *refs) )
	{
		printf( "Rename Result: %s (%d)\n",
			ldap_err2string( code ), code );

		if( text && *text ) {
			printf( "Additional info: %s\n", text );
		}

		if( matcheddn && *matcheddn ) {
			printf( "Matched DN: %s\n", matcheddn );
		}

		if( refs ) {
			int i;
			for( i=0; refs[i]; i++ ) {
				printf("Referral: %s\n", refs[i] );
			}
		}
	}

	ber_memfree( text );
	ber_memfree( matcheddn );
	ber_memvfree( (void **) refs );

	return code;
}
