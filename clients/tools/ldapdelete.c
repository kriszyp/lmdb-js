/* ldapdelete.c - simple program to delete an entry using LDAP */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>

#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <ldap.h>
#include "lutil_ldap.h"
#include "ldap_defaults.h"

static char	*prog;
static char	*binddn = NULL;
static struct berval passwd = { 0, NULL };
static char	*ldaphost = NULL;
static int	ldapport = 0;
static int	prune = 0;
#ifdef HAVE_CYRUS_SASL
static char	*sasl_authc_id = NULL;
static char	*sasl_authz_id = NULL;
static char	*sasl_mech = NULL;
static char	*sasl_secprops = NULL;
#endif
static int	use_tls = 0;
static int	not, verbose, contoper;
static LDAP	*ld;

static int dodelete LDAP_P((
    LDAP *ld,
    const char *dn));

static int deletechildren LDAP_P((
	LDAP *ld,
	const char *dn ));

static void
usage( const char *s )
{
	fprintf( stderr,
"Delete entries from an LDAP server\n\n"
"usage: %s [options] [dn]...\n"
"	dn: list of DNs to delete. If not given, it will be readed from stdin\n"
"	    or from the file specified with \"-f file\".\n"
"Delete Options:\n"
"	-r\t\tdelete recursively\n"
"Common options:\n"
"	-c\t\tcontinuous operation mode (do not stop on errors)\n"
"	-C\t\tchase referrals\n"
"	-d level\tset LDAP debugging level to `level'\n"
"	-D binddn\tbind DN\n"
"	-f file\t\tread operations from `file'\n"
"	-h host\t\tLDAP server\n"
"	-k\t\tuse Kerberos authentication\n"
"	-K\t\tlike -k, but do only step 1 of the Kerberos bind\n"
"	-M\t\tenable Manage DSA IT control (-MM to make it critical)\n"
"	-n\t\tshow what would be done but don't actually delete\n"
"	-O secprops\tSASL security properties\n"
"	-p port\t\tport on LDAP server\n"
"	-P version\tprocotol version (default: 3)\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\trun in verbose mode (diagnostics to standard output)\n"
"	-w passwd\tbind passwd (for simple authentication)\n"
"	-W\t\tprompt for bind passwd\n"
"	-x\t\tSimple authentication\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-Z\t\tissue Start TLS request (-ZZ to require successful response)\n"
,		s );

	exit( EXIT_FAILURE );
}


int
main( int argc, char **argv )
{
	char		buf[ 4096 ];
	FILE		*fp;
	int		i, rc, authmethod, referrals, want_bindpw, version, debug, manageDSAit;

    not = verbose = contoper = want_bindpw = debug = manageDSAit = referrals = 0;
    fp = NULL;
    authmethod = -1;
	version = -1;

    prog = (prog = strrchr(argv[0], *LDAP_DIRSEP)) == NULL ? argv[0] : ++prog;

    while (( i = getopt( argc, argv, "cf:r" "Cd:D:h:kKMnO:p:P:U:vw:WxX:Y:Z" )) != EOF ) {
	switch( i ) {
	/* Delete Specific Options */
	case 'c':	/* continuous operation mode */
	    ++contoper;
	    break;
	case 'f':	/* read DNs from a file */
	    if (( fp = fopen( optarg, "r" )) == NULL ) {
		perror( optarg );
		exit( EXIT_FAILURE );
	    }
	    break;
	case 'r':
		prune = 1;
		break;

	/* Common Options */
	case 'C':
		referrals++;
		break;
	case 'd':
	    debug |= atoi( optarg );
	    break;
	case 'D':	/* bind DN */
	    binddn = strdup( optarg );
	    break;
	case 'h':	/* ldap host */
	    ldaphost = strdup( optarg );
	    break;
	case 'k':	/* kerberos bind */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -k incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}

		if( authmethod != -1 ) {
			fprintf( stderr, "%s: -k incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
			
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf( stderr, "%s: not compiled with Kerberos support\n", prog );
		return EXIT_FAILURE;
#endif
	    break;
	case 'K':	/* kerberos bind, part one only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -k incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 ) {
			fprintf( stderr, "%s: incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}

		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf( stderr, "%s: not compiled with Kerberos support\n", prog );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'M':
		/* enable Manage DSA IT */
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -M incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		manageDSAit++;
		version = LDAP_VERSION3;
		break;
	case 'n':	/* print deletes, don't actually do them */
	    ++not;
	    break;
	case 'O':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s -O incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		sasl_secprops = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'p':
	    ldapport = atoi( optarg );
	    break;
	case 'P':
		switch( atoi(optarg) ) {
		case 2:
			if( version == LDAP_VERSION3 ) {
				fprintf( stderr, "%s: -P 2 incompatible with version %d\n",
					prog, version );
				return EXIT_FAILURE;
			}
			version = LDAP_VERSION2;
			break;
		case 3:
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -P 2 incompatible with version %d\n",
					prog, version );
				return EXIT_FAILURE;
			}
			version = LDAP_VERSION3;
			break;
		default:
			fprintf( stderr, "%s: protocol version should be 2 or 3\n",
				prog );
			usage( prog );
			return( EXIT_FAILURE );
		} break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -U incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible previous "
				"authentication choice\n",
				prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;

		sasl_authc_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s: was not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'v':	/* verbose mode */
	    verbose++;
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
	case 'W':
		want_bindpw++;
		break;
	case 'Y':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -Y incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: incompatible with authentication choice\n", prog );
			return EXIT_FAILURE;
		}

		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;
#else
		fprintf( stderr, "%s: was not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'x':
		if( authmethod != -1 && authmethod != LDAP_AUTH_SIMPLE ) {
			fprintf( stderr, "%s: incompatible with previous "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SIMPLE;
		break;
	case 'X':
#ifdef HAVE_CYRUS_SASL
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s: -X incompatible with LDAPv%d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
			fprintf( stderr, "%s: -X incompatible with "
				"authentication choice\n", prog );
			return EXIT_FAILURE;
		}
		authmethod = LDAP_AUTH_SASL;
		version = LDAP_VERSION3;

		sasl_authz_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Z':
#ifdef HAVE_TLS
		if( version == LDAP_VERSION2 ) {
			fprintf( stderr, "%s -Z incompatible with version %d\n",
				prog, version );
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
		use_tls++;
#else
		fprintf( stderr, "%s: not compiled with TLS support\n",
			prog );
		return( EXIT_FAILURE );
#endif
		break;
	default:
		fprintf( stderr, "%s: unrecongized option -%c\n",
			prog, optopt );
		usage( prog );
		return( EXIT_FAILURE );
	}
    }

	if (version == -1) {
		version = LDAP_VERSION3;
	}
	if (authmethod == -1 && version > LDAP_VERSION2) {
#ifdef HAVE_CYRUS_SASL
		authmethod = LDAP_AUTH_SASL;
#else
		authmethod = LDAP_AUTH_SIMPLE;
#endif
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
		/* this seems prudent for searches below */
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref );
	}

	/* chase referrals */
	if( ldap_set_option( ld, LDAP_OPT_REFERRALS,
		referrals ? LDAP_OPT_ON : LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
		return EXIT_FAILURE;
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
			return EXIT_FAILURE;
		}
		fprintf( stderr, "WARNING: could not start TLS\n" );
	}

	if (want_bindpw) {
		passwd.bv_val = getpassphrase("Enter LDAP Password: ");
		passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		if( sasl_secprops != NULL ) {
			rc = ldap_set_option( ld, LDAP_OPT_X_SASL_SECPROPS,
				(void *) sasl_secprops );
			
			if( rc != LDAP_OPT_SUCCESS ) {
				fprintf( stderr,
					"Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n",
					sasl_secprops );
				return( EXIT_FAILURE );
			}
		}
		
		rc = ldap_sasl_interactive_bind_s( ld, binddn,
			sasl_mech, NULL, NULL, lutil_sasl_interact );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_interactive_bind_s" );
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
    const char	*dn)
{
	int id;
	int	rc, code;
	char *matcheddn = NULL, *text = NULL, **refs = NULL;
	LDAPMessage *res;

	if ( verbose ) {
		printf( "%sdeleting entry \"%s\"\n",
			(not ? "!" : ""), dn );
	}

	if ( not ) {
		return LDAP_SUCCESS;
	}

	/* If prune is on, remove a whole subtree.  Delete the children of the
	 * DN recursively, then the DN requested.
	 */
	if ( prune ) deletechildren( ld, dn );

	rc = ldap_delete_ext( ld, dn, NULL, NULL, &id );
	if ( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "ldapdelete: ldap_delete_ext: %s (%d)\n",
			ldap_err2string( rc ), rc );
		return rc;
	}

	rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res );
	if ( rc < 0 ) {
		ldap_perror( ld, "ldapdelete: ldap_result" );
		return rc;
	}

	rc = ldap_parse_result( ld, res, &code, &matcheddn, &text, &refs, NULL, 1 );

	if( rc != LDAP_SUCCESS ) {
		fprintf( stderr, "ldapdelete: ldap_parse_result: %s (%d)\n",
			ldap_err2string( rc ), rc );
		return rc;
	}

	if( verbose || code != LDAP_SUCCESS ||
		(matcheddn && *matcheddn) || (text && *text) || (refs && *refs) )
	{
		printf( "Delete Result: %s (%d)\n", ldap_err2string( code ), code );

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

/*
 * Delete all the children of an entry recursively until leaf nodes are reached.
 *
 */
static int deletechildren(
	LDAP *ld,
	const char *dn )
{
	LDAPMessage *res, *e;
	int entries;
	int rc;
	static char *attrs[] = { "1.1", NULL };

	if ( verbose ) printf ( "deleting children of: %s\n", dn );
	/*
	 * Do a one level search at dn for children.  For each, delete its children.
	 */

	rc = ldap_search_ext_s( ld, dn, LDAP_SCOPE_ONELEVEL, NULL, attrs, 1,
		NULL, NULL, NULL, -1, &res );
	if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_search" );
		return( rc );
	}

	entries = ldap_count_entries( ld, res );

	if ( entries > 0 ) {
		int i;

		for (e = ldap_first_entry( ld, res ), i = 0; e != NULL;
			e = ldap_next_entry( ld, e ), i++ )
		{
			char *dn = ldap_get_dn( ld, e );

			if( dn == NULL ) {
				ldap_perror( ld, "ldap_prune" );
				ldap_get_option( ld, LDAP_OPT_ERROR_NUMBER, &rc );
				ber_memfree( dn );
				return rc;
			}

			rc = deletechildren( ld, dn );
			if ( rc == -1 ) {
				ldap_perror( ld, "ldap_prune" );
				ber_memfree( dn );
				return rc;
			}

			if ( verbose ) {
				printf( "\tremoving %s\n", dn );
			}

			rc = ldap_delete_s( ld, dn );
			if ( rc == -1 ) {
				ldap_perror( ld, "ldap_delete" );
				ber_memfree( dn );
				return rc;

			}
			
			if ( verbose ) {
				printf( "\t%s removed\n", dn );
			}

			ber_memfree( dn );
		}
	}

	ldap_msgfree( res );
	return rc;
}
