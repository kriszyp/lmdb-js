/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/errno.h>
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"

static void
usage( const char *s )
{
	fprintf( stderr,
"usage: %s [options] DN <attr:value|attr::b64value>\n"
"where:\n"
"  DN\tDistinguished Name\n"
"  attr\tassertion attribute\n"
"  value\tassertion value\n"
"  b64value\tbase64 encoding of assertion value\n"

"Common options:\n"
"  -d level   set LDAP debugging level to `level'\n"
"  -D binddn  bind DN\n"
"  -h host    LDAP server\n"
"  -H URI     LDAP Uniform Resource Indentifier(s)\n"
"  -I         use SASL Interactive mode\n"
"  -k         use Kerberos authentication\n"
"  -K         like -k, but do only step 1 of the Kerberos bind\n"
"  -M         enable Manage DSA IT control (-MM to make critical)\n"
"  -n         show what would be done but don't actually compare\n"
"  -O props   SASL security properties\n"
"  -p port    port on LDAP server\n"
"  -P version procotol version (default: 3)\n"
"  -z         Quiet mode, don't print anything, use return values\n"
"  -Q         use SASL Quiet mode\n"
"  -R realm   SASL realm\n"
"  -U authcid SASL authentication identity\n"
"  -v         run in verbose mode (diagnostics to standard output)\n"
"  -w passwd  bind passwd (for simple authentication)\n"
"  -W         prompt for bind passwd\n"
"  -x         Simple authentication\n"
"  -X authzid SASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"  -Y mech    SASL mechanism\n"
"  -Z         Start TLS request (-ZZ to require successful response)\n"
, s );

	exit( EXIT_FAILURE );
}

static int docompare LDAP_P((
	LDAP *ld,
	char *dn,
	char *attr,
	struct berval *bvalue,
	int quiet,
	LDAPControl **sctrls,
	LDAPControl **cctrls));

static char *prog = NULL;
static char	*binddn = NULL;
static struct berval passwd = { 0, NULL };
static char	*ldaphost = NULL;
static char *ldapuri = NULL;
static int	ldapport = 0;
#ifdef HAVE_CYRUS_SASL
static unsigned sasl_flags = LDAP_SASL_AUTOMATIC;
static char	*sasl_realm = NULL;
static char	*sasl_authc_id = NULL;
static char	*sasl_authz_id = NULL;
static char	*sasl_mech = NULL;
static char	*sasl_secprops = NULL;
#endif
static int	use_tls = 0;
static int	verbose, not;

int
main( int argc, char **argv )
{
	char	*compdn = NULL, *attrs = NULL;
	char	*sep;
	int		rc, i, manageDSAit, quiet;
	int		referrals, debug;
	int		authmethod, version, want_bindpw;
	LDAP	*ld = NULL;
	struct berval bvalue = { 0, NULL };

	debug = verbose = not = referrals =
		manageDSAit = want_bindpw = quiet = 0;

	version = -1;

	authmethod = -1;

	prog = (prog = strrchr(argv[0], *LDAP_DIRSEP)) == NULL ? argv[0] : prog + 1;

	while (( i = getopt( argc, argv,
		"Cd:D:h:H:IkKMnO:p:P:qQR:U:vw:WxX:Y:zZ")) != EOF )
	{
		switch( i ) {

		/* Common Options */
		case 'C':
			referrals++;
			break;
		case 'd':
			debug |= atoi( optarg );
			break;
		case 'D':	/* bind DN */
			if( binddn != NULL ) {
				fprintf( stderr, "%s: -D previously specified\n", prog );
				return EXIT_FAILURE;
			}
			binddn = strdup( optarg );
			break;
		case 'h':	/* ldap host */
			if( ldapuri != NULL ) {
				fprintf( stderr, "%s: -h incompatible with -H\n", prog );
				return EXIT_FAILURE;
			}
			if( ldaphost != NULL ) {
				fprintf( stderr, "%s: -h previously specified\n", prog );
				return EXIT_FAILURE;
			}
			ldaphost = strdup( optarg );
			break;
		case 'H':	/* ldap URI */
			if( ldaphost != NULL ) {
				fprintf( stderr, "%s: -H incompatible with -h\n", prog );
				return EXIT_FAILURE;
			}
			if( ldapport ) {
				fprintf( stderr, "%s: -H incompatible with -p\n", prog );
				return EXIT_FAILURE;
			}
			if( ldapuri != NULL ) {
				fprintf( stderr, "%s: -H previously specified\n", prog );
				return EXIT_FAILURE;
			}
			ldapuri = strdup( optarg );
			break;
		case 'I':
#ifdef HAVE_CYRUS_SASL
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -I incompatible with version %d\n",
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
			sasl_flags = LDAP_SASL_INTERACTIVE;
			break;
#else
			fprintf( stderr, "%s: was not compiled with SASL support\n",
				prog );
			return( EXIT_FAILURE );
#endif
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
		case 'n':	/* print compares, don't actually do them */
			++not;
			break;
		case 'O':
#ifdef HAVE_CYRUS_SASL
			if( sasl_secprops != NULL ) {
				fprintf( stderr, "%s: -O previously specified\n", prog );
				return EXIT_FAILURE;
			}
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -O incompatible with LDAPv%d\n",
					prog, version );
				return EXIT_FAILURE;
			}
			if( authmethod != -1 && authmethod != LDAP_AUTH_SASL ) {
				fprintf( stderr, "%s: incompatible previous "
					"authentication choice\n", prog );
				return EXIT_FAILURE;
			}
			authmethod = LDAP_AUTH_SASL;
			version = LDAP_VERSION3;
			sasl_secprops = strdup( optarg );
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
				prog );
			return( EXIT_FAILURE );
#endif
			break;
		case 'p':
			if( ldapport ) {
				fprintf( stderr, "%s: -p previously specified\n", prog );
				return EXIT_FAILURE;
			}
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
		case 'Q':
#ifdef HAVE_CYRUS_SASL
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -Q incompatible with version %d\n",
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
			sasl_flags = LDAP_SASL_QUIET;
			break;
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
				prog );
			return( EXIT_FAILURE );
#endif
		case 'R':
#ifdef HAVE_CYRUS_SASL
			if( sasl_realm != NULL ) {
				fprintf( stderr, "%s: -R previously specified\n", prog );
				return EXIT_FAILURE;
			}
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -R incompatible with version %d\n",
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
			sasl_realm = strdup( optarg );
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
				prog );
			return( EXIT_FAILURE );
#endif
			break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
			if( sasl_authc_id != NULL ) {
				fprintf( stderr, "%s: -U previously specified\n", prog );
				return EXIT_FAILURE;
			}
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
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
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

				for( p = optarg; *p != '\0'; p++ ) {
					*p = '\0';
				}
			}
			passwd.bv_len = strlen( passwd.bv_val );
			break;
		case 'W':
			want_bindpw++;
			break;
		case 'Y':
#ifdef HAVE_CYRUS_SASL
			if( sasl_mech != NULL ) {
				fprintf( stderr, "%s: -Y previously specified\n", prog );
				return EXIT_FAILURE;
			}
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
			sasl_mech = strdup( optarg );
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
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
			if( sasl_authz_id != NULL ) {
				fprintf( stderr, "%s: -X previously specified\n", prog );
				return EXIT_FAILURE;
			}
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
#else
			fprintf( stderr, "%s: not compiled with SASL support\n",
				prog );
			return( EXIT_FAILURE );
#endif
			break;
		case 'z':
			quiet++;
			break;
		case 'Z':
#ifdef HAVE_TLS
			if( version == LDAP_VERSION2 ) {
				fprintf( stderr, "%s: -Z incompatible with version %d\n",
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
			fprintf( stderr, "%s: unrecognized option -%c\n",
				prog, optopt );
			usage( argv[0] );
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

	if ( argc - optind != 2 ) {
		usage( argv[ 0 ] );
	}

	compdn = argv[optind++];
	attrs = argv[optind++];

	/* user passed in only 2 args, the last one better be in
	 * the form attr:value or attr::b64value
	 */
	sep = strchr(attrs, ':');
	if (!sep) {
		usage( argv[ 0 ] );
	}

	*sep++='\0';
	if ( *sep != ':' ) {
		bvalue.bv_val = strdup( sep );
		bvalue.bv_len = strlen( bvalue.bv_val );

	} else {
		/* it's base64 encoded. */
		bvalue.bv_val = malloc( strlen( &sep[1] ));
		bvalue.bv_len = lutil_b64_pton( &sep[1],
			bvalue.bv_val, strlen( &sep[1] ));

		if (bvalue.bv_len == -1) {
			fprintf(stderr, "base64 decode error\n");
			exit(-1);
		}
	}

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug )
			!= LBER_OPT_SUCCESS )
		{
			fprintf( stderr,
				"Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug )
			!= LDAP_OPT_SUCCESS )
		{
			fprintf( stderr,
				"Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
		ldif_debug = debug;
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

	if( ( ldaphost != NULL || ldapport ) && ( ldapuri == NULL ) ) {
		if ( verbose ) {
			fprintf( stderr, "ldap_init( %s, %d )\n",
				ldaphost != NULL ? ldaphost : "<DEFAULT>",
				ldapport );
		}

		ld = ldap_init( ldaphost, ldapport );
		if( ld == NULL ) {
			perror("ldapcompare: ldap_init");
			return EXIT_FAILURE;
		}

	} else {
		if ( verbose ) {
			fprintf( stderr, "ldap_initialize( %s )\n",
				ldapuri != NULL ? ldapuri : "<DEFAULT>" );
		}

		rc = ldap_initialize( &ld, ldapuri );
		if( rc != LDAP_SUCCESS ) {
			fprintf( stderr,
				"Could not create LDAP session handle (%d): %s\n",
				rc, ldap_err2string(rc) );
			return EXIT_FAILURE;
		}
	}


	/* referrals */
	if (ldap_set_option( ld, LDAP_OPT_REFERRALS,
		referrals ? LDAP_OPT_ON : LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
		return EXIT_FAILURE;
	}

	if (version == -1 ) {
		version = LDAP_VERSION3;
	}

	if( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version )
		!= LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
			version );
		return EXIT_FAILURE;
	}

	if ( use_tls && ( ldap_start_tls_s( ld, NULL, NULL ) != LDAP_SUCCESS )) {
		ldap_perror( ld, "ldap_start_tls" );
		if ( use_tls > 1 ) {
			return EXIT_FAILURE;
		}
	}

	if (want_bindpw) {
		passwd.bv_val = getpassphrase("Enter LDAP Password: ");
		passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		void *defaults;

		if( sasl_secprops != NULL ) {
			rc = ldap_set_option( ld, LDAP_OPT_X_SASL_SECPROPS,
				(void *) sasl_secprops );

			if( rc != LDAP_OPT_SUCCESS ) {
				fprintf( stderr,
					"Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n",
					sasl_secprops );
				return EXIT_FAILURE;
			}
		}

		defaults = lutil_sasl_defaults( ld,
			sasl_mech,
			sasl_realm,
			sasl_authc_id,
			passwd.bv_val,
			sasl_authz_id );

		rc = ldap_sasl_interactive_bind_s( ld, binddn,
			sasl_mech, NULL, NULL,
			sasl_flags, lutil_sasl_interact, defaults );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_interactive_bind_s" );
			return EXIT_FAILURE;
		}
#else
		fprintf( stderr, "%s: not compiled with SASL support\n",
			prog, argv[0] );
		return EXIT_FAILURE;
#endif
	} else {
		if ( ldap_bind_s( ld, binddn, passwd.bv_val, authmethod )
				!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
			return EXIT_FAILURE;
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

		err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, ctrls );

		if( err != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set ManageDSAit %scontrol\n",
				c.ldctl_iscritical ? "critical " : "" );
			if( c.ldctl_iscritical ) {
				return EXIT_FAILURE;
			}
		}
	}

	if ( verbose ) {
		fprintf( stderr, "DN:%s, attr:%s, value:%s\n",
			compdn, attrs, sep );
	}

	rc = docompare( ld, compdn, attrs, &bvalue, quiet, NULL, NULL );

	free( bvalue.bv_val );

	ldap_unbind( ld );

	return rc;
}


static int docompare(
	LDAP *ld,
	char *dn,
	char *attr,
	struct berval *bvalue,
	int quiet,
	LDAPControl **sctrls,
	LDAPControl **cctrls )
{
	int			rc;

	if ( not ) {
		return LDAP_SUCCESS;
	}

	rc = ldap_compare_ext_s( ld, dn, attr, bvalue,
		sctrls, cctrls );

	if ( rc == -1 ) {
		ldap_perror( ld, "ldap_result" );
		return( rc );
	}

	/* if we were told to be quiet, use the return value. */
	if ( !quiet ) {
		if ( rc == LDAP_COMPARE_TRUE ) {
			rc = 0;
			printf("TRUE\n");
		} else if ( rc == LDAP_COMPARE_FALSE ) {
			rc = 0;
			printf("FALSE\n");
		} else {
			ldap_perror( ld, "ldap_compare" );
		}
	}

	return( rc );
}

